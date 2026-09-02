package singboxapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// End to end: the PANEL's own builder produces the config, a real sing-box runs
// it, real Hysteria2 traffic goes through, and the panel's own client reads the
// per-user counters back.
//
// It needs a sing-box built with -tags with_v2ray_api, which the official
// release archives are not. FORGEPANEL_SINGBOX_V2RAY points at one; without it
// the test skips rather than pretending to have covered this.
func v2raySingbox(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("FORGEPANEL_SINGBOX_V2RAY")
	if bin == "" {
		t.Skip("set FORGEPANEL_SINGBOX_V2RAY to a sing-box built with -tags with_v2ray_api")
	}
	if sup := Detect(bin); !sup.Supported {
		t.Skipf("%s cannot report per-user traffic: %s", bin, sup.Reason)
	}
	return bin
}

func TestSingboxReportsPerUserHysteria2Traffic(t *testing.T) {
	bin := v2raySingbox(t)
	dir := t.TempDir()
	certPath, keyPath := e2eCert(t, dir)

	apiPort := freePort(t)
	hyPort := freePort(t)

	// Build through the panel's own aggregator, with the stats section enabled
	// exactly as a real reload would.
	prev := engine.SingboxAPIPort
	engine.SingboxAPIPort = apiPort
	t.Cleanup(func() { engine.SingboxAPIPort = prev })

	n := &model.Node{
		Protocol: model.ProtoHysteria2, Address: "127.0.0.1", Port: hyPort, Remark: "hy2-metered",
		Password: "template-unused",
		Security: model.Security{Type: model.SecTLS, ServerName: "example.com",
			CertificateFile: certPath, KeyFile: keyPath},
	}
	n.Normalize()
	specs := []engine.InboundSpec{{Node: n, Clients: []engine.ClientCred{
		{Email: "u42", Password: "pw-u42"},
	}}}

	b, err := engine.BuildMulti(specs, 10099, certPath, keyPath)
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) > 0 {
		t.Fatalf("inbound skipped: %+v", b.Skipped)
	}
	// The stats section must be present, and must ENUMERATE the user: sing-box
	// collects nothing from `enabled: true` alone, and reports an empty result
	// that reads exactly like an idle server.
	var cfg map[string]any
	if err := json.Unmarshal(b.Singbox, &cfg); err != nil {
		t.Fatal(err)
	}
	exp, _ := cfg["experimental"].(map[string]any)
	api, _ := exp["v2ray_api"].(map[string]any)
	stats, _ := api["stats"].(map[string]any)
	users, _ := stats["users"].([]any)
	if len(users) != 1 || users[0] != "u42" {
		t.Fatalf("the stats section does not enumerate the user: %v", stats)
	}

	srvCfg := filepath.Join(dir, "server.json")
	if err := os.WriteFile(srvCfg, b.Singbox, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startSB(t, bin, srvCfg)
	defer srv()

	// A client that speaks hysteria2 as u42, and an origin to fetch.
	origin := startOrigin(t, 40000)
	socks := freePort(t)
	cliCfg := filepath.Join(dir, "client.json")
	writeJSON(t, cliCfg, map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": socks,
		}},
		"outbounds": []any{map[string]any{
			"type": "hysteria2", "tag": "out",
			"server": "127.0.0.1", "server_port": hyPort, "password": "pw-u42",
			"tls": map[string]any{"enabled": true, "server_name": "example.com", "insecure": true},
		}},
	})
	cli := startSB(t, bin, cliCfg)
	defer cli()

	waitFor(t, 20*time.Second, func() error {
		return fetchThroughSocks(socks, origin)
	})

	// Read the counters the way the panel does.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got map[string]int64
	waitFor(t, 15*time.Second, func() error {
		var err error
		got, err = Query(ctx, fmt.Sprintf("127.0.0.1:%d", apiPort), "user>>>", false)
		if err != nil {
			return err
		}
		if got["user>>>u42>>>traffic>>>downlink"] < 40000 {
			return fmt.Errorf("downlink is %d, want at least the 40000 bytes fetched",
				got["user>>>u42>>>traffic>>>downlink"])
		}
		return nil
	})

	if got["user>>>u42>>>traffic>>>uplink"] <= 0 {
		t.Errorf("uplink is %d, want a positive count", got["user>>>u42>>>traffic>>>uplink"])
	}
	t.Logf("metered hysteria2 for u42: up=%d down=%d",
		got["user>>>u42>>>traffic>>>uplink"], got["user>>>u42>>>traffic>>>downlink"])
}

// --- helpers ---------------------------------------------------------------

func startSB(t *testing.T, bin, cfg string) func() {
	t.Helper()
	cmd := exec.Command(bin, "run", "-c", cfg)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sing-box: %v", err)
	}
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

func startOrigin(t *testing.T, size int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, size)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String() + "/"
}

func fetchThroughSocks(socksPort int, url string) error {
	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
	out, err := exec.Command("curl", "-s", "--max-time", "8", "--proxy", proxyURL,
		"-o", "/dev/null", "-w", "%{http_code}", url).CombinedOutput()
	if err != nil {
		return fmt.Errorf("curl: %v (%s)", err, out)
	}
	if string(out) != "200" {
		return fmt.Errorf("fetch returned %q", out)
	}
	return nil
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func e2eCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	cp := filepath.Join(dir, "c.pem")
	kp := filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return cp, kp
}

// freePort returns a port nothing is listening on. Local to this package since
// the code moved out of internal/core, where the original lived.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitFor polls until a condition holds. Local copy for the same reason as
// freePort: the code under test moved out of internal/core.
func waitFor(t *testing.T, d time.Duration, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if last = cond(); last == nil {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("condition never held within %s: %v", d, last)
}
