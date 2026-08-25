package render

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// xhttpNode is a VLESS node with the full modern XHTTP field set plus REALITY,
// which is the combination operators actually deploy against Iranian DPI.
func xhttpNode() *model.Node {
	return &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.10", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Tag: "xh",
		Transport: model.Transport{
			Network: model.NetXHTTP, Path: "/xh", Host: "edge.example.com",
			Headers:   map[string]string{"X-Real-IP": "198.51.100.7"},
			XHTTPMode: model.XHTTPModePacketUp, XPaddingB: "100-1000",
			XPaddingObfsMode: true, XPaddingKey: "x_padding", XPaddingHeader: "X-Padding",
			XPaddingPlacement: "queryInHeader", XPaddingMethod: "tokenish",
			NoGRPCHeader: true, NoSSEHeader: true,
			SCMaxEachPostBytes: "1000000", SCMinPostsIntervalMs: "30",
			SCMaxBufferedPosts: 30, SCStreamUpServerSecs: "20-80",
			SessionPlacement: "header", SessionKey: "x_session",
			SeqPlacement: "cookie", SeqKey: "x_seq",
			UplinkDataPlacement: "cookie", UplinkDataKey: "x_data",
			UplinkHTTPMethod: "GET", UplinkChunkSize: 8192,
			ServerMaxHeaderBytes: 16384,
			XMux: &model.XMux{MaxConcurrency: "16-32", CMaxReuseTimes: "64-128",
				HMaxRequestTime: "800-900", HMaxReusableSecs: "1800-3000", HKeepAlivePeriod: 45},
			XHTTPDownload: &model.XHTTPDownload{
				Address: "dl.example.com", Port: 8443,
				Transport: model.Transport{Network: model.NetXHTTP, Path: "/dl", Host: "dl.example.com",
					XHTTPMode: model.XHTTPModeStreamUp},
				Security: model.Security{Type: model.SecTLS, ServerName: "dl.example.com", Fingerprint: "chrome"},
			},
		},
		Security: model.Security{Type: model.SecReality, ServerName: "www.microsoft.com", Fingerprint: "chrome",
			Reality: &model.Reality{
				Dest: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
				PrivateKey: "WACNs2z5ejGKKUAWvOxDp6jVjSjZL5YJa-8HrTfEyWs",
				PublicKey:  "QGgTZbMYYEqAPnwR2mFmr9RphV5aE1JlrIvIhVmH2Ac",
				ShortIDs:   []string{"0123abcd"}, ShortID: "0123abcd", SpiderX: "/",
			}},
	}
}

// TestXrayXHTTPFullFieldSet: every modern XHTTP knob must reach xhttpSettings.
// Before the field set was rendered, only path/host/mode/xPaddingBytes/xmux were
// emitted, so an operator's padding, session-carriage and flow-control tuning
// was configured in the panel and absent from the running engine.
func TestXrayXHTTPFullFieldSet(t *testing.T) {
	in, err := XrayInbound(xhttpNode())
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	xh := sub(t, sub(t, in, "streamSettings"), "xhttpSettings")

	wantStr := map[string]string{
		"path": "/xh", "host": "edge.example.com", "mode": "packet-up",
		"xPaddingBytes": "100-1000", "xPaddingKey": "x_padding", "xPaddingHeader": "X-Padding",
		"xPaddingPlacement": "queryInHeader", "xPaddingMethod": "tokenish",
		"scMaxEachPostBytes": "1000000", "scMinPostsIntervalMs": "30", "scStreamUpServerSecs": "20-80",
		"sessionPlacement": "header", "sessionKey": "x_session",
		"seqPlacement": "cookie", "seqKey": "x_seq",
		"uplinkDataPlacement": "cookie", "uplinkDataKey": "x_data", "uplinkHTTPMethod": "GET",
	}
	for k, want := range wantStr {
		if got := str(t, xh, k); got != want {
			t.Errorf("xhttpSettings.%s = %q, want %q", k, got, want)
		}
	}
	wantNum := map[string]int{"scMaxBufferedPosts": 30, "uplinkChunkSize": 8192, "serverMaxHeaderBytes": 16384}
	for k, want := range wantNum {
		if got := num(t, xh, k); got != want {
			t.Errorf("xhttpSettings.%s = %d, want %d", k, got, want)
		}
	}
	for _, k := range []string{"xPaddingObfsMode", "noGRPCHeader", "noSSEHeader"} {
		if xh[k] != true {
			t.Errorf("xhttpSettings.%s = %v, want true", k, xh[k])
		}
	}
	if str(t, sub(t, xh, "headers"), "X-Real-IP") != "198.51.100.7" {
		t.Errorf("headers = %v", xh["headers"])
	}
	xm := sub(t, xh, "xmux")
	for k, want := range map[string]string{"maxConcurrency": "16-32", "cMaxReuseTimes": "64-128",
		"hMaxRequestTimes": "800-900", "hMaxReusableSecs": "1800-3000"} {
		if str(t, xm, k) != want {
			t.Errorf("xmux.%s = %v, want %q", k, xm[k], want)
		}
	}
	if num(t, xm, "hKeepAlivePeriod") != 45 {
		t.Errorf("xmux.hKeepAlivePeriod = %v", xm["hKeepAlivePeriod"])
	}
	// downloadSettings is client-side; the core does not act on it for a listener.
	mustAbsent(t, xh, "downloadSettings")
}

// TestXrayXHTTPDownloadSettings: the download leg is a complete second stream —
// its own address/port, transport and TLS layer — and is emitted only on the
// client outbound.
func TestXrayXHTTPDownloadSettings(t *testing.T) {
	out, err := XrayOutbound(xhttpNode())
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	xh := sub(t, sub(t, out, "streamSettings"), "xhttpSettings")
	ds := sub(t, xh, "downloadSettings")
	if str(t, ds, "network") != "xhttp" || str(t, ds, "address") != "dl.example.com" {
		t.Fatalf("downloadSettings = %v", ds)
	}
	if num(t, ds, "port") != 8443 {
		t.Errorf("downloadSettings.port = %v", ds["port"])
	}
	dxh := sub(t, ds, "xhttpSettings")
	if str(t, dxh, "path") != "/dl" || str(t, dxh, "mode") != "stream-up" || str(t, dxh, "host") != "dl.example.com" {
		t.Fatalf("download xhttpSettings = %v", dxh)
	}
	if str(t, ds, "security") != "tls" || str(t, sub(t, ds, "tlsSettings"), "serverName") != "dl.example.com" {
		t.Fatalf("download TLS layer = %v", ds)
	}
	// A download leg never nests another one.
	mustAbsent(t, dxh, "downloadSettings")
	// serverMaxHeaderBytes bounds what a LISTENER accepts; on a client it is noise.
	mustAbsent(t, xh, "serverMaxHeaderBytes")
}

// TestXrayXHTTPOmitsPaddingFamilyWhenObfsOff: emitting a padding key/placement
// the core never reads would advertise a configuration that is not in effect.
func TestXrayXHTTPOmitsPaddingFamilyWhenObfsOff(t *testing.T) {
	n := xhttpNode()
	n.Transport.XPaddingObfsMode = false
	out, err := XrayOutbound(n)
	if err != nil {
		t.Fatalf("XrayOutbound: %v", err)
	}
	xh := sub(t, sub(t, out, "streamSettings"), "xhttpSettings")
	mustAbsent(t, xh, "xPaddingObfsMode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod")
	if str(t, xh, "xPaddingBytes") != "100-1000" {
		t.Errorf("xPaddingBytes must survive with obfuscation off, got %v", xh["xPaddingBytes"])
	}
}

// findXrayBinary locates a usable xray for the config-validation test. The
// pinned binary the panel manages lives under the data dir; a system install or
// an explicit override is accepted too.
func findXrayBinary() string {
	if p := os.Getenv("FORGEPANEL_XRAY_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// The pinned binary the panel manages, then the repo's own test cache
	// (walking up out of the package directory to the repo root).
	home, _ := os.UserHomeDir()
	pats := []string{filepath.Join(home, ".forgepanel", "bin", "xray-*", "xray")}
	for dir, up := ".", 0; up < 5; up, dir = up+1, filepath.Join(dir, "..") {
		pats = append(pats, filepath.Join(dir, "test", "harness", ".cache", "bin", "xray-*", "xray"))
	}
	for _, pat := range pats {
		if ms, _ := filepath.Glob(pat); len(ms) > 0 {
			return ms[len(ms)-1]
		}
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/local/bin/xray", "/usr/bin/xray"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestXrayXHTTPAcceptedByRealCore is the check that matters: a JSON object that
// merely looks right is worthless if the engine refuses it. Both directions of
// the full field set are handed to the actual xray binary's config test.
func TestXrayXHTTPAcceptedByRealCore(t *testing.T) {
	bin := findXrayBinary()
	if bin == "" {
		t.Skip("no xray binary available to validate against")
	}
	dir := t.TempDir()

	n := xhttpNode()
	n.Security.CertificateFile, n.Security.KeyFile = "", ""

	inbound, err := XrayInbound(n)
	if err != nil {
		t.Fatalf("XrayInbound: %v", err)
	}
	srv := jobj{
		"log":       jobj{"loglevel": "warning"},
		"inbounds":  []any{inbound},
		"outbounds": []any{jobj{"protocol": "freedom"}},
	}
	client, err := RenderXrayJSON(n)
	if err != nil {
		t.Fatalf("RenderXrayJSON: %v", err)
	}

	srvJSON, err := json.MarshalIndent(srv, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string][]byte{"inbound.json": srvJSON, "outbound.json": client} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, cfg, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "run", "-test", "-c", p).CombinedOutput()
		if err != nil {
			t.Fatalf("%s rejected by %s: %v\n%s\n%s", name, bin, err, out, cfg)
		}
	}
}

// TestXrayXHTTPModeMatrixAcceptedByRealCore walks every mode against the core,
// with the mode-specific knobs the panel offers for it. This is what catches a
// field that is valid in one mode and refused in another.
func TestXrayXHTTPModeMatrixAcceptedByRealCore(t *testing.T) {
	bin := findXrayBinary()
	if bin == "" {
		t.Skip("no xray binary available to validate against")
	}
	dir := t.TempDir()
	for _, mode := range model.AllXHTTPModes() {
		t.Run(mode, func(t *testing.T) {
			n := xhttpNode()
			n.Security = model.Security{Type: model.SecTLS, ServerName: "edge.example.com", Fingerprint: "chrome"}
			n.Transport.XHTTPMode = mode
			if mode != model.XHTTPModePacketUp {
				// header/cookie uplink carriage and GET are packet-up only.
				n.Transport.UplinkDataPlacement, n.Transport.UplinkDataKey = "body", ""
				n.Transport.UplinkHTTPMethod = "POST"
			}
			if mode == model.XHTTPModeStreamOne {
				n.Transport.XHTTPDownload = nil // refused by the core in this mode
			}
			cfg, err := RenderXrayJSON(n)
			if err != nil {
				t.Fatalf("RenderXrayJSON: %v", err)
			}
			p := filepath.Join(dir, "out-"+mode+".json")
			if err := os.WriteFile(p, cfg, 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(bin, "run", "-test", "-c", p).CombinedOutput(); err != nil {
				t.Fatalf("mode %s rejected: %v\n%s\n%s", mode, err, out, cfg)
			}
		})
	}
}
