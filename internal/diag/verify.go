package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// Result is the outcome of a live proof-of-work verification (§3 Layer 3).
type Result struct {
	Pass       bool      `json:"pass"`
	LatencyMs  int64     `json:"latency_ms"`
	Finding    Finding   `json:"finding"`
	ClientLog string `json:"client_log,omitempty"`
	// ServerLog is the INBOUND core's own output.
	//
	// It was thrown away, and it is the only witness for a whole class of
	// failure: when the server accepts a connection and then tears it down —
	// because its ShadowTLS camouflage target is dead, because a detour points
	// nowhere — the client sees nothing but "connection reset by peer". That is
	// indistinguishable from a firewall, so the verdict said "confirm the core is
	// listening and the firewall permits it" about a core that was listening and
	// a firewall that was not involved, which is worse than saying nothing.
	ServerLog string `json:"server_log,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
	// Unprovable marks a config that cannot be proven by this loopback harness —
	// REALITY (needs a live TLS-1.3 dest) and the UDP/QUIC protocols (TUIC,
	// Hysteria2, WireGuard/AmneziaWG, Brook). It is NOT a failure: the config is
	// very likely fine, it just has to be tested from a real client. The UI shows
	// it neutrally rather than as a red ✗.
	Unprovable bool `json:"unprovable,omitempty"`
}

// loopbackUnprovable reports whether a node cannot be honestly proven by the
// TCP-loopback verifier — REALITY and the UDP/QUIC-listening protocols, whose
// server end never opens the TCP port this harness waits on.
func loopbackUnprovable(node *model.Node) bool {
	if node.Security.Type == model.SecReality {
		return true
	}
	switch node.Protocol {
	case model.ProtoHysteria2, model.ProtoTUIC, model.ProtoWireGuard, model.ProtoAmneziaWG, model.ProtoBrook:
		return true
	}
	return false
}

// Cores is where the client/server binaries live.
type Cores struct {
	Singbox string
}

// FindSingbox locates a sing-box binary, or "" if none is installed.
func FindSingbox() string {
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/sing-box", "/usr/local/bin/sing-box"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// VerifySingbox proves an inbound end to end using sing-box for BOTH ends, built
// from ONE canonical node — which is exactly what catches the "client link and
// server inbound disagree" class of bug. It starts the server inbound, starts a
// client whose outbound is rendered from the same node with a local SOCKS port,
// sends a real HTTP request through the tunnel to a known local endpoint, and
// reports PASS/FAIL with measured latency and the client log on failure.
//
// REALITY is skipped here (it requires a live TLS-1.3 dest and cannot be proven
// offline); the caller uses the environment layer for that.
func VerifySingbox(ctx context.Context, node *model.Node, cores Cores) Result {
	now := time.Now()
	if loopbackUnprovable(node) {
		msg := "REALITY can't be proven on loopback (needs a live TLS-1.3 destination) — test it from a real client."
		if node.Security.Type != model.SecReality {
			msg = string(node.Protocol) + " is a UDP/QUIC protocol that can't be proven by the loopback verifier — test it from a real client. This is NOT a failure."
		}
		return Result{Unprovable: true, VerifiedAt: now, Finding: New("FP-VERIFY-UNPROVABLE", msg)}
	}
	bin := cores.Singbox
	if bin == "" {
		bin = FindSingbox()
	}
	if bin == "" {
		return fail(now, "FP-VERIFY-CORE-DOWN", "sing-box binary not available to run the verification")
	}

	// A known local origin the tunnelled request must reach intact.
	const body = "forgepanel-verify-ok"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer origin.Close()

	srvPort := freePort()
	socksPort := freePort()

	// Server node: bind localhost:srvPort.
	srv := clone(node)
	srv.Address = "127.0.0.1"
	srv.Port = srvPort
	srvIn, err := render.SingboxInbound(srv)
	if err != nil {
		return fail(now, "FP-VERIFY-CONFIG", "cannot render server inbound: "+err.Error())
	}
	serverCfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{srvIn},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}

	// Client node: outbound dials 127.0.0.1:srvPort; self-signed TLS is accepted.
	cli := clone(node)
	cli.Address = "127.0.0.1"
	cli.Port = srvPort
	if cli.Security.Type == model.SecTLS {
		cli.Security.AllowInsecure = true
	}
	// Plural: ShadowTLS renders as a pair, and verifying with only the
	// camouflage half would report a protocol as working when the config it
	// hands to clients carries no traffic.
	rendered, err := render.SingboxOutbounds(cli)
	if err != nil {
		return fail(now, "FP-VERIFY-CONFIG", "cannot render client outbound: "+err.Error())
	}
	render.RetagOutbounds(rendered, "proxy")
	clientOuts := make([]any, 0, len(rendered)+1)
	for _, o := range rendered {
		clientOuts = append(clientOuts, o)
	}
	clientOuts = append(clientOuts, map[string]any{"type": "direct", "tag": "direct"})
	clientCfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": clientOuts,
		"route":     map[string]any{"final": "proxy"},
	}

	dir, _ := os.MkdirTemp("", "fp-verify-")
	defer os.RemoveAll(dir)
	writeJSON(filepath.Join(dir, "server.json"), serverCfg)
	writeJSON(filepath.Join(dir, "client.json"), clientCfg)

	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var serverLog capture
	serverProc := exec.CommandContext(sctx, bin, "run", "-c", filepath.Join(dir, "server.json"))
	serverProc.Stderr = &serverLog
	if err := serverProc.Start(); err != nil {
		return fail(now, "FP-VERIFY-CORE-DOWN", "server core failed to start: "+err.Error())
	}
	defer kill(serverProc)
	if !waitPort("127.0.0.1", srvPort, 5*time.Second) {
		return fail(now, "FP-VERIFY-CORE-DOWN", "server core did not open its port")
	}

	var clientLog capture
	clientProc := exec.CommandContext(sctx, bin, "run", "-c", filepath.Join(dir, "client.json"))
	clientProc.Stderr = &clientLog
	if err := clientProc.Start(); err != nil {
		return fail(now, "FP-VERIFY-CORE-DOWN", "client core failed to start: "+err.Error())
	}
	defer kill(clientProc)
	if !waitPort("127.0.0.1", socksPort, 5*time.Second) {
		return Result{Pass: false, VerifiedAt: now, ClientLog: clientLog.String(),
			Finding: New("FP-VERIFY-CORE-DOWN", "client core did not open its SOCKS port")}
	}

	// Real traffic: HTTP GET through the SOCKS tunnel.
	start := time.Now()
	got, err := fetchThroughSocks(socksPort, origin.URL)
	lat := time.Since(start).Milliseconds()
	if err != nil || got != body {
		// One "verification failed" for every runtime failure sent operators
		// hunting through a client log for a cause the evidence already named,
		// so the cause is classified here and carried in the code.
		log := clientLog.waitForLog(500 * time.Millisecond)
		slog := serverLog.waitForLog(500 * time.Millisecond)
		code := classifyVerifyFailure(err, got, body, log, slog)
		return Result{Pass: false, LatencyMs: lat, VerifiedAt: now, ClientLog: log, ServerLog: slog,
			Finding: New(code, fmt.Sprintf("traffic did not arrive intact: got %q err %v", got, err))}
	}
	return Result{Pass: true, LatencyMs: lat, VerifiedAt: now, Finding: New(verifySuccessCode(lat), fmt.Sprintf("%dms", lat))}
}

// --- helpers --------------------------------------------------------------

func clone(n *model.Node) *model.Node {
	b, _ := json.Marshal(n)
	var c model.Node
	json.Unmarshal(b, &c)
	return &c
}

// fail builds a failed Result under a taxonomy code. Every failure path names
// the cause it actually observed rather than the generic FP-VERIFY-FAIL, which
// is now reserved for evidence that points at nothing in particular.
func fail(now time.Time, code, msg string) Result {
	return Result{Pass: false, VerifiedAt: now, Finding: New(code, msg)}
}

// degradedLatencyMs is the loopback round trip above which a pass is reported
// as degraded. Both cores run on this machine with no network in between, so a
// healthy round trip is tens of milliseconds; seconds means the core is starved
// or the transport is doing something expensive and wrong.
const degradedLatencyMs = 2000

// verifySuccessCode grades a pass. The tunnel carried traffic either way, so
// Result.Pass stays true; the code is what tells the operator it is not healthy.
func verifySuccessCode(latencyMs int64) string {
	if latencyMs >= degradedLatencyMs {
		return "FP-VERIFY-DEGRADED"
	}
	return "FP-VERIFY-OK"
}

// classifyVerifyFailure maps the transport error and the client core's log onto
// the failure taxonomy: net_unreachable, handshake_failed, auth_rejected or
// tunnel_no_data. It returns the generic FP-VERIFY-FAIL when nothing in the
// evidence distinguishes a cause, because naming the wrong cause is worse than
// admitting we do not know which one it was.
func classifyVerifyFailure(err error, got, want, clientLog, serverLog string) string {
	// The SERVER's own log is consulted first, because it is the only witness
	// for a failure the server causes and then hides.
	//
	// When the inbound accepts a connection and tears it down — its ShadowTLS
	// camouflage host is dead, a detour points nowhere — the client sees
	// "connection reset by peer" and nothing else. That is byte-identical to
	// what a firewall produces, so classifying from the client alone returned
	// FP-VERIFY-NET-UNREACHABLE, whose remedy is "confirm the core is listening
	// on that port and that the host firewall permits it" — advice about a core
	// that WAS listening and a firewall that was not involved. Sending an
	// operator to inspect the wrong subsystem is worse than the generic verdict
	// this taxonomy replaced.
	if c := classifyFromServerLog(serverLog); c != "" {
		return c
	}
	if err == nil {
		// The request completed, so the tunnel was up end to end — the payload
		// itself is what did not survive.
		if got != want {
			return "FP-VERIFY-NO-DATA"
		}
		return "FP-VERIFY-FAIL"
	}
	// The client core's own log is the better witness: the SOCKS layer collapses
	// every remote cause into "general SOCKS server failure".
	hay := strings.ToLower(err.Error() + "\n" + clientLog)
	// Auth is checked first: an authentication rejection usually also tears the
	// connection down, so the log carries reset/EOF noise alongside the real
	// cause and a network-first order would mislabel it.
	for _, m := range []string{
		"authentication failed", "auth failed", "authentication error",
		"invalid user", "unknown user", "user not found", "unauthorized",
		"wrong password", "invalid password", "bad password",
		"invalid request from", "invalid uuid", "invalid key",
	} {
		if strings.Contains(hay, m) {
			return "FP-VERIFY-AUTH"
		}
	}
	for _, m := range []string{
		"handshake", "tls:", "x509", "certificate", "bad record mac",
		"unknown certificate", "protocol version", "reality",
	} {
		if strings.Contains(hay, m) {
			return "FP-VERIFY-HANDSHAKE"
		}
	}
	for _, m := range []string{
		"connection refused", "connection reset", "no route to host",
		"network is unreachable", "host is unreachable", "i/o timeout",
		"broken pipe", "eof", "timeout",
	} {
		if strings.Contains(hay, m) {
			return "FP-VERIFY-NET-UNREACHABLE"
		}
	}
	return "FP-VERIFY-FAIL"
}

// classifyFromServerLog names a cause the inbound core reported about itself,
// or "" when its log says nothing decisive.
//
// Only server-side causes belong here. A reset or a timeout in the server log
// is as ambiguous as it is in the client's, so those are deliberately absent:
// this returns a verdict only when the server has said something the client
// could not possibly know.
func classifyFromServerLog(serverLog string) string {
	if strings.TrimSpace(serverLog) == "" {
		return ""
	}
	hay := strings.ToLower(serverLog)
	// The inbound could not reach something IT dials — the ShadowTLS handshake
	// host being the case that motivated this. The connection dies at the
	// server, and the client cannot tell that from a blocked port.
	for _, m := range []string{
		"handshake", "shadowtls", "tls:", "x509", "certificate", "reality",
	} {
		if strings.Contains(hay, m) {
			return "FP-VERIFY-HANDSHAKE"
		}
	}
	for _, m := range []string{
		"authentication failed", "auth failed", "invalid user", "unknown user",
		"wrong password", "invalid password", "invalid request from",
	} {
		if strings.Contains(hay, m) {
			return "FP-VERIFY-AUTH"
		}
	}
	return ""
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	_ = os.WriteFile(path, b, 0o600)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(host string, port int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func kill(c *exec.Cmd) {
	if c != nil && c.Process != nil {
		_ = c.Process.Kill()
		_ = c.Wait()
	}
}

func fetchThroughSocks(socksPort int, url string) (string, error) {
	dialer, err := socksDialer("127.0.0.1:" + strconv.Itoa(socksPort))
	if err != nil {
		return "", err
	}
	tr := &http.Transport{DialContext: dialer}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), nil
}

// capture collects a bounded head of the client core's stderr. os/exec copies
// stderr on its own goroutine, so String() is read while Write() may still be
// running: the mutex is what makes that legal rather than a data race.
type capture struct {
	mu sync.Mutex
	b  []byte
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.b) < 8192 {
		c.b = append(c.b, p...)
	}
	return len(p), nil
}

func (c *capture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.b)
}

// waitForLog gives the client core a moment to flush the line explaining a
// failure. The core writes its log from another process, so reading it the
// instant the request fails usually catches nothing — and an empty log is
// exactly the evidence classifyVerifyFailure needs to name the cause, so
// without this wait a resettable connection is regularly reported as the
// generic "we do not know why" verdict.
func (c *capture) waitForLog(d time.Duration) string {
	deadline := time.Now().Add(d)
	for {
		if s := c.String(); s != "" {
			return s
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// socksDialer returns a DialContext that routes through a SOCKS5 proxy.
func socksDialer(addr string) (func(ctx context.Context, network, target string) (net.Conn, error), error) {
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, network, target string) (net.Conn, error) {
		return d.Dial(network, target)
	}, nil
}
