//go:build harness

// clientcore.go turns what the panel *emitted* into something a real proxy core
// will run, and then runs it.
//
// The rule the harness holds itself to: the emitted per-node object is used
// verbatim. Anything the harness has to add or change to make the core start is
// recorded as a named mutation on the result, so a green cell that needed help
// is distinguishable from one that did not. That distinction is the entire
// point — a subscription a client cannot run is a broken subscription, however
// well the tunnel underneath it works.
package harness

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Mutation records one change the harness made to an emitted config.
type Mutation struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// ClientConfig is a runnable client configuration derived from a subscription.
type ClientConfig struct {
	Engine    string     `json:"engine"` // "xray" | "sing-box"
	JSON      []byte     `json:"-"`
	SocksPort int        `json:"socks_port"`
	Mutations []Mutation `json:"mutations"`
}

func (c *ClientConfig) note(kind, detail string) {
	c.Mutations = append(c.Mutations, Mutation{Kind: kind, Detail: detail})
}

// FromXraySubscription adapts /sub/<token>/xray. That format already ships a
// complete client config with a SOCKS inbound, so the only change is the local
// listen port, which the harness varies to keep concurrent cases apart.
func FromXraySubscription(raw []byte, socksPort int) (*ClientConfig, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("xray subscription is not JSON: %w", err)
	}
	cfg := &ClientConfig{Engine: "xray", SocksPort: socksPort}
	ins, _ := doc["inbounds"].([]any)
	outs, _ := doc["outbounds"].([]any)
	if countProxyOutbounds(outs) == 0 {
		return nil, fmt.Errorf("xray subscription carries no proxy outbound (the panel dropped this node)")
	}
	found := false
	for _, v := range ins {
		in, _ := v.(map[string]any)
		if in == nil {
			continue
		}
		if in["protocol"] == "socks" {
			in["port"] = socksPort
			in["listen"] = "127.0.0.1"
			found = true
			continue
		}
		// The http inbound would collide between concurrent cases; move it out of
		// the way rather than deleting it, so the emitted shape is preserved.
		if in["protocol"] == "http" {
			in["port"] = socksPort + 1
			in["listen"] = "127.0.0.1"
		}
	}
	if !found {
		return nil, fmt.Errorf("xray subscription has no socks inbound to drive")
	}
	cfg.note("listen-port", fmt.Sprintf("socks inbound retargeted to 127.0.0.1:%d", socksPort))
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	cfg.JSON = b
	return cfg, nil
}

func countProxyOutbounds(outs []any) int {
	n := 0
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil {
			continue
		}
		switch o["protocol"] {
		case "freedom", "blackhole", nil:
			continue
		}
		n++
	}
	return n
}

// FromSingboxSubscription adapts /sub/<token>/sing-box. That format emits only
// log + outbounds, so it cannot be run as handed out; the harness adds the
// local mixed inbound and the route that sends it to the emitted selector, and
// records both as mutations.
func FromSingboxSubscription(raw []byte, socksPort int) (*ClientConfig, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("sing-box subscription is not JSON: %w", err)
	}
	cfg := &ClientConfig{Engine: "sing-box", SocksPort: socksPort}
	outs, _ := doc["outbounds"].([]any)
	var selector string
	proxies := 0
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil {
			continue
		}
		switch o["type"] {
		case "selector":
			selector, _ = o["tag"].(string)
		case "direct", "block":
		default:
			proxies++
		}
	}
	if proxies == 0 {
		return nil, fmt.Errorf("sing-box subscription carries no proxy outbound (the panel dropped this node)")
	}
	if selector == "" {
		return nil, fmt.Errorf("sing-box subscription carries no selector outbound to route to")
	}
	if _, ok := doc["inbounds"]; !ok {
		cfg.note("added-inbound",
			"the sing-box subscription format emits no inbounds[], so it cannot be run as delivered; "+
				"the harness added a mixed inbound on 127.0.0.1 and left every outbound byte-identical")
	}
	doc["inbounds"] = []any{map[string]any{
		"type": "mixed", "tag": "harness-in", "listen": "127.0.0.1", "listen_port": socksPort,
	}}
	doc["route"] = map[string]any{
		"rules": []any{map[string]any{"inbound": []string{"harness-in"}, "outbound": selector}},
		"final": selector,
	}
	cfg.note("added-route", "route: harness-in -> "+selector)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	cfg.JSON = b
	return cfg, nil
}

// PinXrayTLS repairs the one thing Xray 26 made impossible to express from a
// self-signed inbound: it removed allowInsecure in favour of
// pinnedPeerCertSha256, and the panel never fills that in. Without it every TLS
// client config the panel emits fails certificate verification.
//
// The pin is the hex SHA-256 of the server's leaf certificate in DER form,
// which is what Xray compares against (verified against the running core).
func (c *ClientConfig) PinXrayTLS(serverAddr, sni string) error {
	if c.Engine != "xray" {
		return nil
	}
	sum, err := LeafCertSHA256(serverAddr, sni)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(c.JSON, &doc); err != nil {
		return err
	}
	outs, _ := doc["outbounds"].([]any)
	patched := 0
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil {
			continue
		}
		ss, _ := o["streamSettings"].(map[string]any)
		if ss == nil || ss["security"] != "tls" {
			continue
		}
		ts, _ := ss["tlsSettings"].(map[string]any)
		if ts == nil {
			ts = map[string]any{}
			ss["tlsSettings"] = ts
		}
		ts["pinnedPeerCertSha256"] = sum
		patched++
	}
	if patched == 0 {
		return nil
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	c.JSON = b
	c.note("repair:xray-tls-pin",
		"emitted config had no way to accept the panel's self-signed certificate "+
			"(Xray 26 removed allowInsecure); injected pinnedPeerCertSha256="+sum)
	return nil
}

// ChainShadowTLS repairs a ShadowTLS client config. ShadowTLS is camouflage,
// not transport: sing-box requires a shadowsocks outbound that *detours* to the
// shadowtls one. The panel emits the shadowtls outbound alone, which connects
// and then carries nothing.
func (c *ClientConfig) ChainShadowTLS(innerMethod, innerPassword string) error {
	if c.Engine != "sing-box" {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(c.JSON, &doc); err != nil {
		return err
	}
	outs, _ := doc["outbounds"].([]any)
	var rebuilt []any
	changed := false
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil || o["type"] != "shadowtls" {
			rebuilt = append(rebuilt, v)
			continue
		}
		tag, _ := o["tag"].(string)
		inner := tag + "-stls"
		o["tag"] = inner
		rebuilt = append(rebuilt, o, map[string]any{
			"type": "shadowsocks", "tag": tag,
			"method": innerMethod, "password": innerPassword, "detour": inner,
		})
		changed = true
	}
	if !changed {
		return nil
	}
	doc["outbounds"] = rebuilt
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	c.JSON = b
	c.note("repair:shadowtls-chain",
		"emitted config had a bare shadowtls outbound, which carries no traffic; "+
			"wrapped it in the inner shadowsocks outbound sing-box requires (detour)")
	return nil
}

// StripSingboxUTLS removes the uTLS block from QUIC outbounds. uTLS mimics a
// browser's TCP TLS ClientHello; QUIC carries its own TLS 1.3 stack, and
// sing-box refuses the combination outright ("unsupported usage for uTLS").
// The panel emits it anyway because applyCreateDefaults stamps a chrome
// fingerprint onto any security=tls node, Hysteria2 and TUIC included.
func (c *ClientConfig) StripSingboxUTLS() bool {
	if c.Engine != "sing-box" {
		return false
	}
	var doc map[string]any
	if err := json.Unmarshal(c.JSON, &doc); err != nil {
		return false
	}
	outs, _ := doc["outbounds"].([]any)
	stripped := 0
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil {
			continue
		}
		switch o["type"] {
		case "hysteria2", "tuic":
		default:
			continue
		}
		t, _ := o["tls"].(map[string]any)
		if t == nil {
			continue
		}
		if _, ok := t["utls"]; ok {
			delete(t, "utls")
			stripped++
		}
	}
	if stripped == 0 {
		return false
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false
	}
	c.JSON = b
	c.note("repair:singbox-quic-utls",
		"the emitted config put a uTLS block on a QUIC outbound, which sing-box rejects "+
			"per connection with \"unsupported usage for uTLS\"; removed it")
	return true
}

// UseCredential rewrites the proxy outbound's credential, so a failure caused by
// the subscription handing out the wrong secret can be told apart from a
// transport that does not work. The replacement comes from the inbound the
// panel is actually serving, read back through the admin API.
func (c *ClientConfig) UseCredential(field, value string) bool {
	if value == "" {
		return false
	}
	var doc map[string]any
	if err := json.Unmarshal(c.JSON, &doc); err != nil {
		return false
	}
	outs, _ := doc["outbounds"].([]any)
	changed := 0
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil {
			continue
		}
		switch o["protocol"] {
		case "freedom", "blackhole":
			continue
		}
		switch o["type"] {
		case "direct", "block", "selector":
			continue
		}
		changed += replaceField(o, field, value)
	}
	if changed == 0 {
		return false
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false
	}
	c.JSON = b
	c.note("repair:credential-from-inbound",
		fmt.Sprintf("replaced the subscription's %s with the one the served inbound actually holds", field))
	return true
}

func replaceField(v any, field, value string) int {
	n := 0
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == field {
				if _, ok := val.(string); ok {
					t[k] = value
					n++
					continue
				}
			}
			n += replaceField(val, field, value)
		}
	case []any:
		for _, val := range t {
			n += replaceField(val, field, value)
		}
	}
	return n
}

// Tamper corrupts every credential in the config. It is how the harness proves
// that authentication is actually enforced rather than assumed.
func (c *ClientConfig) Tamper() error {
	var doc map[string]any
	if err := json.Unmarshal(c.JSON, &doc); err != nil {
		return err
	}
	n := tamperValue(doc)
	if n == 0 {
		return fmt.Errorf("no credential field found to tamper with")
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	c.JSON = b
	c.note("tamper", fmt.Sprintf("replaced %d credential field(s) with a wrong value", n))
	return nil
}

// tamperValue rewrites id/uuid/password fields anywhere in the tree.
func tamperValue(v any) int {
	n := 0
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			switch k {
			case "id", "uuid", "password":
				if s, ok := val.(string); ok && s != "" {
					t[k] = wrongCredential(k, s)
					n++
					continue
				}
			}
			n += tamperValue(val)
		}
	case []any:
		for _, val := range t {
			n += tamperValue(val)
		}
	}
	return n
}

// wrongCredential keeps the shape of the value (a UUID stays a UUID, a base64
// PSK stays the same length) so the failure is an auth failure and not a parse
// error in the core.
func wrongCredential(field, old string) string {
	if field == "id" || field == "uuid" {
		return "00000000-dead-4000-8000-000000000000"
	}
	sum := sha256.Sum256([]byte("harness-wrong-credential:" + old))
	enc := hex.EncodeToString(sum[:])
	if len(old) <= len(enc) {
		return enc[:len(old)]
	}
	return enc
}

// LeafCertSHA256 handshakes with a TLS listener and returns the hex SHA-256 of
// its leaf certificate in DER form.
func LeafCertSHA256(addr, sni string) (string, error) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // the point of the call is to read the cert, not trust it
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", fmt.Errorf("read server certificate from %s (sni=%s): %w", addr, sni, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("%s presented no certificate", addr)
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

// Core is a running client proxy core.
type Core struct {
	Bin     string
	Cfg     *ClientConfig
	Dir     string
	cmd     *exec.Cmd
	logPath string
}

// Launch validates the config with the core's own checker, then starts it and
// waits for the local SOCKS port to accept a connection.
func Launch(bin string, cfg *ClientConfig, dir, name string, wait time.Duration) (*Core, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, name+".client.json")
	if err := os.WriteFile(cfgPath, cfg.JSON, 0o644); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, name+".client.log")

	checkArgs := []string{"run", "-test", "-c", cfgPath}
	runArgs := []string{"run", "-c", cfgPath}
	if cfg.Engine == "sing-box" {
		checkArgs = []string{"check", "-c", cfgPath}
	}
	if out, err := exec.Command(bin, checkArgs...).CombinedOutput(); err != nil {
		_ = os.WriteFile(logPath, out, 0o644)
		return nil, fmt.Errorf("%s rejected the emitted client config: %w: %s",
			cfg.Engine, err, lastLines(string(out), 3))
	}

	lf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, runArgs...)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, err
	}
	c := &Core{Bin: bin, Cfg: cfg, Dir: dir, cmd: cmd, logPath: logPath}
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort)
	if err := waitPort(addr, wait); err != nil {
		log := c.Log()
		c.Stop()
		return nil, fmt.Errorf("%s did not open %s: %w: %s", cfg.Engine, addr, err, lastLines(log, 4))
	}
	return c, nil
}

// Dialer returns a SOCKS dialer pointed at this core's local inbound.
func (c *Core) Addr() string { return fmt.Sprintf("127.0.0.1:%d", c.Cfg.SocksPort) }

// Log returns everything the core has written so far.
func (c *Core) Log() string {
	b, err := os.ReadFile(c.logPath)
	if err != nil {
		return ""
	}
	return string(b)
}

// LogPath is where the core's output was captured.
func (c *Core) LogPath() string { return c.logPath }

// Stop terminates the core.
func (c *Core) Stop() {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_, _ = c.cmd.Process.Wait()
}

func waitPort(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		time.Sleep(150 * time.Millisecond)
	}
	return last
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
