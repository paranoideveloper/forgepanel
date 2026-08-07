//go:build harness

// runner.go executes the matrix. For one case it walks the whole product path —
// create the inbound through the REST API, create and entitle a user, fetch the
// subscription the user would fetch, run the real client core from what came
// back, push traffic, and read the panel's own counters back — and records what
// actually happened at each step.
//
// Nothing here asserts by inference. "The config validates" is not a pass;
// bytes arriving intact at the far side of an otherwise unreachable network is.
package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Env is everything the runner needs from its surroundings.
type Env struct {
	PanelURL    string
	AdminUser   string
	AdminPass   string
	SetupToken  string
	Origin      Origin
	XrayBin     string
	SingboxBin  string
	ResultsDir  string
	RealityDest string
	BasePort    int // first inbound port; each case takes the next one
	BaseSocks   int // first local client port
	Timeout     time.Duration
	// AccountingWait bounds how long the runner waits for the panel's traffic
	// poller to attribute the bytes it just pushed. The scheduler polls every
	// 10s, so anything under that would report a false negative.
	AccountingWait time.Duration
}

// Status is the verdict recorded for a case.
type Status string

const (
	StatusPass         Status = "pass"
	StatusFail         Status = "fail"
	StatusExperimental Status = "experimental"
	StatusUnsupported  Status = "unsupported"
)

// Result is one row of the machine-readable matrix.
type Result struct {
	Case
	Engine     string     `json:"engine"`
	Status     Status     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	Port       int        `json:"port"`
	Steps      []Step     `json:"steps"`
	TCP        *TCPResult `json:"tcp,omitempty"`
	TLS        *TCPResult `json:"tls,omitempty"`
	UDPRes     *UDPResult `json:"udp_probe,omitempty"`
	Accounting *Acct      `json:"accounting,omitempty"`
	Online     *OnlineRes `json:"online,omitempty"`
	Mutations  []Mutation `json:"mutations,omitempty"`
	SubURI     string     `json:"sub_uri,omitempty"`
	SubFormat  string     `json:"sub_format,omitempty"`
	Artifacts  []string   `json:"artifacts,omitempty"`
	DurationMS int64      `json:"duration_ms"`
}

// Step is one action with its outcome, so a failure points at the stage rather
// than at the case as a whole.
type Step struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Acct records whether the panel attributed the pushed bytes to the user.
type Acct struct {
	OK      bool   `json:"ok"`
	Before  int64  `json:"used_before"`
	After   int64  `json:"used_after"`
	Delta   int64  `json:"delta"`
	WantMin int64  `json:"want_min"`
	Waited  int64  `json:"waited_ms"`
	Reason  string `json:"reason,omitempty"`
}

// OnlineRes records whether the panel marked the user as having connected.
type OnlineRes struct {
	OK     bool   `json:"ok"`
	Field  string `json:"field"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Runner executes cases against one panel.
type Runner struct {
	Env      Env
	Panel    *Panel
	nextPort int
	nextSock int
}

// NewRunner prepares a runner and its results directory.
func NewRunner(env Env) (*Runner, error) {
	if env.Timeout == 0 {
		env.Timeout = 25 * time.Second
	}
	if env.AccountingWait == 0 {
		env.AccountingWait = 40 * time.Second
	}
	if env.BasePort == 0 {
		env.BasePort = 31000
	}
	if env.BaseSocks == 0 {
		env.BaseSocks = 21000
	}
	if err := os.MkdirAll(filepath.Join(env.ResultsDir, "logs"), 0o755); err != nil {
		return nil, err
	}
	return &Runner{Env: env, Panel: NewPanel(env.PanelURL), nextPort: env.BasePort, nextSock: env.BaseSocks}, nil
}

// Bootstrap brings the panel from a fresh data directory to an authenticated
// session, tolerating an already-initialised panel so a re-run works.
func (r *Runner) Bootstrap() error {
	if err := r.Panel.WaitHealthy(90 * time.Second); err != nil {
		return err
	}
	need, err := r.Panel.SetupRequired()
	if err != nil {
		return err
	}
	if need {
		if r.Env.SetupToken == "" {
			return errors.New("panel needs first-run setup but no setup token was provided (HARNESS_SETUP_TOKEN)")
		}
		if err := r.Panel.SetupInit(r.Env.SetupToken, r.Env.AdminUser, r.Env.AdminPass); err != nil {
			return fmt.Errorf("first-run setup: %w", err)
		}
	}
	return r.Panel.Login(r.Env.AdminUser, r.Env.AdminPass)
}

// coreFor returns the client binary that speaks the engine a case routes to.
func (r *Runner) coreFor(engine string) (string, error) {
	switch engine {
	case "xray":
		if r.Env.XrayBin == "" {
			return "", errors.New("no xray binary configured")
		}
		return r.Env.XrayBin, nil
	case "sing-box":
		if r.Env.SingboxBin == "" {
			return "", errors.New("no sing-box binary configured")
		}
		return r.Env.SingboxBin, nil
	default:
		return "", fmt.Errorf("no client core available for engine %q", engine)
	}
}

// Run executes one connectivity case end to end.
func (r *Runner) Run(c Case) Result {
	start := time.Now()
	res := Result{Case: c, Engine: c.Engine(), Status: StatusFail}
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()

	port := r.nextPort
	r.nextPort++
	socks := r.nextSock
	r.nextSock += 2
	res.Port = port

	step := func(name string, err error, note string) bool {
		s := Step{Name: name, OK: err == nil, Note: note}
		if err != nil {
			s.Error = err.Error()
		}
		res.Steps = append(res.Steps, s)
		return err == nil
	}

	// --- 1. create the inbound -------------------------------------------
	in, err := r.Panel.CreateInbound(c.InboundPayload(port, r.Env.RealityDest))
	if !step("create-inbound", err, fmt.Sprintf("port %d", port)) {
		// A create the panel refuses is the correct outcome for the combinations
		// it declares removed; anything else is a genuine failure.
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == 400 && c.Why != "" {
			res.Status = StatusUnsupported
			res.Reason = "panel refused at create time (expected): " + firstLine(ae.Body)
			return res
		}
		if errors.As(err, &ae) && ae.Status == 400 {
			res.Status = StatusUnsupported
			res.Reason = "panel refused at create time: " + firstLine(ae.Body)
			return res
		}
		res.Reason = "create inbound: " + err.Error()
		return res
	}
	if c.Why != "" {
		// The panel accepted something it documents as unsupported. That is worth
		// failing on: it produces an engine config that cannot start.
		defer func() { _ = r.Panel.DeleteInbound(in.ID) }()
		res.Status = StatusFail
		res.Reason = "panel accepted a combination it declares unsupported (" + c.Why + ")"
		return res
	}
	defer func() { _ = r.Panel.DeleteInbound(in.ID) }()

	// --- 2. create + entitle the user ------------------------------------
	user, err := r.Panel.CreateUser("h-" + sanitize(c.ID))
	if !step("create-user", err, "") {
		res.Reason = "create user: " + err.Error()
		return res
	}
	defer func() { _ = r.Panel.DeleteUser(user.ID) }()
	if !step("assign-inbound", r.Panel.SetUserInbounds(user.ID, []uint{in.ID}), "") {
		res.Reason = "assign inbound to user"
		return res
	}

	// --- 3. did the engine actually accept it? ---------------------------
	if skipped, err := r.skipReason(c.ID, port); err == nil && skipped != "" {
		res.Status = StatusUnsupported
		res.Reason = "engine layer refused to serve this inbound: " + skipped
		step("engine-render", errors.New(skipped), "")
		return res
	}
	listen := fmt.Sprintf("%s:%d", hostOf(r.Env.PanelURL), port)
	tcpProto := c.Protocol != "hysteria2" && c.Protocol != "tuic" && c.Protocol != "wireguard" && c.Protocol != "amneziawg"
	if tcpProto {
		// Creating the inbound, creating the user and assigning it each fire their
		// own asynchronous engine reload, and every reload restarts the core. The
		// budget is generous for that reason. A port that still has not come up is
		// recorded but not treated as terminal: the probe below produces a far more
		// specific error than "did not listen", and letting it run means a real
		// failure is described by the core rather than by a timeout.
		err := waitPort(listen, 45*time.Second)
		step("inbound-listening", err, listen)
	}

	// --- 4. fetch the subscription the user would fetch -------------------
	format := "xray"
	ua := "v2rayNG/1.8.0"
	if res.Engine == "sing-box" {
		format, ua = "sing-box", "sing-box/1.13.0"
	}
	res.SubFormat = format
	raw, hdr, err := r.Panel.Subscription(user.SubToken, format, ua)
	if !step("fetch-subscription", err, "/sub/<token>/"+format) {
		res.Reason = "fetch subscription: " + err.Error()
		return res
	}
	res.Artifacts = append(res.Artifacts, r.save(c.ID+".sub."+format+".json", raw))
	if ui := hdr.Get("Subscription-Userinfo"); ui != "" {
		step("subscription-userinfo", nil, ui)
	}
	if links, _, err := r.Panel.Subscription(user.SubToken, "links", ua); err == nil {
		res.SubURI = firstLine(string(links))
	}

	// --- 5. build and launch the real client core -------------------------
	var cfg *ClientConfig
	if res.Engine == "sing-box" {
		cfg, err = FromSingboxSubscription(raw, socks)
	} else {
		cfg, err = FromXraySubscription(raw, socks)
	}
	if !step("parse-client-config", err, "") {
		res.Status = StatusFail
		res.Reason = "the emitted subscription is not a runnable client config: " + err.Error()
		return res
	}

	// ShadowTLS needs its inner hop before the config can start at all, so it is
	// applied up front rather than as a diagnosis-driven retry.
	if c.Protocol == "shadowtls" {
		if m, p, err := r.shadowTLSInner(user.SubToken); err == nil {
			_ = cfg.ChainShadowTLS(m, p)
		} else {
			step("shadowtls-inner", err, "")
		}
	}
	res.Mutations = cfg.Mutations

	// --- 6. run the core and push traffic, repairing to attribute failures --
	//
	// The first attempt is always the config exactly as the panel emitted it.
	// If it fails, the harness applies one targeted repair at a time and tries
	// again. A case that only succeeds after a repair is still not a pass for
	// the product — it is recorded with the repair that made it work, which is
	// what turns "hysteria2 is broken" into "the emitted hysteria2 config
	// carries a uTLS block sing-box refuses".
	logDir := filepath.Join(r.Env.ResultsDir, "logs")
	before := r.usedTraffic(user.ID)
	seed := time.Now().UnixNano()

	var core *Core
	var tcp TCPResult
	defer func() {
		if core != nil {
			core.Stop()
		}
	}()

	attempt := func(label string) (launchErr error) {
		if core != nil {
			core.Stop()
			core = nil
		}
		name := sanitize(c.ID)
		if label != "" {
			name += "." + label
		}
		cr, err := Launch(r.mustCore(res.Engine), cfg, logDir, name, 20*time.Second)
		if err != nil {
			tcp = TCPResult{Error: err.Error()}
			return err
		}
		core = cr
		tcp = r.probeWithRetry(core.Addr(), seed)
		return nil
	}

	launchErr := attempt("")
	step("launch-client", launchErr, res.Engine)
	if launchErr == nil {
		step("tcp-payload", errFrom(tcp.OK, tcp.Error), fmt.Sprintf("%d bytes", tcp.Bytes))
	}

	for round := 0; !tcp.OK && round < 3; round++ {
		repair, label := r.chooseRepair(c, res.Engine, cfg, core, launchErr, in.ID, listen)
		if repair == "" {
			break
		}
		res.Mutations = cfg.Mutations
		launchErr = attempt(label)
		step("retry:"+repair, launchErr, "")
		if launchErr == nil {
			step("tcp-payload:"+repair, errFrom(tcp.OK, tcp.Error), fmt.Sprintf("%d bytes", tcp.Bytes))
		}
	}
	res.Mutations = cfg.Mutations
	res.Artifacts = append(res.Artifacts, r.save(c.ID+".client.json", cfg.JSON))
	if core != nil {
		res.Artifacts = append(res.Artifacts, core.LogPath())
	}

	if !tcp.OK {
		res.Status = StatusFail
		if launchErr != nil {
			res.Reason = "client core would not run the emitted config: " + launchErr.Error()
		} else {
			res.Reason = "payload did not arrive intact: " + tcp.Error
		}
		if core != nil {
			if lg := lastLines(core.Log(), 3); lg != "" {
				res.Reason += " | core: " + lg
			}
		}
		res.TCP = &tcp
		return res
	}
	res.TCP = &tcp

	// HTTPS through the tunnel: proves an opaque stream, not just cleartext.
	if pin, perr := OriginCertPin(core.Addr(), r.Env.Origin, r.Env.Timeout); perr == nil {
		tlsRes := ProbeHTTPS(core.Addr(), r.Env.Origin, seed+1, r.Env.Timeout, pin)
		res.TLS = &tlsRes
		step("https-payload", errFrom(tlsRes.OK, tlsRes.Error), "")
	}

	// --- 7. UDP --------------------------------------------------------
	if c.UDP {
		u := ProbeDNS(core.Addr(), r.Env.Origin, r.Env.Timeout)
		res.UDPRes = &u
		step("udp-dns", errFrom(u.OK, u.Error), u.Answer)
	}

	// --- 8. the panel's own bookkeeping ----------------------------------
	r.checkAccounting(&res, user.ID, before)
	r.checkOnline(&res, user.ID)

	grade(&res)
	return res
}

// grade turns the collected evidence into the verdict. The rule it encodes:
// the deliverable is a subscription that works AS DELIVERED, so a case the
// harness had to repair is not a pass however well the tunnel underneath it
// performs. Structural adaptations (retargeting a listen port, adding the local
// inbound the sing-box format omits) are not repairs — they change nothing
// about whether the tunnel authenticates or carries bytes — and are reported as
// their own findings instead.
func grade(res *Result) {
	for _, m := range res.Mutations {
		if strings.HasPrefix(m.Kind, "repair:") {
			res.Status = StatusFail
			res.Reason = "the emitted config did not work as delivered; it carried traffic only after " +
				strings.TrimPrefix(m.Kind, "repair:") + " — " + m.Detail
			return
		}
	}
	if res.TCP == nil || !res.TCP.OK {
		res.Status = StatusFail
		if res.Reason == "" {
			res.Reason = "no payload arrived through the tunnel"
		}
		return
	}
	if res.UDPRes != nil && !res.UDPRes.OK {
		res.Status = StatusExperimental
		res.Reason = "TCP is proven but UDP does not traverse the tunnel: " + res.UDPRes.Error
		return
	}
	if res.Accounting != nil && !res.Accounting.OK {
		if res.Engine == "sing-box" {
			res.Status = StatusExperimental
			res.Reason = "traffic is proven, but per-user accounting cannot be proven for this engine: " +
				"the official sing-box archives the panel pins are built without with_v2ray_api, so the " +
				"panel collects no counters for sing-box inbounds (documented in internal/core/engine/multi.go). " +
				res.Accounting.Reason
			return
		}
		res.Status = StatusFail
		res.Reason = "traffic flows but the panel did not account it: " + res.Accounting.Reason
		return
	}
	res.Status = StatusPass
	res.Reason = ""
}

// chooseRepair inspects why the last attempt failed and applies the single most
// specific fix that has not been tried yet. It returns the repair's name, or ""
// when nothing further can be attributed. Every branch corresponds to a defect
// in what the panel emitted, not to a workaround for the harness.
func (r *Runner) chooseRepair(c Case, engine string, cfg *ClientConfig, core *Core, launchErr error, inboundID uint, listen string) (repair, label string) {
	diag := ""
	if launchErr != nil {
		diag = launchErr.Error()
	}
	if core != nil {
		diag += " " + core.Log()
	}

	// A QUIC outbound carrying a uTLS block: sing-box rejects it per connection.
	if engine == "sing-box" && strings.Contains(diag, "unsupported usage for uTLS") &&
		!hasMutation(cfg, "repair:singbox-quic-utls") {
		if cfg.StripSingboxUTLS() {
			return "singbox-quic-utls", "no-utls"
		}
	}
	// A TLS client config with no way to accept the panel's self-signed cert.
	if engine == "xray" && c.Security == "tls" && !hasMutation(cfg, "repair:xray-tls-pin") {
		if err := cfg.PinXrayTLS(listen, sniOf(cfg)); err == nil && hasMutation(cfg, "repair:xray-tls-pin") {
			return "xray-tls-pin", "pinned"
		}
	}
	// The subscription's credential is not the one the server holds. Read the
	// served inbound back and substitute it: if the case then works, the
	// transport is fine and the subscription is handing out the wrong secret.
	if !hasMutation(cfg, "repair:credential-from-inbound") {
		if node, err := r.Panel.InboundNode(inboundID); err == nil {
			for _, field := range []string{"password", "uuid"} {
				want, _ := node[field].(string)
				if want == "" {
					continue
				}
				if cfg.UseCredential(credField(engine, field), want) {
					return "credential-from-inbound", "srvcred"
				}
			}
		}
	}
	return "", ""
}

// credField maps a canonical node field to the key the engine's client config
// uses for it.
func credField(engine, field string) string {
	if engine == "xray" && field == "uuid" {
		return "id"
	}
	return field
}

// probeWithRetry gives a freshly reloaded engine a moment to pick up the user's
// credential. Creating a user and assigning an inbound each trigger their own
// asynchronous engine reload, so the first attempt can legitimately race.
func (r *Runner) probeWithRetry(socksAddr string, seed int64) TCPResult {
	// A shorter budget than Env.Timeout: 256 KiB across a container bridge is
	// milliseconds, so anything near this deadline is a stall, and the whole
	// matrix would otherwise spend minutes waiting on tunnels that are dead.
	budget := 12 * time.Second
	var last TCPResult
	for attempt := 0; attempt < 3; attempt++ {
		last = ProbeHTTP(socksAddr, r.Env.Origin, seed, budget)
		if last.OK {
			return last
		}
		time.Sleep(2 * time.Second)
	}
	return last
}

func (r *Runner) checkAccounting(res *Result, userID uint, before int64) {
	a := &Acct{Before: before, WantMin: int64(PayloadSize / 2)}
	start := time.Now()
	deadline := start.Add(r.Env.AccountingWait)
	for time.Now().Before(deadline) {
		now := r.usedTraffic(userID)
		if now-before >= a.WantMin {
			a.After, a.Delta, a.OK = now, now-before, true
			a.Waited = time.Since(start).Milliseconds()
			res.Accounting = a
			return
		}
		a.After, a.Delta = now, now-before
		time.Sleep(2 * time.Second)
	}
	a.Waited = time.Since(start).Milliseconds()
	a.Reason = fmt.Sprintf("used_traffic rose by %d bytes in %s, expected at least %d",
		a.Delta, r.Env.AccountingWait, a.WantMin)
	res.Accounting = a
}

func (r *Runner) checkOnline(res *Result, userID uint) {
	u, err := r.Panel.GetUser(userID)
	o := &OnlineRes{Field: "first_connect_at"}
	if err != nil {
		o.Reason = err.Error()
		res.Online = o
		return
	}
	if u.FirstConnectAt != nil {
		o.OK = true
		o.Value = u.FirstConnectAt.Format(time.RFC3339)
	} else {
		o.Reason = "the panel exposes no online/last-seen signal: store.User.FirstConnectAt is the only " +
			"candidate field and no code path writes it (it is read once, in internal/job/scheduler.go, " +
			"for the on-hold transition), and there is no last_seen column"
	}
	res.Online = o
}

func (r *Runner) usedTraffic(userID uint) int64 {
	u, err := r.Panel.GetUser(userID)
	if err != nil {
		return 0
	}
	return u.UsedTraffic
}

// skipReason reports the engine layer's own explanation for refusing an inbound,
// or "" once the inbound is present in a generated engine config. The presence
// test keys on the tag engine.BuildMulti assigns ("in-<port>", derived from the
// port, which is unique) rather than the remark, which never reaches the engine
// config at all.
func (r *Runner) skipReason(remark string, port int) (string, error) {
	tag := fmt.Sprintf(`"in-%d"`, port)
	// The reload is asynchronous; give it a moment to produce a bundle.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		cfg, err := r.Panel.EngineConfigDump()
		if err != nil {
			return "", err
		}
		for _, s := range cfg.Skipped {
			if s.Remark == remark {
				return s.Reason, nil
			}
		}
		if strings.Contains(cfg.Xray, tag) || strings.Contains(cfg.Singbox, tag) {
			return "", nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", nil
}

// shadowTLSInner reads the inner Shadowsocks credentials out of the /json
// subscription, which is where the panel does expose them.
func (r *Runner) shadowTLSInner(token string) (method, password string, err error) {
	raw, _, err := r.Panel.Subscription(token, "json", "")
	if err != nil {
		return "", "", err
	}
	var nodes []struct {
		ShadowTLS struct {
			InnerMethod   string `json:"inner_method"`
			InnerPassword string `json:"inner_password"`
		} `json:"shadowtls"`
	}
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return "", "", err
	}
	for _, n := range nodes {
		if n.ShadowTLS.InnerPassword != "" {
			return n.ShadowTLS.InnerMethod, n.ShadowTLS.InnerPassword, nil
		}
	}
	return "", "", errors.New("subscription carried no shadowtls inner credentials")
}

func (r *Runner) mustCore(engine string) string {
	bin, err := r.coreFor(engine)
	if err != nil {
		return ""
	}
	return bin
}

func (r *Runner) save(name string, data []byte) string {
	p := filepath.Join(r.Env.ResultsDir, "logs", sanitize(name))
	_ = os.WriteFile(p, data, 0o644)
	return p
}

func errFrom(ok bool, msg string) error {
	if ok {
		return nil
	}
	if msg == "" {
		msg = "failed"
	}
	return errors.New(msg)
}

func hasMutation(c *ClientConfig, kind string) bool {
	for _, m := range c.Mutations {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

// sniOf digs the server_name out of a client config so a certificate can be
// fetched with the SNI the client will actually send.
func sniOf(c *ClientConfig) string {
	var doc map[string]any
	if err := json.Unmarshal(c.JSON, &doc); err != nil {
		return ""
	}
	outs, _ := doc["outbounds"].([]any)
	for _, v := range outs {
		o, _ := v.(map[string]any)
		if o == nil {
			continue
		}
		if ss, ok := o["streamSettings"].(map[string]any); ok {
			if ts, ok := ss["tlsSettings"].(map[string]any); ok {
				if s, _ := ts["serverName"].(string); s != "" {
					return s
				}
			}
		}
		if t, ok := o["tls"].(map[string]any); ok {
			if s, _ := t["server_name"].(string); s != "" {
				return s
			}
		}
	}
	return ""
}

func hostOf(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
