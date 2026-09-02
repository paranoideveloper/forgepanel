// Command forgenode is the lightweight remote node agent (spec §10). It enrolls
// with the panel using a one-time token, then heartbeats on an interval,
// receiving the engine config to run locally and supervising the proxy core.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/singboxapi"
	"github.com/forgepanel/forgepanel/internal/version"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/core/porthop"
)

type NodeAgent struct {
	panel string
	// token is the LEGACY credential — a permanent bearer string. Kept so a
	// node can still reach a panel that has not been upgraded, and unused once
	// a client certificate has been obtained.
	token string
	// bootstrapToken is spent ONCE for a client certificate and then worthless.
	bootstrapToken string
	// pin is the panel's certificate SHA-256, hex. Empty means "use the system
	// trust store", which is correct once the panel has a real certificate.
	pin     string
	client  *http.Client
	dataDir string
	binMgr  *binmgr.Manager
	mu      sync.Mutex
	// sbStats caches whether this node's sing-box can meter users. Detected from
	// the binary, once — running the detector on every heartbeat would exec a
	// process every ten seconds to answer a question that cannot change without
	// a restart.
	sbStatsOnce sync.Once
	sbStats     bool
	// hops installs the firewall redirects a hysteria2 hop range needs. The
	// same implementation the panel uses for its own inbounds, so a range
	// behaves identically whether it is served here or there.
	hops *porthop.Manager
	// hopsInstalled records whether this node currently owns any redirect, so an
	// empty map from a panel with no hop ranges does not warn on every beat
	// about a capability nobody asked for.
	hopsInstalled bool
	// engines is every core this node can supervise, keyed by name.
	//
	// A map rather than one xray field: the node ran exactly one process, so
	// every hysteria2, tuic, anytls, shadowtls and wireguard inbound vanished
	// the moment it was assigned to a remote node.
	engines map[string]*engineProc
	// logSeq is how many log lines this agent has had ACCEPTED by the panel. It
	// is the sequence the panel dedups against, and it advances only on a
	// successful post — see collectLogs.
	logSeq int
	// logEpoch identifies this agent PROCESS. A restarted agent numbers from
	// zero again, which the panel cannot tell from a re-send of the first batch
	// unless it is told which process is speaking; getting that wrong one way
	// loses every line after a restart, and the other way duplicates lines on
	// every dropped response.
	logEpoch string
}

// collectLogs gathers what the cores have said that the panel has not accepted,
// and returns the func that marks it accepted.
//
// Nothing is committed until the heartbeat SUCCEEDS, for the same reason the
// traffic counters are cumulative: a dropped response must not cost the operator
// the lines that explain why their node is down. Re-sending is free — the panel
// files by absolute position and discards what it already holds.
//
// Lines are grouped by core within a batch rather than interleaved by time. A
// batch covers one ten-second poll, and merging two cores' output by timestamp
// would mean parsing two cores' log formats to gain ordering nobody can act on.
func (a *NodeAgent) collectLogs() ([]string, func()) {
	a.mu.Lock()
	defer a.mu.Unlock()

	names := make([]string, 0, len(a.engines))
	for name := range a.engines {
		names = append(names, name)
	}
	// Deterministic, so a node's log panel does not reorder itself between
	// heartbeats purely because Go randomised a map.
	sort.Strings(names)

	var out []string
	cursors := make(map[string]int, len(names))
	for _, name := range names {
		e := a.engines[name]
		lines, next := e.ring().Since(e.logCursor)
		cursors[name] = next
		for _, ln := range lines {
			// Prefixed, because the panel shows one stream per node and "failed
			// to start inbound" means something different depending on which
			// core said it.
			out = append(out, name+": "+ln)
		}
	}
	if extra := len(out) - nodeLogBatch; extra > 0 {
		// Keep the TAIL: when a core is looping, the newest lines describe the
		// state it is in now. The dropped ones are still in the node's journal.
		out = out[extra:]
	}
	return out, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		for name, next := range cursors {
			if e := a.engines[name]; e != nil {
				e.logCursor = next
			}
		}
		a.logSeq += len(out)
	}
}

// nodeLogBatch bounds what one heartbeat carries. A core looping on a stack
// trace would otherwise put an unbounded body on the wire every ten seconds.
const nodeLogBatch = 200

// lastFailure is this node's verdict on itself: what most recently stopped one
// of its cores from serving, in that core's own words.
//
// The panel has no other way to learn it. A node whose agent is perfectly
// healthy can be running an xray that refuses every config it is handed, and
// without this the panel called that node "connected" indefinitely while it
// served nobody.
func (a *NodeAgent) lastFailure() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	names := make([]string, 0, len(a.engines))
	for name, e := range a.engines {
		if e.lastErr != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+": "+a.engines[name].lastErr)
	}
	return strings.Join(parts, "; ")
}

// stateDir is the filesystem the node's own data lives on, and the one whose
// exhaustion actually takes the node down.
func (a *NodeAgent) stateDir() string {
	if a.dataDir != "" {
		return a.dataDir
	}
	return "/"
}

func main() {
	if nodeVersionRequested(os.Args[1:]) {
		fmt.Println(version.String("forgenode"))
		return
	}
	panel := os.Getenv("PANEL")
	token := os.Getenv("TOKEN")
	bootstrap := os.Getenv("BOOTSTRAP")
	pin := os.Getenv("PANEL_FINGERPRINT")
	// Either credential is enough to start: BOOTSTRAP on a current panel, TOKEN
	// against one that has not been upgraded yet. Requiring both would refuse to
	// run on exactly the mixed fleet this change has to survive.
	if panel == "" || (token == "" && bootstrap == "") {
		fmt.Fprintln(os.Stderr, "forgenode: set PANEL and either BOOTSTRAP or TOKEN")
		os.Exit(2)
	}

	dataDir := os.Getenv("FORGEPANEL_DATA")
	if dataDir == "" {
		dataDir = "/var/lib/forgepanel"
	}
	_ = os.MkdirAll(dataDir, 0o700)

	bm := binmgr.New(dataDir)
	agent := &NodeAgent{
		panel:          panel,
		token:          token,
		bootstrapToken: bootstrap,
		pin:            pin,
		dataDir:        dataDir,
		binMgr:         bm,
		hops:           porthop.New(),
		engines:        map[string]*engineProc{},
		// A fresh identity per agent process, so the panel can tell "I restarted
		// and my line numbers begin again" from "you did not answer, here they
		// are again". Both are ordinary on a flaky link and they look identical
		// without it.
		logEpoch: newLogEpoch(),
	}
	for _, spec := range engineSpecs() {
		// Resolved LAZILY per engine, and a failure is not fatal: a node that
		// serves only xray protocols must not refuse to start because the
		// sing-box download failed, and an offline test environment must still
		// be able to run the agent.
		bin, err := bm.Ensure(spec.engine)
		if err != nil {
			bin, _ = exec.LookPath(spec.name)
		}
		agent.engines[spec.name] = &engineProc{spec: spec, bin: bin}
	}

	// Obtain a client certificate before anything else, so register and every
	// heartbeat after it are authenticated by the certificate rather than by a
	// bearer string. A failure here is not fatal: a panel that predates mTLS has
	// no bootstrap endpoint, and the node must still be able to enrol against it.
	if err := agent.bootstrap(); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: continuing with token authentication:", err)
	} else if fp := agent.identityFingerprint(); fp != "" {
		fmt.Println("forgenode: client certificate", fp)
	}

	if err := agent.register(); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: register error:", err)
		os.Exit(1)
	}
	fmt.Println("forgenode: enrolled successfully with", panel)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Initial heartbeat immediately
	agent.step()

	for range ticker.C {
		agent.step()
	}
}

// newLogEpoch mints this process's log identity. Time is not enough on its own —
// a supervised agent that crash-loops can restart inside the same second — so it
// is a random value, and it never leaves the node except in its own heartbeat.
func newLogEpoch() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Randomness is unavailable on this box for the moment. A timestamp is
		// a weaker epoch, not a broken one, and refusing to start the agent over
		// a log cursor would be absurd.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

func nodeVersionRequested(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version")
}

func (a *NodeAgent) step() {
	// Renew from the heartbeat loop rather than a timer of its own: the
	// heartbeat is already this node's proof that it can reach the panel.
	a.renewIfNeeded()
	cfgs, err := a.heartbeat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: heartbeat error:", err)
		return
	}
	a.applyConfigs(cfgs)
}

// applyConfigs hands each engine its share of the panel's bundle.
//
// An engine whose config is EMPTY is stopped rather than skipped: a core still
// serving inbounds the panel has removed is exactly the drift this exists to
// prevent. The one exception is a panel that sent nothing at all — see
// heartbeat's note on why that is not the same as "serve nothing".
func (a *NodeAgent) applyConfigs(cfgs map[string]string) {
	// A server certificate has to exist before a config that references one is
	// handed to a core. The panel names <dataDir>/certs/self.{crt,key} for every
	// TLS-terminating inbound it assigns here; if the file is not there, sing-box
	// refuses the whole config with "initialize inbound[0]: missing certificate"
	// and the node serves nothing at all — not just the TLS inbounds.
	//
	// Generated locally, never shipped from the panel: a node holding the panel's
	// private key would mean one stolen node compromises the panel and every
	// other node with it. Self-signed is the right default for the protocols
	// that need it — Hysteria2 and TUIC clients pin or accept it, and a node with
	// a real domain can have a real certificate dropped in at the same path.
	if err := a.ensureServerCert(); err != nil {
		fmt.Fprintf(os.Stderr, "forgenode: could not prepare the TLS certificate: %v\n", err)
		// Not fatal: the plaintext inbounds on this node still work, and failing
		// the whole apply would take them down over a certificate they never
		// needed.
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for name, e := range a.engines {
		e.apply(a.dataDir, cfgs[name])
	}
}

// ensureServerCert materialises the node's own TLS certificate, once.
func (a *NodeAgent) ensureServerCert() error {
	_, _, err := cert.EnsureSelfSigned(filepath.Join(a.dataDir, "certs"))
	return err
}

func (a *NodeAgent) register() error {
	body, _ := json.Marshal(map[string]string{"token": a.token, "core_version": "xray"})
	return a.post("/api/node/register", body, nil)
}

func (a *NodeAgent) heartbeat() (map[string]string, error) {
	cpu, mem := systemMetrics()
	diskUsed, diskTotal := diskUsage(a.stateDir())
	conns := tcpConnections()
	// The uptime of the longest-running supervised core. With more than one
	// engine there is no single "the core" any more, and reporting the newest
	// would make an ordinary sing-box restart look like the whole node had just
	// come back.
	coreUptime := 0
	a.mu.Lock()
	for _, e := range a.engines {
		if e.running() && !e.startedAt.IsZero() {
			if up := int(time.Since(e.startedAt).Seconds()); up > coreUptime {
				coreUptime = up
			}
		}
	}
	a.mu.Unlock()
	// Report CUMULATIVE counters and never reset them.
	//
	// This agent used to post deltas and reset after a successful response, and
	// that loses money in the customer's favour and then in ours: if the panel
	// received the post and ACCOUNTED it but the response was lost — a dropped
	// link, a panel restart mid-reply, a client timeout — the reset never ran,
	// the next heartbeat reported the same bytes, and the panel added them a
	// second time. A flaky link therefore inflated every user's usage and cut
	// them off early, silently.
	//
	// Cumulative reporting makes a heartbeat idempotent: re-sending the same
	// totals yields a zero delta on the panel, so a lost response costs nothing
	// and no reset has to succeed for accounting to be correct.
	traffic := a.collectTraffic(false)
	logs, acceptLogs := a.collectLogs()
	body, _ := json.Marshal(map[string]any{
		"token": a.token, "cpu": cpu, "mem_mb": mem, "traffic": traffic,
		// Tells the panel these are running totals rather than deltas. An older
		// agent omits it and is accounted the old way, so a panel upgraded ahead
		// of its nodes does not silently mis-count either fleet.
		"traffic_cumulative": true,
		"disk_used_mb":       diskUsed, "disk_total_mb": diskTotal,
		"tcp_conns": conns, "core_uptime_sec": coreUptime,
		// Where this node keeps its state, so the panel can name a certificate
		// path that exists HERE. Without it the panel built every node's config
		// with an empty certificate path and every TLS-terminating inbound —
		// hysteria2, TUIC, AnyTLS, ShadowTLS, and any TLS xray inbound — was
		// refused by sing-box with "initialize inbound[0]: missing certificate",
		// forever, on every node. An older agent omits this and the panel falls
		// back to the default path, which is what the installer configures.
		"data_dir": a.dataDir,
		// Whether THIS node's sing-box can report per-user counters.
		//
		// The panel cannot know: the capability is a property of the binary
		// installed here, and enabling the config section on a build without it
		// is a STARTUP failure that takes every sing-box inbound down rather
		// than merely leaving them unmetered. So the node says, and the panel
		// only asks for what the node can serve.
		"singbox_stats": a.singboxStatsSupported(),
		// What went wrong here, so the panel can say so instead of showing a
		// green node that serves nobody.
		"last_error": a.lastFailure(),
		// The cores' own output. This is the whole of the panel's live log panel:
		// the agent is strictly pull — the panel can never open a connection to a
		// node behind NAT — so the lines ride the request the node is already
		// making.
		"logs":      logs,
		"log_seq":   a.logSeq,
		"log_epoch": a.logEpoch,
	})
	var resp struct {
		XrayConfig string `json:"xray_config"`
		// A panel that predates multi-core omits this entirely, which reads as
		// "sing-box has nothing to serve here" — correct, because such a panel
		// never assigned sing-box protocols to a node in the first place.
		SingboxConfig string `json:"singbox_config"`
		// PortHops maps a hysteria2 inbound's listen port to its hop range.
		// Absent from an older panel, which simply means no hopping here.
		PortHops map[int]string `json:"port_hops"`
	}
	if err := a.post("/api/node/heartbeat", body, &resp); err != nil {
		return nil, err
	}
	// The panel has them now, so stop re-sending them. Only here: a lost
	// response leaves the cursor where it was and the next beat repeats the
	// batch, which the panel discards by sequence.
	acceptLogs()
	a.applyPortHops(resp.PortHops)
	return map[string]string{
		"xray":     resp.XrayConfig,
		"sing-box": resp.SingboxConfig,
	}, nil
}

// applyPortHops installs the firewall redirects a hysteria2 hop range needs.
//
// A hop range is TWO things: a hint in the client's share link, and redirects
// that send the whole range at the port the core listens on. The panel installed
// the redirects for its own inbounds; nothing installed them on a node. So a
// hysteria2 inbound assigned to a node handed out a link advertising
// mport=30000-30100 and redirected none of those ports — the tunnel worked until
// the client hopped and then broke. Measured on a real node: sing-box listening,
// nft ruleset empty.
//
// Failures are reported and not fatal. The inbound still serves on its base
// port, which is a working tunnel; refusing to apply the config over a missing
// CAP_NET_ADMIN would take that away too. The panel surfaces the same
// distinction for its own host through PortHopStatus.
func (a *NodeAgent) applyPortHops(want map[int]string) {
	if want == nil {
		want = map[int]string{}
	}
	// Nothing to do and nothing installed: stay quiet rather than warning about
	// a capability this node has never been asked to use.
	if len(want) == 0 && !a.hopsInstalled {
		return
	}
	if err := a.hops.Sync(want); err != nil {
		fmt.Fprintf(os.Stderr, "forgenode: port hopping: %v\n", err)
		return
	}
	a.hopsInstalled = len(want) > 0
}

// httpClient returns the client used for every panel call.
//
// A fresh panel serves HTTPS with a self-signed certificate, because a domain
// is optional and most installs start life reachable only by IP. A remote node
// cannot verify that certificate against the system trust store — measured on
// live servers, forgenode crash-looped on "certificate signed by unknown
// authority" and a multi-node install simply could not complete.
//
// Disabling verification outright would be the easy fix and the wrong one: the
// node ships its enrolment token on this connection, so an unverified transport
// hands that token to anyone who can intercept it. Instead the node PINS the
// panel's certificate by SHA-256 fingerprint, supplied at enrolment time
// alongside the token. Verification still happens; the trust anchor is just the
// pin rather than a public CA. With no pin configured the system trust store is
// used unchanged, which is what a panel with a real certificate wants.
func (a *NodeAgent) httpClient() *http.Client {
	if a.client != nil {
		return a.client
	}
	c := &http.Client{Timeout: 10 * time.Second}
	tlsCfg := &tls.Config{}
	// The node's own identity for the handshake. Presenting it is what replaces
	// sending a bearer token in the request body: the private key stays here,
	// so nothing that authenticates this node is ever transmitted.
	if pair := a.clientCertificate(); pair != nil {
		tlsCfg.Certificates = []tls.Certificate{*pair}
	}
	if a.pin != "" {
		want := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(a.pin))
		// The pin IS the verification, so the default chain check is bypassed
		// and replaced below rather than simply switched off.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				sum := sha256.Sum256(raw)
				if hex.EncodeToString(sum[:]) == want {
					return nil
				}
			}
			return fmt.Errorf("panel certificate does not match the pinned fingerprint %s; "+
				"re-run enrolment to get the current pin, or the connection is being intercepted", want)
		}
	}
	c.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	a.client = c
	return c
}

func (a *NodeAgent) post(path string, body []byte, out any) error {
	url := a.panel + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := a.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		b, _ := io.ReadAll(r.Body)
		return fmt.Errorf("status %d: %s", r.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(r.Body).Decode(out)
	}
	return nil
}

// nodeXrayAPIPort is the port the panel puts the local gRPC api inbound on when
// it builds a node's config (see handleNodeHeartbeat -> engine.BuildMulti).
// The node reads its own counters through it.
const nodeXrayAPIPort = 10085

// nodeSingboxAPIPort mirrors internal/api.nodeSingboxAPIPort. Both ends have to
// agree on it, and it is fixed rather than negotiated so a partial update cannot
// leave them disagreeing.
const nodeSingboxAPIPort = 10086

// collectTraffic reads per-user counters from the node's OWN xray and RESETS
// them, so each heartbeat carries a delta.
//
// Without this a node reported nothing but cpu and memory, and traffic it served
// was never counted anywhere: measured on live hosts, 4 MB pushed through a
// remote node moved the panel's used_traffic by exactly 0. A user assigned to a
// node therefore had unlimited traffic and no quota could ever apply to them.
//
// Resetting on read is what makes the value a delta the panel can simply add.
// It also means a heartbeat that is COLLECTED but never DELIVERED loses that
// slice of traffic, so the counters are only reset once the post succeeds —
// see heartbeat().
// collectTraffic reports per-user counters from EVERY metered core.
//
// Both engines, merged. A node used to poll xray only, so hysteria2, tuic,
// anytls, shadowtls and wireguard traffic was invisible to the panel and a user
// could exhaust their plan on those protocols from a node and stay active
// forever — the quota system guarding traffic it could not see.
func (a *NodeAgent) collectTraffic(reset bool) map[string]int64 {
	out := a.collectXrayTraffic(reset)
	if out == nil {
		// collectXrayTraffic returns nil when xray is absent or unreadable, and
		// assigning into a nil map PANICS — on the heartbeat goroutine, for a
		// node that happens to serve only sing-box protocols.
		out = map[string]int64{}
	}
	for name, v := range a.collectSingboxTraffic(reset) {
		// SUMMED, not overwritten. One user can be served by both engines on the
		// same node — a VLESS inbound and a hysteria2 inbound — and taking either
		// side alone silently discards half their usage.
		out[name] += v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectSingboxTraffic reads the sing-box v2ray API, when this node has one.
func (a *NodeAgent) collectSingboxTraffic(reset bool) map[string]int64 {
	if !a.singboxStatsSupported() {
		return nil
	}
	a.mu.Lock()
	e, ok := a.engines["sing-box"]
	running := ok && e.running()
	a.mu.Unlock()
	if !running {
		// Querying a core that is not running yields a connection error every
		// heartbeat. Nothing is served, so nothing is owed.
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats, err := singboxapi.Query(ctx,
		"127.0.0.1:"+strconv.Itoa(nodeSingboxAPIPort), "user>>>", reset)
	if err != nil {
		// Reported, not silent. A node whose sing-box counters stop being
		// readable is serving traffic nobody is billing for, and the previous
		// version of that condition was "no error and a usage figure that never
		// moves".
		fmt.Fprintln(os.Stderr, "forgenode: sing-box stats unavailable:", err)
		return nil
	}
	return stats
}

func (a *NodeAgent) collectXrayTraffic(reset bool) map[string]int64 {
	bin := a.engineBin("xray")
	if bin == "" {
		return nil
	}
	args := []string{"api", "statsquery",
		"--server=127.0.0.1:" + strconv.Itoa(nodeXrayAPIPort), "-pattern", "user>>>"}
	if reset {
		args = append(args, "-reset")
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return nil
	}
	var parsed struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil
	}
	totals := map[string]int64{}
	for _, s := range parsed.Stat {
		// user>>>EMAIL>>>traffic>>>uplink|downlink
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			continue
		}
		// Xray writes the value as a JSON number or a quoted string depending on
		// version; accept both rather than silently counting zero.
		raw := strings.Trim(string(s.Value), `"`)
		if raw == "" || raw == "null" {
			continue
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v <= 0 {
			continue
		}
		totals[parts[1]] += v
	}
	return totals
}

// systemMetrics reports this host's real CPU and memory use.
//
// The heartbeat previously sent the constants cpu:0.1 and mem_mb:128, which is
// why every enrolled node displayed identical figures in the panel no matter
// what it was doing — a dashboard that cannot show a node under load.
// diskUsage reports the used and total megabytes of the filesystem holding path.
// Disk is the metric that turns into an outage without warning: a node whose
// disk fills stops writing configs and logs and simply goes quiet, and the panel
// had no way to see it coming.
func diskUsage(path string) (usedMB, totalMB int) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := uint64(st.Bsize)
	total := st.Blocks * bs
	// Free-to-unprivileged, not free-to-root: the reserved blocks are not usable
	// by the agent, so counting them as free would report headroom that does not
	// exist for the process that needs it.
	free := st.Bavail * bs
	const mb = 1024 * 1024
	return int((total - free) / mb), int(total / mb)
}

// tcpConnections counts ESTABLISHED sockets across IPv4 and IPv6.
//
// This is the closest thing to "how many clients are on this node" that needs no
// per-protocol support, so it works for every engine the node runs rather than
// only the ones with a stats API.
func tcpConnections() int {
	const stateEstablished = "01"
	n := 0
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // header
			}
			fields := strings.Fields(line)
			// local, remote, st -> the state column is index 3.
			if len(fields) > 3 && fields[3] == stateEstablished {
				n++
			}
		}
	}
	return n
}

func systemMetrics() (cpuPct float64, memMB int) {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if la, err := strconv.ParseFloat(f[0], 64); err == nil {
				n := runtime.NumCPU()
				if n < 1 {
					n = 1
				}
				// Load average over core count, as a percentage. It is not
				// instantaneous utilisation, but it is a real measurement of
				// this machine rather than a constant.
				cpuPct = la / float64(n) * 100
				if cpuPct > 100 {
					cpuPct = 100
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail int64
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				continue
			}
			switch f[0] {
			case "MemTotal:":
				total = v
			case "MemAvailable:":
				avail = v
			}
		}
		if total > 0 && avail >= 0 {
			memMB = int((total - avail) / 1024)
		}
	}
	return cpuPct, memMB
}

// engineBin returns a supervised engine's binary path, or "" when it is not
// available on this node.
func (a *NodeAgent) engineBin(name string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.engines[name]; ok {
		return e.bin
	}
	return ""
}

// singboxStatsSupported reports whether this node's sing-box can meter users.
//
// Detected from the binary itself, once. Assuming it — in either direction —
// is what produced the original gap: assuming yes breaks startup, assuming no
// leaves the traffic unmetered forever.
func (a *NodeAgent) singboxStatsSupported() bool {
	a.mu.Lock()
	e, ok := a.engines["sing-box"]
	a.mu.Unlock()
	if !ok || e.bin == "" {
		return false
	}
	a.sbStatsOnce.Do(func() { a.sbStats = singboxapi.Detect(e.bin).Supported })
	return a.sbStats
}
