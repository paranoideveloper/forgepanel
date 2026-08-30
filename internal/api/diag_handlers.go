package api

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/diag"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// This file exposes the Validation & Proof engine (§3): Layer-1 static
// validation, the Layer-3 live Verify, and the Panel Doctor battery.

// usedPortsExcept builds a port→remark map of enabled inbounds other than the
// given id, for the port-conflict check.
func (s *Server) usedPortsExcept(exceptID uint) map[int]string {
	out := map[int]string{}
	ins, _ := s.db.ListInbounds()
	for _, in := range ins {
		if in.ID == exceptID {
			continue
		}
		out[in.Port] = in.Remark
	}
	return out
}

// handleValidateInbound runs the instant static checks (Layer 1) on a posted
// node OR an existing inbound and returns coded findings.
func (s *Server) handleValidateInbound(c *gin.Context) {
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		failErr(c, 400, err)
		return
	}
	findings := diag.StaticValidate(&n, s.usedPortsExcept(0))
	c.JSON(200, gin.H{"findings": findings, "ok": !hasCritical(findings)})
}

// handleVerifyInbound runs the live proof-of-work (Layer 3): a real client core
// carries traffic through the inbound. The result is the badge the UI shows.
func (s *Server) handleVerifyInbound(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		fail(c, 404, "inbound not found")
		return
	}
	n, err := in.Node()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	// Run the verification with the exact sing-box the supervisor uses. binmgr
	// installs it under <dataDir>/bin, which is not on $PATH, so without this the
	// diagnostic falls back to a $PATH lookup that fails on every clean install
	// and reports "sing-box binary not available" even though the core is present.
	cores := diag.Cores{}
	if s.engine != nil {
		if bin, err := s.engine.SingboxBinary(); err == nil {
			cores.Singbox = bin
		}
	}
	res := diag.VerifySingbox(ctx, n, cores)
	s.audit(c, "inbound.verify", res.Finding.Code)
	c.JSON(200, res)
}

// handleDoctor runs the whole battery (§3 Panel Doctor): system checks plus
// static validation of every inbound, producing one shareable report.
func (s *Server) handleDoctor(c *gin.Context) {
	report := gin.H{"checked_at": time.Now()}
	var findings []diag.Finding

	// System: clock sync is a classic silent killer for REALITY/TLS.
	findings = append(findings, clockFindings(c.Request.Context())...)

	// Per-inbound static validation.
	ins, _ := s.db.ListInbounds()
	perInbound := make([]gin.H, 0, len(ins))
	for _, in := range ins {
		n, err := in.Node()
		if err != nil {
			continue
		}
		fs := diag.StaticValidate(n, s.usedPortsExcept(in.ID))
		findings = append(findings, fs...)
		perInbound = append(perInbound, gin.H{"id": in.ID, "remark": in.Remark, "findings": fs})
	}

	report["system_findings"] = findings
	report["inbounds"] = perInbound
	report["health"] = s.healthReport()
	report["ok"] = !hasCritical(findings)
	c.JSON(200, report)
}

func hasCritical(fs []diag.Finding) bool {
	for _, f := range fs {
		if f.Severity == diag.SevCritical {
			return true
		}
	}
	return false
}

// --- host clock discipline ------------------------------------------------
//
// VMess AEAD stamps a timestamp into every request and REALITY/TLS reject a
// handshake whose clock has drifted, so a skewed host clock presents itself as
// "my UUID/password stopped working" and sends the operator hunting through
// credentials. The doctor therefore measures the clock instead of assuming it:
// clockSkew() used to be a hardcoded `return 0`, which meant the 5s threshold
// below could never trip and FP-CLOCK-001 was dead code shipping a green light
// for a check that never ran.

const (
	// clockSkewTolerance is the drift above which handshakes start failing.
	// REALITY/VMess allow a couple of seconds either way; 5s is comfortably
	// past "normal jitter" and comfortably short of "clients are broken".
	clockSkewTolerance = 5 * time.Second
	// ntpQueryTimeout bounds the WHOLE clock check. The doctor is a synchronous
	// admin request, so an unreachable pool server must not stall it: all
	// servers are queried concurrently under this one deadline.
	ntpQueryTimeout = 1200 * time.Millisecond
	// ntpEpochOffset is the number of seconds between the NTP epoch
	// (1900-01-01) and the Unix epoch (1970-01-01).
	ntpEpochOffset = 2208988800
)

// ntpServers is the trusted time source. It is a var so tests can point the
// probe at a local fake server instead of the public pool.
var ntpServers = []string{"time.cloudflare.com:123", "pool.ntp.org:123"}

// clockState is everything the host clock check could establish. Measured and
// SyncKnown are separate on purpose: "we could not check" is a different answer
// from "the clock is fine", and reporting the first as the second is exactly
// the bug this replaces.
type clockState struct {
	Measured  bool          // an SNTP round trip succeeded and Skew is real
	Skew      time.Duration // signed: how far the local clock must move forward
	Source    string        // which server answered
	SyncKnown bool          // the host told us whether a time daemon has synced
	Synced    bool          // ...and this is what it said
	Detail    string        // last probe error, for the finding's detail line
}

// timeSyncProbe is the seam for the local half of the check. A test cannot make
// the host it runs on report NTPSynchronized=no, so the probe is swappable;
// production always uses systemTimeSynced.
var timeSyncProbe = systemTimeSynced

// checkClock measures the local clock against an external SNTP server and asks
// systemd whether a time daemon is disciplining it. Both halves are best
// effort; neither failing is itself reported as a broken clock.
func checkClock(ctx context.Context) clockState {
	var st clockState
	st.Synced, st.SyncKnown = timeSyncProbe(ctx)

	cctx, cancel := context.WithTimeout(ctx, ntpQueryTimeout)
	defer cancel()
	type probe struct {
		off time.Duration
		srv string
		err error
	}
	// Buffered so that the goroutines for the servers we stop waiting on can
	// still finish and exit instead of blocking forever on the send.
	ch := make(chan probe, len(ntpServers))
	for _, srv := range ntpServers {
		go func(srv string) {
			off, err := ntpOffset(cctx, srv)
			ch <- probe{off, srv, err}
		}(srv)
	}
	for range ntpServers {
		p := <-ch
		if p.err == nil {
			st.Measured, st.Skew, st.Source = true, p.off, p.srv
			break
		}
		st.Detail = p.srv + ": " + p.err.Error()
	}
	return st
}

// clockFindings turns a clock measurement into diagnostic findings.
func clockFindings(ctx context.Context) []diag.Finding {
	st := checkClock(ctx)
	var out []diag.Finding
	switch {
	case st.Measured && absDuration(st.Skew) > clockSkewTolerance:
		out = append(out, diag.New("FP-CLOCK-001",
			fmt.Sprintf("local clock is %s off %s", st.Skew.Round(time.Millisecond), st.Source)))
	case !st.Measured && !st.SyncKnown:
		// No trusted source AND no local sync daemon to vouch for the clock. Say
		// so (severity info) rather than stay silent, which would read as a pass.
		detail := st.Detail
		if detail == "" {
			detail = "no NTP server configured"
		}
		out = append(out, diag.New("FP-CLOCK-003", detail))
	}
	if st.SyncKnown && !st.Synced {
		// Worth reporting even when the current offset is still inside tolerance:
		// an undisciplined clock drifts, so this is tomorrow's FP-CLOCK-001.
		out = append(out, diag.New("FP-CLOCK-002", "systemd reports NTPSynchronized=no"))
	}
	return out
}

// ntpOffset runs one SNTP client transaction (RFC 4330 §5) and returns the
// offset of the server's clock from ours — positive when the local clock is
// behind. Only a well-formed answer from a synchronised server counts.
func ntpOffset(ctx context.Context, server string) (time.Duration, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(ntpQueryTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}

	req := make([]byte, 48)
	req[0] = 0x1B // LI=0, VN=3, Mode=3 (client)
	t1 := time.Now()
	binary.BigEndian.PutUint64(req[40:48], timeToNTP(t1))
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	if err != nil {
		return 0, err
	}
	t4 := time.Now()
	if n < 48 {
		return 0, fmt.Errorf("short NTP reply (%d bytes)", n)
	}
	if li := resp[0] >> 6; li == 3 {
		// Leap indicator 3 means the server's own clock is unsynchronised, so
		// its timestamps are worthless — trusting them would invent a skew.
		return 0, fmt.Errorf("server clock unsynchronised")
	}
	if mode := resp[0] & 0x07; mode != 4 && mode != 5 {
		return 0, fmt.Errorf("not a server-mode NTP reply (mode %d)", mode)
	}
	if resp[1] == 0 {
		// Stratum 0 is a kiss-o'-death packet (rate limit, deny, restrict).
		return 0, fmt.Errorf("kiss-o'-death from server")
	}
	t2 := ntpToTime(binary.BigEndian.Uint64(resp[32:40])) // server receive
	t3 := ntpToTime(binary.BigEndian.Uint64(resp[40:48])) // server transmit
	if t2.IsZero() || t3.IsZero() {
		return 0, fmt.Errorf("NTP reply carries no timestamps")
	}
	// RFC 4330 §5: theta = ((T2 - T1) + (T3 - T4)) / 2. Averaging the two legs
	// cancels the network delay, so a slow link does not look like drift.
	return (t2.Sub(t1) + t3.Sub(t4)) / 2, nil
}

// systemTimeSynced asks the host whether a time-sync daemon has actually
// disciplined the clock. known is false when nothing on this host can answer —
// a container without systemd, for instance — and the caller must not read that
// as "not synced".
func systemTimeSynced(ctx context.Context) (synced, known bool) {
	if bin, err := exec.LookPath("timedatectl"); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, bin, "show", "-p", "NTPSynchronized").Output()
		if err == nil {
			if v, ok := parseNTPSynchronized(string(out)); ok {
				return v, true
			}
		}
	}
	// systemd-timesyncd drops this stamp file once it has stepped or slewed the
	// clock from a server, so it answers the same question without the CLI.
	if _, err := os.Stat("/run/systemd/timesync/synchronized"); err == nil {
		return true, true
	}
	return false, false
}

// parseNTPSynchronized reads `timedatectl show -p NTPSynchronized` output
// ("NTPSynchronized=yes"). ok is false when the property is absent, which older
// systemd versions do instead of reporting "no".
func parseNTPSynchronized(out string) (synced, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		v, found := strings.CutPrefix(line, "NTPSynchronized=")
		if !found {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "yes" || v == "true" || v == "1", true
	}
	return false, false
}

// timeToNTP and ntpToTime convert between Go time and the 64-bit NTP timestamp
// (32 bits of seconds since 1900, 32 bits of binary fraction).
func timeToNTP(t time.Time) uint64 {
	sec := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) << 32 / uint64(time.Second)
	return sec<<32 | frac
}

func ntpToTime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	sec := int64(v>>32) - ntpEpochOffset
	nsec := int64(v&0xFFFFFFFF) * int64(time.Second) >> 32
	return time.Unix(sec, nsec)
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// (tests for these handlers live in diag_handlers_test.go)
