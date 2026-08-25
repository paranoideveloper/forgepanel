package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// statValue decodes an Xray statsquery counter that may be a JSON number
// (modern Xray emits "value": 12345), a numeric string ("value": "12345", older
// builds), or null/missing (→ 0). Fractional or out-of-int64-range values are
// errors so a single malformed counter is skipped rather than silently
// corrupting usage accounting. Exact int64 values are preserved without float
// rounding.
type statValue int64

func (v *statValue) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		*v = 0
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		*v = 0
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		// Xray traffic counters are monotonic byte totals. A negative value is
		// corruption, and applying it would credit the user bytes back and
		// silently weaken quota enforcement.
		if n < 0 {
			return fmt.Errorf("stats: negative counter %q", s)
		}
		*v = statValue(n)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f != math.Trunc(f) || f < 0 || f >= math.MaxInt64 {
			return fmt.Errorf("stats: value %q is not an exact non-negative int64", s)
		}
		*v = statValue(int64(f))
		return nil
	}
	return fmt.Errorf("stats: unparseable counter %q", s)
}

// UserTraffic is a per-user traffic sample keyed by the stats email tag.
type UserTraffic struct {
	Email    string `json:"email"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// QueryUserStats shells `xray api statsquery` against the local gRPC API and
// returns per-user traffic (spec §11). It parses Xray's `user>>>email>>>traffic
// >>>uplink|downlink` counter names. Reset zeroes the counters after reading so
// the next poll yields a delta.
func (c *Controller) QueryUserStats(reset bool) (map[string]*UserTraffic, error) {
	bin := c.bins.Path(binmgr.EngineXray)
	args := []string{"api", "statsquery", "--server=127.0.0.1:" + strconv.Itoa(c.xrayAPIPort), "-pattern", "user>>>"}
	if reset {
		args = append(args, "-reset")
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return nil, err
	}
	res, skipped := parseStatsQuery(out)
	if skipped > 0 {
		// Surface malformed counters instead of letting them look like flat
		// usage: a sustained run of them means accounting is silently degraded,
		// which is exactly the condition that stops quota enforcement working.
		c.mMalformedStats.Add(int64(skipped))
	}
	c.mergeSingboxStats(res, reset)
	return res, nil
}

// mergeSingboxStats folds in the counters for the protocols only sing-box
// serves: hysteria2, tuic, anytls, shadowtls and wireguard.
//
// Those were metered by NOTHING. A user could exhaust their plan entirely on
// them and stay active forever, because the quota system was guarding traffic it
// could never see — a failure that is silent and always in the customer's
// favour, which is why it lasted.
//
// The two cores are summed into one number per user rather than reported
// separately: a user's quota is one allowance regardless of which core happened
// to carry the bytes, and two half-counts nobody reconciles is how the panel
// would end up under-billing again.
//
// A failure here is recorded and never fatal. Losing sing-box counters must not
// also lose the xray ones that were read successfully.
func (c *Controller) mergeSingboxStats(into map[string]*UserTraffic, reset bool) {
	if c.sbAPIPort <= 0 || !c.SingboxStatsSupported().Supported {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := querySingboxStats(ctx, "127.0.0.1:"+strconv.Itoa(c.sbAPIPort), "user>>>", reset)
	if err != nil {
		c.setSingboxStatsErr(err.Error())
		return
	}
	c.setSingboxStatsErr("")
	for name, value := range raw {
		email, dir, ok := parseUserCounterName(name)
		if !ok {
			c.mMalformedStats.Add(1)
			continue
		}
		ut := into[email]
		if ut == nil {
			ut = &UserTraffic{}
			into[email] = ut
		}
		switch dir {
		case "uplink":
			ut.Uplink += value
		case "downlink":
			ut.Downlink += value
		}
	}
}

// parseUserCounterName splits "user>>><email>>>>traffic>>>uplink".
//
// sing-box emits the identical grammar to xray, which is what lets one
// accounting path serve both cores.
func parseUserCounterName(name string) (email, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", "", false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", "", false
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

func (c *Controller) setSingboxStatsErr(msg string) {
	c.sbStatsErrMu.Lock()
	c.sbStatsErr = msg
	c.sbStatsErrMu.Unlock()
}

// SingboxStatsError reports the most recent sing-box stats failure, so degraded
// accounting is visible rather than looking like users who stopped transferring.
func (c *Controller) SingboxStatsError() string {
	c.sbStatsErrMu.Lock()
	defer c.sbStatsErrMu.Unlock()
	return c.sbStatsErr
}

// MalformedStatsTotal is the number of engine stat counters that could not be
// parsed since start. A non-zero and growing value means per-user accounting is
// incomplete.
func (c *Controller) MalformedStatsTotal() int64 { return c.mMalformedStats.Load() }

// parseStatsQuery decodes the JSON `xray api statsquery` emits: {"stat":[{"name":
// "user>>>alice>>>traffic>>>uplink","value":"123"}, ...]}. It returns the
// per-user totals and how many entries were skipped as malformed.
func parseStatsQuery(out []byte) (map[string]*UserTraffic, int) {
	res := map[string]*UserTraffic{}
	skipped := 0
	var doc struct {
		Stat []json.RawMessage `json:"stat"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return res, 0
	}
	for _, raw := range doc.Stat {
		var e struct {
			Name  string    `json:"name"`
			Value statValue `json:"value"`
		}
		// Decode each stat independently so one malformed counter (bad value type
		// or overflow) never discards the whole document.
		if err := json.Unmarshal(raw, &e); err != nil {
			skipped++
			continue
		}
		parts := strings.Split(e.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			continue
		}
		email, dir := parts[1], parts[3]
		ut := res[email]
		if ut == nil {
			ut = &UserTraffic{Email: email}
			res[email] = ut
		}
		switch dir {
		case "uplink":
			ut.Uplink = int64(e.Value)
		case "downlink":
			ut.Downlink = int64(e.Value)
		}
	}
	return res, skipped
}

// RemoveUser was here: a hot-remove helper with ZERO callers, so the promise it
// carried ("never restart Xray to add a user") was never kept by anything. It
// also discarded the CLI's output and returned only the exit status, which for
// `xray api` is not enough to tell success from a silent no-op.
//
// The working version is in hotuser.go, reached automatically from the reload
// path rather than needing a caller to remember it.
