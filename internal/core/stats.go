package core

import (
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"

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
	return res, nil
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

// RemoveUser hot-removes a user from a live inbound via the Xray HandlerService
// gRPC (spec §6: "Never restart Xray to add a user"). Best-effort: if it fails
// the caller falls back to a regenerate-and-reload.
func (c *Controller) RemoveUser(inboundTag, email string) error {
	bin := c.bins.Path(binmgr.EngineXray)
	cmd := exec.Command(bin, "api", "rmu",
		"--server=127.0.0.1:"+strconv.Itoa(c.xrayAPIPort),
		"-tag", inboundTag, email)
	return cmd.Run()
}
