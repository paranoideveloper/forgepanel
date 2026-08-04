package core

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

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
	return parseStatsQuery(out), nil
}

// parseStatsQuery decodes the JSON `xray api statsquery` emits: {"stat":[{"name":
// "user>>>alice>>>traffic>>>uplink","value":"123"}, ...]}.
func parseStatsQuery(out []byte) map[string]*UserTraffic {
	res := map[string]*UserTraffic{}
	var doc struct {
		Stat []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return res
	}
	for _, s := range doc.Stat {
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			continue
		}
		email, dir := parts[1], parts[3]
		v, _ := strconv.ParseInt(s.Value, 10, 64)
		ut := res[email]
		if ut == nil {
			ut = &UserTraffic{Email: email}
			res[email] = ut
		}
		switch dir {
		case "uplink":
			ut.Uplink = v
		case "downlink":
			ut.Downlink = v
		}
	}
	return res
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
