package core

// Liveness probes for the supervised cores.
//
// The supervisor could only ever see a core that EXITED. A core whose gRPC API
// has stopped answering — a wedged event loop, a start that never finished, a
// box thrashing under memory pressure — keeps its process alive indefinitely, so
// cmd.Wait() never returns, the state stays "running", and the panel reports a
// healthy engine while it serves nobody. These are the questions that tell the
// two apart, and they are asked of the same local APIs the panel already depends
// on for accounting, so a core that cannot answer them cannot be metered either.

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/singboxapi"
)

// livenessPattern matches no counter that can exist: real ones are
// "user>>>…" or "inbound>>>…". An empty result set is the SUCCESS case — the
// question is whether the core scheduled the gRPC handler at all, not whether
// anything matched — and asking for nothing keeps the probe from dragging a
// full counter table back every interval.
const livenessPattern = "forgepanel>>>liveness"

// probeXrayAPI asks the running Xray whether its local API still answers.
//
// The api inbound it talks to is rendered into every config the panel builds
// (engine.BuildMulti and engine.Build both emit it unconditionally), so the
// target is guaranteed to be there whenever Xray is running a panel-generated
// config. It shells the binary rather than speaking gRPC directly for the same
// reason QueryUserStats does: xray's own CLI is the only client of that service
// the panel has, and a second hand-rolled one would be a second thing to drift.
func (c *Controller) probeXrayAPI(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, c.bins.Path(binmgr.EngineXray), "api", "statsquery",
		"--server=127.0.0.1:"+strconv.Itoa(c.xrayAPIPort), "-pattern", livenessPattern).CombinedOutput()
	if err == nil {
		return nil
	}
	// The core's own words, trimmed: "connection refused" and "context
	// deadline exceeded" are different faults and the operator has to see which.
	if msg := firstLine(string(out)); msg != "" {
		return fmt.Errorf("xray stats api on 127.0.0.1:%d: %v: %s", c.xrayAPIPort, err, msg)
	}
	return fmt.Errorf("xray stats api on 127.0.0.1:%d: %w", c.xrayAPIPort, err)
}

// probeSingboxAPI asks the running sing-box the same question, when it can be
// asked at all.
//
// Returning nil when there is no stats API is mandatory, not laziness: the
// official sing-box archives are built without with_v2ray_api, and binmgr pins
// those archives. Treating "no API to answer" as "not answering" would mark
// every stock installation unresponsive and hold it in a permanent restart loop
// — a liveness check that takes down every host it was meant to protect. The
// guard is the same one mergeSingboxStats uses, for the same reason.
func (c *Controller) probeSingboxAPI(ctx context.Context) error {
	if c.sbAPIPort <= 0 || !c.SingboxStatsSupported().Supported {
		return nil
	}
	if _, err := singboxapi.Query(ctx, "127.0.0.1:"+strconv.Itoa(c.sbAPIPort), livenessPattern, false); err != nil {
		return err
	}
	return nil
}

// firstLine trims an engine's output down to something an operator can read in a
// status line. Xray's failures are several clauses deep and only the first
// carries the cause.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
