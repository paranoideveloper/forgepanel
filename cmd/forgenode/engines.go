package main

// Supervising more than one core on a node.
//
// The agent ran exactly one process, xray, from one config. The heartbeat
// carried only the xray half of the panel's bundle, so every hysteria2, tuic,
// anytls, shadowtls and wireguard inbound VANISHED the moment it was assigned to
// a remote node: the panel listed it, the node never served it, and nothing
// anywhere said why. Half the protocol matrix worked locally and not remotely.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"strconv"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/xrayapi"
)

// engineSpec describes how to validate and run one core.
//
// The differences between the cores are exactly these fields, so they live in
// data rather than in a switch that has to be extended in three places every
// time a core is added.
type engineSpec struct {
	name       string
	engine     binmgr.Engine
	configFile string
	// testArgs validates a config without running it. Every core here has its
	// own validator and none of them agree on the flag, which is precisely why
	// this is not hardcoded.
	testArgs func(path string) []string
	runArgs  func(path string) []string
	// hotApply, when set, is offered the old and new configs before the core is
	// restarted. Returning true means the change reached the running process.
	//
	// Only Xray has one: sing-box has no equivalent handler API in the builds
	// shipped here, and claiming otherwise would leave its users out of sync
	// with its config.
	hotApply func(bin, dataDir string, oldCfg, newCfg []byte) (bool, error)
}

func engineSpecs() []engineSpec {
	return []engineSpec{
		{
			name: "xray", engine: binmgr.EngineXray, configFile: "node-xray.json",
			testArgs: func(p string) []string { return []string{"run", "-test", "-config", p} },
			runArgs:  func(p string) []string { return []string{"run", "-config", p} },
			hotApply: func(bin, dataDir string, oldCfg, newCfg []byte) (bool, error) {
				return xrayapi.HotApply(xrayapi.HotApplyOptions{
					Bin:    bin,
					Server: "127.0.0.1:" + strconv.Itoa(nodeXrayAPIPort),
					// Under the node's own data directory, not /tmp: the
					// documents carry user credentials for as long as the call
					// takes.
					WorkDir: filepath.Join(dataDir, "hot"),
				}, oldCfg, newCfg)
			},
		},
		{
			name: "sing-box", engine: binmgr.EngineSingbox, configFile: "node-singbox.json",
			testArgs: func(p string) []string { return []string{"check", "-c", p} },
			runArgs:  func(p string) []string { return []string{"run", "-c", p} },
		},
	}
}

// engineProc is one supervised core.
type engineProc struct {
	spec      engineSpec
	bin       string
	lastCfg   string
	cmd       *exec.Cmd
	startedAt time.Time
}

// apply validates and installs a new config, restarting the core.
//
// An EMPTY config means "this engine has nothing to serve here", which is the
// normal state for a node running only xray protocols. It stops the core rather
// than leaving it running on a stale config — a core still serving inbounds the
// panel has removed is the failure this whole path exists to avoid.
func (e *engineProc) apply(dataDir, cfg string) {
	if cfg == e.lastCfg {
		return
	}
	configPath := filepath.Join(dataDir, e.spec.configFile)

	if cfg == "" {
		e.stop()
		_ = os.Remove(configPath)
		e.lastCfg = ""
		return
	}

	tmp := tempConfigPath(configPath)
	if err := os.WriteFile(tmp, []byte(cfg), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "forgenode: %s: write temp config: %v\n", e.spec.name, err)
		return
	}

	if e.bin != "" {
		// Validated BEFORE the running process is touched, so a bad config
		// leaves the node serving the last good one rather than nothing.
		out, err := exec.Command(e.bin, e.spec.testArgs(tmp)...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "forgenode: %s rejected the config: %v: %s\n",
				e.spec.name, err, out)
			_ = os.Remove(tmp)
			return
		}
	}
	if err := os.Rename(tmp, configPath); err != nil {
		fmt.Fprintf(os.Stderr, "forgenode: %s: commit config: %v\n", e.spec.name, err)
		_ = os.Remove(tmp)
		return
	}
	prev := e.lastCfg
	e.lastCfg = cfg

	// A user-only change is applied to the RUNNING core rather than restarting
	// it. Without this, one user tripping a quota or one account being created
	// dropped EVERY connection on this node — the panel solved that for its own
	// cores and the fleet kept restarting.
	//
	// Only when the core is already up: there is nothing to hot-apply into
	// otherwise, and the start below is the correct path.
	if e.bin != "" && e.running() && e.spec.hotApply != nil {
		if applied, err := e.spec.hotApply(e.bin, dataDir, []byte(prev), []byte(cfg)); err == nil && applied {
			fmt.Printf("forgenode: %s users updated without a restart\n", e.spec.name)
			return
		} else if err != nil {
			// Fall through to the restart, which is the one action that always
			// reconciles a core with its config. Recorded so the restart is not
			// a mystery.
			fmt.Fprintf(os.Stderr, "forgenode: %s hot apply failed, restarting: %v\n",
				e.spec.name, err)
		}
	}

	e.stop()
	if e.bin == "" {
		fmt.Printf("forgenode: %s config updated (binary not available to launch)\n", e.spec.name)
		return
	}
	cmd := exec.Command(e.bin, e.spec.runArgs(configPath)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// Stamped on every (re)start so the heartbeat reports real uptime. A core
	// that is quietly crash-looping shows a permanently near-zero value, which is
	// the only signal the panel gets that a node is "connected" but serving
	// nothing.
	e.startedAt = time.Now()
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "forgenode: failed to start %s: %v\n", e.spec.name, err)
		return
	}
	e.cmd = cmd
	fmt.Printf("forgenode: started %s with the new config\n", e.spec.name)
}

func (e *engineProc) stop() {
	if e.cmd != nil && e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
		_ = e.cmd.Wait()
	}
	e.cmd = nil
	e.startedAt = time.Time{}
}

// running reports whether the core is currently supervised.
func (e *engineProc) running() bool { return e.cmd != nil && e.cmd.Process != nil }

// tempConfigPath returns a sibling temp path that KEEPS the config's extension.
//
// It used to be configPath + ".tmp", giving node-xray.json.tmp — and Xray infers
// a config's format from its file EXTENSION, so it refused the temp file
// outright:
//
//	Failed to start: main: failed to load config files:
//	[/var/lib/forgepanel/node-xray.json.tmp] >
//	core: Failed to get format of /var/lib/forgepanel/node-xray.json.tmp
//
// Validation happens against the temp path, so EVERY config a node was sent was
// rejected before it could be committed, whatever it contained. A node enrolled,
// heartbeated, reported healthy, received its config, refused it, and retried
// every ten seconds forever: the remote-node feature did not work at all.
//
// The panel's own supervised adapter carries a comment about exactly this
// ("Xray infers the config format from the file EXTENSION, which is why every
// path this adapter writes keeps a .json suffix"). The agent was written without
// it. Nothing caught the difference because the agent's tests drive it against
// an httptest server and never run a real core.
//
// The temp file stays a sibling so the commit is still an atomic same-directory
// rename.
func tempConfigPath(configPath string) string {
	ext := filepath.Ext(configPath)
	if ext == "" {
		return configPath + ".tmp"
	}
	return strings.TrimSuffix(configPath, ext) + ".tmp" + ext
}
