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
	"time"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
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
}

func engineSpecs() []engineSpec {
	return []engineSpec{
		{
			name: "xray", engine: binmgr.EngineXray, configFile: "node-xray.json",
			testArgs: func(p string) []string { return []string{"run", "-test", "-config", p} },
			runArgs:  func(p string) []string { return []string{"run", "-config", p} },
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

	tmp := configPath + ".tmp"
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
	e.lastCfg = cfg

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
