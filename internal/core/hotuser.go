package core

// Hot user add/remove, instead of restarting every core on every mutation.
//
// The mechanism lives in internal/core/xrayapi so the NODE AGENT can use it too.
// It was here, unexported, so a remote node restarted its cores on EVERY config
// change — one user tripping a quota dropped every other connection on that
// node. The panel had solved that for itself and the fleet had not.

import (
	"path/filepath"
	"strconv"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/xrayapi"
)

// hotApplyDir is where the short-lived `adu` documents are written.
//
// Under the panel's own data directory rather than the system temp dir: they
// carry user credentials, and a world-readable /tmp on a shared host would
// expose them for as long as the call takes.
func (c *Controller) hotApplyDir() string {
	return filepath.Join(c.dataDir, "engines", "hot")
}

// xrayHotApply is the supervisor's HotApply hook for Xray.
//
// It returns true only when every part of the change was applied to the running
// core. Anything else returns false (restart) or an error (restart, with the
// reason recorded).
func (c *Controller) xrayHotApply(oldCfg, newCfg []byte) (bool, error) {
	return xrayapi.HotApply(xrayapi.HotApplyOptions{
		Bin:     c.bins.Path(binmgr.EngineXray),
		Server:  "127.0.0.1:" + strconv.Itoa(c.xrayAPIPort),
		WorkDir: c.hotApplyDir(),
	}, oldCfg, newCfg)
}
