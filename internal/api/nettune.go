package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"

	"github.com/forgepanel/forgepanel/internal/nettune"
)

// Host network tuning: TCP BBR + fq, behind an operator toggle.
//
// The setting lives in the KV table rather than panel.json because it is host
// state the panel merely mirrors — the truth is /proc, and the stored value only
// answers "did an operator ask for this", which is the question boot and
// maintenance need to re-apply it.

// settingNetTuneBBR is the stored toggle. "1" means the operator asked for BBR.
const settingNetTuneBBR = "net_tune_bbr"

// The host-mutating seam, kept as vars so tests can exercise the wiring without
// rewriting the sysctls of the machine running them.
var (
	nettuneApply  = nettune.Apply
	nettuneRevert = nettune.Revert
	nettuneStatus = nettune.Current
)

// netTuneLog reports a change in the host's willingness to be tuned. A var so a
// test can count how often a standing failure is announced.
var netTuneLog = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format, args...) }

func (s *Server) bbrEnabled() bool {
	// Through the typed registry, not the raw settings table. The registry owns
	// the default, so a reader that consulted the table directly would carry its
	// own copy of it — and the two would drift the first time either changed.
	return s.db != nil && s.knobs().Bool(settingNetTuneBBR)
}

// applyNetTune re-asserts the operator's choice on the host.
//
// Called at boot and from maintenance, because neither /proc write is durable:
// a reboot returns the host to cubic, and anything else on the box that writes
// net.ipv4.tcp_congestion_control (a stray sysctl file, a hosting provider's
// cloud-init, a kernel upgrade) takes BBR away silently. Applying only when the
// toggle is flipped would leave the panel reporting a setting the host stopped
// honouring days ago.
func (s *Server) applyNetTune() {
	if !s.bbrEnabled() {
		return
	}
	err := nettuneApply()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	// Only a CHANGE is worth a line. This runs once a minute for the life of the
	// process, and a host that refuses the write refuses it every time — 1440
	// identical lines a day is how an operator learns to stop reading the
	// journal. The first success is silent (the empty string is the starting
	// state); a recovery after a failure is not.
	s.netTuneMu.Lock()
	repeat := msg == s.netTuneLast
	s.netTuneLast = msg
	s.netTuneMu.Unlock()
	if repeat {
		return
	}
	if err != nil {
		netTuneLog("forgepanel: applying BBR congestion control: %v\n", err)
		return
	}
	netTuneLog("forgepanel: BBR congestion control applied\n")
}

type netTuneView struct {
	Enabled bool `json:"enabled"`
	nettune.Status
}

func (s *Server) handleGetNetTune(c *gin.Context) {
	c.JSON(200, netTuneView{Enabled: s.bbrEnabled(), Status: nettuneStatus()})
}

func (s *Server) handleSetNetTune(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	value := "0"
	if req.Enabled {
		value = "1"
	}
	// Persist BEFORE touching the host, and keep the stored choice even when the
	// apply fails. A kernel that gains BBR after a `apt install` and a reboot
	// then comes up with it on, because the boot path re-applies what is stored.
	// Set, not SetSetting: the registry validates the value against the knob's
	// declared kind before it is stored, so the table cannot end up holding
	// something no reader can parse.
	if err := s.knobs().Set(settingNetTuneBBR, value); err != nil {
		failErr(c, 500, err)
		return
	}
	action := nettuneApply
	if !req.Enabled {
		action = nettuneRevert
	}
	err := action()
	st := nettuneStatus()
	s.audit(c, "settings.net_tune_bbr", value)
	if err != nil {
		// Reported as a failure rather than a 200 with a quiet flag: a green
		// toggle over a host still running cubic is precisely how this feature
		// gets shipped broken. The stored setting stands, so the panel will try
		// again at the next boot and the next maintenance sweep.
		e := apierr.New(http.StatusInternalServerError, err.Error())
		e.Op = "nettune.apply"
		e.Remediation = st.Remediation
		// The host's own report travels with the refusal. Without it the UI can
		// say the apply failed but not WHY the kernel refused, which is the only
		// part an operator can act on.
		e.Details = map[string]any{"enabled": req.Enabled, "status": st}
		apierr.Fail(c, e)
		return
	}
	c.JSON(200, netTuneView{Enabled: req.Enabled, Status: st})
}
