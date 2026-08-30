package api

// The settings surface, described by the panel rather than by the UI.
//
// Every enum the settings cards offer, every default they show as pre-selected
// and every one-line explanation next to a checkbox was hardcoded on the client,
// a second copy of what internal/settings/defs.go now owns. Two copies of a list
// of legal values, only one of which is enforced, is how "block" quietly became
// a preset the UI offered and the validator had never heard of.
//
// This route serves the registry itself, so an operator (or a client, or
// forgectl, or a support script) can ask the panel what it can be told.

import (
	"strings"
	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/deploy"
	"github.com/forgepanel/forgepanel/internal/settings"
)

// settingDefView is one knob as the API describes it. Default and Value are
// rendered in the setting's OWN type — a checkbox gets true, not "1" — so a
// client never has to know the storage encoding.
type settingDefView struct {
	Key      string   `json:"key"`
	Type     string   `json:"type"`
	Scope    string   `json:"scope"`
	Default  any      `json:"default"`
	Value    any      `json:"value"`
	Choices  []string `json:"choices,omitempty"`
	Secret   bool     `json:"secret,omitempty"`
	HasValue bool     `json:"has_value"`
	Help     string   `json:"help"`
}

// handleSettingsRegistry lists every operator-editable setting with its type,
// its default, its legal values and its current value.
//
// ScopeInternal keys are left out entirely: the edge feed's bearer token and the
// half-finished TOTP secrets are panel-owned state, and listing them as settings
// would invite editing them. A secret's value is never included either — only
// whether one is set, which is the same contract the Telegram card already has.
func (s *Server) handleSettingsRegistry(c *gin.Context) {
	defs := settings.All()
	// What this deployment cannot do, it does not get controls for. A setting the
	// platform owns is REMOVED rather than shown and ignored: an operator who
	// tunes BBR inside a container, or types a public address the platform will
	// override, gets no error at the switch and a failure somewhere else.
	sur := s.deploySurface()
	needs := deploy.SettingRequires()
	inapplicable := func(key string) bool {
		for k, capability := range needs {
			// Prefix families (core_version_) are registered as one def whose key
			// is the prefix, so an exact match covers both forms.
			if k == key || (strings.HasSuffix(k, "_") && strings.HasPrefix(key, k)) {
				return !sur.Allows(capability)
			}
		}
		return false
	}

	out := make([]settingDefView, 0, len(defs))
	for _, d := range defs {
		if d.Scope == settings.ScopeInternal {
			continue
		}
		if inapplicable(d.Key) {
			continue
		}
		out = append(out, settingDefView{
			Key:      d.Key,
			Type:     string(d.Kind),
			Scope:    string(d.Scope),
			Default:  settings.DefaultValue(d),
			Value:    s.knobs().Value(d),
			Choices:  d.Choices,
			Secret:   d.Secret,
			HasValue: s.knobs().Has(d.Key),
			Help:     d.Help,
		})
	}
	c.JSON(200, gin.H{"settings": out})
}
