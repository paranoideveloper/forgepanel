package api

// Operator-selectable proxy-core versions (FP-ADAPT-014).
//
// binmgr pins one version per engine as a compile-time constant. That made the
// only route off a broken or vulnerable core a rebuild of the panel, which an
// operator running a released binary cannot do at all. These three routes move
// the selection into the database and — the part that matters — into the SHARED
// binmgr.Manager the supervisor resolves every core through, so the change takes
// effect on the next reload rather than only in what the API says.
//
// The digest is mandatory. binmgr refuses to install an artifact it has no
// SHA-256 for, and nothing here relaxes that: a pin is validated against the
// asset THIS HOST would download before a single row is written.

import (
	"regexp"
	"strings"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/gin-gonic/gin"
)

// coreVersionKey and corePrevKey name the two settings that hold one engine's
// selection. Both are ScopeInternal: the settings UI must not offer a way to set
// a version without a digest.
func coreVersionKey(e binmgr.Engine) string { return "core_version_" + string(e) }
func corePrevKey(e binmgr.Engine) string    { return "core_version_prev_" + string(e) }

// coreVersionPattern is what may appear in a version string.
//
// This is a path and URL component, not a label: it becomes the cache directory
// name in binmgr.Path and a segment of the GitHub download URL. A version
// containing a slash or a "." pair would let a pin write outside the bin
// directory entirely.
var coreVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

var coreHexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// nodeCoreNote is what GET /api/admin/cores reports for the fleet.
//
// It says "not yet" rather than echoing the panel's selection back because the
// heartbeat carries no core pin: a node still resolves the version compiled into
// its own forgenode binary. Reporting a fleet-wide version the fleet is not
// running would be worse than reporting nothing.
const nodeCoreNote = "shipped pin (this panel cannot yet re-pin nodes)"

// coreState is one engine's version picture: what this build shipped, what the
// operator selected, what a rollback would return to, and what is on disk.
type coreState struct {
	Engine    string   `json:"engine"`
	Shipped   string   `json:"shipped"`
	Pinned    string   `json:"pinned"`
	Previous  string   `json:"previous"`
	Running   string   `json:"running"`
	Asset     string   `json:"asset"`
	Installed []string `json:"installed"`
	Available []string `json:"available"`
	Nodes     string   `json:"nodes"`
}

type corePinRequest struct {
	Version string            `json:"version"`
	SHA256  map[string]string `json:"sha256"`
}

// coreVersion is the version the panel is really resolving for e, falling back
// to the compiled constant in the light constructor where there is no engine.
func (s *Server) coreVersion(e binmgr.Engine) string {
	if s == nil || s.engine == nil {
		return binmgr.ShippedVersion(e)
	}
	return s.engine.Bins().Version(e)
}

// coreSelection reads the stored version choice for every managed engine. An
// empty value means "the version this build shipped with".
func (s *Server) coreSelection() map[binmgr.Engine]string {
	out := make(map[binmgr.Engine]string, len(binmgr.ManagedEngines()))
	k := s.knobs()
	for _, e := range binmgr.ManagedEngines() {
		out[e] = k.String(coreVersionKey(e))
	}
	return out
}

// corePinsFrom turns a version selection into the manager's pin map, reading
// each selected version's digests out of the store. An engine with no selection
// is absent from the result, which is how it keeps the compiled default.
func (s *Server) corePinsFrom(sel map[binmgr.Engine]string) (map[binmgr.Engine]binmgr.Pin, error) {
	out := map[binmgr.Engine]binmgr.Pin{}
	for e, ver := range sel {
		if ver == "" {
			continue
		}
		rows, err := s.db.CorePinsFor(string(e), ver)
		if err != nil {
			return nil, err
		}
		sums := make(map[string]string, len(rows))
		for _, r := range rows {
			sums[r.Asset] = r.SHA256
		}
		out[e] = binmgr.Pin{Version: ver, SHA256: sums}
	}
	return out, nil
}

// applyStoredCorePins re-applies the operator's selection to the shared binary
// manager at boot.
//
// WITHOUT THIS the feature dies quietly across a restart: the rows are still
// there, GET /api/admin/cores still reports them, and the supervisor resolves
// every core through the compiled constant again.
func (s *Server) applyStoredCorePins() error {
	if s.engine == nil || s.db == nil {
		return nil
	}
	pins, err := s.corePinsFrom(s.coreSelection())
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		return nil
	}
	return s.engine.SetCorePins(pins)
}

// coreEngineParam resolves :engine, refusing anything binmgr does not manage.
func coreEngineParam(c *gin.Context) (binmgr.Engine, bool) {
	e := binmgr.Engine(c.Param("engine"))
	if !binmgr.Managed(e) {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindNotFound,
			Message: "no such core: " + c.Param("engine")})
		return "", false
	}
	return e, true
}

func (s *Server) handleListCores(c *gin.Context) {
	k := s.knobs()
	out := make([]coreState, 0, len(binmgr.ManagedEngines()))
	for _, e := range binmgr.ManagedEngines() {
		st := coreState{
			Engine:   string(e),
			Shipped:  binmgr.ShippedVersion(e),
			Pinned:   k.String(coreVersionKey(e)),
			Previous: k.String(corePrevKey(e)),
			Running:  s.coreVersion(e),
			Nodes:    nodeCoreNote,
		}
		// Named so an operator knows exactly which file to hash. Three upstream
		// projects name their platform builds three different ways, and guessing
		// wrong is a refused pin with nothing to show for it.
		if asset, err := binmgr.HostAssetName(e, st.Running); err == nil {
			st.Asset = asset
		}
		if s.engine != nil {
			st.Installed = s.engine.Bins().InstalledVersions(e)
		}
		if s.db != nil {
			if vers, err := s.db.CorePinVersions(string(e)); err == nil {
				st.Available = vers
			}
		}
		out = append(out, st)
	}
	c.JSON(200, out)
}

func (s *Server) handlePinCore(c *gin.Context) {
	e, ok := coreEngineParam(c)
	if !ok {
		return
	}
	if s.engine == nil {
		s.engineUnavailable(c)
		return
	}
	var req corePinRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindValidation,
			Message: "malformed request body", Cause: err})
		return
	}
	req.Version = strings.TrimSpace(req.Version)
	rows, err := coreDigestRows(req)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindValidation, Message: err.Error(), Cause: err})
		return
	}
	if err := s.applyCoreSelection(c, e, req.Version, binmgr.Pin{Version: req.Version, SHA256: req.SHA256}, rows); err != nil {
		return
	}
	s.auditNote(c, "core.pinned", string(e), req.Version)
	c.JSON(200, s.coreStateFor(e))
}

func (s *Server) handleRollbackCore(c *gin.Context) {
	e, ok := coreEngineParam(c)
	if !ok {
		return
	}
	if s.engine == nil {
		s.engineUnavailable(c)
		return
	}
	k := s.knobs()
	cur, target := k.String(coreVersionKey(e)), k.String(corePrevKey(e))
	if cur == target {
		apierr.Fail(c, &apierr.Error{Op: "core-rollback", Kind: apierr.KindNotFound,
			Message: "there is no previous " + string(e) + " version to roll back to"})
		return
	}
	// Rolling back costs no download: binmgr.Path keys the cache directory by
	// version, so the binary this returns to is still on disk and Ensure finds it
	// installed and executable.
	var pin binmgr.Pin
	if target != "" {
		stored, err := s.db.CorePinsFor(string(e), target)
		if err != nil {
			apierr.Fail(c, &apierr.Error{Op: "core-rollback", Kind: apierr.KindServer, Message: err.Error(), Cause: err})
			return
		}
		pin.Version = target
		pin.SHA256 = make(map[string]string, len(stored))
		for _, r := range stored {
			pin.SHA256[r.Asset] = r.SHA256
		}
	}
	if err := s.applyCoreSelection(c, e, target, pin, nil); err != nil {
		return
	}
	s.auditNote(c, "core.rolled_back", string(e), target)
	c.JSON(200, s.coreStateFor(e))
}

// applyCoreSelection is the one write path both routes share: validate against
// this host, persist, then re-point the running manager.
//
// The order is deliberate. Validation happens BEFORE anything is stored, so a
// pin the manager would refuse never becomes a database row claiming a version
// the panel is not running. The two settings are written in one SetAll batch, so
// a half-written pair can never leave rollback pointing at the wrong version.
// It writes the refusal itself and returns the error for the caller to abort on.
func (s *Server) applyCoreSelection(c *gin.Context, e binmgr.Engine, version string, pin binmgr.Pin, rows []store.CorePin) error {
	sel := s.coreSelection()
	prev := sel[e]
	sel[e] = version
	pins, err := s.corePinsFrom(sel)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindServer, Message: err.Error(), Cause: err})
		return err
	}
	if version == "" {
		delete(pins, e)
	} else {
		pins[e] = pin
	}
	if err := binmgr.ValidatePins(pins); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindValidation,
			Message: err.Error(), Cause: err,
			Details: map[string]any{"hint": "supply the SHA-256 of the release asset this host downloads; " +
				"GET /api/admin/cores names it"}})
		return err
	}
	if len(rows) > 0 {
		if err := s.db.SaveCorePins(string(e), version, rows); err != nil {
			apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindServer, Message: err.Error(), Cause: err})
			return err
		}
	}
	write := map[string]string{coreVersionKey(e): version}
	// Re-pinning the version already selected must not overwrite the rollback
	// target with itself, which would silently strand the operator on it.
	if prev != version {
		write[corePrevKey(e)] = prev
	}
	if err := s.knobs().SetAll(write); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindValidation, Message: err.Error(), Cause: err})
		return err
	}
	if err := s.engine.SetCorePins(pins); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "core-pin", Kind: apierr.KindValidation, Message: err.Error(), Cause: err})
		return err
	}
	// The running cores are still the old binaries until something reloads them.
	s.startBackground(s.reloadEngines)
	return nil
}

// coreStateFor is the single-engine view the two mutating routes answer with.
func (s *Server) coreStateFor(e binmgr.Engine) coreState {
	k := s.knobs()
	st := coreState{
		Engine:   string(e),
		Shipped:  binmgr.ShippedVersion(e),
		Pinned:   k.String(coreVersionKey(e)),
		Previous: k.String(corePrevKey(e)),
		Running:  s.coreVersion(e),
		Nodes:    nodeCoreNote,
	}
	if asset, err := binmgr.HostAssetName(e, st.Running); err == nil {
		st.Asset = asset
	}
	if s.engine != nil {
		st.Installed = s.engine.Bins().InstalledVersions(e)
	}
	return st
}

// coreDigestRows validates a pin request into storable rows.
func coreDigestRows(req corePinRequest) ([]store.CorePin, error) {
	if !coreVersionPattern.MatchString(req.Version) {
		return nil, errCoreVersion
	}
	rows := make([]store.CorePin, 0, len(req.SHA256))
	for asset, sum := range req.SHA256 {
		if asset == "" || strings.ContainsAny(asset, "/\\") || len(asset) > 128 {
			return nil, errCoreAsset
		}
		if !coreHexPattern.MatchString(sum) {
			return nil, errCoreDigest
		}
		rows = append(rows, store.CorePin{Asset: asset, SHA256: strings.ToLower(sum)})
	}
	return rows, nil
}

// The three refusals a malformed pin can produce, as values so the messages
// cannot drift between the validator and the response.
var (
	errCoreVersion = coreErr("version must be a release tag such as v26.3.27: letters, digits, dot, dash, underscore or plus")
	errCoreAsset   = coreErr("each sha256 key must be a release file name, not a path")
	errCoreDigest  = coreErr("each sha256 value must be 64 hexadecimal characters")
)

type coreErr string

func (e coreErr) Error() string { return string(e) }
