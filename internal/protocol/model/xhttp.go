// xhttp.go carries the XHTTP transport's full modern field set.
//
// WHY a file of its own: XHTTP is the only transport whose knobs the operator
// actually tunes per-deployment (CDN buffering limits, padding shape, session
// carriage, split up/down legs), and every one of those knobs is rejected by
// the core when it is out of range or combined with the wrong mode. Keeping the
// enum tables, the validation and the share-link codec together means the model,
// the renderer and the parser can never disagree about what XHTTP accepts.
//
// Every value set and every cross-field rule below was confirmed against the
// pinned Xray build with `xray run -test`; the comment on each rule names the
// core's own rejection message.
package model

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// XHTTP transport modes (xhttpSettings.mode).
const (
	XHTTPModeAuto      = "auto"
	XHTTPModePacketUp  = "packet-up"
	XHTTPModeStreamUp  = "stream-up"
	XHTTPModeStreamOne = "stream-one"
)

// AllXHTTPModes lists every mode the core accepts. Anything else is rejected
// with "unsupported mode".
func AllXHTTPModes() []string {
	return []string{XHTTPModeAuto, XHTTPModePacketUp, XHTTPModeStreamUp, XHTTPModeStreamOne}
}

// AllXHTTPPaddingPlacements lists where the padding token may be carried.
// Note there is deliberately no "path" here: the core rejects it.
func AllXHTTPPaddingPlacements() []string {
	return []string{"queryInHeader", "header", "cookie", "query"}
}

// AllXHTTPPaddingMethods lists how the padding token is generated.
func AllXHTTPPaddingMethods() []string { return []string{"repeat-x", "tokenish"} }

// AllXHTTPPlacements lists where the session id and the sequence number may be
// carried. Both share the same value set.
func AllXHTTPPlacements() []string { return []string{"path", "header", "cookie", "query"} }

// AllXHTTPUplinkDataPlacements lists where packet-up uplink payload may ride.
// "header" and "cookie" are packet-up-only; see validateXHTTP.
func AllXHTTPUplinkDataPlacements() []string { return []string{"body", "header", "cookie"} }

// AllXHTTPUplinkMethods lists the HTTP methods the uplink may use. "GET" is
// packet-up-only; see validateXHTTP.
func AllXHTTPUplinkMethods() []string { return []string{"POST", "PUT", "PATCH", "GET"} }

// XHTTPDownload is XHTTP's `downloadSettings`: a COMPLETE second stream that
// carries the download direction while the primary stream carries the upload.
// It has its own address/port, its own transport and its own TLS/REALITY layer,
// which is exactly what makes "upload through the CDN, download direct" (or the
// reverse) expressible — the single most useful XHTTP feature for operators
// fighting asymmetric throttling.
//
// It is a CLIENT-side construct: the core only honours it on an outbound.
type XHTTPDownload struct {
	Address   string    `json:"address,omitempty"`
	Port      int       `json:"port,omitempty"`
	Transport Transport `json:"transport"`
	Security  Security  `json:"security"`
}

// SNI returns the effective server name for the download leg, mirroring
// Node.SNI: the explicit TLS server name, else the transport Host, else the
// leg's own address.
func (d *XHTTPDownload) SNI() string {
	if d.Security.ServerName != "" {
		return d.Security.ServerName
	}
	if d.Transport.Host != "" {
		return d.Transport.Host
	}
	return d.Address
}

func (d *XHTTPDownload) clone() *XHTTPDownload {
	if d == nil {
		return nil
	}
	c := *d
	c.Transport = d.Transport.clone()
	c.Security = d.Security.clone()
	return &c
}

// normalize canonicalizes the download leg. Its transport is a real transport,
// so it goes through the same field-clearing the primary one does; nesting a
// further download leg is not something the core supports, so it is dropped.
func (d *XHTTPDownload) normalize() {
	d.Address = strings.TrimSpace(d.Address)
	if d.Transport.Network == "" {
		d.Transport.Network = NetXHTTP
	}
	d.Transport.Network = Network(strings.ToLower(string(d.Transport.Network)))
	if string(d.Transport.Network) == "splithttp" {
		d.Transport.Network = NetXHTTP
	}
	d.Transport.XHTTPDownload = nil
	d.Transport.normalizeXHTTP()
	d.Transport.clearIrrelevant()
	if d.Security.Type == "" {
		d.Security.Type = SecNone
	}
	d.Security.Type = SecurityType(strings.ToLower(string(d.Security.Type)))
	sort.Strings(d.Security.ALPN)
	if r := d.Security.Reality; r != nil {
		sort.Strings(r.ServerNames)
		sort.Strings(r.ShortIDs)
	}
}

// normalizeXHTTP canonicalizes the XHTTP enum-ish fields. Operators type
// "Header" or "STREAM-UP"; the core does a byte-exact comparison and refuses to
// start, so fold anything that differs only in case onto the canonical spelling
// instead of handing the operator an unstartable config.
func (t *Transport) normalizeXHTTP() {
	t.XHTTPMode = canonXHTTP(t.XHTTPMode, AllXHTTPModes())
	if t.XHTTPMode == "" {
		t.XHTTPMode = XHTTPModeAuto
	}
	t.XPaddingPlacement = canonXHTTP(t.XPaddingPlacement, AllXHTTPPaddingPlacements())
	t.XPaddingMethod = canonXHTTP(t.XPaddingMethod, AllXHTTPPaddingMethods())
	t.SessionPlacement = canonXHTTP(t.SessionPlacement, AllXHTTPPlacements())
	t.SeqPlacement = canonXHTTP(t.SeqPlacement, AllXHTTPPlacements())
	t.UplinkDataPlacement = canonXHTTP(t.UplinkDataPlacement, AllXHTTPUplinkDataPlacements())
	t.UplinkHTTPMethod = canonXHTTP(t.UplinkHTTPMethod, AllXHTTPUplinkMethods())

	// The padding key/header/placement/method family only reaches the wire when
	// obfuscated padding is on; keeping it otherwise makes two semantically
	// identical nodes compare unequal and breaks the round-trip property.
	if !t.XPaddingObfsMode {
		t.XPaddingKey, t.XPaddingHeader = "", ""
		t.XPaddingPlacement, t.XPaddingMethod = "", ""
	}
	// A key without a placement is dead weight: "path" carries the value in the
	// URL, so the core never reads the key name.
	if t.SessionPlacement == "" || t.SessionPlacement == "path" {
		t.SessionKey = ""
	}
	if t.SeqPlacement == "" || t.SeqPlacement == "path" {
		t.SeqKey = ""
	}
	if t.UplinkDataPlacement == "" || t.UplinkDataPlacement == "body" {
		t.UplinkDataKey, t.UplinkChunkSize = "", 0
	}
	if x := t.XMux; x != nil && *x == (XMux{}) {
		t.XMux = nil
	}
	if d := t.XHTTPDownload; d != nil {
		d.normalize()
	}
}

// canonXHTTP folds v onto the matching canonical value, case-insensitively.
// An unrecognized value is returned trimmed and untouched so Validate can name
// it in the error rather than silently swallowing the operator's typo.
func canonXHTTP(v string, allowed []string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return a
		}
	}
	return v
}

// validateXHTTP enforces every XHTTP rule the core enforces, so a config the
// panel accepts is a config Xray will start. Each rule below mirrors a specific
// rejection from `xray run -test`.
func validateXHTTP(t *Transport) error {
	// An empty mode is the "auto" default; Validate must accept a node that has
	// not been through Normalize, because Config Doctor runs on raw input.
	mode := t.XHTTPMode
	if mode == "" {
		mode = XHTTPModeAuto
	}
	if !containsStr(AllXHTTPModes(), mode) {
		return fmt.Errorf("xhttp: unsupported mode %q (want one of %s)", mode, strings.Join(AllXHTTPModes(), ", "))
	}
	packetUp := mode == XHTTPModePacketUp

	for _, f := range []struct {
		name, val string
	}{
		{"xPaddingBytes", t.XPaddingB},
		{"scMaxEachPostBytes", t.SCMaxEachPostBytes},
		{"scMinPostsIntervalMs", t.SCMinPostsIntervalMs},
		{"scStreamUpServerSecs", t.SCStreamUpServerSecs},
	} {
		if err := checkInt32Range("xhttp", f.name, f.val); err != nil {
			return err
		}
	}

	if err := checkXHTTPEnum("xPaddingPlacement", t.XPaddingPlacement, AllXHTTPPaddingPlacements()); err != nil {
		return err
	}
	if err := checkXHTTPEnum("xPaddingMethod", t.XPaddingMethod, AllXHTTPPaddingMethods()); err != nil {
		return err
	}
	if err := checkXHTTPEnum("sessionPlacement", t.SessionPlacement, AllXHTTPPlacements()); err != nil {
		return err
	}
	if err := checkXHTTPEnum("seqPlacement", t.SeqPlacement, AllXHTTPPlacements()); err != nil {
		return err
	}
	if err := checkXHTTPEnum("uplinkDataPlacement", t.UplinkDataPlacement, AllXHTTPUplinkDataPlacements()); err != nil {
		return err
	}
	if err := checkXHTTPEnum("uplinkHTTPMethod", t.UplinkHTTPMethod, AllXHTTPUplinkMethods()); err != nil {
		return err
	}

	// "UplinkDataPlacement can be header only in packet-up mode" (core).
	switch t.UplinkDataPlacement {
	case "header", "cookie":
		if !packetUp {
			return fmt.Errorf("xhttp: uplinkDataPlacement %q requires mode %q, not %q",
				t.UplinkDataPlacement, XHTTPModePacketUp, mode)
		}
	}
	// "uplinkHTTPMethod can be GET only in packet-up mode" (core).
	if t.UplinkHTTPMethod == "GET" && !packetUp {
		return fmt.Errorf("xhttp: uplinkHTTPMethod GET requires mode %q, not %q", XHTTPModePacketUp, mode)
	}
	if t.UplinkChunkSize < 0 {
		return fmt.Errorf("xhttp: uplinkChunkSize must not be negative, got %d", t.UplinkChunkSize)
	}
	if t.SCMaxBufferedPosts < 0 {
		return fmt.Errorf("xhttp: scMaxBufferedPosts must not be negative, got %d", t.SCMaxBufferedPosts)
	}
	if t.ServerMaxHeaderBytes < 0 {
		return fmt.Errorf("xhttp: serverMaxHeaderBytes must not be negative, got %d", t.ServerMaxHeaderBytes)
	}

	if x := t.XMux; x != nil {
		// "maxConnections cannot be specified together with maxConcurrency" (core).
		if x.MaxConcurrency != "" && x.MaxConnections != "" {
			return fmt.Errorf("xhttp: xmux maxConnections cannot be combined with maxConcurrency — they are alternative strategies")
		}
		for _, f := range []struct{ name, val string }{
			{"maxConcurrency", x.MaxConcurrency},
			{"maxConnections", x.MaxConnections},
			{"cMaxReuseTimes", x.CMaxReuseTimes},
			{"hMaxRequestTimes", x.HMaxRequestTime},
			{"hMaxReusableSecs", x.HMaxReusableSecs},
		} {
			if err := checkInt32Range("xhttp: xmux", f.name, f.val); err != nil {
				return err
			}
		}
		if x.HKeepAlivePeriod < 0 {
			return fmt.Errorf("xhttp: xmux hKeepAlivePeriod must not be negative, got %d", x.HKeepAlivePeriod)
		}
	}

	if d := t.XHTTPDownload; d != nil {
		// `Can not use "downloadSettings" in "stream-one" mode.` (core).
		if mode == XHTTPModeStreamOne {
			return fmt.Errorf("xhttp: downloadSettings cannot be used in %q mode", XHTTPModeStreamOne)
		}
		if strings.TrimSpace(d.Address) == "" {
			return fmt.Errorf("xhttp: downloadSettings needs an address")
		}
		if d.Port < 1 || d.Port > 65535 {
			return fmt.Errorf("xhttp: downloadSettings port must be in 1..65535, got %d", d.Port)
		}
		if d.Transport.Network == NetXHTTP {
			if err := validateXHTTP(&d.Transport); err != nil {
				return fmt.Errorf("downloadSettings: %w", err)
			}
		}
	}
	return nil
}

func checkXHTTPEnum(name, v string, allowed []string) error {
	if v == "" || containsStr(allowed, v) {
		return nil
	}
	return fmt.Errorf("xhttp: unsupported %s %q (want one of %s)", name, v, strings.Join(allowed, ", "))
}

// checkInt32Range validates an Xray Int32Range literal. The core accepts a bare
// decimal ("1000000") or an inclusive range ("100-1000") and rejects everything
// else -- including surrounding spaces, which is the mistake operators actually
// make when they copy a value out of a forum post.
func checkInt32Range(scope, name, v string) error {
	if v == "" {
		return nil
	}
	lo, hi, isRange := strings.Cut(v, "-")
	if !allDigits(lo) || (isRange && !allDigits(hi)) {
		return fmt.Errorf("%s: %s must be a number or a \"min-max\" range of numbers, got %q", scope, name, v)
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// xhttpExtra is the wire shape of the `extra` share-link parameter: the XHTTP
// knobs a CLIENT needs, serialized as the same camelCase JSON object the core
// itself takes. Emitting the core's own spelling is what makes the link
// importable by v2rayN/v2rayNG and by the other panels, and re-importable here.
//
// Server-only knobs (scMaxBufferedPosts, scStreamUpServerSecs,
// serverMaxHeaderBytes) are deliberately absent: a client that honoured them
// would mis-tune itself against a server it cannot see.
type xhttpExtra struct {
	// Mode is only READ for the primary transport: ForgePanel links carry the
	// mode in the standard `mode=` query parameter, but foreign links (3x-ui and
	// friends) bury it in the extra payload, so importing one has to look here
	// too. For a nested download leg, which has no query parameters of its own,
	// Mode/Path/Host are written as well.
	Mode string `json:"mode,omitempty"`
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`

	XPaddingBytes     string `json:"xPaddingBytes,omitempty"`
	XPaddingObfsMode  bool   `json:"xPaddingObfsMode,omitempty"`
	XPaddingKey       string `json:"xPaddingKey,omitempty"`
	XPaddingHeader    string `json:"xPaddingHeader,omitempty"`
	XPaddingPlacement string `json:"xPaddingPlacement,omitempty"`
	XPaddingMethod    string `json:"xPaddingMethod,omitempty"`

	NoGRPCHeader bool `json:"noGRPCHeader,omitempty"`
	NoSSEHeader  bool `json:"noSSEHeader,omitempty"`

	SCMaxEachPostBytes   string `json:"scMaxEachPostBytes,omitempty"`
	SCMinPostsIntervalMs string `json:"scMinPostsIntervalMs,omitempty"`

	SessionPlacement string `json:"sessionPlacement,omitempty"`
	SessionKey       string `json:"sessionKey,omitempty"`
	SeqPlacement     string `json:"seqPlacement,omitempty"`
	SeqKey           string `json:"seqKey,omitempty"`

	UplinkDataPlacement string `json:"uplinkDataPlacement,omitempty"`
	UplinkDataKey       string `json:"uplinkDataKey,omitempty"`
	UplinkHTTPMethod    string `json:"uplinkHTTPMethod,omitempty"`
	UplinkChunkSize     int    `json:"uplinkChunkSize,omitempty"`

	Headers map[string]string `json:"headers,omitempty"`

	// RawXMux/RawDownload keep the nested objects in the core's spelling.
	RawXMux     json.RawMessage `json:"xmux,omitempty"`
	RawDownload json.RawMessage `json:"downloadSettings,omitempty"`
}

// xhttpExtraOf projects a transport onto the wire struct. withIdentity adds
// mode/path/host, which the primary transport carries as its own share-link
// parameters but a nested download leg has nowhere else to put.
func (t Transport) xhttpExtraOf(withIdentity bool) xhttpExtra {
	e := xhttpExtra{
		XPaddingBytes:        t.XPaddingB,
		XPaddingObfsMode:     t.XPaddingObfsMode,
		XPaddingKey:          t.XPaddingKey,
		XPaddingHeader:       t.XPaddingHeader,
		XPaddingPlacement:    t.XPaddingPlacement,
		XPaddingMethod:       t.XPaddingMethod,
		NoGRPCHeader:         t.NoGRPCHeader,
		NoSSEHeader:          t.NoSSEHeader,
		SCMaxEachPostBytes:   t.SCMaxEachPostBytes,
		SCMinPostsIntervalMs: t.SCMinPostsIntervalMs,
		SessionPlacement:     t.SessionPlacement,
		SessionKey:           t.SessionKey,
		SeqPlacement:         t.SeqPlacement,
		SeqKey:               t.SeqKey,
		UplinkDataPlacement:  t.UplinkDataPlacement,
		UplinkDataKey:        t.UplinkDataKey,
		UplinkHTTPMethod:     t.UplinkHTTPMethod,
		UplinkChunkSize:      t.UplinkChunkSize,
		Headers:              t.Headers,
	}
	if withIdentity {
		e.Mode, e.Path, e.Host = t.XHTTPMode, t.Path, t.Host
	}
	if t.XMux != nil {
		if raw, err := json.Marshal(xmuxWire(t.XMux)); err == nil {
			e.RawXMux = raw
		}
	}
	if t.XHTTPDownload != nil {
		if raw, err := json.Marshal(downloadWire(t.XHTTPDownload)); err == nil {
			e.RawDownload = raw
		}
	}
	return e
}

// applyTo is the inverse projection. withIdentity mirrors xhttpExtraOf: the
// primary transport already has its mode/path/host from the query parameters,
// so a payload must not be allowed to blank them.
func (e xhttpExtra) applyTo(t *Transport, withIdentity bool) error {
	if e.Mode != "" {
		t.XHTTPMode = e.Mode
	}
	if withIdentity {
		if e.Path != "" {
			t.Path = e.Path
		}
		if e.Host != "" {
			t.Host = e.Host
		}
	}
	t.XPaddingB = e.XPaddingBytes
	t.XPaddingObfsMode = e.XPaddingObfsMode
	t.XPaddingKey = e.XPaddingKey
	t.XPaddingHeader = e.XPaddingHeader
	t.XPaddingPlacement = e.XPaddingPlacement
	t.XPaddingMethod = e.XPaddingMethod
	t.NoGRPCHeader = e.NoGRPCHeader
	t.NoSSEHeader = e.NoSSEHeader
	t.SCMaxEachPostBytes = e.SCMaxEachPostBytes
	t.SCMinPostsIntervalMs = e.SCMinPostsIntervalMs
	t.SessionPlacement = e.SessionPlacement
	t.SessionKey = e.SessionKey
	t.SeqPlacement = e.SeqPlacement
	t.SeqKey = e.SeqKey
	t.UplinkDataPlacement = e.UplinkDataPlacement
	t.UplinkDataKey = e.UplinkDataKey
	t.UplinkHTTPMethod = e.UplinkHTTPMethod
	t.UplinkChunkSize = e.UplinkChunkSize
	if len(e.Headers) > 0 {
		t.Headers = e.Headers
	}
	if len(e.RawXMux) > 0 {
		var w xmuxJSON
		if err := json.Unmarshal(e.RawXMux, &w); err != nil {
			return fmt.Errorf("xhttp: malformed xmux in extra payload: %w", err)
		}
		t.XMux = w.model()
	}
	if len(e.RawDownload) > 0 {
		var w downloadJSON
		if err := json.Unmarshal(e.RawDownload, &w); err != nil {
			return fmt.Errorf("xhttp: malformed downloadSettings in extra payload: %w", err)
		}
		d, err := w.model()
		if err != nil {
			return err
		}
		t.XHTTPDownload = d
	}
	return nil
}

// XHTTPExtra returns the `extra=` share-link payload for this transport, or ""
// when nothing beyond path/host/mode is configured (so the common link stays
// short). Nested xmux and downloadSettings ride along in the core's own
// spelling, which is what makes a split up/down node survive an export/import.
func (t Transport) XHTTPExtra() string {
	if t.Network != NetXHTTP {
		return ""
	}
	raw, err := json.Marshal(t.xhttpExtraOf(false))
	if err != nil || string(raw) == "{}" {
		return ""
	}
	return string(raw)
}

// ApplyXHTTPExtra is the inverse of XHTTPExtra. A malformed payload is reported
// rather than half-applied: a partially decoded transport is worse than one the
// operator is told to re-import.
func (t *Transport) ApplyXHTTPExtra(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var e xhttpExtra
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return fmt.Errorf("xhttp: malformed extra payload: %w", err)
	}
	return e.applyTo(t, false)
}

// xmuxJSON is the core's spelling of the xmux object. Ranges are Int32Range,
// which the core writes as either a number or a "min-max" string, so they are
// decoded leniently and stored canonically as strings.
type xmuxJSON struct {
	MaxConcurrency   json.RawMessage `json:"maxConcurrency,omitempty"`
	MaxConnections   json.RawMessage `json:"maxConnections,omitempty"`
	CMaxReuseTimes   json.RawMessage `json:"cMaxReuseTimes,omitempty"`
	HMaxRequestTimes json.RawMessage `json:"hMaxRequestTimes,omitempty"`
	HMaxReusableSecs json.RawMessage `json:"hMaxReusableSecs,omitempty"`
	HKeepAlivePeriod int             `json:"hKeepAlivePeriod,omitempty"`
}

func (w xmuxJSON) model() *XMux {
	x := &XMux{
		MaxConcurrency:   rangeString(w.MaxConcurrency),
		MaxConnections:   rangeString(w.MaxConnections),
		CMaxReuseTimes:   rangeString(w.CMaxReuseTimes),
		HMaxRequestTime:  rangeString(w.HMaxRequestTimes),
		HMaxReusableSecs: rangeString(w.HMaxReusableSecs),
		HKeepAlivePeriod: w.HKeepAlivePeriod,
	}
	if *x == (XMux{}) {
		return nil
	}
	return x
}

func xmuxWire(x *XMux) map[string]any {
	m := map[string]any{}
	if x.MaxConcurrency != "" {
		m["maxConcurrency"] = x.MaxConcurrency
	}
	if x.MaxConnections != "" {
		m["maxConnections"] = x.MaxConnections
	}
	if x.CMaxReuseTimes != "" {
		m["cMaxReuseTimes"] = x.CMaxReuseTimes
	}
	if x.HMaxRequestTime != "" {
		m["hMaxRequestTimes"] = x.HMaxRequestTime
	}
	if x.HMaxReusableSecs != "" {
		m["hMaxReusableSecs"] = x.HMaxReusableSecs
	}
	if x.HKeepAlivePeriod > 0 {
		m["hKeepAlivePeriod"] = x.HKeepAlivePeriod
	}
	return m
}

// rangeString renders an Int32Range that arrived as either a JSON number or a
// JSON string into the canonical string form the model stores.
func rangeString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

// downloadJSON is the core's `downloadSettings` object: a full stream config.
// Its xhttpSettings reuse the same wire struct as the primary transport, so the
// download leg keeps its padding/session/flow-control contract through a link
// instead of arriving with only a path and losing the shape the server expects.
type downloadJSON struct {
	Address     string            `json:"address,omitempty"`
	Port        int               `json:"port,omitempty"`
	Network     string            `json:"network,omitempty"`
	Security    string            `json:"security,omitempty"`
	TLSSettings *tlsJSON          `json:"tlsSettings,omitempty"`
	Reality     *realityJSON      `json:"realitySettings,omitempty"`
	XHTTP       *xhttpExtra       `json:"xhttpSettings,omitempty"`
	WS          *downloadPathHost `json:"wsSettings,omitempty"`
}

type downloadPathHost struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type tlsJSON struct {
	ServerName  string   `json:"serverName,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
}

type realityJSON struct {
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (w downloadJSON) model() (*XHTTPDownload, error) {
	d := &XHTTPDownload{Address: w.Address, Port: w.Port}
	d.Transport.Network = Network(strings.ToLower(w.Network))
	switch d.Transport.Network {
	case NetXHTTP, "splithttp", "":
		d.Transport.Network = NetXHTTP
		if x := w.XHTTP; x != nil {
			if err := x.applyTo(&d.Transport, true); err != nil {
				return nil, err
			}
			// A download leg never nests another one; the core has no such shape.
			d.Transport.XHTTPDownload = nil
		}
	case NetWS:
		if s := w.WS; s != nil {
			d.Transport.Path, d.Transport.Host = s.Path, s.Host
		}
	}
	switch strings.ToLower(w.Security) {
	case "tls":
		d.Security.Type = SecTLS
		if s := w.TLSSettings; s != nil {
			d.Security.ServerName, d.Security.Fingerprint, d.Security.ALPN = s.ServerName, s.Fingerprint, s.ALPN
		}
	case "reality":
		d.Security.Type = SecReality
		if r := w.Reality; r != nil {
			d.Security.ServerName, d.Security.Fingerprint = r.ServerName, r.Fingerprint
			d.Security.Reality = &Reality{PublicKey: r.PublicKey, ShortID: r.ShortID, SpiderX: r.SpiderX}
		}
	default:
		d.Security.Type = SecNone
	}
	return d, nil
}

func downloadWire(d *XHTTPDownload) map[string]any {
	m := map[string]any{"network": string(d.Transport.Network)}
	if d.Address != "" {
		m["address"] = d.Address
	}
	if d.Port > 0 {
		m["port"] = d.Port
	}
	switch d.Transport.Network {
	case NetXHTTP:
		e := d.Transport.xhttpExtraOf(true)
		e.RawDownload = nil // never nested
		m["xhttpSettings"] = e
	case NetWS:
		m["wsSettings"] = downloadPathHost{Path: d.Transport.Path, Host: d.Transport.Host}
	}
	switch d.Security.Type {
	case SecTLS:
		m["security"] = "tls"
		tls := tlsJSON{ServerName: d.SNI(), Fingerprint: d.Security.Fingerprint, ALPN: d.Security.ALPN}
		m["tlsSettings"] = tls
	case SecReality:
		m["security"] = "reality"
		rs := realityJSON{ServerName: d.SNI(), Fingerprint: d.Security.Fingerprint}
		if r := d.Security.Reality; r != nil {
			rs.PublicKey, rs.ShortID, rs.SpiderX = r.PublicKey, r.ShortID, r.SpiderX
		}
		m["realitySettings"] = rs
	}
	return m
}
