package upstream

import (
	"fmt"
	"sort"
)

// Import: adopting a config file the operator already runs.
//
// The rule that shapes this file: NEVER discard a key. An operator importing a
// hand-tuned server_config.toml is handing over a file that works, possibly with
// knobs this panel has never read about (§0 — three forks, one dialect, and no
// published key list). Dropping an unrecognised key would silently change how
// their tunnel behaves the moment the panel rewrites the file. So the split is
// exhaustive: every key lands either in the managed layer (the panel models it)
// or in the override layer (kept verbatim, written back on every render).

// Managed is the recognised half of an imported config: values the panel can
// project onto a zone's typed settings.
type Managed struct {
	Adapter  string   `json:"adapter"`
	Scope    Scope    `json:"scope"`
	Values   Document `json:"-"` // may carry key material; mask before returning
	Warnings []string `json:"warnings"`
}

// ImportServerTOML parses an existing server_config.toml into the managed values
// the panel understands plus an override document holding everything else.
func ImportServerTOML(text string) (Managed, Document, error) {
	return importTOML(ScopeServer, text)
}

// ImportClientTOML does the same for a client_config.toml.
func ImportClientTOML(text string) (Managed, Document, error) {
	return importTOML(ScopeClient, text)
}

func importTOML(scope Scope, text string) (Managed, Document, error) {
	doc, err := ParseTOML(text)
	if err != nil {
		return Managed{}, nil, err
	}
	im := Managed{Scope: scope, Values: Document{}, Warnings: []string{}}
	override := Document{}

	// The dialect version identifies the fork (§4b), which is the only reliable
	// signal in the file itself — the key sets overlap too much to fingerprint.
	im.Adapter = DefaultAdapter
	switch version, ok := doc["CONFIG_VERSION"].(string); {
	case !ok:
		im.Warnings = append(im.Warnings,
			fmt.Sprintf("no CONFIG_VERSION in the file; assuming the %s dialect", DefaultAdapter))
	default:
		if a, known := AdapterForConfigVersion(version); known {
			im.Adapter = a
		} else {
			im.Warnings = append(im.Warnings, fmt.Sprintf(
				"CONFIG_VERSION %q is not a dialect this panel knows; assuming %s", version, DefaultAdapter))
		}
	}
	m, err := ManifestFor(im.Adapter)
	if err != nil {
		return Managed{}, nil, err
	}

	// Values are checked against the fork detected above. CONFIG_VERSION itself
	// is panel-owned and therefore skipped by ValidateDocument, which is what
	// makes importing a sibling fork's file a supported action rather than an
	// error: it was already used as the dialect marker.
	if err := ValidateDocument(m, scope, doc); err != nil {
		return Managed{}, nil, err
	}

	for _, k := range sortedKeys(doc) {
		v := doc[k]
		o, known := m.Option(scope, k)
		switch {
		case !known:
			override[k] = v
		case o.Managed:
			im.Values[k] = v
		default:
			// Known, but the panel does not write it — the override layer is the
			// only place it can live and still reach the rendered file.
			override[k] = v
		}
		if known && o.Runtime && k != "CONFIG_VERSION" {
			im.Warnings = append(im.Warnings, fmt.Sprintf(
				"%s: the panel owns this value and will regenerate it", k))
		}
		if known && !o.Verified {
			im.Warnings = append(im.Warnings, fmt.Sprintf(
				"%s: not present in %s's own shipped sample — kept, but verify your build accepts it", k, im.Adapter))
		}
	}
	sort.Strings(im.Warnings)
	return im, override, nil
}

// ApplyTo projects imported managed values onto a zone. Only keys the file
// actually carried are touched, so importing a partial config leaves the rest of
// the zone's settings alone.
func (im Managed) ApplyTo(z *ZoneConfig) {
	if im.Adapter != "" {
		z.Adapter = im.Adapter
	}
	domainKey := "DOMAIN"
	if im.Scope == ScopeClient {
		domainKey = "DOMAINS"
	}
	if list, ok := asStrings(im.Values[domainKey]); ok && len(list) > 0 {
		if z.Zone == "" {
			z.Zone = list[0]
		}
		z.Domains = list
	}
	if s, ok := im.Values["PROTOCOL_TYPE"].(string); ok {
		z.Mode = ModeSocks5
		if s == "TCP" {
			z.Mode = ModeTCP
		}
	}
	setString(im.Values, "UDP_HOST", &z.BindHost)
	setString(im.Values, "FORWARD_IP", &z.ForwardIP)
	setString(im.Values, "LOG_LEVEL", &z.LogLevel)
	setString(im.Values, "ENCRYPTION_KEY", &z.EncryptKey)
	setInt(im.Values, "UDP_PORT", &z.BindPort)
	setInt(im.Values, "FORWARD_PORT", &z.ForwardPort)
	setInt(im.Values, "DATA_ENCRYPTION_METHOD", &z.Cipher)
	setBool(im.Values, "USE_EXTERNAL_SOCKS5", &z.ExternalSocks5)
	setBool(im.Values, "TCP_LISTENER_ENABLED", &z.TCPListener)
	setBool(im.Values, "DOT_LISTENER_ENABLED", &z.DoTListener)
	setInt(im.Values, "DOT_LISTEN_PORT", &z.DoTPort)
	setInt(im.Values, "DOH_LISTEN_PORT", &z.DoHPort)
	setBool(im.Values, "DOH_LISTENER_ENABLED", &z.DoHListener)
	setBool(im.Values, "ENCRYPTION_AUTO_DETECT", &z.AutoDetect)
	setBool(im.Values, "A_RECORD_DATA_DELIVERY", &z.ARecordDelivery)
	if list, ok := asStrings(im.Values["QUERY_TYPES"]); ok {
		z.QueryTypes = NormalizeQueryTypes(list)
	}
}

func setString(doc Document, key string, dst *string) {
	if v, ok := doc[key].(string); ok {
		*dst = v
	}
}

func setInt(doc Document, key string, dst *int) {
	if n, ok := asInt(doc[key]); ok {
		*dst = int(n)
	}
}

func setBool(doc Document, key string, dst *bool) {
	if v, ok := doc[key].(bool); ok {
		*dst = v
	}
}

// RenderOverride writes an override document back to text for storage, with
// deterministic key order so an unchanged override never looks changed.
func RenderOverride(m Manifest, scope Scope, doc Document) (string, error) {
	if len(doc) == 0 {
		return "", nil
	}
	return renderDocument("", orderKeys(m, scope, doc), doc)
}
