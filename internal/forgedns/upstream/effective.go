package upstream

import (
	"fmt"
	"strings"
)

// The bridge between the panel's typed zone settings and the layered document
// model: the MANAGED layer of a zone, expressed as the exact key set the
// renderer writes, plus the RUNTIME layer the panel refuses to give up.
//
// ServerManagedDocument mirrors RenderServer key for key on purpose — and
// render_manifest_test.go asserts it by parsing the rendered file and comparing.
// Duplicating the key list is the lesser evil: rewriting the renderer to emit
// from the document would drop the per-key comments that let an operator diff
// the panel's file against the release's own sample, and a drifting pair of key
// lists is exactly what the test catches.

// ServerManagedDocument projects a normalised zone onto the server keys the
// panel manages. Runtime-owned keys (the key file path, CONFIG_VERSION) are NOT
// here; they come from serverRuntimeDocument, above every override.
func ServerManagedDocument(d Descriptor, z ZoneConfig) Document {
	z.Normalize(d)
	doc := Document{
		"DOMAIN":        append([]string(nil), z.Domains...),
		"PROTOCOL_TYPE": z.protocolType(),
		"UDP_HOST":      z.BindHost,
		"UDP_PORT":      z.BindPort,
	}
	if d.HasListenerToggles {
		doc["TCP_LISTENER_ENABLED"] = z.TCPListener
		doc["DOT_LISTENER_ENABLED"] = z.DoTListener
		doc["DOT_LISTEN_HOST"] = tlsListenHost(z.BindHost, z.DoTPort, DefaultDoTPort)
		doc["DOT_LISTEN_PORT"] = z.DoTPort
		doc["DOH_LISTENER_ENABLED"] = z.DoHListener
		doc["DOH_LISTEN_HOST"] = tlsListenHost(z.BindHost, z.DoHPort, DefaultDoHPort)
		doc["DOH_LISTEN_PORT"] = z.DoHPort
	}
	doc["USE_EXTERNAL_SOCKS5"] = z.ExternalSocks5
	doc["FORWARD_IP"] = z.ForwardIP
	doc["FORWARD_PORT"] = z.ForwardPort
	doc["DATA_ENCRYPTION_METHOD"] = z.Cipher
	if d.HasAutoDetect {
		doc["ENCRYPTION_AUTO_DETECT"] = z.AutoDetect
	}
	if d.HasARecordDelivery {
		doc["A_RECORD_DATA_DELIVERY"] = z.ARecordDelivery
	}
	doc["LOG_LEVEL"] = z.LogLevel
	return doc
}

// serverRuntimeDocument is the top layer of the server merge: the key file the
// panel writes and the config dialect the binary demands (§4b).
func serverRuntimeDocument(d Descriptor) Document {
	return Document{
		"ENCRYPTION_KEY_FILE": EncryptKeyFile,
		"CONFIG_VERSION":      d.ConfigVersion,
	}
}

// ClientManagedDocument projects a zone onto the client keys the panel manages.
func ClientManagedDocument(d Descriptor, z ZoneConfig, opt ClientOptions) Document {
	z.Normalize(d)
	opt = opt.withDefaults()
	doc := Document{"DOMAINS": append([]string(nil), z.Domains...)}
	if d.HasQueryTypes {
		doc["QUERY_TYPES"] = append([]string(nil), z.QueryTypes...)
	}
	doc["DATA_ENCRYPTION_METHOD"] = z.Cipher
	doc["PROTOCOL_TYPE"] = z.protocolType()
	doc["LISTEN_IP"] = opt.ListenIP
	doc["LISTEN_PORT"] = opt.ListenPort
	doc["STARTUP_MODE"] = "resolvers"
	if d.HasResolverTransp {
		doc["RESOLVER_TRANSPORT"] = "auto"
	}
	if d.HasBalancing {
		doc["RESOLVER_BALANCING_STRATEGY"] = 3
	}
	if d.HasCompression {
		doc["UPLOAD_COMPRESSION_TYPE"] = 2
		doc["DOWNLOAD_COMPRESSION_TYPE"] = 2
	}
	return doc
}

// clientRuntimeDocument carries the zone secret. It is the reason the client
// file is the credential (§4d) and the reason no override may set it.
func clientRuntimeDocument(d Descriptor, z ZoneConfig) Document {
	return Document{
		"ENCRYPTION_KEY": z.EncryptKey,
		"CONFIG_VERSION": d.ConfigVersion,
	}
}

// withDefaults fills the client listener defaults RenderClient also applies.
func (o ClientOptions) withDefaults() ClientOptions {
	if o.ListenIP == "" {
		o.ListenIP = DefaultClientListenIP
	}
	if o.ListenPort == 0 {
		o.ListenPort = DefaultClientPort
	}
	return o
}

// EffectiveServer merges every layer for a zone's server config. A stored
// override that no longer validates is an error rather than a silent drop: the
// operator wrote it, it was validated when they saved it, and a fork upgrade
// that invalidates it must be visible in the zone's status.
func EffectiveServer(d Descriptor, z ZoneConfig) (Effective, error) {
	m, err := ManifestFor(d.Adapter)
	if err != nil {
		return Effective{}, err
	}
	z.Normalize(d)
	if err := z.Validate(); err != nil {
		return Effective{}, err
	}
	override, err := ParseTOML(z.OverrideTOML)
	if err != nil {
		return Effective{}, err
	}
	if err := ValidateDocument(m, ScopeServer, override); err != nil {
		return Effective{}, err
	}
	return Merge(m, ScopeServer, m.Defaults(ScopeServer),
		ServerManagedDocument(d, z), override, serverRuntimeDocument(d)), nil
}

// EffectiveClient merges every layer for a zone's client config.
func EffectiveClient(d Descriptor, z ZoneConfig, opt ClientOptions) (Effective, error) {
	m, err := ManifestFor(d.Adapter)
	if err != nil {
		return Effective{}, err
	}
	z.Normalize(d)
	if err := z.Validate(); err != nil {
		return Effective{}, err
	}
	override, err := ParseTOML(z.ClientOverrideTOML)
	if err != nil {
		return Effective{}, err
	}
	if err := ValidateDocument(m, ScopeClient, override); err != nil {
		return Effective{}, err
	}
	return Merge(m, ScopeClient, m.Defaults(ScopeClient),
		ClientManagedDocument(d, z, opt), override, clientRuntimeDocument(d, z)), nil
}

// renderServerOverride is the RenderServer path for a zone that has an advanced
// override. The hand-written renderer keeps its per-key comments for the common
// case; once an override is in play the file is generated from the merged
// document instead, so precedence is visible in the bytes that hit the disk.
func renderServerOverride(d Descriptor, z ZoneConfig) (string, error) {
	e, err := EffectiveServer(d, z)
	if err != nil {
		return "", err
	}
	return e.TOML(effectiveHeader(d, z, e, "server"))
}

func renderClientOverride(d Descriptor, z ZoneConfig, opt ClientOptions) (string, error) {
	e, err := EffectiveClient(d, z, opt)
	if err != nil {
		return "", err
	}
	return e.TOML(effectiveHeader(d, z, e, "client"))
}

// effectiveHeader explains, in the file itself, that an override is in force and
// which keys it changed — the operator reading /etc on a broken box gets the same
// provenance the API returns.
func effectiveHeader(d Descriptor, z ZoneConfig, e Effective, kind string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ForgeDNS %s config — generated by ForgePanel, do not edit by hand.\n", kind)
	fmt.Fprintf(&b, "# zone      : %s\n", z.Zone)
	fmt.Fprintf(&b, "# adapter   : %s (%s/%s), CONFIG_VERSION %s\n", d.Adapter, d.Owner, d.Repo, d.ConfigVersion)
	b.WriteString("# layers    : default < managed < advanced override < panel runtime\n")
	if ov := e.keysAt(LayerOverride); len(ov) > 0 {
		fmt.Fprintf(&b, "# overridden: %s\n", strings.Join(ov, ", "))
	}
	if len(e.Ignored) > 0 {
		fmt.Fprintf(&b, "# ignored   : %s (panel-owned, see docs)\n", strings.Join(e.Ignored, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// keysAt lists the keys resolved at one layer, in file order.
func (e Effective) keysAt(l Layer) []string {
	out := []string{}
	for _, k := range e.Order {
		if e.Origin[k] == l {
			out = append(out, k)
		}
	}
	return out
}
