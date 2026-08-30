package upstream

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// This file is the single, adapter-versioned config renderer described in §4b.
// One renderer with three thin key sets, not one lowest-common-denominator
// file: the binaries reject a config whose CONFIG_VERSION they do not know, and
// a key a given version has never heard of is a needless risk. Hence every
// optional block is gated on a Descriptor capability flag.

// Client-side constants from §1–§3: every one of the three clients listens for
// SOCKS5 on 127.0.0.1:18000 by default, and that is what the user points apps at.
const (
	DefaultClientListenIP = "127.0.0.1"
	DefaultClientPort     = 18000
	DefaultUDPHost        = "0.0.0.0"
	DefaultUDPPort        = 53
	// EncryptKeyFile is written next to the config; the process CWD is the
	// config dir so this relative name resolves (§4b, §4c).
	EncryptKeyFile = "encrypt_key.txt"
)

// Modes for PROTOCOL_TYPE.
const (
	ModeSocks5 = "socks5"
	ModeTCP    = "tcp"
)

// Public TLS ports for a DNS tunnel. Not negotiable from the client side: a DoT
// client goes to 853 and a DoH client to 443, which is exactly why two zones
// that both serve them collide, and why the panel offers a private port instead.
const (
	DefaultDoTPort = 853
	DefaultDoHPort = 443
)

// tlsListenHost decides where a zone's TLS listener binds.
//
// Loopback whenever the port is private. A private PORT alone does not isolate
// the backend: bound to a public interface it is still reachable directly, so a
// client that knows the number bypasses the router and the isolation the port
// move exists to create is silently gone.
func tlsListenHost(bindHost string, port, public int) string {
	if port > 0 && port != public {
		return tlsFrontHost
	}
	return bindHost
}

// tlsFrontHost is where a front-routed TLS listener binds.
//
// Loopback, always. A private PORT alone does not isolate the backend: bound to
// a public interface it is still reachable directly, so a client that knows the
// number bypasses the router, and the isolation the port move exists to create
// is silently gone. CottenRouter's own installer enforces the same rule.
const tlsFrontHost = "127.0.0.1"

// ZoneConfig is the panel's view of one upstream tunnel zone — the input to
// both the server and client renderers. It is a plain value so the API layer
// can build it from a store row and tests can build it literally.
type ZoneConfig struct {
	Zone    string   // primary tunnel domain (kept for back-compat / display)
	Adapter string   // stormdns | masterdns | cottendns
	Domains []string // every tunnel domain this instance answers (§3 multi-domain)

	BindHost string // UDP_HOST
	BindPort int    // UDP_PORT
	Mode     string // socks5 | tcp  -> PROTOCOL_TYPE
	Cipher   int    // DATA_ENCRYPTION_METHOD 0..5

	// TCP / chained-proxy egress (§4b).
	ForwardIP      string
	ForwardPort    int
	ExternalSocks5 bool

	// CottenDNS extras (§3). Ignored by adapters whose descriptor does not
	// advertise the capability.
	TCPListener bool
	DoTListener bool
	DoHListener bool
	// DoTPort / DoHPort move a zone's TLS listeners off the public ports so the
	// front router can own 853 and 443 and fan them out by SNI. Zero keeps the
	// upstream default, which is the public port — correct for a single zone and
	// a guaranteed collision for the second one.
	DoTPort         int
	DoHPort         int
	AutoDetect      bool
	ARecordDelivery bool
	QueryTypes      []string // client-side rotation list

	// EncryptKey is the panel-generated shared secret. The panel is the key
	// authority (§4b): it is generated once per zone, written to encrypt_key.txt
	// for the server and embedded in the client config. It is a server-side
	// secret and must never appear in an exported link.
	EncryptKey string

	LogLevel string

	// OverrideTOML / ClientOverrideTOML are the operator's advanced-override
	// layer, stored as raw TOML text so an unknown upstream key survives a
	// round-trip through the panel untouched. They sit ABOVE the managed
	// settings above and BELOW the panel-owned runtime values — see layers.go.
	// Empty (the common case) keeps the hand-written renderer below verbatim.
	OverrideTOML       string
	ClientOverrideTOML string
}

// Normalize fills defaults and canonicalises the zone. Call it before Validate,
// Render* or Signature so equality and output are well-defined.
func (z *ZoneConfig) Normalize(d Descriptor) {
	// Default the TLS ports rather than leaving them zero: the renderer always
	// writes them, and a zero would tell the backend to bind port 0 — a random
	// high port that nothing knows to reach.
	if d.HasListenerToggles {
		if z.DoTPort <= 0 {
			z.DoTPort = DefaultDoTPort
		}
		if z.DoHPort <= 0 {
			z.DoHPort = DefaultDoHPort
		}
	}
	z.Adapter = Canonical(z.Adapter)
	z.Zone = normDomain(z.Zone)
	z.Domains = dedupeDomains(append([]string{z.Zone}, z.Domains...))
	if z.BindHost == "" {
		z.BindHost = DefaultUDPHost
	}
	if z.BindPort == 0 {
		z.BindPort = DefaultUDPPort
	}
	switch strings.ToLower(strings.TrimSpace(z.Mode)) {
	case ModeTCP:
		z.Mode = ModeTCP
	default:
		z.Mode = ModeSocks5
	}
	if z.Cipher == 0 && d.DefaultCipher != 0 {
		// 0 is a legal value (no encryption) but a zero-value struct field is far
		// more likely to mean "unset", so a fresh zone gets the adapter default.
		z.Cipher = d.DefaultCipher
	}
	if z.LogLevel == "" {
		z.LogLevel = "INFO"
	}
	if d.HasQueryTypes {
		// Upper-case and de-duplicate: the upstream matches these against DNS
		// type names, and a rotation list with the same type twice just skews
		// the distribution.
		z.QueryTypes = NormalizeQueryTypes(z.QueryTypes)
		if len(z.QueryTypes) == 0 {
			z.QueryTypes = []string{"TXT"} // upstream default (§3)
		}
	}
	if !d.HasQueryTypes {
		z.QueryTypes = nil
	}
	if !d.HasListenerToggles {
		z.TCPListener, z.DoTListener, z.DoHListener = false, false, false
	}
	if !d.HasAutoDetect {
		z.AutoDetect = false
	}
	if !d.HasARecordDelivery {
		z.ARecordDelivery = false
	}
}

// Validate rejects a zone the upstream binary would reject or that would make
// the panel write a nonsensical config.
func (z *ZoneConfig) Validate() error {
	if len(z.Domains) == 0 {
		return fmt.Errorf("forgedns: zone has no tunnel domain")
	}
	for _, dom := range z.Domains {
		if !validDomain(dom) {
			return fmt.Errorf("forgedns: %q is not a valid tunnel domain", dom)
		}
	}
	if z.Cipher < 0 || z.Cipher > 5 {
		return fmt.Errorf("forgedns: DATA_ENCRYPTION_METHOD must be 0..5, got %d", z.Cipher)
	}
	if z.BindPort < 1 || z.BindPort > 65535 {
		return fmt.Errorf("forgedns: UDP_PORT %d out of range", z.BindPort)
	}
	if z.Mode == ModeTCP && z.ForwardIP == "" {
		return fmt.Errorf("forgedns: PROTOCOL_TYPE=TCP needs a forward target (FORWARD_IP/FORWARD_PORT)")
	}
	if z.ExternalSocks5 && z.ForwardIP == "" {
		return fmt.Errorf("forgedns: USE_EXTERNAL_SOCKS5 needs the upstream proxy host in FORWARD_IP")
	}
	if z.EncryptKey == "" {
		return fmt.Errorf("forgedns: zone has no encryption key")
	}
	for _, qt := range z.QueryTypes {
		if !validQueryType(qt) {
			return fmt.Errorf("forgedns: %q is not a recognised DNS query type", qt)
		}
	}
	return nil
}

// protocolType maps the panel's mode onto the upstream PROTOCOL_TYPE spelling.
func (z *ZoneConfig) protocolType() string {
	if z.Mode == ModeTCP {
		return "TCP"
	}
	return "SOCKS5"
}

// RenderServer produces the server_config.toml for this zone and adapter.
// Key order and comments mirror the shipped upstream files so an operator can
// diff the panel's file against the release's own sample.
func RenderServer(d Descriptor, z ZoneConfig) (string, error) {
	z.Normalize(d)
	if err := z.Validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(z.OverrideTOML) != "" {
		return renderServerOverride(d, z)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# ForgeDNS server config — generated by ForgePanel, do not edit by hand.\n")
	fmt.Fprintf(&b, "# zone      : %s\n", z.Zone)
	fmt.Fprintf(&b, "# adapter   : %s (%s/%s)\n", d.Adapter, d.Owner, d.Repo)
	fmt.Fprintf(&b, "# dialect   : docs/FORGEDNS_UPSTREAM_SETUP.md §4b, CONFIG_VERSION %s\n\n", d.ConfigVersion)

	b.WriteString("# Tunnel domains handled by this server. Must match client DOMAINS,\n")
	b.WriteString("# and every one of them must be NS-delegated to this host.\n")
	fmt.Fprintf(&b, "DOMAIN = %s\n", tomlStrings(z.Domains))
	fmt.Fprintf(&b, "PROTOCOL_TYPE = %q\n", z.protocolType())
	fmt.Fprintf(&b, "UDP_HOST = %q\n", z.BindHost)
	fmt.Fprintf(&b, "UDP_PORT = %d\n", z.BindPort)

	if d.HasListenerToggles {
		fmt.Fprintf(&b, "TCP_LISTENER_ENABLED = %t\n", z.TCPListener)
		fmt.Fprintf(&b, "DOT_LISTENER_ENABLED = %t\n", z.DoTListener)
		fmt.Fprintf(&b, "DOT_LISTEN_HOST = %q\n", tlsListenHost(z.BindHost, z.DoTPort, DefaultDoTPort))
		fmt.Fprintf(&b, "DOT_LISTEN_PORT = %d\n", z.DoTPort)
		fmt.Fprintf(&b, "DOH_LISTENER_ENABLED = %t\n", z.DoHListener)
		fmt.Fprintf(&b, "DOH_LISTEN_HOST = %q\n", tlsListenHost(z.BindHost, z.DoHPort, DefaultDoHPort))
		fmt.Fprintf(&b, "DOH_LISTEN_PORT = %d\n", z.DoHPort)
	}

	fmt.Fprintf(&b, "USE_EXTERNAL_SOCKS5 = %t\n", z.ExternalSocks5)
	fmt.Fprintf(&b, "FORWARD_IP = %q\n", z.ForwardIP)
	fmt.Fprintf(&b, "FORWARD_PORT = %d\n", z.ForwardPort)

	b.WriteString("# 0=None 1=XOR 2=ChaCha20 3=AES128 4=AES192 5=AES256-GCM\n")
	fmt.Fprintf(&b, "DATA_ENCRYPTION_METHOD = %d\n", z.Cipher)
	if d.HasAutoDetect {
		fmt.Fprintf(&b, "ENCRYPTION_AUTO_DETECT = %t\n", z.AutoDetect)
	}
	if d.HasARecordDelivery {
		fmt.Fprintf(&b, "A_RECORD_DATA_DELIVERY = %t\n", z.ARecordDelivery)
	}
	b.WriteString("# The panel owns this key: it is generated once per zone and reused for\n")
	b.WriteString("# the client bundle. Relative name — the process CWD is this directory.\n")
	fmt.Fprintf(&b, "ENCRYPTION_KEY_FILE = %q\n", EncryptKeyFile)
	fmt.Fprintf(&b, "LOG_LEVEL = %q\n", z.LogLevel)
	fmt.Fprintf(&b, "CONFIG_VERSION = %q\n", d.ConfigVersion)
	return b.String(), nil
}

// ClientOptions are the client-side knobs the panel exposes in a bundle.
type ClientOptions struct {
	ListenIP   string
	ListenPort int
	// Resolvers is the client_resolvers.txt content source: one resolver per
	// line, "IP", "IP:PORT", "CIDR" or "CIDR:PORT" (§1).
	Resolvers []string
}

// RenderClient produces the client_config.toml a user runs next to the matching
// client binary. Neither tool has a URI scheme — this file IS the credential
// (§4d), which is why it carries ENCRYPTION_KEY inline rather than a key file.
func RenderClient(d Descriptor, z ZoneConfig, opt ClientOptions) (string, error) {
	z.Normalize(d)
	if err := z.Validate(); err != nil {
		return "", err
	}
	opt = opt.withDefaults()
	if strings.TrimSpace(z.ClientOverrideTOML) != "" {
		return renderClientOverride(d, z, opt)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# ForgeDNS client config for %s — generated by ForgePanel.\n", z.Zone)
	fmt.Fprintf(&b, "# Run:  ./%s_Client_<OS>_<ARCH>_<TAG> --config client_config.toml\n", d.Project)
	fmt.Fprintf(&b, "# Then point your apps at  SOCKS5 %s:%d\n", opt.ListenIP, opt.ListenPort)
	b.WriteString("# This file is the credential — it carries the shared key. Keep it private.\n\n")

	b.WriteString("# All domains must be handled by the SAME server; do not mix servers.\n")
	fmt.Fprintf(&b, "DOMAINS = %s\n", tomlStrings(z.Domains))
	if d.HasQueryTypes {
		b.WriteString("# Query-type rotation (anti-fingerprinting). Recognised: TXT, CNAME, A,\n")
		b.WriteString("# AAAA, NULL, MX, NS, PTR, SRV, SVCB, CAA, NAPTR, SOA, HTTPS.\n")
		fmt.Fprintf(&b, "QUERY_TYPES = %s\n", tomlStrings(z.QueryTypes))
	}
	fmt.Fprintf(&b, "DATA_ENCRYPTION_METHOD = %d\n", z.Cipher)
	fmt.Fprintf(&b, "ENCRYPTION_KEY = %q\n", z.EncryptKey)
	fmt.Fprintf(&b, "PROTOCOL_TYPE = %q\n", z.protocolType())
	fmt.Fprintf(&b, "LISTEN_IP = %q\n", opt.ListenIP)
	fmt.Fprintf(&b, "LISTEN_PORT = %d\n", opt.ListenPort)
	b.WriteString("STARTUP_MODE = \"resolvers\"   # \"ask\" | \"resolvers\" | \"logs\"\n")
	if d.HasResolverTransp {
		b.WriteString("RESOLVER_TRANSPORT = \"auto\"   # UDP first, escalate to TCP\n")
	}
	if d.HasBalancing {
		b.WriteString("RESOLVER_BALANCING_STRATEGY = 3   # 1=random 2=round-robin 3=least-loss 4=lowest-latency\n")
	}
	if d.HasCompression {
		b.WriteString("UPLOAD_COMPRESSION_TYPE = 2   # 0=off 1=ZSTD 2=LZ4 3=ZLIB\n")
		b.WriteString("DOWNLOAD_COMPRESSION_TYPE = 2\n")
	}
	fmt.Fprintf(&b, "CONFIG_VERSION = %q\n", d.ConfigVersion)
	return b.String(), nil
}

// DefaultResolvers is the starter client_resolvers.txt: public recursives that
// are reachable on most networks. The operator is expected to add whatever the
// censored network hands out over DHCP, which is usually the one that works.
var DefaultResolvers = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"}

// RenderResolvers builds client_resolvers.txt (one resolver per line, §1).
func RenderResolvers(list []string) string {
	if len(list) == 0 {
		list = DefaultResolvers
	}
	var b strings.Builder
	b.WriteString("# client_resolvers.txt — one per line: IP, IP:PORT, CIDR or CIDR:PORT.\n")
	b.WriteString("# Add the resolver your network hands out over DHCP: on a captive or\n")
	b.WriteString("# filtered network that one is usually the only one allowed out.\n")
	for _, r := range list {
		r = strings.TrimSpace(r)
		if r != "" {
			b.WriteString(r + "\n")
		}
	}
	return b.String()
}

// GenerateKey mints a zone's shared secret: 16 random bytes hex-encoded, i.e. a
// 32-character key. StormDNS/CottenDNS/MasterDNS treat ENCRYPTION_KEY as a
// fixed 32-char secret (their own configs use keys like 0411c15335081ae243d6070e4551bbe0),
// and their clients reject a 64-char key outright — so this must be 16 bytes, not
// 32. Hex keeps it safe to embed in TOML and in a plain encrypt_key.txt without
// quoting or encoding surprises.
func GenerateKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- small TOML/domain helpers -------------------------------------------

// tomlStrings renders a []string as a TOML inline array.
func tomlStrings(in []string) string {
	parts := make([]string, 0, len(in))
	for _, s := range in {
		parts = append(parts, strconv.Quote(s))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func normDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// dedupeDomains normalises, drops blanks and removes duplicates while keeping
// the first occurrence first — the primary zone stays at index 0.
func dedupeDomains(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		d := normDomain(s)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// SplitList parses a comma / space / newline / semicolon separated list, the
// format the store columns and query parameters use.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ';'
	})
}

// SplitDomains parses the store's domain column into normalised domains.
func SplitDomains(s string) []string { return dedupeDomains(SplitList(s)) }

// JoinDomains renders a domain list back into the store column format.
func JoinDomains(in []string) string { return strings.Join(dedupeDomains(in), ",") }

func validDomain(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// queryTypes is the recognised QUERY_TYPES set (§3, verbatim).
var queryTypes = map[string]bool{
	"TXT": true, "CNAME": true, "A": true, "AAAA": true, "NULL": true,
	"MX": true, "NS": true, "PTR": true, "SRV": true, "SVCB": true,
	"CAA": true, "NAPTR": true, "SOA": true, "HTTPS": true,
}

func validQueryType(s string) bool { return queryTypes[strings.ToUpper(strings.TrimSpace(s))] }

// NormalizeQueryTypes upper-cases and de-duplicates a query-type list.
func NormalizeQueryTypes(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		q := strings.ToUpper(strings.TrimSpace(s))
		if q == "" || seen[q] {
			continue
		}
		seen[q] = true
		out = append(out, q)
	}
	return out
}

// QueryTypeChoices lists the recognised query types for the UI, sorted.
func QueryTypeChoices() []string {
	out := make([]string, 0, len(queryTypes))
	for q := range queryTypes {
		out = append(out, q)
	}
	sort.Strings(out)
	return out
}
