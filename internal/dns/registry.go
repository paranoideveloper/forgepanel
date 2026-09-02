package dns

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Factory builds a Provider from credentials.
type Factory func(Credentials) (Provider, error)

// CredentialField describes one input the provider needs, so the UI can render
// the credential form without hard-coding provider knowledge.
type CredentialField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
	Help     string `json:"help,omitempty"`
}

// ProviderInfo is the registry entry for one DNS backend.
type ProviderInfo struct {
	Name string `json:"name"`
	// Title is the operator-facing name.
	Title string `json:"title"`
	// Implemented is false for entries that exist so the UI can list them but
	// whose factory returns a KindNotImplemented error.
	Implemented bool `json:"implemented"`
	// Proxy is true when the provider has a CDN whose per-record proxy flag
	// this package can toggle.
	Proxy bool `json:"proxy"`
	// ZoneSettings is true when edge TLS/WebSocket/gRPC settings are managed.
	ZoneSettings     bool              `json:"zone_settings"`
	CredentialFields []CredentialField `json:"credential_fields"`
	TokenURL         string            `json:"token_url,omitempty"`
	Notes            string            `json:"notes,omitempty"`
}

type registryEntry struct {
	info    ProviderInfo
	factory Factory
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*registryEntry{}
)

// Register adds or replaces a provider entry. It is safe for concurrent use so
// a deployment can register a private backend at init time.
func Register(info ProviderInfo, factory Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := strings.ToLower(strings.TrimSpace(info.Name))
	if name == "" {
		panic("dns: cannot register a provider with an empty name")
	}
	info.Name = name
	registry[name] = &registryEntry{info: info, factory: factory}
}

// Providers lists every registered provider, implemented ones first then
// alphabetically, so the UI's default selection is always a working backend.
func Providers() []ProviderInfo {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]ProviderInfo, 0, len(registry))
	for _, e := range registry {
		out = append(out, e.info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Implemented != out[j].Implemented {
			return out[i].Implemented
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Lookup returns the registry entry for a provider name.
func Lookup(name string) (ProviderInfo, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	e, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return ProviderInfo{}, false
	}
	return e.info, true
}

// NewProvider builds a provider by registry name. An unknown name lists the
// names that do exist rather than just saying "unknown".
func NewProvider(name string, creds Credentials) (Provider, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	registryMu.RLock()
	e, ok := registry[key]
	registryMu.RUnlock()
	if !ok {
		known := make([]string, 0, len(registry))
		for _, info := range Providers() {
			known = append(known, info.Name)
		}
		return nil, &Error{Op: "new-provider", Kind: KindValidation,
			Message:     fmt.Sprintf("unknown DNS provider %q", name),
			Remediation: "use one of: " + strings.Join(known, ", ")}
	}
	return e.factory(creds)
}

// ImplementedProviders returns the names with a working backend.
func ImplementedProviders() []string {
	var out []string
	for _, info := range Providers() {
		if info.Implemented {
			out = append(out, info.Name)
		}
	}
	return out
}

func init() {
	Register(ProviderInfo{
		Name: "cloudflare", Title: "Cloudflare", Implemented: true, Proxy: true, ZoneSettings: true,
		TokenURL: "https://dash.cloudflare.com/profile/api-tokens",
		CredentialFields: []CredentialField{
			{Key: "api_token", Label: "API token", Secret: true, Required: true,
				Help: "Needs " + ScopeZoneRead + ", " + ScopeDNSEdit + ", " + ScopeSettingsEdit + " and " + ScopeSSLEdit + ", with Zone Resources covering the domain."},
			{Key: "account_id", Label: "Account ID", Required: false,
				Help: "Optional. When set, the token is verified against the account endpoint and zone listing is filtered to that account."},
		},
		Notes: "Full support: records, orange-cloud proxying, edge TLS/WebSocket/gRPC settings, and clean-IP scanning against Cloudflare's ranges.",
	}, NewCloudflare)

	Register(ProviderInfo{
		Name: "arvancloud", Title: "ArvanCloud", Implemented: true, Proxy: true,
		TokenURL: "https://panel.arvancloud.ir/profile/api-keys",
		CredentialFields: []CredentialField{
			{Key: "api_key", Label: "API key", Secret: true, Required: true,
				Help: "The machine-user key from the ArvanCloud profile. Paste with or without the \"Apikey \" prefix."},
		},
		Notes: "Records and the CDN cloud flag. Reachable from inside Iran when Cloudflare's API is not, which is why it is the domestic fallback.",
	}, NewArvan)

	Register(ProviderInfo{
		Name: "desec", Title: "deSEC", Implemented: true,
		TokenURL: "https://desec.io/tokens",
		CredentialFields: []CredentialField{
			{Key: "token", Label: "API token", Secret: true, Required: true,
				Help: "The token value from https://desec.io/tokens — not the token id."},
		},
		Notes: "Free, DNSSEC-signed authoritative DNS with no CDN. The right backend for REALITY and direct-TLS inbounds, where proxying would break the handshake. TTLs are clamped to the domain's minimum (3600 on free accounts).",
	}, NewDesec)

	// Providers below are registered so the UI can list and plan for them, but
	// have no backend in this build. Their factory returns a typed
	// KindNotImplemented error naming where to create the records by hand.
	for _, stub := range []struct {
		name, title, docs string
		fields            []CredentialField
	}{
		{"digitalocean", "DigitalOcean", "https://cloud.digitalocean.com/networking/domains",
			[]CredentialField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}},
		{"gcore", "Gcore", "https://dnsapi.gcore.com",
			[]CredentialField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}},
		{"namecheap", "Namecheap", "https://ap.www.namecheap.com/settings/tools/apiaccess/",
			[]CredentialField{
				{Key: "api_user", Label: "API user", Required: true},
				{Key: "api_key", Label: "API key", Secret: true, Required: true},
				{Key: "client_ip", Label: "Whitelisted client IP", Required: true},
			}},
		{"godaddy", "GoDaddy", "https://developer.godaddy.com/keys",
			[]CredentialField{
				{Key: "api_key", Label: "API key", Required: true},
				{Key: "api_secret", Label: "API secret", Secret: true, Required: true},
			}},
		{"vultr", "Vultr", "https://my.vultr.com/settings/#settingsapi",
			[]CredentialField{{Key: "api_key", Label: "API key", Secret: true, Required: true}}},
		{"hetzner", "Hetzner DNS", "https://dns.hetzner.com/settings/api-token",
			[]CredentialField{{Key: "api_token", Label: "API token", Secret: true, Required: true}}},
	} {
		name, docs := stub.name, stub.docs
		Register(ProviderInfo{
			Name: name, Title: stub.title, Implemented: false,
			TokenURL: docs, CredentialFields: stub.fields,
			Notes: "Listed for planning. No backend in this build — create the records at " + docs +
				" and run `forgectl provision --skip-dns` to verify and wire up the inbounds.",
		}, func(Credentials) (Provider, error) {
			return nil, notImplemented(name, docs)
		})
	}
}
