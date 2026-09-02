package dns

import (
	"strings"
	"testing"
)

// The three fully-implemented providers must be implemented, and the six extra
// entries must be listed but explicitly not.
func TestRegistryContents(t *testing.T) {
	wantImplemented := map[string]bool{"cloudflare": true, "arvancloud": true, "desec": true}
	wantListed := []string{"digitalocean", "gcore", "namecheap", "godaddy", "vultr", "hetzner"}

	infos := Providers()
	if len(infos) != 9 {
		t.Fatalf("expected 9 registered providers, got %d", len(infos))
	}
	byName := map[string]ProviderInfo{}
	for _, info := range infos {
		byName[info.Name] = info
	}
	for name := range wantImplemented {
		info, ok := byName[name]
		if !ok {
			t.Fatalf("provider %q is not registered", name)
		}
		if !info.Implemented {
			t.Fatalf("provider %q must be implemented", name)
		}
		if len(info.CredentialFields) == 0 {
			t.Fatalf("provider %q must document its credential fields", name)
		}
		if info.TokenURL == "" {
			t.Fatalf("provider %q must say where to get a token", name)
		}
	}
	for _, name := range wantListed {
		info, ok := byName[name]
		if !ok {
			t.Fatalf("provider %q is not registered", name)
		}
		if info.Implemented {
			t.Fatalf("provider %q claims to be implemented but has no backend", name)
		}
	}

	// Implemented providers must sort first so the UI's default is a working one.
	if !infos[0].Implemented {
		t.Fatalf("implemented providers must sort first, got %q", infos[0].Name)
	}
	impl := ImplementedProviders()
	if len(impl) != 3 {
		t.Fatalf("expected 3 implemented providers, got %v", impl)
	}
}

func TestRegistryCapabilityFlagsMatchTheCode(t *testing.T) {
	cases := []struct {
		name     string
		proxy    bool
		settings bool
		creds    Credentials
	}{
		{"cloudflare", true, true, Credentials{"api_token": "t"}},
		{"arvancloud", true, false, Credentials{"api_key": "k"}},
		{"desec", false, false, Credentials{"token": "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := Lookup(tc.name)
			if !ok {
				t.Fatalf("provider %q is not registered", tc.name)
			}
			p, err := NewProvider(tc.name, tc.creds)
			requireNoError(t, err)

			_, hasProxy := p.(ProxyController)
			if hasProxy != tc.proxy || info.Proxy != tc.proxy {
				t.Fatalf("%s: proxy capability mismatch — code=%v registry=%v want=%v",
					tc.name, hasProxy, info.Proxy, tc.proxy)
			}
			_, hasSettings := p.(ZoneSettingsController)
			if hasSettings != tc.settings || info.ZoneSettings != tc.settings {
				t.Fatalf("%s: zone-settings capability mismatch — code=%v registry=%v want=%v",
					tc.name, hasSettings, info.ZoneSettings, tc.settings)
			}
		})
	}
}

// A registered-but-unbuilt provider must fail with a typed error that says
// exactly what to do instead — never a nil provider or a vague message.
func TestUnimplementedProvidersReturnTypedError(t *testing.T) {
	for _, name := range []string{"digitalocean", "gcore", "namecheap", "godaddy", "vultr", "hetzner"} {
		p, err := NewProvider(name, Credentials{"api_token": "t", "api_key": "k", "api_secret": "s", "api_user": "u", "client_ip": "1.2.3.4"})
		if p != nil {
			t.Fatalf("%s: expected no provider, got %T", name, p)
		}
		e := requireKind(t, err, KindNotImplemented)
		if !IsNotImplemented(err) {
			t.Fatalf("%s: IsNotImplemented should be true", name)
		}
		requireContains(t, e.Message, name, name+" message names itself")
		requireContains(t, e.Remediation, "--skip-dns", name+" remediation offers the manual path")
		requireContains(t, e.Remediation, "cloudflare, arvancloud, desec", name+" remediation lists working providers")
		info, _ := Lookup(name)
		requireContains(t, e.Remediation, info.TokenURL, name+" remediation names where to create the records")
	}
}

func TestNewProviderUnknownNameListsTheKnownOnes(t *testing.T) {
	_, err := NewProvider("route53", Credentials{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "route53", "unknown provider message")
	for _, name := range []string{"cloudflare", "arvancloud", "desec"} {
		requireContains(t, e.Remediation, name, "unknown provider remediation")
	}
}

func TestNewProviderIsCaseInsensitive(t *testing.T) {
	p, err := NewProvider("  CloudFlare  ", Credentials{"api_token": "t"})
	requireNoError(t, err)
	if p.Name() != "cloudflare" {
		t.Fatalf("unexpected provider name %q", p.Name())
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("nope"); ok {
		t.Fatal("expected an unknown provider to be absent")
	}
}

// The Cloudflare entry must tell the operator every scope the wizard needs,
// because a token missing one of them is the most common provisioning failure.
func TestCloudflareRegistryEntryDocumentsEveryScope(t *testing.T) {
	info, ok := Lookup("cloudflare")
	if !ok {
		t.Fatal("cloudflare is not registered")
	}
	var help string
	for _, f := range info.CredentialFields {
		if f.Key == "api_token" {
			if !f.Secret || !f.Required {
				t.Fatalf("the API token field must be secret and required: %+v", f)
			}
			help = f.Help
		}
	}
	for _, scope := range []string{ScopeZoneRead, ScopeDNSEdit, ScopeSettingsEdit, ScopeSSLEdit} {
		requireContains(t, help, scope, "cloudflare credential help")
	}
}

func TestNormalizeType(t *testing.T) {
	for _, in := range []string{"a", "A", " aaaa ", "cname", "TXT", "srv", "ns", "mx", "caa"} {
		if _, err := NormalizeType(in); err != nil {
			t.Errorf("NormalizeType(%q) failed: %v", in, err)
		}
	}
	_, err := NormalizeType("SPF")
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "A, AAAA, CNAME", "unsupported type remediation")
}

func TestErrorKindHelpers(t *testing.T) {
	perm := &Error{Kind: KindPermission, Message: "nope"}
	if !IsPermission(perm) || IsNotFound(perm) || IsRetryable(perm) {
		t.Fatal("permission helpers are wrong")
	}
	for _, kind := range []Kind{KindRateLimit, KindNetwork, KindServer} {
		if !IsRetryable(&Error{Kind: kind}) {
			t.Fatalf("%s should be retryable", kind)
		}
	}
	if KindOf(nil) != "" {
		t.Fatal("KindOf(nil) should be empty")
	}
}

// The error string must always carry both the missing scope and the fix, since
// that string is what an operator actually reads.
func TestErrorStringCarriesScopeAndRemediation(t *testing.T) {
	e := &Error{
		Provider: "cloudflare", Op: "create-record", Kind: KindPermission,
		Status: 403, Code: 9109, Message: "Unauthorized to access requested resource",
		MissingScope: ScopeDNSEdit, Remediation: "add the scope",
	}
	s := e.Error()
	for _, needle := range []string{"cloudflare", "create-record", "HTTP 403", "code 9109", ScopeDNSEdit, "fix: add the scope"} {
		requireContains(t, s, needle, "error string")
	}
	if !strings.Contains(s, "missing API token permission") {
		t.Fatalf("expected the permission label, got %q", s)
	}
}
