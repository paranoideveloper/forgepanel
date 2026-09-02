package upstream

import (
	"strings"
	"testing"
)

// TestDescriptorTable pins the values verified in docs/FORGEDNS_UPSTREAM_SETUP.md
// §4a. They are not guesses: a wrong owner, repo or asset spelling means a 404
// at install time, and the CottenDNS asset casing ("CottenDns", lower-case "ns",
// while the repo is "CottenDNS") is exactly the trap §0 calls out.
func TestDescriptorTable(t *testing.T) {
	want := map[string]struct {
		owner, repo, project, version, serverAsset, exeGlob string
	}{
		AdapterStormDNS: {"nullroute1970", "StormDNS", "StormDNS", "10",
			"StormDNS_Server_Linux_AMD64", "StormDNS_Server_Linux_AMD64_"},
		AdapterMasterDNS: {"masterking32", "MasterDnsVPN", "MasterDnsVPN", "12",
			"MasterDnsVPN_Server_Linux_AMD64", "MasterDnsVPN_Server_Linux_AMD64_"},
		AdapterCottenDNS: {"WhiteDNS", "CottenDNS", "CottenDns", "14",
			"CottenDns_Server_Linux_AMD64", "CottenDns_Server_Linux_AMD64_"},
	}
	for name, w := range want {
		d, err := Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if d.Owner != w.owner || d.Repo != w.repo || d.Project != w.project {
			t.Errorf("%s: %s/%s project %s, want %s/%s project %s",
				name, d.Owner, d.Repo, d.Project, w.owner, w.repo, w.project)
		}
		if d.ConfigVersion != w.version {
			t.Errorf("%s: CONFIG_VERSION %q, want %q", name, d.ConfigVersion, w.version)
		}
		if got := d.ServerAsset("AMD64"); got != w.serverAsset {
			t.Errorf("%s: server asset %q, want %q", name, got, w.serverAsset)
		}
		if got := d.ExeGlobPrefix("AMD64"); got != w.exeGlob {
			t.Errorf("%s: exe prefix %q, want %q", name, got, w.exeGlob)
		}
	}
}

// TestReleaseURLs matches the verified download URLs in §0 exactly.
func TestReleaseURLs(t *testing.T) {
	cases := []struct{ adapter, tag, want string }{
		{AdapterStormDNS, "v2026.05.13.223445-87348df",
			"https://github.com/nullroute1970/StormDNS/releases/download/v2026.05.13.223445-87348df/StormDNS_Server_Linux_AMD64.tar.gz"},
		{AdapterCottenDNS, "v2026.07.22.231403-a360409",
			"https://github.com/WhiteDNS/CottenDNS/releases/download/v2026.07.22.231403-a360409/CottenDns_Server_Linux_AMD64.tar.gz"},
		{AdapterMasterDNS, "v2026.06.13.234407-7de2476",
			"https://github.com/masterking32/MasterDnsVPN/releases/download/v2026.06.13.234407-7de2476/MasterDnsVPN_Server_Linux_AMD64.tar.gz"},
	}
	for _, c := range cases {
		d, _ := Lookup(c.adapter)
		if got := d.AssetURL(c.tag, d.ServerAsset("AMD64")+".tar.gz"); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.adapter, got, c.want)
		}
		if got := d.LatestReleaseAPI(); !strings.HasPrefix(got, "https://api.github.com/repos/") ||
			!strings.HasSuffix(got, "/releases/latest") {
			t.Errorf("%s: latest-release API %q", c.adapter, got)
		}
	}
}

// TestOnlyCottenHasHealthEndpoint: the supervisor's health strategy branches on
// this (§4c), so a wrong flag would mean fabricating a health state.
func TestCapabilityFlags(t *testing.T) {
	cotten, _ := Lookup(AdapterCottenDNS)
	if cotten.HealthURL != "http://127.0.0.1:9090/healthz" {
		t.Errorf("cottendns health URL = %q", cotten.HealthURL)
	}
	if !cotten.HasListenerToggles || !cotten.HasQueryTypes || !cotten.HasAutoDetect {
		t.Error("cottendns must advertise its listener/query-type/auto-detect knobs")
	}
	for _, name := range []string{AdapterStormDNS, AdapterMasterDNS} {
		d, _ := Lookup(name)
		if d.HealthURL != "" {
			t.Errorf("%s has no health endpoint; got %q", name, d.HealthURL)
		}
		if d.HasListenerToggles || d.HasQueryTypes || d.HasAutoDetect || d.HasARecordDelivery {
			t.Errorf("%s must not advertise CottenDNS-only knobs", name)
		}
	}
}

func TestIsUpstreamAndDefault(t *testing.T) {
	for _, name := range []string{"stormdns", "MasterDNS", " cottendns "} {
		if !IsUpstream(name) {
			t.Errorf("IsUpstream(%q) = false", name)
		}
	}
	// The panel-native path must never be mistaken for a real binary.
	for _, name := range []string{"forge", "native", "", "unknown"} {
		if IsUpstream(name) {
			t.Errorf("IsUpstream(%q) = true, want false", name)
		}
	}
	if DefaultAdapter != AdapterCottenDNS {
		t.Errorf("default adapter = %q, want cottendns (§4e)", DefaultAdapter)
	}
	if len(Descriptors()) != 3 || Descriptors()[0].Adapter != AdapterCottenDNS {
		t.Errorf("Descriptors() should list all three with the recommended one first")
	}
	if _, err := Lookup("forge"); err == nil {
		t.Error("Lookup(forge) must fail: it is the panel-native adapter, not an upstream binary")
	}
}

func TestArchToken(t *testing.T) {
	for goarch, want := range map[string]string{"amd64": "AMD64", "arm64": "ARM64", "arm": "ARMV7"} {
		got, err := ArchToken(goarch)
		if err != nil || got != want {
			t.Errorf("ArchToken(%q) = %q, %v; want %q", goarch, got, err, want)
		}
	}
	if _, err := ArchToken("riscv64"); err == nil {
		t.Error("an unsupported arch must be an error, not a guessed asset name")
	}
}

// TestDelegation covers §4d: one A record for the nameserver host plus one NS
// record per tunnel domain, and the Cloudflare grey-cloud warning must travel
// with them — a proxied record silently breaks delegation.
func TestDelegation(t *testing.T) {
	recs := Delegation([]string{"a.example.com", "b.example.com"}, "203.0.113.9", "")
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 1 A + 2 NS: %+v", len(recs), recs)
	}
	if recs[0].Type != "A" || recs[0].Name != "ns.example.com" || recs[0].Value != "203.0.113.9" {
		t.Errorf("glue record = %+v", recs[0])
	}
	if !strings.Contains(recs[0].Note, "grey cloud") {
		t.Errorf("glue record must carry the Cloudflare warning: %q", recs[0].Note)
	}
	for _, r := range recs[1:] {
		if r.Type != "NS" || r.Value != "ns.example.com" {
			t.Errorf("delegation record = %+v", r)
		}
	}
	if got := NSHostFor("v.example.com", "ns1.custom.net"); got != "ns1.custom.net" {
		t.Errorf("explicit NS host override ignored: %q", got)
	}
	// Domains in two different parent zones need their own glue records.
	if recs := Delegation([]string{"a.example.com", "b.example.net"}, "203.0.113.9", ""); len(recs) != 4 {
		t.Errorf("two parents should yield 2 A + 2 NS, got %d", len(recs))
	}
}

func TestBuildBundle(t *testing.T) {
	d, _ := Lookup(AdapterCottenDNS)
	z := zone(AdapterCottenDNS, "a.example.com", "b.example.com")
	tag := "v2026.07.22.231403-a360409"
	b, err := BuildBundle(d, z, BundleOptions{ServerIP: "203.0.113.9", Tag: tag})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Domains) != 2 || b.Socks5 != "127.0.0.1:18000" {
		t.Errorf("bundle domains %v socks %q", b.Domains, b.Socks5)
	}
	if !strings.Contains(b.ClientConfigTOML, "deadbeef") {
		t.Error("client config must embed the shared key — it IS the credential (§4d)")
	}
	if len(b.Downloads) == 0 || !strings.Contains(b.Downloads[0].URL, tag) {
		t.Errorf("client downloads = %+v", b.Downloads)
	}
	if b.Warning == "" || len(b.Steps) == 0 {
		t.Error("bundle must carry the Cloudflare warning and the setup steps")
	}
	// Without a pinned tag there is no honest download URL to offer.
	nb, _ := BuildBundle(d, z, BundleOptions{ServerIP: "203.0.113.9"})
	if len(nb.Downloads) != 0 {
		t.Errorf("no tag pinned, yet downloads offered: %+v", nb.Downloads)
	}
}

func TestSanitizeZonePath(t *testing.T) {
	for in, want := range map[string]string{
		"v.example.com":  "v.example.com",
		"V.Example.COM.": "v.example.com",
		"../../etc":      "_.._etc", // no separators survive, so it cannot escape the zone dir
		"":               "zone",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookupSum(t *testing.T) {
	listing := "abc123  OtherFile.tar.gz\ndef456  StormDNS_Server_Linux_AMD64.tar.gz\n"
	got, ok := lookupSum(listing, "StormDNS_Server_Linux_AMD64.tar.gz")
	if !ok || got != "def456" {
		t.Fatalf("lookupSum = %q, %v", got, ok)
	}
	if _, ok := lookupSum(listing, "Missing.tar.gz"); ok {
		t.Error("a missing file must not report a digest")
	}
}
