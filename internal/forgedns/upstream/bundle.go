package upstream

import (
	"fmt"
	"strings"
)

// This file builds the two things §4d says the panel must show per zone. Neither
// tool defines a URI scheme, so there is no "copy link" to hand a user: the
// generated client_config.toml IS the credential, and the NS delegation block is
// the other half of the setup. Both are produced here so the API layer stays a
// thin marshaller.

// CloudflareWarning is the delegation gotcha the upstream READMEs call out
// explicitly (§3): a proxied (orange-cloud) A record breaks delegation, because
// Cloudflare answers for the name instead of pointing at the tunnel server.
const CloudflareWarning = "If this domain is on Cloudflare, the ns A record MUST be " +
	"\"DNS only\" (grey cloud), never proxied — a proxied record breaks NS delegation " +
	"and the tunnel will never receive a query."

// Record is one DNS record the operator must create at their registrar.
type Record struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// Download is a release asset the user fetches to run the client.
type Download struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
}

// Bundle is everything a user needs to connect to one zone.
type Bundle struct {
	Zone      string   `json:"zone"`
	Adapter   string   `json:"adapter"`
	Repo      string   `json:"repo"`
	Tag       string   `json:"tag,omitempty"`
	Domains   []string `json:"domains"`
	ServerIP  string   `json:"server_ip,omitempty"`
	NSHost    string   `json:"ns_host"`
	NSRecords []Record `json:"ns_records"`
	Warning   string   `json:"cloudflare_warning"`

	ClientConfigTOML   string `json:"client_config_toml"`
	ClientResolversTXT string `json:"client_resolvers_txt"`
	ClientFilenames    struct {
		Config    string `json:"config"`
		Resolvers string `json:"resolvers"`
	} `json:"client_filenames"`

	Downloads    []Download `json:"downloads"`
	ReleasesPage string     `json:"releases_page"`
	Socks5       string     `json:"socks5"`
	Steps        []string   `json:"steps"`
}

// BundleOptions parameterises bundle generation.
type BundleOptions struct {
	ServerIP  string   // public IP the zone's NS record must point at
	NSHost    string   // optional override; default is "ns.<parent of zone>"
	Tag       string   // release tag to link client downloads for
	Resolvers []string // seeds client_resolvers.txt
	Client    ClientOptions
}

// BuildBundle renders the client config, resolvers file, download links and NS
// delegation records for a zone.
func BuildBundle(d Descriptor, z ZoneConfig, opt BundleOptions) (Bundle, error) {
	z.Normalize(d)
	if err := z.Validate(); err != nil {
		return Bundle{}, err
	}
	cfg, err := RenderClient(d, z, opt.Client)
	if err != nil {
		return Bundle{}, err
	}
	listen := opt.Client.ListenIP
	if listen == "" {
		listen = DefaultClientListenIP
	}
	port := opt.Client.ListenPort
	if port == 0 {
		port = DefaultClientPort
	}

	b := Bundle{
		Zone: z.Zone, Adapter: d.Adapter, Repo: d.Owner + "/" + d.Repo, Tag: opt.Tag,
		Domains: z.Domains, ServerIP: opt.ServerIP,
		NSHost:             NSHostFor(z.Zone, opt.NSHost),
		Warning:            CloudflareWarning,
		ClientConfigTOML:   cfg,
		ClientResolversTXT: RenderResolvers(opt.Resolvers),
		ReleasesPage:       d.ReleasesPage(),
		Socks5:             fmt.Sprintf("%s:%d", listen, port),
	}
	b.ClientFilenames.Config = "client_config.toml"
	b.ClientFilenames.Resolvers = "client_resolvers.txt"
	b.NSRecords = Delegation(z.Domains, opt.ServerIP, opt.NSHost)
	b.Downloads = ClientDownloads(d, opt.Tag)
	b.Steps = steps(d, z, b)
	return b, nil
}

// NSHostFor derives the nameserver hostname for a tunnel zone. Per the verified
// examples in §1–§3, a zone "v.example.com" is delegated to "ns.example.com" —
// the ns host lives in the PARENT zone, since that is where the operator can
// create records. An explicit override wins.
func NSHostFor(zone, override string) string {
	if o := normDomain(override); o != "" {
		return o
	}
	z := normDomain(zone)
	if i := strings.Index(z, "."); i >= 0 && strings.Count(z, ".") >= 2 {
		return "ns." + z[i+1:]
	}
	return "ns." + z
}

// Delegation returns the records to paste at the DNS provider (§4d). Every
// tunnel domain of a multi-domain zone gets its own NS record, because all of
// them must resolve to this same server for the client's domain rotation to
// work (§3).
func Delegation(domains []string, serverIP, nsOverride string) []Record {
	out := []Record{}
	seenNS := map[string]bool{}
	for _, dom := range dedupeDomains(domains) {
		ns := NSHostFor(dom, nsOverride)
		if !seenNS[ns] {
			seenNS[ns] = true
			out = append(out, Record{
				Type: "A", Name: ns, Value: serverIP,
				Note: "glue: the nameserver host points at this tunnel server. " + CloudflareWarning,
			})
		}
		out = append(out, Record{
			Type: "NS", Name: dom, Value: ns,
			Note: "delegate the tunnel domain to that nameserver",
		})
	}
	return out
}

// ClientDownloads lists the client release assets. Only the Linux asset naming
// is verified (§0); for every other platform the panel links the releases page
// rather than guessing a filename that may not exist.
func ClientDownloads(d Descriptor, tag string) []Download {
	if tag == "" {
		return nil
	}
	out := []Download{}
	for _, a := range []struct{ label, arch string }{
		{"Linux x86-64", "AMD64"},
		{"Linux ARM64", "ARM64"},
	} {
		file := d.ClientAsset("Linux", a.arch) + ".tar.gz"
		out = append(out, Download{Platform: a.label, URL: d.AssetURL(tag, file)})
	}
	return out
}

// steps is the ordered checklist the UI renders next to the bundle.
func steps(d Descriptor, z ZoneConfig, b Bundle) []string {
	dom := strings.Join(z.Domains, ", ")
	return []string{
		fmt.Sprintf("At your DNS provider, create the records above so %s is delegated to %s.", dom, b.NSHost),
		CloudflareWarning,
		fmt.Sprintf("Download the %s client for your platform (links above; other platforms are on the releases page).", d.Repo),
		"Save client_config.toml and client_resolvers.txt next to the client binary.",
		fmt.Sprintf("Run:  ./%s_Client_<OS>_<ARCH>_<TAG> --config client_config.toml", d.Project),
		fmt.Sprintf("Point your apps at SOCKS5 %s.", b.Socks5),
		"Delegation can take a few minutes to propagate; until it does the client sees no answers.",
	}
}
