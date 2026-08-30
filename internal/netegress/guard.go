package netegress

// Where the panel is allowed to point an outbound request.
//
// Several endpoints fetch a URL the OPERATOR typed: the egress test button, a
// webhook receiver, a DNS provider's base URL. None of them checked where that
// URL resolved to, so the panel would happily HEAD its own loopback ports and
// POST a signed webhook body to 169.254.169.254 — the cloud instance-metadata
// service, which hands out the hosting account's credentials to anything on the
// box. Owning the panel is not the same as owning the hosting account, and the
// webhook retry ladder keeps dialling with nobody watching.
//
// The guard lives here rather than at the call sites because this package owns
// the Transport (and because wiring_test.go forbids building a client anywhere
// else), and it carries two policies rather than one — see Policy.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Policy is how much of the address space a particular sink may reach.
//
// One policy would have been wrong in one direction or the other. A blanket
// private-address block breaks the DOCUMENTED webhook case — transport.go says
// a receiver "is very often an internal service on the other side of a
// different hop entirely" — while allowing private addresses on the egress test
// button leaves an internal port scanner in the settings page.
type Policy int

const (
	// PolicyStrict refuses everything that is not public unicast. For a target
	// the panel fetches on the operator's behalf and then reports on, where
	// reaching an internal address is never the point.
	PolicyStrict Policy = iota

	// PolicyNoMetadata refuses only what no operator ever legitimately targets:
	// the cloud instance-metadata endpoints. Loopback and RFC1918 stay allowed,
	// because an internal receiver is the intended case for a webhook.
	PolicyNoMetadata
)

// BlockedError is the guard's refusal, typed so internal/apierr can classify it
// as a validation error with remediation instead of a bare 500.
//
// It deliberately does not reference apierr: apierr already imports this
// package (through internal/dns), so the dependency has to run one way.
type BlockedError struct {
	Target string // the URL as the operator gave it
	Addr   string // the address that was refused
	Reason string // why, in words an operator can act on
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("refusing to fetch %s: %s is %s", e.Target, e.Addr, e.Reason)
}

// The two metadata endpoints that no general rule catches: one is a ULA and one
// is inside CGNAT, so neither IsLinkLocalUnicast nor IsPrivate sees them.
var (
	awsIMDSv6    = net.ParseIP("fd00:ec2::254")
	alibabaMeta  = net.ParseIP("100.100.100.200")
	benchmarking = net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}
)

// blockedIP is the whole policy, in one place so the resolve-time check and the
// dial-time check cannot drift apart.
func blockedIP(p Policy, ip net.IP) (string, bool) {
	if ip == nil {
		return "not an address", true
	}
	// Unwrap IPv4-mapped IPv6 FIRST. Without this every v4 test below misses
	// ::ffff:169.254.169.254, which is the same packet with a longer spelling.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Refused under every policy: the metadata set.
	switch {
	case ip.IsLinkLocalUnicast():
		// 169.254.0.0/16 and fe80::/10 — where AWS, GCP, Azure, DigitalOcean
		// and Hetzner all serve instance credentials.
		return "link-local (cloud instance metadata)", true
	case ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return "a link-local multicast address", true
	case ip.Equal(awsIMDSv6):
		return "the AWS IMDSv6 endpoint", true
	case ip.Equal(alibabaMeta):
		return "the Alibaba Cloud metadata endpoint", true
	}
	if p == PolicyNoMetadata {
		return "", false
	}

	switch {
	case ip.IsLoopback():
		return "this machine itself", true
	case ip.IsUnspecified():
		return "the unspecified address", true
	case ip.IsPrivate():
		return "a private network address", true
	case ip.IsMulticast():
		return "a multicast address", true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64:
			// 100.64.0.0/10 (CGNAT) is not covered by net.IP.IsPrivate.
			return "a carrier-grade NAT address", true
		case v4[0] == 0:
			return "in 0.0.0.0/8", true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
			return "in the IETF protocol assignments range", true
		case benchmarking.Contains(v4):
			return "in the network benchmarking range", true
		}
	}
	return "", false
}

// ValidateURL checks everything that can be decided from the URL text alone.
func ValidateURL(p Policy, raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("the URL must be http or https, not %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q has no host", raw)
	}
	// Embedded user:password is deliberately NOT refused.
	//
	// It is not an SSRF control — what stops an internal fetch is the resolved
	// IP, checked below and again at dial time — and refusing it here broke a
	// working feature. ValidateURL runs on every STORED webhook row at delivery
	// time, so refusing userinfo turned every endpoint behind HTTP basic auth
	// into a permanent failure on upgrade: retryable, six attempts, given up.
	// The remediation it printed ("put them in a header") named a field that
	// does not exist — webhook.Endpoint has no headers and the panel's UI
	// offers none — so an operator had no way to comply.
	//
	// The genuine risk is the credential LEAKING: into a log, an echoed error,
	// or a cross-host redirect. That is answered where it happens — redirects
	// are not followed to a different host, and errors carry u.Redacted() —
	// not by refusing the only way this product lets a receiver authenticate.
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if reason, blocked := blockedIP(p, ip); blocked {
			return nil, &BlockedError{Target: raw, Addr: ip.String(), Reason: reason}
		}
	}
	return u, nil
}

// ResolveAllowed refuses if ANY answer is blocked, not merely the first.
//
// A DNS-rebinding record hands back a public address and a private one in the
// same reply and lets the client pick; checking only answers[0] is how that
// attack is normally allowed through.
func ResolveAllowed(ctx context.Context, p Policy, host string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if reason, blocked := blockedIP(p, ip); blocked {
			return nil, &BlockedError{Target: host, Addr: ip.String(), Reason: reason}
		}
	}
	return ips, nil
}

// GuardTarget is the one entry point every call site uses.
func GuardTarget(ctx context.Context, p Policy, raw string) (*url.URL, error) {
	u, err := ValidateURL(p, raw)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(u.Hostname()) != nil {
		return u, nil // ValidateURL already ran the policy over it
	}
	if _, err := ResolveAllowed(ctx, p, u.Hostname()); err != nil {
		var be *BlockedError
		if errors.As(err, &be) {
			return nil, err
		}
		// A lookup FAILURE is not a refusal. On the censored networks this
		// panel exists for, local resolution is routinely broken while the
		// configured proxy resolves the same name fine — turning that into a
		// block converts a security fix into "the panel can no longer reach
		// anything". With a proxy configured, let the proxy try.
		if proxyConfigured() {
			return u, nil
		}
		return nil, err
	}
	return u, nil
}

// proxyConfigured reports whether some deliberate hop is in the way.
//
// Not just Current(): proxyFor falls back to http.ProxyFromEnvironment, so an
// env-configured proxy is equally a hop the operator chose.
func proxyConfigured() bool {
	if Current() != "" {
		return true
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// guardControl is the TOCTOU re-check: it sees the address the kernel is ABOUT
// to connect to, not the one LookupIP returned a moment earlier.
func guardControl(p Policy) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip := net.ParseIP(host)
		if reason, blocked := blockedIP(p, ip); blocked {
			return &BlockedError{Target: address, Addr: host, Reason: reason}
		}
		return nil
	}
}

// GuardedClient is Client with the address policy applied at dial time.
func GuardedClient(p Policy, timeout time.Duration) *http.Client {
	t := Transport()
	// Only when we are dialling the DESTINATION ourselves. With a proxy set the
	// transport dials the PROXY, so Control would be inspecting the proxy's
	// address — and the common ForgePanel deployment is socks5://127.0.0.1:1080,
	// which every policy refuses. Installing this unconditionally takes every
	// outbound call down on exactly the deployments the proxy exists for, and
	// the outage looks identical to the censorship it defeats. Resolve-time
	// validation in GuardTarget still runs in that case.
	if !proxyConfigured() {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: guardControl(p)}
		// MUST overwrite: Transport() is a Clone of http.DefaultTransport and
		// already carries a DialContext, so a Dialer built and not assigned
		// leaves the hook dead while every resolve-time test still passes.
		t.DialContext = d.DialContext
	}
	return &http.Client{Transport: t, Timeout: timeout}
}

// GuardedClientVia is ClientVia with the address policy applied. A non-empty
// override is a deliberate hop, so it never installs the dial-time hook.
func GuardedClientVia(p Policy, proxyURL string, timeout time.Duration) (*http.Client, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return GuardedClient(p, timeout), nil
	}
	return ClientVia(proxyURL, timeout)
}

// MaxFetchBytes is the default ceiling on a fetched body. A remote that answers
// forever must cost the panel a bounded amount of memory.
const MaxFetchBytes = 4 << 20

// Fetch GETs a guarded target and returns at most limit bytes.
//
// It exists so that the next thing to fetch an operator-supplied URL — the
// panel-side subscription aggregation of FP-SUB-007 — reaches for this rather
// than reinventing a client without the guard, which is how every sink in this
// file got here.
func Fetch(ctx context.Context, p Policy, target string, limit int64) ([]byte, int, error) {
	u, err := GuardTarget(ctx, p, target)
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = MaxFetchBytes
	}
	client := GuardedClient(p, 30*time.Second)
	// A redirect is a second target the operator did not type, so it gets the
	// same check. Without this, a public URL that 302s to 169.254.169.254 walks
	// straight past everything above.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("%s redirected more than 5 times", target)
		}
		_, err := GuardTarget(req.Context(), p, req.URL.String())
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	// limit+1 so an oversized body is an ERROR rather than a silent truncation:
	// a subscription list cut off mid-entry parses as a shorter valid list, and
	// the operator is never told half their nodes went missing.
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(b)) > limit {
		return nil, resp.StatusCode, fmt.Errorf("%s returned more than %d bytes", target, limit)
	}
	return b, resp.StatusCode, nil
}
