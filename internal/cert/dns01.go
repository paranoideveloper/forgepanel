package cert

// DNS-01 issuance, and with it wildcard certificates.
//
// The panel already offered this everywhere except where it counts: the config
// file takes `acme.challenge: dns-01`, the status endpoint reports it back, the
// wizard selects it, forgectl defaults its preflight to it, and the HTTP-01
// preflight's own remediation text tells an operator to "use a dns-01 challenge
// instead". Nothing issued one. autocert — which is what the panel's Store is
// built on — speaks HTTP-01 and TLS-ALPN-01 only, so the setting was accepted,
// echoed back, and silently ignored; issuance kept trying HTTP-01 and kept
// failing for the operator whose port 80 is blocked, which is the entire reason
// they chose dns-01.
//
// It is also the only way to get a wildcard: Let's Encrypt will not issue
// *.example.com against an HTTP-01 or TLS-ALPN-01 challenge, by policy.
//
// This is written directly against golang.org/x/crypto/acme rather than through
// autocert, because autocert has no DNS-01 seam to extend.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Solver publishes and retracts the TXT records an ACME DNS-01 challenge needs.
//
// Present must ADD a record, never replace one at the same name. This is not a
// stylistic preference: issuing a certificate for both example.com and
// *.example.com produces TWO authorizations whose challenges live at the SAME
// name, _acme-challenge.example.com, with DIFFERENT values, and the CA checks
// each of them. An upsert satisfies whichever was published last and fails the
// other, so the wildcard order dies with "incorrect TXT record" on a zone that
// looks correct by the time anyone goes to inspect it.
type Solver interface {
	// Present publishes value as a TXT record at fqdn, alongside any record
	// already there.
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes the record Present created. It is called for every
	// published record even when issuance failed, so it must tolerate a record
	// that is already gone.
	CleanUp(ctx context.Context, fqdn, value string) error
}

// TXTLookup reads the TXT records currently visible for a name. It is used only
// as a propagation gate before the CA is asked to look.
type TXTLookup func(ctx context.Context, fqdn string) ([]string, error)

// DNS01Options configures an issuance run.
type DNS01Options struct {
	// Solver publishes the challenge records. Required.
	Solver Solver
	// Email is the ACME account contact. Optional, but a CA can only warn you
	// about an expiring certificate if it has one.
	Email string
	// Staging points at Let's Encrypt's staging directory. Every code path
	// below is identical, which is the point: staging exists so a first run
	// cannot burn the production rate limit, and a limit reached is a multi-hour
	// lockout, not an error to retry.
	Staging bool
	// DirectoryURL overrides the ACME directory entirely (another CA, or a test
	// server). Takes precedence over Staging.
	DirectoryURL string
	// Lookup gates on propagation. When nil, issuance proceeds straight to the
	// CA — correct for a test double, wrong for a real zone.
	Lookup TXTLookup
	// PropagationTimeout bounds the wait for a published record to become
	// visible. Default 3 minutes.
	PropagationTimeout time.Duration
	// PollInterval is how often propagation is re-checked. Default 5 seconds.
	PollInterval time.Duration
	// now is injectable for tests.
	now func() time.Time
}

func (o *DNS01Options) fill() {
	if o.PropagationTimeout <= 0 {
		o.PropagationTimeout = 3 * time.Minute
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 5 * time.Second
	}
	if o.now == nil {
		o.now = time.Now
	}
}

func (o DNS01Options) directory() string {
	switch {
	case o.DirectoryURL != "":
		return o.DirectoryURL
	case o.Staging:
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	default:
		return acme.LetsEncryptURL
	}
}

// IssueDNS01 obtains a certificate for domains using the DNS-01 challenge and
// stores it so TLSConfig serves it.
//
// domains may include wildcards. The apex is NOT added automatically: a cert for
// *.example.com does not cover example.com (TLS wildcards match exactly one
// label), and silently widening the request would change what the operator asked
// the CA for.
func (s *Store) IssueDNS01(ctx context.Context, opts DNS01Options, domains ...string) (*Imported, error) {
	opts.fill()
	if opts.Solver == nil {
		return nil, errors.New("cert: DNS-01 issuance needs a solver to publish the challenge records")
	}
	names, err := normalizeDomains(domains)
	if err != nil {
		return nil, err
	}

	key, err := s.accountKey()
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: opts.directory()}

	acct := &acme.Account{}
	if opts.Email != "" {
		acct.Contact = []string{"mailto:" + opts.Email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("cert: ACME account registration failed: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, fmt.Errorf("cert: could not open an ACME order for %s: %w", strings.Join(names, ", "), err)
	}

	// Published records are cleaned up even when issuance fails. Leaving them
	// behind is not cosmetic: a stale _acme-challenge value is a record the CA
	// will read on the NEXT run and find stale, so one failed attempt makes the
	// following attempts fail too.
	var pubs []published
	defer func() {
		for _, p := range pubs {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_ = opts.Solver.CleanUp(cleanupCtx, p.fqdn, p.value)
			cancel()
		}
	}()

	var pending []*acme.Challenge
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("cert: could not read an ACME authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			// Already authorized from a previous run and still cached by the CA.
			continue
		}
		chal := dns01Challenge(authz)
		if chal == nil {
			return nil, fmt.Errorf("cert: the CA offered no dns-01 challenge for %q", authz.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("cert: could not compute the dns-01 record value: %w", err)
		}
		// The identifier for a wildcard authorization is the bare domain, with
		// Wildcard set — there is no "*." in it — so the challenge name is the
		// same for the wildcard and the apex. Both records must exist at once.
		fqdn := ChallengeName(authz.Identifier.Value)
		if err := opts.Solver.Present(ctx, fqdn, value); err != nil {
			return nil, fmt.Errorf("cert: could not publish the dns-01 record at %s: %w", fqdn, err)
		}
		pubs = append(pubs, published{fqdn, value})
		pending = append(pending, chal)
	}

	// Wait for every record to be visible BEFORE accepting any challenge.
	// Accepting early is the expensive mistake here: the CA checks immediately,
	// a miss marks the authorization invalid rather than retryable, and each
	// failed order counts against a rate limit measured in hours.
	if err := waitForPropagation(ctx, opts, pubs); err != nil {
		return nil, err
	}

	for _, chal := range pending {
		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("cert: the CA rejected a dns-01 challenge: %w", err)
		}
	}
	for _, authzURL := range order.AuthzURLs {
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("cert: dns-01 validation failed: %w", err)
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("cert: the ACME order did not become ready: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: could not generate a certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("cert: could not build the CSR: %w", err)
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("cert: the CA refused to issue: %w", err)
	}

	keyPEM, err := marshalECKey(certKey)
	if err != nil {
		return nil, err
	}
	var chain []byte
	for _, b := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	if err := s.saveDNS01(names[0], append(keyPEM, chain...)); err != nil {
		return nil, err
	}
	// Reuse the imported-cert path: it already matches wildcard SANs against SNI
	// correctly, and a DNS-01 certificate is served under exactly the same rules.
	return s.Import(chain, keyPEM)
}

// ChallengeName is the TXT record name an ACME DNS-01 challenge is published at.
// The leading "*." of a wildcard is stripped because the CA's authorization
// identifier carries the bare domain, and _acme-challenge.*.example.com is not a
// name that can exist.
func ChallengeName(domain string) string {
	d := strings.TrimPrefix(normalizeSNI(domain), "*.")
	return "_acme-challenge." + d
}

func dns01Challenge(a *acme.Authorization) *acme.Challenge {
	for _, c := range a.Challenges {
		if c.Type == "dns-01" {
			return c
		}
	}
	return nil
}

// published is one challenge record this run put into the zone.
type published struct{ fqdn, value string }

// waitForPropagation blocks until every published value is visible at its name.
func waitForPropagation(ctx context.Context, opts DNS01Options, pubs []published) error {
	if opts.Lookup == nil || len(pubs) == 0 {
		return nil
	}
	deadline := opts.now().Add(opts.PropagationTimeout)
	var lastMissing string
	for {
		missing := ""
		for _, p := range pubs {
			got, err := opts.Lookup(ctx, p.fqdn)
			if err != nil {
				missing = fmt.Sprintf("%s (lookup failed: %v)", p.fqdn, err)
				break
			}
			if !containsValue(got, p.value) {
				missing = p.fqdn
				break
			}
		}
		if missing == "" {
			return nil
		}
		lastMissing = missing
		if !opts.now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(opts.PollInterval):
		}
	}
	return fmt.Errorf("cert: the dns-01 record at %s was not visible after %s — "+
		"check that the zone is delegated to the provider holding this credential, "+
		"and that no CNAME at _acme-challenge points somewhere else",
		lastMissing, opts.PropagationTimeout)
}

func containsValue(got []string, want string) bool {
	for _, g := range got {
		if strings.TrimSpace(strings.Trim(g, `"`)) == want {
			return true
		}
	}
	return false
}

// normalizeDomains lowercases, de-duplicates and sorts the requested names, and
// rejects the shapes a CA will refuse anyway.
func normalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		n := normalizeSNI(d)
		if n == "" {
			continue
		}
		if strings.Count(n, "*") > 0 && !strings.HasPrefix(n, "*.") {
			return nil, fmt.Errorf("cert: %q is not a valid name — a wildcard may only be the left-most label, as in *.example.com", d)
		}
		if strings.HasPrefix(n, "*.") && strings.Contains(n[2:], "*") {
			return nil, fmt.Errorf("cert: %q has more than one wildcard label", d)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("cert: no domains were requested")
	}
	sort.Strings(out)
	return out, nil
}

// accountKey loads the ACME account key, generating it on first use.
//
// The key IS the account. Losing it does not lose the certificates, but it does
// orphan the registration — a new key is a new account, with its own fresh rate
// limits and no record of what was issued before.
func (s *Store) accountKey() (crypto.Signer, error) {
	if s.cacheDir == "" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	path := filepath.Join(s.cacheDir, "dns01-account.key")
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: could not generate an ACME account key: %w", err)
	}
	pemBytes, err := marshalECKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("cert: could not create the ACME cache directory: %w", err)
	}
	// 0600: the account key is a credential.
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("cert: could not save the ACME account key: %w", err)
	}
	return k, nil
}

func marshalECKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("cert: could not encode the key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// saveDNS01 persists the issued pair so it survives a restart. The filename
// keeps the wildcard's "*" escaped, since it is not portable in a path.
func (s *Store) saveDNS01(primary string, pemBytes []byte) error {
	if s.cacheDir == "" {
		return nil
	}
	dir := filepath.Join(s.cacheDir, "dns01")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cert: could not create the DNS-01 cache directory: %w", err)
	}
	name := strings.ReplaceAll(primary, "*", "_wildcard_")
	if err := os.WriteFile(filepath.Join(dir, name+".pem"), pemBytes, 0o600); err != nil {
		return fmt.Errorf("cert: could not save the issued certificate: %w", err)
	}
	return nil
}

// LoadDNS01Cache re-imports certificates issued by DNS-01 in an earlier run.
//
// Without this the panel would re-issue on every restart, which is how an
// operator discovers Let's Encrypt's duplicate-certificate limit: five per week
// for the same name set, then a week of nothing.
func (s *Store) LoadDNS01Cache() (int, error) {
	if s.cacheDir == "" {
		return 0, nil
	}
	dir := filepath.Join(s.cacheDir, "dns01")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("cert: could not read the DNS-01 cache: %w", err)
	}
	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		keyPEM, chainPEM := splitPEM(raw)
		if len(keyPEM) == 0 || len(chainPEM) == 0 {
			continue
		}
		if _, err := s.Import(chainPEM, keyPEM); err != nil {
			continue
		}
		loaded++
	}
	return loaded, nil
}

// splitPEM separates the leading private key from the certificate chain.
func splitPEM(raw []byte) (key, chain []byte) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return key, chain
		}
		encoded := pem.EncodeToMemory(block)
		if strings.Contains(block.Type, "PRIVATE KEY") {
			key = append(key, encoded...)
		} else if block.Type == "CERTIFICATE" {
			chain = append(chain, encoded...)
		}
	}
}
