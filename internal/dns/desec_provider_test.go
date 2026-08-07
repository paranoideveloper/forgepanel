package dns

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestDesecVerifyAndAuthHeader(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 3600)

	ident, err := m.client().VerifyCredentials(context.Background())
	requireNoError(t, err)
	requireContains(t, ident.Detail, "1 domain", "identity detail")
	if m.AuthHeader != "Token desec-token" {
		t.Fatalf("expected the Token scheme, got %q", m.AuthHeader)
	}
}

func TestDesecFindZoneReportsFixedNameservers(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 3600)
	z, err := m.client().FindZone(context.Background(), "example.com")
	requireNoError(t, err)
	if len(z.NameServers) != 2 || z.NameServers[0] != "ns1.desec.io" {
		t.Fatalf("unexpected nameservers: %+v", z.NameServers)
	}
	if z.MinimumTTL != 3600 {
		t.Fatalf("expected the minimum TTL to be reported, got %d", z.MinimumTTL)
	}
	if !z.Active() {
		t.Fatal("a listed deSEC domain should count as active")
	}
}

func TestDesecRecordCRUDUsesRRsetSemantics(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	c := m.client()
	ctx := context.Background()

	created, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", TTL: 120,
	})
	requireNoError(t, err)
	if created.ID != "ws/A" {
		t.Fatalf("expected the synthetic subname/TYPE id, got %q", created.ID)
	}
	if created.Name != "ws.example.com" {
		t.Fatalf("expected the name to be re-qualified, got %q", created.Name)
	}

	list, err := c.ListRecords(ctx, "example.com", RecordFilter{Type: TypeA, Name: "ws.example.com"})
	requireNoError(t, err)
	if len(list) != 1 || list[0].Content != "203.0.113.10" {
		t.Fatalf("unexpected list: %+v", list)
	}

	updated, err := c.UpdateRecord(ctx, "example.com", "ws/A", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.99", TTL: 120,
	})
	requireNoError(t, err)
	if updated.Content != "203.0.113.99" {
		t.Fatalf("unexpected update: %+v", updated)
	}

	requireNoError(t, c.DeleteRecord(ctx, "example.com", "ws/A"))
	list, err = c.ListRecords(ctx, "example.com", RecordFilter{})
	requireNoError(t, err)
	if len(list) != 0 {
		t.Fatalf("expected the RRset to be gone, got %+v", list)
	}
	// Deleting again must be a no-op, not a failure.
	requireNoError(t, c.DeleteRecord(ctx, "example.com", "ws/A"))
}

// deSEC stores presentation format: TXT quoted, targets trailing-dotted, SRV
// and MX as space-separated fields.
func TestDesecPresentationFormatRoundTrip(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	c := m.client()
	ctx := context.Background()

	txt, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeTXT, Name: "_acme-challenge.example.com", Content: "abc123", TTL: 60,
	})
	requireNoError(t, err)
	if txt.Content != "abc123" {
		t.Fatalf("expected the TXT value to be unquoted on read, got %q", txt.Content)
	}
	m.mu.Lock()
	stored := m.RRsets["example.com"]["_acme-challenge/TXT"].Records[0]
	m.mu.Unlock()
	if stored != `"abc123"` {
		t.Fatalf("expected the stored TXT to be quoted, got %q", stored)
	}

	cname, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeCNAME, Name: "cdn.example.com", Content: "edge.example.net", TTL: 60,
	})
	requireNoError(t, err)
	if cname.Content != "edge.example.net" {
		t.Fatalf("expected the CNAME target to lose its trailing dot on read, got %q", cname.Content)
	}
	m.mu.Lock()
	storedCNAME := m.RRsets["example.com"]["cdn/CNAME"].Records[0]
	m.mu.Unlock()
	if storedCNAME != "edge.example.net." {
		t.Fatalf("expected the stored CNAME to be fully qualified, got %q", storedCNAME)
	}

	srv, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeSRV, Name: "_grpc._tcp.example.com", TTL: 60,
		SRV: &SRVData{Priority: 10, Weight: 5, Port: 443, Target: "edge.example.com"},
	})
	requireNoError(t, err)
	if srv.SRV == nil || srv.SRV.Port != 443 || srv.SRV.Priority != 10 {
		t.Fatalf("SRV did not round-trip: %+v", srv.SRV)
	}

	mx, err := c.CreateRecord(ctx, "example.com", Record{
		Type: TypeMX, Name: "example.com", Content: "mail.example.com", Priority: 10, TTL: 60,
	})
	requireNoError(t, err)
	if mx.Priority != 10 || mx.Content != "mail.example.com" {
		t.Fatalf("MX did not round-trip: %+v", mx)
	}
}

// deSEC clamps TTLs to the domain minimum; the client must retry at that
// minimum rather than leaving the operator to work it out.
func TestDesecRetriesAtDomainMinimumTTL(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 3600)
	created, err := m.client().CreateRecord(context.Background(), "example.com", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", TTL: 120,
	})
	requireNoError(t, err)
	if created.TTL != 3600 {
		t.Fatalf("expected the TTL to be raised to the domain minimum 3600, got %d", created.TTL)
	}
}

// deSEC has no CDN at all; asking for a proxied record must be a clear
// unsupported error, not a confusing provider rejection.
func TestDesecRejectsProxied(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	_, err := m.client().CreateRecord(context.Background(), "example.com", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", Proxied: true,
	})
	e := requireKind(t, err, KindUnsupported)
	requireContains(t, e.Remediation, "REALITY", "proxied remediation mentions the case where that is fine")
}

func TestDesecHonoursRetryAfterOn429(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	m.Throttle429 = 1
	slept := []time.Duration{}
	c := m.client()
	c.Sleep = func(d time.Duration) { slept = append(slept, d) }

	zones, err := c.ListZones(context.Background())
	requireNoError(t, err)
	if len(zones) != 1 {
		t.Fatalf("expected the retry to succeed, got %d zones", len(zones))
	}
	if len(slept) != 1 || slept[0] != time.Second {
		t.Fatalf("expected one 1s backoff from Retry-After, got %v", slept)
	}
}

func TestDesecExhaustedRetriesReportsRateLimit(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	m.Throttle429 = 10
	c := m.client()
	c.Sleep = func(time.Duration) {}

	_, err := c.ListZones(context.Background())
	e := requireKind(t, err, KindRateLimit)
	requireContains(t, e.Remediation, "Retry-After: 1s", "rate limit remediation quotes the header")
}

func TestDesecErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		detail string
		want   Kind
		needle string
	}{
		{"forbidden", http.StatusForbidden, "You do not have permission.", KindPermission, "restricted to other subnets"},
		{"not found", http.StatusNotFound, "Not found.", KindNotFound, "desec.io/domains"},
		{"validation", http.StatusBadRequest, "Malformed record content.", KindValidation, "must be quoted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newDesecMock(t)
			m.addDomain("example.com", 60)
			m.Status["GET /domains/"] = tc.status
			m.Detail["GET /domains/"] = tc.detail
			_, err := m.client().ListZones(context.Background())
			e := requireKind(t, err, tc.want)
			requireContains(t, e.Message, tc.detail, tc.name+" message")
			requireContains(t, e.Remediation, tc.needle, tc.name+" remediation")
		})
	}
}

func TestDesecBadTokenIsAuth(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	c := m.client()
	c.Token = "wrong"
	_, err := c.ListZones(context.Background())
	e := requireKind(t, err, KindAuth)
	requireContains(t, e.Remediation, "token value (not the token id)", "auth remediation")
}

func TestDesecRecordIDParsing(t *testing.T) {
	sub, rtype, err := parseRRsetID("ws/A")
	requireNoError(t, err)
	if sub != "ws" || rtype != "A" {
		t.Fatalf("unexpected parse: %q %q", sub, rtype)
	}
	sub, rtype, err = parseRRsetID("@/TXT")
	requireNoError(t, err)
	if sub != "" || rtype != "TXT" {
		t.Fatalf("expected @ to mean the apex, got %q %q", sub, rtype)
	}
	_, _, err = parseRRsetID("nonsense")
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "ws-node1/A", "record id remediation")
}

func TestNewDesecRequiresToken(t *testing.T) {
	_, err := NewDesec(Credentials{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "token", "missing credential message")
}
