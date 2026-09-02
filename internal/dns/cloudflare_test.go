package dns

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCloudflareVerifyToken_UserEndpoint(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()

	ident, err := c.VerifyCredentials(context.Background())
	requireNoError(t, err)
	if ident.TokenID != "tok-123" || ident.Status != "active" {
		t.Fatalf("unexpected identity: %+v", ident)
	}
	requireContains(t, ident.Detail, "1 zone", "identity detail")

	var hitUser bool
	for _, req := range m.Requests {
		if strings.HasPrefix(req, "GET /user/tokens/verify") {
			hitUser = true
		}
	}
	if !hitUser {
		t.Fatalf("expected the user token verify endpoint to be called, got %v", m.Requests)
	}
}

func TestCloudflareVerifyToken_AccountEndpoint(t *testing.T) {
	m := newCFMock(t)
	m.AccountID = "acct-9"
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	c.AccountID = "acct-9"

	ident, err := c.VerifyCredentials(context.Background())
	requireNoError(t, err)
	if ident.AccountID != "acct-9" {
		t.Fatalf("expected the account id to be reported, got %+v", ident)
	}
	var hitAccount bool
	for _, req := range m.Requests {
		if strings.HasPrefix(req, "GET /accounts/acct-9/tokens/verify") {
			hitAccount = true
		}
	}
	if !hitAccount {
		t.Fatalf("expected the account token verify endpoint to be called, got %v", m.Requests)
	}
}

func TestCloudflareVerifyToken_WrongAccountExplainsItself(t *testing.T) {
	m := newCFMock(t)
	m.AccountID = "acct-9"
	c := m.client()
	c.AccountID = "acct-wrong"

	_, err := c.VerifyCredentials(context.Background())
	e := requireKind(t, err, KindNotFound)
	requireContains(t, e.Remediation, "acct-wrong", "wrong-account remediation")
	requireContains(t, e.Remediation, "omit --cf-account", "wrong-account remediation")
}

func TestCloudflareVerifyToken_InactiveIsAuthFailure(t *testing.T) {
	m := newCFMock(t)
	m.TokenStatus = "disabled"
	c := m.client()

	_, err := c.VerifyCredentials(context.Background())
	e := requireKind(t, err, KindAuth)
	requireContains(t, e.Message, "disabled", "inactive token message")
	requireContains(t, e.Remediation, "api-tokens", "inactive token remediation")
}

func TestCloudflareBadTokenIsAuthFailure(t *testing.T) {
	m := newCFMock(t)
	c := m.client()
	c.Token = "wrong"

	_, err := c.VerifyCredentials(context.Background())
	e := requireKind(t, err, KindAuth)
	if e.Status != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401, got %d", e.Status)
	}
	requireContains(t, e.Remediation, "without surrounding whitespace", "bad token remediation")
}

// Each scope-specific permission failure must name the exact Cloudflare
// permission the operator has to tick, in Cloudflare's own wording.
func TestCloudflarePermissionErrorsNameTheMissingScope(t *testing.T) {
	unauthorized := cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	t.Run("zone read", func(t *testing.T) {
		m := newCFMock(t)
		m.Deny["GET /zones"] = unauthorized
		_, err := m.client().ListZones(context.Background())
		e := requireKind(t, err, KindPermission)
		if e.MissingScope != ScopeZoneRead {
			t.Fatalf("expected missing scope %q, got %q", ScopeZoneRead, e.MissingScope)
		}
		requireContains(t, e.Remediation, "Zone Resources", "zone read remediation")
	})

	t.Run("dns read", func(t *testing.T) {
		m := newCFMock(t)
		m.addZone("zone1", "example.com", "active")
		m.Deny["GET /zones/zone1/dns_records"] = unauthorized
		_, err := m.client().ListRecords(context.Background(), "zone1", RecordFilter{})
		e := requireKind(t, err, KindPermission)
		if e.MissingScope != ScopeDNSRead {
			t.Fatalf("expected missing scope %q, got %q", ScopeDNSRead, e.MissingScope)
		}
	})

	t.Run("dns edit", func(t *testing.T) {
		m := newCFMock(t)
		m.addZone("zone1", "example.com", "active")
		m.Deny["POST /zones/zone1/dns_records"] = unauthorized
		_, err := m.client().CreateRecord(context.Background(), "zone1",
			Record{Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10"})
		e := requireKind(t, err, KindPermission)
		if e.MissingScope != ScopeDNSEdit {
			t.Fatalf("expected missing scope %q, got %q", ScopeDNSEdit, e.MissingScope)
		}
		requireContains(t, e.Remediation, "implies read", "dns edit remediation")
	})

	t.Run("ssl and certificates edit", func(t *testing.T) {
		m := newCFMock(t)
		m.addZone("zone1", "example.com", "active")
		m.Deny["PATCH /zones/zone1/settings/ssl"] = unauthorized
		strict := TLSFullStrict
		results, err := m.client().ApplyZoneSettings(context.Background(), "zone1", ZoneSettings{SSL: &strict})
		e := requireKind(t, err, KindPermission)
		if e.MissingScope != ScopeSSLEdit {
			t.Fatalf("expected missing scope %q, got %q", ScopeSSLEdit, e.MissingScope)
		}
		requireContains(t, e.Remediation, ScopeSettingsEdit, "ssl remediation names both scopes")
		if len(results) != 1 || results[0].Applied {
			t.Fatalf("expected one unapplied setting result, got %+v", results)
		}
	})

	t.Run("zone settings edit", func(t *testing.T) {
		m := newCFMock(t)
		m.addZone("zone1", "example.com", "active")
		m.Deny["PATCH /zones/zone1/settings/websockets"] = unauthorized
		on := true
		_, err := m.client().ApplyZoneSettings(context.Background(), "zone1", ZoneSettings{WebSockets: &on})
		e := requireKind(t, err, KindPermission)
		if e.MissingScope != ScopeSettingsEdit {
			t.Fatalf("expected missing scope %q, got %q", ScopeSettingsEdit, e.MissingScope)
		}
	})
}

func TestCloudflareListZonesFollowsPagination(t *testing.T) {
	m := newCFMock(t)
	m.PageSize = 2
	for i := 0; i < 5; i++ {
		m.addZone(fmt.Sprintf("zone%d", i), fmt.Sprintf("z%d.example", i), "active")
	}
	zones, err := m.client().ListZones(context.Background())
	requireNoError(t, err)
	if len(zones) != 5 {
		t.Fatalf("expected all 5 zones across 3 pages, got %d", len(zones))
	}
	pages := 0
	for _, req := range m.Requests {
		if strings.HasPrefix(req, "GET /zones?") {
			pages++
		}
	}
	if pages != 3 {
		t.Fatalf("expected 3 paginated requests, got %d (%v)", pages, m.Requests)
	}
}

func TestCloudflareFindZoneNotFoundExplainsSubdomains(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	_, err := m.client().FindZone(context.Background(), "other.test")
	e := requireKind(t, err, KindNotFound)
	requireContains(t, e.Remediation, "provisioning node.example.com works through the example.com zone", "find-zone remediation")
}

func TestCloudflareRecordCRUD(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	ctx := context.Background()

	created, err := c.CreateRecord(ctx, "zone1", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", TTL: 120, Proxied: true,
	})
	requireNoError(t, err)
	if created.ID == "" {
		t.Fatal("expected the created record to carry an id")
	}
	// A proxied record must be sent with ttl=1: Cloudflare rejects a custom TTL
	// on an orange-clouded record.
	if got := m.Records["zone1"][created.ID].TTL; got != 1 {
		t.Fatalf("expected a proxied record to be sent with ttl=1, got %d", got)
	}
	if !created.Proxied {
		t.Fatal("expected the created record to come back proxied")
	}

	list, err := c.ListRecords(ctx, "zone1", RecordFilter{Type: TypeA, Name: "ws.example.com"})
	requireNoError(t, err)
	if len(list) != 1 || list[0].Content != "203.0.113.10" {
		t.Fatalf("unexpected list result: %+v", list)
	}

	updated, err := c.UpdateRecord(ctx, "zone1", created.ID, Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.20", TTL: 120,
	})
	requireNoError(t, err)
	if updated.Content != "203.0.113.20" || updated.Proxied {
		t.Fatalf("unexpected update result: %+v", updated)
	}

	requireNoError(t, c.DeleteRecord(ctx, "zone1", created.ID))
	list, err = c.ListRecords(ctx, "zone1", RecordFilter{})
	requireNoError(t, err)
	if len(list) != 0 {
		t.Fatalf("expected the record to be gone, got %+v", list)
	}
}

func TestCloudflareSRVRecordUsesDataObject(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	created, err := m.client().CreateRecord(context.Background(), "zone1", Record{
		Type: TypeSRV, Name: "_grpc._tcp.example.com",
		SRV: &SRVData{Priority: 10, Weight: 5, Port: 443, Target: "edge.example.com"},
	})
	requireNoError(t, err)
	if created.SRV == nil {
		t.Fatalf("expected SRV data to round-trip, got %+v", created)
	}
	if created.SRV.Port != 443 || created.SRV.Target != "edge.example.com" {
		t.Fatalf("unexpected SRV data: %+v", created.SRV)
	}
}

func TestCloudflareEnsureRecordIsIdempotent(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	ctx := context.Background()
	rec := Record{Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", TTL: 120}

	first, err := EnsureRecord(ctx, c, "zone1", rec)
	requireNoError(t, err)
	if first.Action != "created" {
		t.Fatalf("expected the first ensure to create, got %q", first.Action)
	}

	second, err := EnsureRecord(ctx, c, "zone1", rec)
	requireNoError(t, err)
	if second.Action != "unchanged" {
		t.Fatalf("expected the second ensure to be a no-op, got %q", second.Action)
	}

	rec.Content = "203.0.113.99"
	third, err := EnsureRecord(ctx, c, "zone1", rec)
	requireNoError(t, err)
	if third.Action != "updated" || third.Record.Content != "203.0.113.99" {
		t.Fatalf("expected the third ensure to update, got %+v", third)
	}
	if len(m.Records["zone1"]) != 1 {
		t.Fatalf("expected exactly one record to exist, got %d", len(m.Records["zone1"]))
	}
}

func TestCloudflareDuplicateRecordIsConflict(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	ctx := context.Background()
	rec := Record{Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10"}
	_, err := c.CreateRecord(ctx, "zone1", rec)
	requireNoError(t, err)

	_, err = c.CreateRecord(ctx, "zone1", rec)
	e := requireKind(t, err, KindConflict)
	if e.Code != 81053 {
		t.Fatalf("expected Cloudflare code 81053, got %d", e.Code)
	}
	requireContains(t, e.Remediation, "upserts", "conflict remediation")
}

func TestCloudflareSetProxiedPreservesContent(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	ctx := context.Background()
	created, err := c.CreateRecord(ctx, "zone1", Record{
		Type: TypeA, Name: "ws.example.com", Content: "203.0.113.10", TTL: 300,
	})
	requireNoError(t, err)

	updated, err := c.SetProxied(ctx, "zone1", created.ID, true)
	requireNoError(t, err)
	if !updated.Proxied {
		t.Fatal("expected the record to come back proxied")
	}
	if updated.Content != "203.0.113.10" {
		t.Fatalf("expected the content to survive the proxy toggle, got %q", updated.Content)
	}
}

func TestCloudflareSetProxiedRejectsNonProxiableType(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	created, err := c.CreateRecord(context.Background(), "zone1", Record{
		Type: TypeTXT, Name: "_acme-challenge.example.com", Content: "token",
	})
	requireNoError(t, err)

	_, err = c.SetProxied(context.Background(), "zone1", created.ID, true)
	e := requireKind(t, err, KindUnsupported)
	requireContains(t, e.Remediation, "only A, AAAA and CNAME", "non-proxiable remediation")
}

func TestCloudflareApplyZoneSettings(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	c := m.client()
	ctx := context.Background()

	results, err := c.ApplyZoneSettings(ctx, "zone1", RecommendedZoneSettings())
	requireNoError(t, err)
	if len(results) != 6 {
		t.Fatalf("expected 6 settings to be pushed, got %d", len(results))
	}
	for _, r := range results {
		if !r.Applied {
			t.Fatalf("setting %q was not applied: %s", r.Setting, r.Error)
		}
	}
	if got := m.Settings["zone1"]["ssl"]; got != "strict" {
		t.Fatalf("expected the SSL mode to become strict, got %q", got)
	}
	if got := m.Settings["zone1"]["websockets"]; got != "on" {
		t.Fatalf("expected websockets on, got %q", got)
	}

	read, err := c.GetZoneSettings(ctx, "zone1")
	requireNoError(t, err)
	if read["min_tls_version"] != "1.2" || read["grpc"] != "on" {
		t.Fatalf("unexpected settings read-back: %+v", read)
	}
}

// A setting a plan does not offer must degrade to a per-setting explanation of
// the consequence rather than aborting the whole apply.
func TestCloudflareUnavailableSettingExplainsConsequence(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	delete(m.Settings["zone1"], "grpc")
	m.Deny["PATCH /zones/zone1/settings/grpc"] = cfMessage{Code: 1006, Message: "Unable to find setting grpc"}
	m.DenyStatus["PATCH /zones/zone1/settings/grpc"] = http.StatusNotFound

	results, err := m.client().ApplyZoneSettings(context.Background(), "zone1", RecommendedZoneSettings())
	requireNoError(t, err) // not a permission failure, so no error overall
	var grpc *SettingResult
	for i := range results {
		if results[i].Setting == "grpc" {
			grpc = &results[i]
		}
	}
	if grpc == nil || grpc.Applied {
		t.Fatalf("expected an unapplied grpc result, got %+v", results)
	}
	requireContains(t, grpc.Remediation, "gRPC inbound behind the orange cloud", "grpc consequence")
	applied := 0
	for _, r := range results {
		if r.Applied {
			applied++
		}
	}
	if applied != 5 {
		t.Fatalf("expected the other 5 settings to still apply, got %d", applied)
	}
}

func TestCloudflareRateLimitIsRetryable(t *testing.T) {
	m := newCFMock(t)
	m.Deny["GET /zones"] = cfMessage{Code: 971, Message: "You are being rate limited"}
	m.DenyStatus["GET /zones"] = http.StatusTooManyRequests

	_, err := m.client().ListZones(context.Background())
	e := requireKind(t, err, KindRateLimit)
	if !IsRetryable(err) {
		t.Fatal("expected a rate-limit error to be retryable")
	}
	requireContains(t, e.Remediation, "1200 requests", "rate limit remediation")
}

func TestCloudflareUnreachableAPIIsNetworkError(t *testing.T) {
	c := &Cloudflare{Token: "t", BaseURL: "http://127.0.0.1:1/client/v4", MaxRetries: 0}
	_, err := c.ListZones(context.Background())
	e := requireKind(t, err, KindNetwork)
	requireContains(t, e.Remediation, "outbound HTTPS", "network remediation")
	if !IsRetryable(err) {
		t.Fatal("expected a network error to be retryable")
	}
}

func TestNewCloudflareRequiresToken(t *testing.T) {
	_, err := NewCloudflare(Credentials{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Message, "api_token", "missing credential message")
}
