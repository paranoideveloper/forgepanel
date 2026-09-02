package domain

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeResolver struct {
	hosts map[string][]string
	cname map[string]string
}

func (f fakeResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	if ips, ok := f.hosts[h]; ok {
		return ips, nil
	}
	return nil, errors.New("NXDOMAIN")
}
func (f fakeResolver) LookupCNAME(_ context.Context, h string) (string, error) {
	if c, ok := f.cname[h]; ok {
		return c, nil
	}
	return h + ".", nil
}

func TestCheckMatchesIP(t *testing.T) {
	r := New(fakeResolver{hosts: map[string][]string{"panel.example.com": {"203.0.113.5"}}})
	now := time.Unix(1700000000, 0)
	h := r.Check(context.Background(), "panel.example.com", "203.0.113.5", now)
	if !h.MatchesIP || !h.Reachable {
		t.Fatalf("expected match+reachable, got %+v", h)
	}
	h2 := r.Check(context.Background(), "panel.example.com", "198.51.100.9", now)
	if h2.MatchesIP {
		t.Fatal("should not match a different IP")
	}
	h3 := r.Check(context.Background(), "missing.example.com", "203.0.113.5", now)
	if h3.Reachable || h3.Error == "" {
		t.Fatalf("NXDOMAIN should be unreachable with an error: %+v", h3)
	}
}

func TestNSDelegation(t *testing.T) {
	recs, err := NSDelegation("t.example.com", "203.0.113.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].Type != "A" || recs[0].Value != "203.0.113.5" || recs[0].Name != "ns1.example.com" {
		t.Fatalf("bad glue A record: %+v", recs[0])
	}
	if recs[1].Type != "NS" || recs[1].Name != "t.example.com" || recs[1].Value != "ns1.example.com" {
		t.Fatalf("bad NS record: %+v", recs[1])
	}
}

func TestNSDelegationCases(t *testing.T) {
	// The core regression: example.com must NOT yield ns1.com.
	recs, err := NSDelegation("example.com", "203.0.113.9")
	if err != nil {
		t.Fatalf("example.com: %v", err)
	}
	if recs[0].Name != "ns1.example.com" || recs[1].Value != "ns1.example.com" {
		t.Fatalf("example.com should delegate to ns1.example.com, got %+v", recs)
	}
	if recs[0].Name == "ns1.com" {
		t.Fatal("regression: produced ns1.com")
	}
	// Multi-label public suffix.
	recs, err = NSDelegation("example.co.uk", "203.0.113.9")
	if err != nil || recs[0].Name != "ns1.example.co.uk" {
		t.Fatalf("co.uk: %v %+v", err, recs)
	}
	// IPv6 => AAAA glue.
	recs, err = NSDelegation("example.com", "2001:db8::1")
	if err != nil || recs[0].Type != "AAAA" {
		t.Fatalf("ipv6 glue: %v %+v", err, recs)
	}
	// Uppercase + trailing dot normalize.
	recs, _ = NSDelegation("Example.COM.", "203.0.113.9")
	if recs[1].Name != "example.com" {
		t.Fatalf("normalize: %+v", recs)
	}
	// Invalid inputs.
	for _, bad := range []string{"", "com", "co.uk", "localhost"} {
		if _, err := NSDelegation(bad, "203.0.113.9"); err == nil {
			t.Fatalf("expected error for zone %q", bad)
		}
	}
	if _, err := NSDelegation("example.com", "not-an-ip"); err == nil {
		t.Fatal("expected error for bad IP")
	}
}
