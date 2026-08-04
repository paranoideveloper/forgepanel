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
	recs := NSDelegation("t.example.com", "203.0.113.5")
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
