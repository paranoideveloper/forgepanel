package adapter

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAdapter_ForgeAndNamed(t *testing.T) {
	forge := &Forge{}
	if forge.Name() != "forge" {
		t.Fatalf("unexpected adapter name: %s", forge.Name())
	}

	caps := forge.Caps()
	if caps.MaxUpstreamBytes == 0 {
		t.Fatalf("empty caps")
	}

	msg := new(dns.Msg)
	msg.SetQuestion("t0.example.com.", dns.TypeTXT)
	_ = forge.Match("example.com", msg)

	// Get named adapter
	ad, err := Get("cottendns")
	if err != nil || ad == nil {
		t.Fatalf("Get cottendns failed: %v", err)
	}

	all := Names()
	if len(all) == 0 {
		t.Fatalf("empty Names()")
	}
}

func TestAdapter_VariantEncodings(t *testing.T) {
	adapters := []string{"stormdns", "masterdns", "cottendns"}
	for _, name := range adapters {
		ad, err := Get(name)
		if err != nil || ad == nil {
			t.Fatalf("Get(%s) failed: %v", name, err)
		}
		if ad.Name() != name {
			t.Fatalf("unexpected name: %s", ad.Name())
		}
		caps := ad.Caps()
		if caps.Name != name {
			t.Fatalf("caps name mismatch: %s != %s", caps.Name, name)
		}

		q := new(dns.Msg)
		q.SetQuestion("t0.example.com.", dns.TypeTXT)
		_, _ = ad.Decode("example.com", q)
	}

	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent adapter")
	}
}
