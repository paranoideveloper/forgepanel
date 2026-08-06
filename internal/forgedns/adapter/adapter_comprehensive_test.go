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
