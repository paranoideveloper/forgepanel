package adapter

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
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

func TestEncodeQueryAndDecodeAnswer(t *testing.T) {
	frame := codec.Frame{
		SessionID: 0x1234,
		Seq:       1,
		Flags:     codec.FlagACK,
		Payload:   []byte("test payload"),
	}

	zone := "example.com."
	msg, err := EncodeQuery(zone, frame)
	if err != nil {
		t.Fatalf("EncodeQuery failed: %v", err)
	}
	if len(msg.Question) == 0 {
		t.Fatal("EncodeQuery returned empty question")
	}

	// Test Forge adapter Encode and DecodeAnswer
	forge := &Forge{}
	resp, err := forge.Encode("example.com", msg, frame)
	if err != nil {
		t.Fatalf("Forge.Encode failed: %v", err)
	}

	decoded, err := DecodeAnswer(resp)
	if err != nil {
		t.Fatalf("DecodeAnswer failed: %v", err)
	}
	if decoded.SessionID != frame.SessionID || string(decoded.Payload) != string(frame.Payload) {
		t.Fatalf("Decoded frame mismatch: %+v vs %+v", decoded, frame)
	}

	// Test DecodeAnswer with no TXT
	noTXTMsg := new(dns.Msg)
	noTXTMsg.Answer = append(noTXTMsg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
	})
	if _, err := DecodeAnswer(noTXTMsg); err == nil {
		t.Fatal("expected error from DecodeAnswer with no TXT RR")
	}
}

func TestNamedAdapterMatch(t *testing.T) {
	ad, err := Get("cottendns")
	if err != nil {
		t.Fatal(err)
	}

	q := new(dns.Msg)
	q.SetQuestion("t0.example.com.", dns.TypeTXT)
	if !ad.Match("example.com", q) {
		t.Fatal("expected cottendns Match to return true for matching zone")
	}

	qBad := new(dns.Msg)
	qBad.SetQuestion("t0.otherdomain.com.", dns.TypeTXT)
	if ad.Match("example.com", qBad) {
		t.Fatal("expected Match to return false for non-matching zone")
	}
}
