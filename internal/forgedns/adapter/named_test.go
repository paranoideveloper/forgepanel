package adapter

import (
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/miekg/dns"
	"testing"
)

func TestNamedAdaptersRegistered(t *testing.T) {
	for _, n := range Names() {
		if _, err := Get(n); err != nil {
			t.Fatalf("%s not registered: %v", n, err)
		}
	}
	if _, err := Get("nope"); err == nil {
		t.Fatal("unknown adapter must error")
	}
}
func TestVariantDownstreamEncodings(t *testing.T) {
	zone := "t.example.com"
	for _, name := range []string{"stormdns", "masterdns", "cottendns"} {
		ad, _ := Get(name)
		f := codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagACK | codec.FlagDATA, Payload: []byte("hi")}
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("abc."+zone), dns.TypeTXT)
		resp, err := ad.Encode(zone, q, f)
		if err != nil {
			t.Fatalf("%s encode: %v", name, err)
		}
		if len(resp.Answer) == 0 {
			t.Fatalf("%s produced no answer", name)
		}
	}
}
