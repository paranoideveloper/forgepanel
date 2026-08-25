package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/parse"
)

// BrookOptions.UDPOverTCP was stored, accepted from JSON, and emitted by
// NOTHING. A client configured for it silently ran plain UDP — which is exactly
// the case where UDP does not survive the network in between, and the whole
// reason the setting exists.
//
// The parameter name and value are taken from the pinned brook binary's own
// output, `brook link -s 1.2.3.4:9999 -p pw --udpovertcp`, which prints:
//
//	brook://server?password=pw&server=1.2.3.4%3A9999&udpovertcp=true
func TestBrookUDPOverTCPReachesTheLink(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoBrook, Address: "203.0.113.9", Port: 9999,
		Password: "pw", Remark: "b",
		Brook: &model.BrookOptions{Mode: "server", UDPOverTCP: true},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "udpovertcp=true") {
		t.Fatalf("link = %q, want udpovertcp=true", uri)
	}

	// And it must survive a round trip, or importing a link the panel exported
	// quietly drops the setting again.
	back, err := parse.URI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if back.Brook == nil || !back.Brook.UDPOverTCP {
		t.Fatalf("round trip lost udpovertcp: %+v", back.Brook)
	}
}

func TestBrookWithoutUDPOverTCPOmitsIt(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoBrook, Address: "203.0.113.9", Port: 9999,
		Password: "pw", Brook: &model.BrookOptions{Mode: "server"},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	// brook's own output omits the parameter entirely when the flag is off;
	// emitting udpovertcp=false would be a gratuitous difference from the links
	// every other brook tool produces.
	if strings.Contains(uri, "udpovertcp") {
		t.Fatalf("link = %q, want no udpovertcp parameter at all", uri)
	}
}
