package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The URI exporter reaches the security block directly and never goes through
// Node.SNI(), which is how the first version of this fix landed in a function
// the broken path does not call. The link is what the operator actually pastes
// into a client, so this asserts on the link.
//
// Measured on a live panel: an imported inbound with server_name=slashdot.org
// and serverNames=[www.cloudflare.com] produced a link that failed with "reality
// verification failed", while the identical client with www.cloudflare.com
// connected immediately.
func TestRealityLinkCarriesAnSNITheServerAccepts(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.5", Port: 443,
		UUID: "972f1d1c-08e5-4485-a888-65688b5c7557", Flow: "xtls-rprx-vision",
		Security: model.Security{
			Type: model.SecReality, ServerName: "slashdot.org", Fingerprint: "firefox",
			Reality: &model.Reality{
				Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
				PublicKey: "GfOmSfw8Xx1eSuVdvjJgh0OS6dGKWNZ89KYF9SXwWQw", ShortID: "fd55b698ee8c3629",
			},
		},
	}
	n.Normalize()
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "sni=slashdot.org") {
		t.Errorf("the link advertises an SNI the server refuses; it cannot connect:\n%s", uri)
	}
	if !strings.Contains(uri, "sni=www.cloudflare.com") {
		t.Errorf("the link does not carry a server name this inbound accepts:\n%s", uri)
	}
}

// An SNI the server DOES accept is the operator's choice and must survive.
func TestRealityLinkKeepsAnAcceptedServerName(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.5", Port: 443,
		UUID: "972f1d1c-08e5-4485-a888-65688b5c7557",
		Security: model.Security{
			Type: model.SecReality, ServerName: "www.microsoft.com",
			Reality: &model.Reality{
				ServerNames: []string{"www.cloudflare.com", "www.microsoft.com"},
				PublicKey:   "GfOmSfw8Xx1eSuVdvjJgh0OS6dGKWNZ89KYF9SXwWQw", ShortID: "fd55b698ee8c3629",
			},
		},
	}
	n.Normalize()
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "sni=www.microsoft.com") {
		t.Errorf("the operator's own server name was replaced:\n%s", uri)
	}
}
