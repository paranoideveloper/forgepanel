package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// End-to-end proof that the fancy wizard's fronting + naming produces a link
// that actually carries the camouflage domain (as host + sni) and the styled
// remark. The URI structure itself is proven core-valid by the golden guard;
// ApplyFront only changes the host/sni VALUES, so a fronted node stays valid.
func TestFancyFront_XHTTPRealityURI(t *testing.T) {
	n := &model.Node{
		Protocol:  model.ProtoVLESS,
		Address:   "203.0.113.13",
		Port:      8443,
		UUID:      "11111111-2222-3333-4444-555555555555",
		Transport: model.Transport{Network: model.NetXHTTP, Path: "/aux"},
		Security: model.Security{
			Type: model.SecReality, ServerName: "www.datadoghq.com", Fingerprint: "chrome",
			// The fronting domain is in serverNames, because it has to be.
			// ApplyFront changes the SNI on the EXPORT copy only — the stored
			// inbound, and therefore the running server, keeps whatever
			// serverNames the operator configured. REALITY accepts a ClientHello
			// only if its SNI is in that list, so fronting a REALITY inbound
			// behind a domain the server does not accept produces a link that
			// cannot connect. This test used to omit it and assert the link
			// carried an SNI the server would refuse.
			Reality: &model.Reality{
				Dest:        "www.datadoghq.com:443",
				ServerNames: []string{"www.datadoghq.com", "nobat.com"},
			},
		},
	}
	th, ok := model.FancyThemeByID("nobat-xhttp")
	if !ok {
		t.Fatal("theme nobat-xhttp missing")
	}
	model.ApplyFront(n, "nobat.com", th.Front)
	n.Remark = model.ExpandNameTemplate(th.Template, model.NameFields{Name: "s7"})

	uri, err := URI(n)
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	if !strings.HasPrefix(uri, "vless://") {
		t.Fatalf("not a vless link: %s", uri)
	}
	for _, want := range []string{"host=nobat.com", "sni=nobat.com", "type=xhttp"} {
		if !strings.Contains(uri, want) {
			t.Errorf("fronted link missing %q:\n%s", want, uri)
		}
	}
	// The real address must survive so the client still reaches the server.
	if !strings.Contains(uri, "@203.0.113.13:8443") {
		t.Errorf("real dial address lost:\n%s", uri)
	}
	// The fancy remark rides in the fragment (url-encoded).
	if !strings.Contains(uri, "nobat-xhttp") {
		t.Errorf("fancy remark missing from fragment:\n%s", uri)
	}
}

// CDN mode over a plaintext VMess-WS node sets the Host header to the fronting
// domain without inventing TLS (the taskulu.com pattern).
func TestFancyFront_VMessCDNHostOnly(t *testing.T) {
	n := &model.Node{
		Protocol:  model.ProtoVMess,
		Address:   "s3.example.org",
		Port:      2053,
		UUID:      "11111111-2222-3333-4444-555555555555",
		Transport: model.Transport{Network: model.NetWS, Path: "/vm"},
		Security:  model.Security{Type: model.SecNone},
	}
	th, _ := model.FancyThemeByID("taskulu-ws")
	model.ApplyFront(n, "taskulu.com", th.Front)
	n.Remark = model.ExpandNameTemplate(th.Template, model.NameFields{Name: "s3"})

	uri, err := URI(n)
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	if n.Transport.Host != "taskulu.com" {
		t.Fatalf("CDN Host not set: %q", n.Transport.Host)
	}
	if n.Security.Type != model.SecNone {
		t.Fatalf("CDN mode must not add TLS, got %v", n.Security.Type)
	}
	if !strings.HasPrefix(uri, "vmess://") {
		t.Fatalf("not a vmess link: %s", uri)
	}
}
