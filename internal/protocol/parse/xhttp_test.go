package parse

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// fullXHTTPTransport is the client-visible half of the modern XHTTP field set:
// what a share link can carry, and therefore what a link must round-trip.
func fullXHTTPTransport() model.Transport {
	return model.Transport{
		Network: model.NetXHTTP, Path: "/xh", Host: "edge.example.com",
		Headers:   map[string]string{"X-Real-IP": "198.51.100.7"},
		XHTTPMode: model.XHTTPModePacketUp, XPaddingB: "100-1000",
		XPaddingObfsMode: true, XPaddingKey: "x_padding", XPaddingHeader: "X-Padding",
		XPaddingPlacement: "queryInHeader", XPaddingMethod: "tokenish",
		NoGRPCHeader: true, NoSSEHeader: true,
		SCMaxEachPostBytes: "1000000", SCMinPostsIntervalMs: "30",
		SessionPlacement: "header", SessionKey: "x_session",
		SeqPlacement: "cookie", SeqKey: "x_seq",
		UplinkDataPlacement: "cookie", UplinkDataKey: "x_data",
		UplinkHTTPMethod: "GET", UplinkChunkSize: 8192,
		XMux: &model.XMux{MaxConcurrency: "16-32", CMaxReuseTimes: "64-128",
			HMaxRequestTime: "800-900", HMaxReusableSecs: "1800-3000", HKeepAlivePeriod: 45},
		XHTTPDownload: &model.XHTTPDownload{
			Address: "dl.example.com", Port: 8443,
			Transport: model.Transport{Network: model.NetXHTTP, Path: "/dl", Host: "dl.example.com",
				XHTTPMode: model.XHTTPModeStreamUp},
			Security: model.Security{Type: model.SecTLS, ServerName: "dl.example.com", Fingerprint: "chrome"},
		},
	}
}

// xhttpLink builds the share link for a transport the way an exporter does:
// path/host/mode as plain parameters and the rest in the `extra` payload.
func xhttpLink(tr model.Transport) string {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "tls")
	v.Set("sni", "edge.example.com")
	v.Set("path", tr.Path)
	v.Set("host", tr.Host)
	v.Set("mode", tr.XHTTPMode)
	if extra := tr.XHTTPExtra(); extra != "" {
		v.Set("extra", extra)
	}
	return "vless://" + testUUID + "@203.0.113.10:443?" + v.Encode() + "#xh"
}

// TestParseXHTTPExtendedRoundTrip: a link carrying the full client-visible XHTTP
// field set must parse back into the same transport. Before the extended set was
// modelled, everything but path/host/mode was silently dropped on import, so a
// node imported from a link lost its CDN tuning.
func TestParseXHTTPExtendedRoundTrip(t *testing.T) {
	want := fullXHTTPTransport()
	(&model.Node{Protocol: model.ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: want}).Normalize()

	n := mustURI(t, xhttpLink(want))
	if n.Transport.Network != model.NetXHTTP {
		t.Fatalf("network = %q", n.Transport.Network)
	}
	if !reflect.DeepEqual(n.Transport, want) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", n.Transport, want)
	}
}

// TestExportParseXHTTPRoundTrip is the spec §15 property applied to the modern
// XHTTP field set: parse(export(x)) == x. It goes through the real exporter, so
// it fails if either half of the codec forgets a knob.
func TestExportParseXHTTPRoundTrip(t *testing.T) {
	src := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.10", Port: 443, UUID: testUUID,
		Remark: "xhttp-full", Transport: fullXHTTPTransport(),
		Security: model.Security{Type: model.SecTLS, ServerName: "edge.example.com", Fingerprint: "chrome"},
	}
	src.Normalize()
	link, err := export.URI(src)
	if err != nil {
		t.Fatalf("export.URI: %v", err)
	}
	got := mustURI(t, link)
	if !reflect.DeepEqual(got.Transport, src.Transport) {
		t.Fatalf("export/parse lost xhttp data:\nlink %s\n got %+v\nwant %+v", link, got.Transport, src.Transport)
	}
}

// TestParseXHTTPIndividualParams: panels that spell the knobs out as separate
// camelCase query parameters (instead of one `extra` blob) must import too.
func TestParseXHTTPIndividualParams(t *testing.T) {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "none")
	v.Set("path", "/sp")
	v.Set("mode", "stream-up")
	v.Set("xPaddingBytes", "200-800")
	v.Set("noSSEHeader", "true")
	v.Set("noGRPCHeader", "1")
	v.Set("scMaxEachPostBytes", "2000000")
	v.Set("scMinPostsIntervalMs", "60")
	v.Set("sessionPlacement", "cookie")
	v.Set("sessionKey", "sid")
	v.Set("seqPlacement", "query")
	v.Set("seqKey", "sq")
	v.Set("uplinkHTTPMethod", "PUT")
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?"+v.Encode())

	tr := n.Transport
	if tr.XPaddingB != "200-800" || !tr.NoSSEHeader || !tr.NoGRPCHeader ||
		tr.SCMaxEachPostBytes != "2000000" || tr.SCMinPostsIntervalMs != "60" ||
		tr.SessionPlacement != "cookie" || tr.SessionKey != "sid" ||
		tr.SeqPlacement != "query" || tr.SeqKey != "sq" || tr.UplinkHTTPMethod != "PUT" {
		t.Fatalf("extended params not imported: %+v", tr)
	}
}

// TestParseXHTTPLegacySessionAliases: links minted before the core renamed the
// session parameters carry sessionIDPlacement/sessionIDKey. Dropping them would
// change where the session id rides and break the tunnel.
func TestParseXHTTPLegacySessionAliases(t *testing.T) {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "none")
	v.Set("sessionIDPlacement", "header")
	v.Set("sessionIDKey", "legacy_sid")
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?"+v.Encode())
	if n.Transport.SessionPlacement != "header" || n.Transport.SessionKey != "legacy_sid" {
		t.Fatalf("legacy session aliases not honoured: %+v", n.Transport)
	}
}

// TestParseXHTTPExplicitParamWinsOverExtra: a link may carry a stale `extra`
// blob plus a corrected parameter; the parameter is what the operator edited.
func TestParseXHTTPExplicitParamWinsOverExtra(t *testing.T) {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "none")
	v.Set("extra", `{"xPaddingBytes":"1-2","noSSEHeader":true}`)
	v.Set("xPaddingBytes", "500-900")
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?"+v.Encode())
	if n.Transport.XPaddingB != "500-900" {
		t.Errorf("xPaddingBytes = %q, want the explicit parameter to win", n.Transport.XPaddingB)
	}
	if !n.Transport.NoSSEHeader {
		t.Error("the rest of the extra payload must still apply")
	}
}

// TestParseXHTTPMalformedExtraIsNotFatal: one truncated blob in a subscription
// must not cost the operator the whole node.
func TestParseXHTTPMalformedExtraIsNotFatal(t *testing.T) {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "none")
	v.Set("path", "/keepme")
	v.Set("extra", `{"xPaddingBytes":`)
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?"+v.Encode())
	if n.Transport.Path != "/keepme" || n.Transport.Network != model.NetXHTTP {
		t.Fatalf("a malformed extra payload cost us the node: %+v", n.Transport)
	}
}

// TestParseXHTTPSnakeCasePaddingAlias covers the x_padding_bytes spelling some
// panels emit.
func TestParseXHTTPSnakeCasePaddingAlias(t *testing.T) {
	v := url.Values{}
	v.Set("type", "xhttp")
	v.Set("security", "none")
	v.Set("x_padding_bytes", "10-20")
	n := mustURI(t, "vless://"+testUUID+"@1.2.3.4:443?"+v.Encode())
	if n.Transport.XPaddingB != "10-20" {
		t.Errorf("x_padding_bytes = %q", n.Transport.XPaddingB)
	}
}
