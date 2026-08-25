package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// fullXHTTP is a transport carrying every modern XHTTP knob at once. The values
// are the ones verified to be accepted by the pinned Xray.
func fullXHTTP() Transport {
	return Transport{
		Network: NetXHTTP, Path: "/xh", Host: "edge.example.com",
		Headers:   map[string]string{"X-Real-IP": "1.2.3.4"},
		XHTTPMode: XHTTPModePacketUp, XPaddingB: "100-1000",
		XPaddingObfsMode: true, XPaddingKey: "x_padding", XPaddingHeader: "X-Padding",
		XPaddingPlacement: "queryInHeader", XPaddingMethod: "tokenish",
		NoGRPCHeader: true, NoSSEHeader: true,
		SCMaxEachPostBytes: "1000000", SCMinPostsIntervalMs: "30",
		SCMaxBufferedPosts: 30, SCStreamUpServerSecs: "20-80",
		SessionPlacement: "header", SessionKey: "x_session",
		SeqPlacement: "cookie", SeqKey: "x_seq",
		UplinkDataPlacement: "cookie", UplinkDataKey: "x_data",
		UplinkHTTPMethod: "GET", UplinkChunkSize: 8192,
		ServerMaxHeaderBytes: 16384,
		XMux: &XMux{MaxConcurrency: "16-32", CMaxReuseTimes: "64-128",
			HMaxRequestTime: "800-900", HMaxReusableSecs: "1800-3000", HKeepAlivePeriod: 45},
		XHTTPDownload: &XHTTPDownload{
			Address: "dl.example.com", Port: 443,
			Transport: Transport{Network: NetXHTTP, Path: "/dl", Host: "dl.example.com", XHTTPMode: XHTTPModeStreamOne},
			Security:  Security{Type: SecTLS, ServerName: "dl.example.com", Fingerprint: "chrome"},
		},
	}
}

// TestNormalizeKeepsFullXHTTPFieldSet: the whole modern field set must survive
// Normalize on an xhttp node. Before the field set was modelled, everything
// beyond mode/path/host/xmux was dropped on the floor here, which is why an
// operator's CDN tuning silently never reached the engine.
func TestNormalizeKeepsFullXHTTPFieldSet(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: fullXHTTP()}
	n.Normalize()
	got := n.Transport
	want := fullXHTTP()
	// Normalize canonicalizes the nested leg, so compare it separately.
	if got.XHTTPDownload == nil || got.XHTTPDownload.Address != "dl.example.com" ||
		got.XHTTPDownload.Transport.Path != "/dl" || got.XHTTPDownload.Security.Type != SecTLS {
		t.Fatalf("download leg lost in Normalize: %+v", got.XHTTPDownload)
	}
	got.XHTTPDownload, want.XHTTPDownload = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize changed the xhttp transport:\n got %+v\nwant %+v", got, want)
	}
}

// TestNormalizeClearsXHTTPFieldsOnOtherTransports: the extended knobs are xhttp
// only; leaving them set on a ws node would make two identical nodes compare
// unequal and would break the round-trip property test.
func TestNormalizeClearsXHTTPFieldsOnOtherTransports(t *testing.T) {
	tr := fullXHTTP()
	tr.Network = NetWS
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: tr}
	n.Normalize()
	got := n.Transport
	for _, f := range []string{"XHTTPMode", "XPaddingB", "XPaddingObfsMode", "XPaddingKey",
		"XPaddingHeader", "XPaddingPlacement", "XPaddingMethod", "NoGRPCHeader", "NoSSEHeader",
		"SCMaxEachPostBytes", "SCMinPostsIntervalMs", "SCMaxBufferedPosts", "SCStreamUpServerSecs",
		"SessionPlacement", "SessionKey", "SeqPlacement", "SeqKey", "UplinkDataPlacement",
		"UplinkDataKey", "UplinkHTTPMethod", "UplinkChunkSize", "ServerMaxHeaderBytes",
		"XMux", "XHTTPDownload"} {
		if !reflect.ValueOf(got).FieldByName(f).IsZero() {
			t.Errorf("ws kept xhttp-only field %s = %v", f, reflect.ValueOf(got).FieldByName(f))
		}
	}
}

// TestNormalizeCanonicalizesXHTTPEnums: the core compares these values byte for
// byte, so an operator typing "Stream-Up" or "HEADER" would otherwise get an
// engine that refuses to start.
func TestNormalizeCanonicalizesXHTTPEnums(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Transport: Transport{Network: NetXHTTP, XHTTPMode: " Stream-Up ",
			XPaddingObfsMode: true, XPaddingPlacement: "QUERYINHEADER", XPaddingMethod: "Repeat-X",
			SessionPlacement: "Header", SessionKey: "k", SeqPlacement: "COOKIE", SeqKey: "s",
			UplinkHTTPMethod: "put"}}
	n.Normalize()
	tr := n.Transport
	if tr.XHTTPMode != XHTTPModeStreamUp || tr.XPaddingPlacement != "queryInHeader" ||
		tr.XPaddingMethod != "repeat-x" || tr.SessionPlacement != "header" ||
		tr.SeqPlacement != "cookie" || tr.UplinkHTTPMethod != "PUT" {
		t.Fatalf("enums not canonicalized: %+v", tr)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("canonicalized node must validate: %v", err)
	}
}

// TestNormalizeDropsDeadXHTTPFields: a key whose placement does not read it is
// dead weight in the link and in the config, and makes equality unstable.
func TestNormalizeDropsDeadXHTTPFields(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Transport: Transport{Network: NetXHTTP,
			XPaddingObfsMode: false, XPaddingKey: "k", XPaddingHeader: "H",
			XPaddingPlacement: "header", XPaddingMethod: "tokenish",
			SessionPlacement: "path", SessionKey: "sess",
			SeqPlacement: "", SeqKey: "seq",
			UplinkDataPlacement: "body", UplinkDataKey: "data", UplinkChunkSize: 4096,
			XMux: &XMux{}}}
	n.Normalize()
	tr := n.Transport
	if tr.XPaddingKey != "" || tr.XPaddingHeader != "" || tr.XPaddingPlacement != "" || tr.XPaddingMethod != "" {
		t.Errorf("padding family kept with obfuscation off: %+v", tr)
	}
	if tr.SessionKey != "" || tr.SeqKey != "" {
		t.Errorf("session/seq keys kept for a placement that does not read them: %+v", tr)
	}
	if tr.UplinkDataKey != "" || tr.UplinkChunkSize != 0 {
		t.Errorf("uplink data key/chunk kept for body placement: %+v", tr)
	}
	if tr.XMux != nil {
		t.Errorf("an all-zero xmux must normalize to nil, got %+v", tr.XMux)
	}
}

// TestValidateXHTTPRejectsWhatTheCoreRejects. Every case below was confirmed to
// be refused by `xray run -test` against the pinned build; accepting it in the
// panel would hand the operator an engine that will not start.
func TestValidateXHTTPRejectsWhatTheCoreRejects(t *testing.T) {
	cases := []struct {
		name string
		tr   Transport
		want string
	}{
		{"unknown mode", Transport{Network: NetXHTTP, XHTTPMode: "burst"}, "unsupported mode"},
		{"xmux both strategies", Transport{Network: NetXHTTP,
			XMux: &XMux{MaxConcurrency: "16", MaxConnections: "8"}}, "cannot be combined"},
		{"download leg in stream-one", Transport{Network: NetXHTTP, XHTTPMode: XHTTPModeStreamOne,
			XHTTPDownload: &XHTTPDownload{Address: "d", Port: 443}}, "stream-one"},
		{"uplink header outside packet-up", Transport{Network: NetXHTTP, XHTTPMode: XHTTPModeStreamUp,
			UplinkDataPlacement: "header"}, "requires mode"},
		{"uplink GET outside packet-up", Transport{Network: NetXHTTP, XHTTPMode: XHTTPModeAuto,
			UplinkHTTPMethod: "GET"}, "GET requires mode"},
		{"padding placement path", Transport{Network: NetXHTTP, XPaddingObfsMode: true,
			XPaddingPlacement: "path"}, "xPaddingPlacement"},
		{"padding method unknown", Transport{Network: NetXHTTP, XPaddingObfsMode: true,
			XPaddingMethod: "sprinkle"}, "xPaddingMethod"},
		{"session placement unknown", Transport{Network: NetXHTTP, SessionPlacement: "body"}, "sessionPlacement"},
		{"seq placement unknown", Transport{Network: NetXHTTP, SeqPlacement: "body"}, "seqPlacement"},
		{"uplink data placement query", Transport{Network: NetXHTTP, XHTTPMode: XHTTPModePacketUp,
			UplinkDataPlacement: "query"}, "uplinkDataPlacement"},
		{"uplink method unknown", Transport{Network: NetXHTTP, UplinkHTTPMethod: "TRACE"}, "uplinkHTTPMethod"},
		{"padding range with spaces", Transport{Network: NetXHTTP, XPaddingB: "100 - 200"}, "xPaddingBytes"},
		{"post bytes not a number", Transport{Network: NetXHTTP, SCMaxEachPostBytes: "1e6"}, "scMaxEachPostBytes"},
		{"open-ended range", Transport{Network: NetXHTTP, SCMinPostsIntervalMs: "30-"}, "scMinPostsIntervalMs"},
		{"xmux range malformed", Transport{Network: NetXHTTP,
			XMux: &XMux{HMaxReusableSecs: "abc"}}, "hMaxReusableSecs"},
		{"download leg without address", Transport{Network: NetXHTTP,
			XHTTPDownload: &XHTTPDownload{Port: 443}}, "needs an address"},
		{"download leg bad port", Transport{Network: NetXHTTP,
			XHTTPDownload: &XHTTPDownload{Address: "d", Port: 0}}, "port must be"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: c.tr}
			err := n.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a config the core refuses")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestValidateAcceptsFullXHTTP guards against over-strict validation: the full
// verified-good field set must pass.
func TestValidateAcceptsFullXHTTP(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: fullXHTTP()}
	n.Normalize()
	if err := n.Validate(); err != nil {
		t.Fatalf("Validate rejected a config the core accepts: %v", err)
	}
}

// TestXHTTPExtraRoundTrip: the share-link `extra` payload must carry every
// client-relevant knob, including the nested xmux and download leg, so a node
// exported to a link and re-imported is the same node.
func TestXHTTPExtraRoundTrip(t *testing.T) {
	src := fullXHTTP()
	(&Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: src}).Normalize()

	extra := src.XHTTPExtra()
	if extra == "" {
		t.Fatal("XHTTPExtra produced nothing for a fully configured transport")
	}
	// The payload must use the core's own camelCase spelling: that is what makes
	// it readable by foreign clients, and what lets us re-import theirs.
	var probe map[string]any
	if err := json.Unmarshal([]byte(extra), &probe); err != nil {
		t.Fatalf("extra is not JSON: %v", err)
	}
	for _, k := range []string{"xPaddingBytes", "xPaddingObfsMode", "noGRPCHeader", "noSSEHeader",
		"scMaxEachPostBytes", "scMinPostsIntervalMs", "sessionPlacement", "sessionKey",
		"seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey", "uplinkHTTPMethod",
		"uplinkChunkSize", "headers", "xmux", "downloadSettings"} {
		if _, ok := probe[k]; !ok {
			t.Errorf("extra payload is missing %q", k)
		}
	}
	// Server-only knobs must NOT be in a client link.
	for _, k := range []string{"scMaxBufferedPosts", "scStreamUpServerSecs", "serverMaxHeaderBytes"} {
		if _, ok := probe[k]; ok {
			t.Errorf("extra payload leaks server-only %q to the client", k)
		}
	}

	got := Transport{Network: NetXHTTP, Path: src.Path, Host: src.Host, XHTTPMode: src.XHTTPMode}
	if err := got.ApplyXHTTPExtra(extra); err != nil {
		t.Fatalf("ApplyXHTTPExtra: %v", err)
	}
	// Server-only fields are not in the link, so compare against the client view.
	want := src
	want.SCMaxBufferedPosts, want.SCStreamUpServerSecs, want.ServerMaxHeaderBytes = 0, "", 0
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extra round trip lost data:\n got %+v\nwant %+v", got, want)
	}
}

// TestXHTTPExtraCarriesFullDownloadLeg: the download leg is a stream in its own
// right and shares the padding/session contract with the server. A link that
// carried only its path would come back as a leg the server rejects, so the
// nested payload must carry the leg's whole client-visible field set.
func TestXHTTPExtraCarriesFullDownloadLeg(t *testing.T) {
	src := fullXHTTP()
	src.XHTTPMode = XHTTPModeStreamUp // stream-one forbids a download leg
	leg := src
	leg.XHTTPDownload, leg.XMux = nil, nil
	leg.Path, leg.Host = "/dl", "dl.example.com"
	src.XHTTPDownload = &XHTTPDownload{
		Address: "dl.example.com", Port: 8443, Transport: leg,
		Security: Security{Type: SecReality, ServerName: "www.microsoft.com", Fingerprint: "chrome",
			Reality: &Reality{PublicKey: "pbk", ShortID: "0123abcd", SpiderX: "/"}},
	}
	(&Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: src}).Normalize()

	var got Transport
	if err := got.ApplyXHTTPExtra(src.XHTTPExtra()); err != nil {
		t.Fatalf("ApplyXHTTPExtra: %v", err)
	}
	d := got.XHTTPDownload
	if d == nil {
		t.Fatal("the download leg did not survive the extra payload")
	}
	if d.Address != "dl.example.com" || d.Port != 8443 {
		t.Fatalf("download endpoint = %s:%d", d.Address, d.Port)
	}
	if d.Transport.Path != "/dl" || d.Transport.Host != "dl.example.com" ||
		d.Transport.XHTTPMode != XHTTPModeStreamUp {
		t.Fatalf("download transport identity lost: %+v", d.Transport)
	}
	if !d.Transport.XPaddingObfsMode || d.Transport.XPaddingPlacement != "queryInHeader" ||
		d.Transport.SessionPlacement != "header" || d.Transport.SessionKey != "x_session" ||
		d.Transport.SeqPlacement != "cookie" || d.Transport.SCMaxEachPostBytes != "1000000" {
		t.Fatalf("download leg lost its padding/session contract: %+v", d.Transport)
	}
	if d.Security.Type != SecReality || d.Security.Reality == nil ||
		d.Security.Reality.PublicKey != "pbk" || d.Security.Reality.ShortID != "0123abcd" {
		t.Fatalf("download REALITY layer lost: %+v", d.Security)
	}
}

// TestApplyXHTTPExtraReportsMalformedPayload: half-applying a truncated blob
// would give the operator a silently different transport.
func TestApplyXHTTPExtraReportsMalformedPayload(t *testing.T) {
	var tr Transport
	if err := tr.ApplyXHTTPExtra(`{"xPaddingBytes":`); err == nil {
		t.Fatal("a truncated extra payload must be reported")
	}
	if err := tr.ApplyXHTTPExtra(`{"xmux":"not-an-object"}`); err == nil {
		t.Fatal("a malformed xmux must be reported")
	}
	if err := tr.ApplyXHTTPExtra("   "); err != nil {
		t.Fatalf("an absent payload is not an error: %v", err)
	}
}

// TestXHTTPExtraDecodesNumericRanges: the core writes an Int32Range as either a
// number or a "min-max" string, and foreign panels emit both. Both must import.
func TestXHTTPExtraDecodesNumericRanges(t *testing.T) {
	var tr Transport
	if err := tr.ApplyXHTTPExtra(`{"xmux":{"maxConcurrency":16,"cMaxReuseTimes":"64-128","hKeepAlivePeriod":45}}`); err != nil {
		t.Fatal(err)
	}
	if tr.XMux == nil || tr.XMux.MaxConcurrency != "16" || tr.XMux.CMaxReuseTimes != "64-128" || tr.XMux.HKeepAlivePeriod != 45 {
		t.Fatalf("xmux = %+v", tr.XMux)
	}
}

// TestCloneDeepCopiesXHTTPDownload: an aliased download leg would let an edit to
// a rendered copy mutate the stored inbound.
func TestCloneDeepCopiesXHTTPDownload(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: fullXHTTP()}
	c := n.Clone()
	c.Transport.XHTTPDownload.Address = "mutated.example.com"
	c.Transport.XHTTPDownload.Transport.Path = "/mutated"
	if n.Transport.XHTTPDownload.Address != "dl.example.com" || n.Transport.XHTTPDownload.Transport.Path != "/dl" {
		t.Fatalf("Clone aliased the download leg: %+v", n.Transport.XHTTPDownload)
	}
}
