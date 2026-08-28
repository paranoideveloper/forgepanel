package model

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// b64 is the padded standard encoding of n zero bytes -- a syntactically valid
// SS2022 PSK of exactly the requested key length.
func b64(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

// ---------------------------------------------------------------------------
// enumerations
// ---------------------------------------------------------------------------

func TestAllProtocolsEnumeration(t *testing.T) {
	got := AllProtocols()
	want := []Protocol{
		ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoShadowsocks, ProtoSOCKS,
		ProtoHTTP, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoWireGuard,
		// ProtoAmneziaWG belongs here: it is a declared protocol, it is fully
		// implemented in kernel mode (amneziawg module + awg-quick), it has its
		// own engine, and the README advertises it as supported. This list
		// previously omitted it, which is precisely why it was invisible to the
		// API's protocol metadata, the UI pickers and every test matrix that
		// enumerates AllProtocols().
		ProtoAmneziaWG,
		ProtoShadowTLS, ProtoSSH, ProtoBrook, ProtoForgeDNS,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AllProtocols() = %v, want %v", got, want)
	}
	seen := map[Protocol]bool{}
	for _, p := range got {
		if seen[p] {
			t.Errorf("AllProtocols() contains %q twice", p)
		}
		seen[p] = true
		if string(p) != strings.ToLower(string(p)) {
			t.Errorf("protocol id %q is not lower-case; the value is a stable JSON/DB discriminator", p)
		}
	}
	// AmneziaWG must be present. It was previously excluded here on the grounds
	// that it did not belong in "the matrix list", which conflated two different
	// questions: which protocols the panel SUPPORTS (this list — it feeds
	// /api/protocols, the UI pickers and protocol switching) versus which
	// protocols a config-generation matrix can exercise on a machine without the
	// amneziawg kernel module. The exclusion answered the second question in the
	// place that answers the first, so a fully implemented, README-advertised
	// protocol was invisible to the API. Tests that need the old behaviour
	// narrow the list themselves rather than the list narrowing reality.
	if !seen[ProtoAmneziaWG] {
		t.Error("AllProtocols() is missing amneziawg — it is implemented and advertised, so it must be enumerable")
	}
}

func TestAllNetworksAndSecurityTypes(t *testing.T) {
	nets := AllNetworks()
	wantNets := []Network{NetTCP, NetWS, NetGRPC, NetHTTPUpgrade, NetXHTTP, NetH2, NetMKCP, NetQUIC}
	if !reflect.DeepEqual(nets, wantNets) {
		t.Fatalf("AllNetworks() = %v, want %v", nets, wantNets)
	}
	secs := AllSecurityTypes()
	if !reflect.DeepEqual(secs, []SecurityType{SecNone, SecTLS, SecReality}) {
		t.Fatalf("AllSecurityTypes() = %v", secs)
	}
	fps := ValidFingerprints()
	for _, want := range []string{"chrome", "firefox", "safari", "random"} {
		if !containsStr(fps, want) {
			t.Errorf("ValidFingerprints() missing %q", want)
		}
	}
}

func TestKeySizeForMethod(t *testing.T) {
	cases := []struct {
		method   string
		wantSize int
		want2022 bool
	}{
		{SS2022AES128, 16, true},
		{SS2022AES256, 32, true},
		{SS2022ChaCha20, 32, true},
		{SSAES128GCM, 16, false},
		{SSAES256GCM, 32, false},
		{SSChaCha20Poly, 32, false},
		{SSXChaCha20Poly, 32, false},
		{SSNone, 0, false},
		{"rc4-md5", 0, false},
	}
	for _, c := range cases {
		size, is2022 := KeySizeForMethod(c.method)
		if size != c.wantSize || is2022 != c.want2022 {
			t.Errorf("KeySizeForMethod(%q) = (%d,%v), want (%d,%v)", c.method, size, is2022, c.wantSize, c.want2022)
		}
	}
	// Every advertised method must be known to KeySizeForMethod, otherwise
	// Validate would accept a method it cannot size.
	for _, m := range AllShadowsocksMethods() {
		if _, is2022 := KeySizeForMethod(m); is2022 && !strings.HasPrefix(m, "2022-blake3-") {
			t.Errorf("method %q flagged as SIP022 but is not a 2022-blake3 method", m)
		}
	}
	if len(AllShadowsocksMethods()) != 8 {
		t.Fatalf("AllShadowsocksMethods() = %v, want 8 entries", AllShadowsocksMethods())
	}
}

// ---------------------------------------------------------------------------
// base64 helpers
// ---------------------------------------------------------------------------

func TestDecodeBase64AnyAcceptsAllFourVariants(t *testing.T) {
	payload := []byte{0xfb, 0xff, 0xbe, 0x01, 0x02}
	for name, enc := range map[string]*base64.Encoding{
		"std":    base64.StdEncoding,
		"rawstd": base64.RawStdEncoding,
		"url":    base64.URLEncoding,
		"rawurl": base64.RawURLEncoding,
	} {
		s := enc.EncodeToString(payload)
		got, err := DecodeBase64Any(s)
		if err != nil {
			t.Fatalf("%s: DecodeBase64Any(%q): %v", name, s, err)
		}
		if !reflect.DeepEqual(got, payload) {
			t.Fatalf("%s: decoded %v, want %v", name, got, payload)
		}
	}
	// Surrounding whitespace is tolerated (clients paste with newlines).
	if _, err := DecodeBase64Any("  " + base64.StdEncoding.EncodeToString(payload) + "  "); err != nil {
		t.Fatalf("padded-with-space decode failed: %v", err)
	}
	if _, err := DecodeBase64Any("!!not base64!!"); err == nil {
		t.Fatal("DecodeBase64Any accepted a non-base64 string")
	}
}

func TestValidateSS2022PSKSegments(t *testing.T) {
	// Multi-user EIH form: every "serverPSK:userPSK" segment must be key-sized.
	if err := validateSS2022PSK(b64(16)+":"+b64(16), 16); err != nil {
		t.Fatalf("valid two-segment PSK rejected: %v", err)
	}
	if err := validateSS2022PSK(b64(16)+":"+b64(32), 16); err == nil {
		t.Fatal("second segment with the wrong length must be rejected")
	} else if !strings.Contains(err.Error(), "segment 1") {
		t.Errorf("error should name the offending segment, got %v", err)
	}
	if err := validateSS2022PSK("", 16); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("empty PSK error = %v, want ErrNoCredential", err)
	}
	if err := validateSS2022PSK("%%%%", 16); err == nil {
		t.Fatal("non-base64 PSK must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Normalize
// ---------------------------------------------------------------------------

func TestNormalizeLowercasesAndTrims(t *testing.T) {
	n := &Node{
		Protocol: Protocol("VLESS"), Address: "  1.2.3.4  ", Port: 443,
		UUID: "u", Method: "  AES-256-GCM ", Flow: " xtls-rprx-vision ",
		Transport: Transport{Network: Network("WS")},
		Security:  Security{Type: SecurityType("TLS")},
	}
	n.Normalize()
	if n.Protocol != ProtoVLESS {
		t.Errorf("protocol = %q, want vless", n.Protocol)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("address = %q, want trimmed", n.Address)
	}
	if n.Transport.Network != NetWS {
		t.Errorf("network = %q, want ws", n.Transport.Network)
	}
	if n.Security.Type != SecTLS {
		t.Errorf("security = %q, want tls", n.Security.Type)
	}
	// Method belongs to Shadowsocks only, so a VLESS node must lose it.
	if n.Method != "" {
		t.Errorf("method = %q, want cleared on a non-shadowsocks node", n.Method)
	}
	// Vision is meaningless over ws and must be dropped rather than exported.
	if n.Flow != "" {
		t.Errorf("flow = %q, want dropped over ws", n.Flow)
	}
}

func TestNormalizeNetworkAliases(t *testing.T) {
	cases := map[string]Network{
		"":            NetTCP,
		"splithttp":   NetXHTTP,
		"http":        NetH2,
		"mkcp":        NetMKCP,
		"SPLITHTTP":   NetXHTTP,
		"ws":          NetWS,
		"httpupgrade": NetHTTPUpgrade,
	}
	for in, want := range cases {
		n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u", Transport: Transport{Network: Network(in)}}
		n.Normalize()
		if n.Transport.Network != want {
			t.Errorf("Normalize network %q = %q, want %q", in, n.Transport.Network, want)
		}
	}
}

func TestNormalizeVisionKeptOverTCP(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Flow: "xtls-rprx-vision",
		Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk", ServerNames: []string{"a.com"}}}}
	n.Normalize()
	if n.Flow != "xtls-rprx-vision" {
		t.Fatalf("flow = %q, want preserved over raw TCP", n.Flow)
	}
	if n.Encryption != "none" {
		t.Fatalf("vless encryption = %q, want the default %q", n.Encryption, "none")
	}
}

func TestNormalizeClearsIrrelevantTransportFields(t *testing.T) {
	// A transport carrying every knob at once; Normalize must keep only the
	// fields meaningful for the selected network.
	full := func(net Network) Transport {
		return Transport{
			Network: net, Path: "/p", Host: "h.example.com", Headers: map[string]string{"X": "1"},
			EarlyData: 2048, EDHeader: "Sec-WebSocket-Protocol",
			ServiceName: "svc", MultiMode: true, IdleTimeout: 30, HealthCheckTimeout: 20,
			InitialWindows: 65536, PermitWithout: true,
			XHTTPMode: "stream-up", XPaddingB: "100-1000", XMux: &XMux{MaxConcurrency: "16"},
			H2Hosts:    []string{"a", "b"},
			HeaderObfs: &Header{Type: "http"},
			Seed:       "seed", MTU: 1350, TTI: 50, UplinkCap: 5, DownlinkCap: 20,
			Congestion: true, ReadBufSize: 2, WriteBufSize: 2,
			QUICSecurity: "aes-128-gcm", QUICKey: "qk",
		}
	}
	cases := []struct {
		net       Network
		wantKept  map[string]bool // field name -> must be non-zero after Normalize
		wantClear []string
	}{
		{NetWS, map[string]bool{"Path": true, "Host": true, "Headers": true, "EarlyData": true, "EDHeader": true},
			[]string{"ServiceName", "XHTTPMode", "Seed", "QUICSecurity", "HeaderObfs", "H2Hosts"}},
		{NetHTTPUpgrade, map[string]bool{"Path": true, "Host": true, "Headers": true},
			[]string{"ServiceName", "XHTTPMode", "Seed", "HeaderObfs"}},
		{NetGRPC, map[string]bool{"ServiceName": true, "MultiMode": true, "IdleTimeout": true, "HealthCheckTimeout": true, "InitialWindows": true, "PermitWithout": true, "Host": true},
			[]string{"Path", "Headers", "XHTTPMode", "Seed", "HeaderObfs"}},
		{NetXHTTP, map[string]bool{"Path": true, "Host": true, "Headers": true, "XHTTPMode": true, "XPaddingB": true, "XMux": true},
			[]string{"ServiceName", "Seed", "HeaderObfs", "H2Hosts"}},
		{NetH2, map[string]bool{"Path": true, "Host": true, "H2Hosts": true, "Headers": true},
			[]string{"ServiceName", "XHTTPMode", "Seed", "HeaderObfs"}},
		{NetMKCP, map[string]bool{"Seed": true, "MTU": true, "TTI": true, "UplinkCap": true, "DownlinkCap": true, "Congestion": true, "ReadBufSize": true, "WriteBufSize": true, "HeaderObfs": true},
			[]string{"Path", "Host", "ServiceName", "XHTTPMode", "QUICSecurity"}},
		{NetQUIC, map[string]bool{"QUICSecurity": true, "QUICKey": true, "HeaderObfs": true},
			[]string{"Path", "Host", "ServiceName", "Seed", "XHTTPMode"}},
		{NetTCP, map[string]bool{"HeaderObfs": true, "Host": true, "Path": true},
			[]string{"ServiceName", "XHTTPMode", "Seed", "QUICSecurity", "Headers", "H2Hosts"}},
	}
	for _, c := range cases {
		n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u", Transport: full(c.net)}
		n.Normalize()
		rv := reflect.ValueOf(n.Transport)
		for field := range c.wantKept {
			if rv.FieldByName(field).IsZero() {
				t.Errorf("%s: field %s was cleared but is meaningful for this network", c.net, field)
			}
		}
		for _, field := range c.wantClear {
			if !rv.FieldByName(field).IsZero() {
				t.Errorf("%s: field %s = %v, want zeroed (irrelevant for this network)", c.net, field, rv.FieldByName(field))
			}
		}
		if n.Transport.Network != c.net {
			t.Errorf("network changed to %q", n.Transport.Network)
		}
	}
}

func TestNormalizeDropsEmptyHeaderObfsAndHeaders(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u",
		Transport: Transport{Network: NetTCP, HeaderObfs: &Header{Type: ""}, Headers: map[string]string{}}}
	n.Normalize()
	if n.Transport.HeaderObfs != nil {
		t.Error("a header-obfuscation block with no type must be dropped")
	}
	if n.Transport.Headers != nil {
		t.Error("an empty header map must normalize to nil so equality is stable")
	}
}

func TestNormalizeForcesCanonicalTransportForNonTransportProtocols(t *testing.T) {
	for _, p := range []Protocol{ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoWireGuard, ProtoSSH, ProtoBrook, ProtoForgeDNS, ProtoShadowTLS} {
		n := &Node{Protocol: p, Address: "a", Port: 443, Password: "pw", UUID: "u",
			Transport: Transport{Network: NetWS, Path: "/x", Host: "h"}}
		n.Normalize()
		if !reflect.DeepEqual(n.Transport, Transport{Network: NetTCP}) {
			t.Errorf("%s: transport = %+v, want the canonical zero {tcp}", p, n.Transport)
		}
	}
}

func TestNormalizeSecurityNoneWipesTLSFields(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u",
		Security: Security{
			Type: SecNone, ServerName: "s", ALPN: []string{"h2"}, Fingerprint: "chrome",
			AllowInsecure: true, CertificateFile: "/c", KeyFile: "/k",
			PinSHA256: []string{"p"}, Reality: &Reality{PublicKey: "pk"}, ECH: &ECH{Enabled: true},
		}}
	n.Normalize()
	if !reflect.DeepEqual(n.Security, Security{Type: SecNone}) {
		t.Fatalf("security = %+v, want a bare {none}", n.Security)
	}
}

func TestNormalizeSecurityXTLSAliasAndTLSCleanup(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u",
		Security: Security{Type: SecurityType("xtls"), ServerName: "s",
			Reality: &Reality{PublicKey: "pk"}, ECH: &ECH{}}}
	n.Normalize()
	if n.Security.Type != SecTLS {
		t.Fatalf("xtls should alias to tls, got %q", n.Security.Type)
	}
	if n.Security.Reality != nil {
		t.Error("a REALITY block must not survive on a plain-TLS node")
	}
	if n.Security.ECH != nil {
		t.Error("an all-zero ECH block must be dropped")
	}
}

func TestNormalizeRealitySortsAndBackfills(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Security: Security{Type: SecReality, AllowInsecure: true, ECH: &ECH{Enabled: true},
			Reality: &Reality{PublicKey: "pk", ServerNames: []string{"z.com", "a.com"}, ShortIDs: []string{"ff", "00"}}}}
	n.Normalize()
	r := n.Security.Reality
	if !reflect.DeepEqual(r.ServerNames, []string{"a.com", "z.com"}) {
		t.Errorf("serverNames not sorted: %v", r.ServerNames)
	}
	if !reflect.DeepEqual(r.ShortIDs, []string{"00", "ff"}) {
		t.Errorf("shortIds not sorted: %v", r.ShortIDs)
	}
	if r.SpiderX != "/" {
		t.Errorf("spiderX = %q, want the default %q", r.SpiderX, "/")
	}
	if n.Security.ECH != nil {
		t.Error("ECH does not apply to REALITY and must be dropped")
	}
	if n.Security.AllowInsecure {
		t.Error("allowInsecure is meaningless under REALITY and must be cleared")
	}
	if n.Security.ServerName != "" {
		t.Errorf("SNI = %q; with two serverNames there is nothing unambiguous to adopt", n.Security.ServerName)
	}

	// With exactly one serverName and no explicit SNI, the SNI is adopted.
	one := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk", ServerNames: []string{"only.com"}}}}
	one.Normalize()
	if one.Security.ServerName != "only.com" {
		t.Errorf("SNI = %q, want the sole serverName adopted", one.Security.ServerName)
	}
}

func TestNormalizeForcesTLSOnQUICAndAnyTLS(t *testing.T) {
	for _, p := range []Protocol{ProtoHysteria2, ProtoTUIC, ProtoAnyTLS} {
		n := &Node{Protocol: p, Address: "a", Port: 443, UUID: "u", Password: "pw", Security: Security{Type: SecNone}}
		n.Normalize()
		if n.Security.Type != SecTLS {
			t.Errorf("%s: security = %q, want tls forced (the wire is TLS by construction)", p, n.Security.Type)
		}
	}
	// ShadowTLS is deliberately excluded: sing-box rejects a shadowtls inbound
	// that also carries a top-level tls block.
	st := &Node{Protocol: ProtoShadowTLS, Address: "a", Port: 443, Security: Security{Type: SecNone},
		ShadowTLS: &ShadowTLSOptions{Password: "hs"}}
	st.Normalize()
	if st.Security.Type != SecNone {
		t.Errorf("shadowtls security = %q, want none", st.Security.Type)
	}
}

func TestNormalizeProtocolDefaults(t *testing.T) {
	t.Run("vmess", func(t *testing.T) {
		n := &Node{Protocol: ProtoVMess, Address: "a", Port: 1, UUID: "u", AlterID: 64}
		n.Normalize()
		if n.AlterID != 0 {
			t.Errorf("alterId = %d, want 0 (VMessAEAD only)", n.AlterID)
		}
		if n.Encryption != "auto" {
			t.Errorf("encryption = %q, want auto", n.Encryption)
		}
	})
	t.Run("hysteria2", func(t *testing.T) {
		n := &Node{Protocol: ProtoHysteria2, Address: "a", Port: 443, Password: "pw"}
		n.Normalize()
		if n.Hysteria2 == nil {
			t.Fatal("hysteria2 options block must be materialized")
		}
		if !reflect.DeepEqual(n.Security.ALPN, []string{"h3"}) {
			t.Errorf("alpn = %v, want [h3]", n.Security.ALPN)
		}
	})
	t.Run("tuic", func(t *testing.T) {
		n := &Node{Protocol: ProtoTUIC, Address: "a", Port: 443, UUID: "u", Password: "pw"}
		n.Normalize()
		if n.TUIC.CongestionControl != "bbr" || n.TUIC.UDPRelayMode != "native" {
			t.Errorf("tuic defaults = %+v, want bbr/native", n.TUIC)
		}
		if !reflect.DeepEqual(n.Security.ALPN, []string{"h3"}) {
			t.Errorf("alpn = %v, want [h3]", n.Security.ALPN)
		}
	})
	t.Run("anytls", func(t *testing.T) {
		n := &Node{Protocol: ProtoAnyTLS, Address: "a", Port: 443, Password: "pw"}
		n.Normalize()
		if n.AnyTLS == nil {
			t.Fatal("anytls options block must be materialized")
		}
	})
	t.Run("wireguard", func(t *testing.T) {
		n := &Node{Protocol: ProtoWireGuard, Address: "a", Port: 51820, WireGuard: &WireGuardOptions{PrivateKey: "sk", PublicKey: "pk"}}
		n.Normalize()
		if n.WireGuard.MTU != 1420 {
			t.Errorf("mtu = %d, want the 1420 default", n.WireGuard.MTU)
		}
	})
	t.Run("amneziawg", func(t *testing.T) {
		n := &Node{Protocol: ProtoAmneziaWG, Address: "a", Port: 51820}
		n.Normalize()
		a := n.AmneziaWG
		if a == nil {
			t.Fatal("amneziawg options block must be materialized")
		}
		want := AmneziaWGOptions{Jc: 8, Jmin: 50, Jmax: 1000, S1: 86, S2: 574,
			H1: 1234567, H2: 2345678, H3: 3456789, H4: 4567890}
		want.MTU = 1420
		if a.Jc != want.Jc || a.Jmin != want.Jmin || a.Jmax != want.Jmax ||
			a.S1 != want.S1 || a.S2 != want.S2 || a.MTU != want.MTU ||
			a.H1 != want.H1 || a.H2 != want.H2 || a.H3 != want.H3 || a.H4 != want.H4 {
			t.Fatalf("amneziawg defaults = %+v, want %+v", *a, want)
		}
		// The defaults must themselves satisfy Validate's obfuscation rules.
		if a.Jmin >= a.Jmax {
			t.Error("default Jmin >= Jmax")
		}
		if a.S1+56 == a.S2 {
			t.Error("default S1+56 == S2")
		}
	})
	t.Run("forgedns", func(t *testing.T) {
		n := &Node{Protocol: ProtoForgeDNS, Address: "z", Port: 53,
			ForgeDNS: &ForgeDNSOptions{Adapter: "StormDNS", Zone: "Tunnel.Example.COM.", RRType: "txt"}}
		n.Normalize()
		f := n.ForgeDNS
		if f.Adapter != "stormdns" {
			t.Errorf("adapter = %q, want lower-cased", f.Adapter)
		}
		if f.Zone != "tunnel.example.com" {
			t.Errorf("zone = %q, want lower-cased without the trailing dot", f.Zone)
		}
		if f.RRType != "TXT" {
			t.Errorf("rrtype = %q, want upper-cased", f.RRType)
		}
		if f.EDNSBuffer != 1232 {
			t.Errorf("edns buffer = %d, want the 1232 default", f.EDNSBuffer)
		}
	})
}

func TestNormalizeShadowTLSBackfillsInnerShadowsocks(t *testing.T) {
	n := &Node{Protocol: ProtoShadowTLS, Address: "a", Port: 8443, ShadowTLS: &ShadowTLSOptions{}}
	n.Normalize()
	s := n.ShadowTLS
	if s.Version != 3 {
		t.Errorf("version = %d, want the 3 default", s.Version)
	}
	if s.Password == "" {
		t.Fatal("handshake password must be backfilled; sing-box rejects an empty one")
	}
	if s.InnerMethod != SS2022AES128 {
		t.Errorf("inner method = %q, want %q", s.InnerMethod, SS2022AES128)
	}
	// The derived inner PSK must be a *valid* SS2022 key for the inner method.
	if err := validateSS2022PSK(s.InnerPassword, 16); err != nil {
		t.Fatalf("derived inner PSK is not a valid 16-byte SS2022 PSK: %v", err)
	}
	// Deterministic: the same node normalizes to the same credentials.
	again := &Node{Protocol: ProtoShadowTLS, Address: "a", Port: 8443, ShadowTLS: &ShadowTLSOptions{}}
	again.Normalize()
	if again.ShadowTLS.Password != s.Password || again.ShadowTLS.InnerPassword != s.InnerPassword {
		t.Fatal("backfilled ShadowTLS credentials are not reproducible")
	}
	// A different port yields different credentials (they are port-derived).
	other := &Node{Protocol: ProtoShadowTLS, Address: "a", Port: 9443, ShadowTLS: &ShadowTLSOptions{}}
	other.Normalize()
	if other.ShadowTLS.Password == s.Password {
		t.Error("handshake password should differ per port")
	}
}

func TestDeriveInnerPSKFallsBackToSixteenBytes(t *testing.T) {
	// "none" has no key size; the derivation must still produce a usable PSK.
	got := deriveInnerPSK("seed", SSNone)
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("derived PSK is not standard base64: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("derived PSK is %d bytes, want the 16-byte fallback", len(raw))
	}
	if deriveInnerPSK("seed", SS2022AES256) == got {
		t.Error("PSKs for different key sizes must differ")
	}
}

func TestNormalizeMigratesLegacyHysteria2Masquerade(t *testing.T) {
	n := &Node{Protocol: ProtoHysteria2, Address: "a", Port: 443, Password: "pw",
		Hysteria2: &Hysteria2Options{MasqueradeType: "proxy", MasqueradeURL: "https://example.com"}}
	n.Normalize()
	m := n.Hysteria2.Masquerade
	if m == nil {
		t.Fatal("legacy flat masquerade fields were not migrated")
	}
	if m.Type != "proxy" || m.URL != "https://example.com" {
		t.Fatalf("migrated masquerade = %+v", *m)
	}
	if n.Hysteria2.MasqueradeType != "" || n.Hysteria2.MasqueradeURL != "" {
		t.Error("legacy fields must be cleared after migration")
	}
	// An already-structured masquerade wins and is not overwritten.
	n2 := &Node{Protocol: ProtoHysteria2, Address: "a", Port: 443, Password: "pw",
		Hysteria2: &Hysteria2Options{Masquerade: &Hy2Masquerade{Type: "file", Directory: "/srv"}, MasqueradeType: "proxy"}}
	n2.Normalize()
	if n2.Hysteria2.Masquerade.Type != "file" {
		t.Errorf("structured masquerade overwritten by the legacy field: %+v", *n2.Hysteria2.Masquerade)
	}
}

func TestNormalizeClearsIrrelevantProtocolBlocksAndCredentials(t *testing.T) {
	// A node carrying every extension block and every credential at once.
	loaded := func(p Protocol) *Node {
		return &Node{
			Protocol: p, Address: "a", Port: 443,
			UUID: "uuid", Password: "pw", Username: "user", Method: SSAES128GCM,
			Flow: "xtls-rprx-vision", Encryption: "auto", AlterID: 64,
			Hysteria2: &Hysteria2Options{}, TUIC: &TUICOptions{}, AnyTLS: &AnyTLSOptions{},
			WireGuard: &WireGuardOptions{PrivateKey: "sk", PublicKey: "pk"},
			ShadowTLS: &ShadowTLSOptions{Password: "hs"}, SSH: &SSHOptions{User: "root"},
			Brook: &BrookOptions{Mode: "server"}, ForgeDNS: &ForgeDNSOptions{Zone: "z", Adapter: "stormdns"},
			SSPlugin: &SSPluginOptions{Name: "obfs-local"},
		}
	}
	blockOf := map[Protocol]func(*Node) bool{
		ProtoHysteria2: func(n *Node) bool { return n.Hysteria2 != nil },
		ProtoTUIC:      func(n *Node) bool { return n.TUIC != nil },
		ProtoAnyTLS:    func(n *Node) bool { return n.AnyTLS != nil },
		ProtoWireGuard: func(n *Node) bool { return n.WireGuard != nil },
		ProtoShadowTLS: func(n *Node) bool { return n.ShadowTLS != nil },
		ProtoSSH:       func(n *Node) bool { return n.SSH != nil },
		ProtoBrook:     func(n *Node) bool { return n.Brook != nil },
		ProtoForgeDNS:  func(n *Node) bool { return n.ForgeDNS != nil },
	}
	for owner, present := range blockOf {
		n := loaded(owner)
		n.Normalize()
		if !present(n) {
			t.Errorf("%s: its own extension block was cleared", owner)
		}
		for other, otherPresent := range blockOf {
			if other == owner {
				continue
			}
			if otherPresent(n) {
				t.Errorf("%s: the %s extension block survived normalization", owner, other)
			}
		}
	}

	// Credential hygiene per protocol.
	creds := []struct {
		proto Protocol
		want  map[string]string // field -> expected value ("" means cleared)
	}{
		{ProtoVLESS, map[string]string{"UUID": "uuid", "Password": "", "Username": "", "Method": ""}},
		{ProtoVMess, map[string]string{"UUID": "uuid", "Password": "", "Username": ""}},
		{ProtoTrojan, map[string]string{"UUID": "", "Password": "pw", "Username": "", "Flow": "", "Encryption": ""}},
		{ProtoTUIC, map[string]string{"UUID": "uuid", "Password": "pw", "Username": "", "Flow": "", "Encryption": ""}},
		{ProtoShadowsocks, map[string]string{"UUID": "", "Password": "pw", "Username": "", "Method": SSAES128GCM, "Flow": ""}},
		{ProtoSOCKS, map[string]string{"UUID": "", "Password": "pw", "Username": "user", "Flow": ""}},
		{ProtoHTTP, map[string]string{"UUID": "", "Password": "pw", "Username": "user"}},
		{ProtoSSH, map[string]string{"UUID": "", "Password": "", "Username": "", "Flow": "", "Encryption": ""}},
		{ProtoShadowTLS, map[string]string{"UUID": "", "Password": "", "Username": ""}},
		{ProtoForgeDNS, map[string]string{"UUID": "", "Password": "", "Username": ""}},
		{ProtoWireGuard, map[string]string{"UUID": "", "Password": "", "Username": ""}},
	}
	for _, c := range creds {
		n := loaded(c.proto)
		n.Normalize()
		rv := reflect.ValueOf(*n)
		for field, want := range c.want {
			if got := rv.FieldByName(field).String(); got != want {
				t.Errorf("%s: %s = %q, want %q", c.proto, field, got, want)
			}
		}
		if c.proto != ProtoVMess && n.AlterID != 0 {
			t.Errorf("%s: alterId = %d, want 0", c.proto, n.AlterID)
		}
	}
	// SSPlugin belongs to Shadowsocks alone.
	ss := loaded(ProtoShadowsocks)
	ss.Normalize()
	if ss.SSPlugin == nil {
		t.Error("shadowsocks lost its SIP003 plugin")
	}
	vl := loaded(ProtoVLESS)
	vl.Normalize()
	if vl.SSPlugin != nil {
		t.Error("a SIP003 plugin survived on a VLESS node")
	}
}

func TestNormalizeDropsDisabledMultiplex(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u", Multiplex: &Multiplex{Enabled: false, MaxStreams: 8}}
	n.Normalize()
	if n.Multiplex != nil {
		t.Fatal("a disabled multiplex block must normalize away")
	}
	on := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u", Multiplex: &Multiplex{Enabled: true, MaxStreams: 8}}
	on.Normalize()
	if on.Multiplex == nil || on.Multiplex.MaxStreams != 8 {
		t.Fatal("an enabled multiplex block must be preserved")
	}
}

// TestNormalizeIsIdempotent is what makes the round-trip property test in
// spec §15 meaningful: normalizing twice must equal normalizing once.
func TestNormalizeIsIdempotent(t *testing.T) {
	for _, n := range validNodeMatrix() {
		once := n.Clone()
		once.Normalize()
		twice := once.Clone()
		twice.Normalize()
		if !reflect.DeepEqual(once, twice) {
			t.Errorf("%s: Normalize is not idempotent\n once: %+v\ntwice: %+v", n.Remark, once, twice)
		}
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

// validNodeMatrix returns a representative, fully-populated node per protocol
// across transports and security layers. Every entry must pass Validate after
// Normalize.
func validNodeMatrix() []*Node {
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	reality := func() Security {
		return Security{Type: SecReality, Fingerprint: "chrome",
			Reality: &Reality{Dest: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
				PrivateKey: "sk", PublicKey: "pk", ShortIDs: []string{"0123abcd"}, ShortID: "0123abcd"}}
	}
	tls := func(sni string) Security {
		return Security{Type: SecTLS, ServerName: sni, Fingerprint: "firefox", ALPN: []string{"h2", "http/1.1"}}
	}
	return []*Node{
		{Remark: "vless-vision-reality-tcp", Protocol: ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: uuid,
			Flow: "xtls-rprx-vision", Transport: Transport{Network: NetTCP}, Security: reality()},
		{Remark: "vless-ws-tls", Protocol: ProtoVLESS, Address: "a.example.com", Port: 8443, UUID: uuid,
			Transport: Transport{Network: NetWS, Path: "/ws", Host: "a.example.com", EarlyData: 2048}, Security: tls("a.example.com")},
		{Remark: "vless-grpc-reality", Protocol: ProtoVLESS, Address: "a.example.com", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetGRPC, ServiceName: "svc", MultiMode: true}, Security: reality()},
		{Remark: "vless-xhttp-reality", Protocol: ProtoVLESS, Address: "a.example.com", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetXHTTP, Path: "/xh", XHTTPMode: "stream-up"}, Security: reality()},
		{Remark: "vless-httpupgrade-none", Protocol: ProtoVLESS, Address: "a.example.com", Port: 80, UUID: uuid,
			Transport: Transport{Network: NetHTTPUpgrade, Path: "/hu", Host: "a.example.com"}},
		{Remark: "vmess-ws-tls", Protocol: ProtoVMess, Address: "5.6.7.8", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetWS, Path: "/vm"}, Security: tls("vm.example.com")},
		{Remark: "trojan-tcp-tls", Protocol: ProtoTrojan, Address: "9.9.9.9", Port: 443, Password: "p@ss",
			Transport: Transport{Network: NetTCP}, Security: tls("t.example.com")},
		{Remark: "ss-chacha", Protocol: ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: SSChaCha20Poly, Password: "pw"},
		{Remark: "ss-2022-128", Protocol: ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: SS2022AES128, Password: b64(16)},
		{Remark: "ss-2022-256", Protocol: ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: SS2022AES256, Password: b64(32)},
		{Remark: "ss-none", Protocol: ProtoShadowsocks, Address: "1.1.1.1", Port: 8388, Method: SSNone},
		{Remark: "socks-open", Protocol: ProtoSOCKS, Address: "2.2.2.2", Port: 1080},
		{Remark: "http-auth", Protocol: ProtoHTTP, Address: "3.3.3.3", Port: 8080, Username: "u", Password: "p"},
		{Remark: "hy2", Protocol: ProtoHysteria2, Address: "4.4.4.4", Port: 443, Password: "pw",
			Security:  Security{Type: SecTLS, ServerName: "hy.example.com"},
			Hysteria2: &Hysteria2Options{UpMbps: 100, DownMbps: 200, ObfsType: "salamander", ObfsPassword: "o", PortHopping: "20000-50000", PortHopInterval: 30}},
		{Remark: "tuic", Protocol: ProtoTUIC, Address: "6.6.6.6", Port: 443, UUID: uuid, Password: "pw",
			Security: Security{Type: SecTLS, ServerName: "tuic.example.com"}, TUIC: &TUICOptions{ZeroRTTHandshake: true, HeartbeatSeconds: 10}},
		{Remark: "anytls", Protocol: ProtoAnyTLS, Address: "7.7.7.7", Port: 443, Password: "pw",
			Security: tls("any.example.com"), AnyTLS: &AnyTLSOptions{PaddingScheme: []string{"stop=8"}, MinIdleSessions: 2}},
		{Remark: "wireguard", Protocol: ProtoWireGuard, Address: "8.8.8.8", Port: 51820,
			WireGuard: &WireGuardOptions{PrivateKey: "sk", PublicKey: "pk", PeerPrivateKey: "csk", PeerPublicKey: "cpk",
				ServerAddress: []string{"10.66.66.1/24"}, PeerAddress: []string{"10.66.66.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}, Keepalive: 25}},
		{Remark: "amneziawg", Protocol: ProtoAmneziaWG, Address: "8.8.4.4", Port: 51821,
			AmneziaWG: &AmneziaWGOptions{WireGuardOptions: WireGuardOptions{PrivateKey: "sk", PublicKey: "pk",
				PeerPrivateKey: "csk", PeerPublicKey: "cpk", ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"}}}},
		{Remark: "shadowtls", Protocol: ProtoShadowTLS, Address: "9.8.7.6", Port: 8443,
			ShadowTLS: &ShadowTLSOptions{Version: 3, Password: "hs", HandshakeHost: "www.apple.com", HandshakePort: 443, StrictMode: true}},
		{Remark: "ssh-password", Protocol: ProtoSSH, Address: "11.11.11.11", Port: 22, SSH: &SSHOptions{User: "root", Password: "pw"}},
		{Remark: "ssh-key", Protocol: ProtoSSH, Address: "11.11.11.12", Port: 22, SSH: &SSHOptions{User: "root", PrivateKey: "-----BEGIN-----", HostKeyAlgorithms: []string{"ssh-ed25519"}}},
		{Remark: "brook", Protocol: ProtoBrook, Address: "10.10.10.10", Port: 9999, Password: "pw", Brook: &BrookOptions{Mode: "wsserver", Path: "/b"}},
		{Remark: "forgedns", Protocol: ProtoForgeDNS, Address: "t.example.com", Port: 53,
			ForgeDNS: &ForgeDNSOptions{Adapter: "stormdns", Zone: "t.example.com", Key: "k", NSHost: "ns1.example.com"}},
	}
}

func TestValidateAcceptsTheWholeMatrix(t *testing.T) {
	seen := map[Protocol]bool{}
	for _, n := range validNodeMatrix() {
		c := n.Clone()
		c.Normalize()
		if err := c.Validate(); err != nil {
			t.Errorf("%s: valid node rejected: %v", n.Remark, err)
		}
		seen[c.Protocol] = true
	}
	for _, p := range AllProtocols() {
		if !seen[p] {
			t.Errorf("protocol %q has no entry in the valid-node matrix", p)
		}
	}
	if !seen[ProtoAmneziaWG] {
		t.Error("amneziawg has no entry in the valid-node matrix")
	}
}

func TestValidateRejects(t *testing.T) {
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	cases := []struct {
		name    string
		node    Node
		wantErr error  // errors.Is target, optional
		wantSub string // error text substring, optional
	}{
		{name: "no address", node: Node{Protocol: ProtoVLESS, Port: 443, UUID: uuid}, wantErr: ErrNoAddress},
		{name: "blank address", node: Node{Protocol: ProtoVLESS, Address: "   ", Port: 443, UUID: uuid}, wantErr: ErrNoAddress},
		{name: "port zero", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 0, UUID: uuid}, wantErr: ErrBadPort},
		{name: "port too large", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 65536, UUID: uuid}, wantErr: ErrBadPort},
		{name: "vless without uuid", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443}, wantErr: ErrNoCredential},
		{name: "vless illegal flow", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid, Flow: "xtls-rprx-direct"}, wantSub: "unsupported flow"},
		{name: "vmess without uuid", node: Node{Protocol: ProtoVMess, Address: "a", Port: 443}, wantErr: ErrNoCredential},
		{name: "trojan without password", node: Node{Protocol: ProtoTrojan, Address: "a", Port: 443}, wantErr: ErrNoCredential},
		{name: "anytls without password", node: Node{Protocol: ProtoAnyTLS, Address: "a", Port: 443}, wantErr: ErrNoCredential},
		{name: "brook without password", node: Node{Protocol: ProtoBrook, Address: "a", Port: 443}, wantErr: ErrNoCredential},
		{name: "hysteria2 without password", node: Node{Protocol: ProtoHysteria2, Address: "a", Port: 443}, wantErr: ErrNoCredential},
		{name: "tuic without password", node: Node{Protocol: ProtoTUIC, Address: "a", Port: 443, UUID: uuid}, wantErr: ErrNoCredential},
		{name: "tuic without uuid", node: Node{Protocol: ProtoTUIC, Address: "a", Port: 443, Password: "pw"}, wantErr: ErrNoCredential},
		{name: "ss empty method", node: Node{Protocol: ProtoShadowsocks, Address: "a", Port: 8388, Password: "pw"}, wantErr: ErrBadMethod},
		{name: "ss unknown method", node: Node{Protocol: ProtoShadowsocks, Address: "a", Port: 8388, Method: "rc4-md5", Password: "pw"}, wantErr: ErrBadMethod},
		{name: "ss without password", node: Node{Protocol: ProtoShadowsocks, Address: "a", Port: 8388, Method: SSAES256GCM}, wantErr: ErrNoCredential},
		{name: "ss2022 psk too short", node: Node{Protocol: ProtoShadowsocks, Address: "a", Port: 8388, Method: SS2022AES256, Password: b64(16)}, wantSub: "decodes to 16 bytes"},
		{name: "ss2022 psk not base64", node: Node{Protocol: ProtoShadowsocks, Address: "a", Port: 8388, Method: SS2022AES128, Password: "!!!!"}, wantSub: "not valid base64"},
		{name: "wireguard no block", node: Node{Protocol: ProtoWireGuard, Address: "a", Port: 51820}, wantErr: ErrNoCredential},
		{name: "wireguard no public key", node: Node{Protocol: ProtoWireGuard, Address: "a", Port: 51820, WireGuard: &WireGuardOptions{PrivateKey: "sk"}}, wantErr: ErrNoCredential},
		{name: "wireguard mtu too small", node: Node{Protocol: ProtoWireGuard, Address: "a", Port: 51820, WireGuard: &WireGuardOptions{PrivateKey: "sk", PublicKey: "pk", MTU: 100}}, wantSub: "out of range"},
		{name: "wireguard mtu too large", node: Node{Protocol: ProtoWireGuard, Address: "a", Port: 51820, WireGuard: &WireGuardOptions{PrivateKey: "sk", PublicKey: "pk", MTU: 9000}}, wantSub: "out of range"},
		{name: "wireguard reserved wrong length", node: Node{Protocol: ProtoWireGuard, Address: "a", Port: 51820, WireGuard: &WireGuardOptions{PrivateKey: "sk", PublicKey: "pk", Reserved: []int{1, 2}}}, wantSub: "exactly 3 bytes"},
		{name: "amneziawg no block", node: Node{Protocol: ProtoAmneziaWG, Address: "a", Port: 51820}, wantErr: ErrNoCredential},
		{name: "amneziawg jmin >= jmax", node: Node{Protocol: ProtoAmneziaWG, Address: "a", Port: 51820, AmneziaWG: &AmneziaWGOptions{WireGuardOptions: WireGuardOptions{PrivateKey: "sk", PublicKey: "pk"}, Jmin: 100, Jmax: 50}}, wantSub: "Jmin must be less than Jmax"},
		{name: "amneziawg s1+56 == s2", node: Node{Protocol: ProtoAmneziaWG, Address: "a", Port: 51820, AmneziaWG: &AmneziaWGOptions{WireGuardOptions: WireGuardOptions{PrivateKey: "sk", PublicKey: "pk"}, S1: 100, S2: 156}}, wantSub: "S1+56 must not equal S2"},
		{name: "shadowtls no block", node: Node{Protocol: ProtoShadowTLS, Address: "a", Port: 8443}, wantErr: ErrNoCredential},
		{name: "shadowtls empty password", node: Node{Protocol: ProtoShadowTLS, Address: "a", Port: 8443, ShadowTLS: &ShadowTLSOptions{Version: 3}}, wantErr: ErrNoCredential},
		{name: "shadowtls version zero", node: Node{Protocol: ProtoShadowTLS, Address: "a", Port: 8443, ShadowTLS: &ShadowTLSOptions{Password: "hs"}}, wantSub: "version must be 1..3"},
		{name: "shadowtls version four", node: Node{Protocol: ProtoShadowTLS, Address: "a", Port: 8443, ShadowTLS: &ShadowTLSOptions{Password: "hs", Version: 4}}, wantSub: "version must be 1..3"},
		{name: "ssh no block", node: Node{Protocol: ProtoSSH, Address: "a", Port: 22}, wantErr: ErrNoCredential},
		{name: "ssh no user", node: Node{Protocol: ProtoSSH, Address: "a", Port: 22, SSH: &SSHOptions{Password: "pw"}}, wantSub: "needs user"},
		{name: "ssh no auth", node: Node{Protocol: ProtoSSH, Address: "a", Port: 22, SSH: &SSHOptions{User: "root"}}, wantSub: "needs password or private key"},
		{name: "forgedns no block", node: Node{Protocol: ProtoForgeDNS, Address: "a", Port: 53}, wantSub: "zone is required"},
		{name: "forgedns no zone", node: Node{Protocol: ProtoForgeDNS, Address: "a", Port: 53, ForgeDNS: &ForgeDNSOptions{Adapter: "stormdns"}}, wantSub: "zone is required"},
		{name: "forgedns no adapter", node: Node{Protocol: ProtoForgeDNS, Address: "a", Port: 53, ForgeDNS: &ForgeDNSOptions{Zone: "z"}}, wantSub: "adapter is required"},
		{name: "unknown protocol", node: Node{Protocol: Protocol("carrier-pigeon"), Address: "a", Port: 443}, wantErr: ErrUnknownProto},
		{name: "h2 transport removed", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid, Transport: Transport{Network: NetH2}}, wantSub: "h2 was removed in Xray 26"},
		{name: "quic transport removed", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid, Transport: Transport{Network: NetQUIC}}, wantSub: "quic was removed in Xray 26"},
		{name: "mkcp transport removed", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid, Transport: Transport{Network: NetMKCP}}, wantSub: "mKCP was removed in Xray 26"},
		{name: "reality over ws", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetWS}, Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk", Dest: "d:443"}}}, wantSub: "REALITY only supports"},
		{name: "reality without block", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality}}, wantErr: ErrRealityNoKey},
		{name: "reality without keys", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality, Reality: &Reality{Dest: "d:443"}}}, wantErr: ErrRealityNoKey},
		{name: "reality without dest", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk"}}}, wantErr: ErrRealityNoDest},
		{name: "reality odd-length shortId", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk", Dest: "d:443", ShortID: "abc"}}}, wantSub: "invalid shortId"},
		{name: "reality non-hex shortId", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk", Dest: "d:443", ShortID: "zzzz"}}}, wantSub: "invalid shortId"},
		{name: "reality overlong shortId", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecReality, Reality: &Reality{PublicKey: "pk", Dest: "d:443", ShortIDs: []string{"0123456789abcdef01"}}}}, wantSub: "invalid shortId"},
		{name: "unknown fingerprint", node: Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: uuid,
			Transport: Transport{Network: NetTCP}, Security: Security{Type: SecTLS, Fingerprint: "netscape"}}, wantSub: "unknown uTLS fingerprint"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := c.node
			err := n.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error")
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("Validate() = %v, want errors.Is(%v)", err, c.wantErr)
			}
			if c.wantSub != "" && !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("Validate() = %v, want it to mention %q", err, c.wantSub)
			}
		})
	}
}

func TestValidateAcceptsRealityViaExplicitSNIAndEmptyShortID(t *testing.T) {
	// serverNames/dest may both be empty as long as an explicit SNI is set, and
	// an empty shortId (match-any) must not be rejected by the hex check.
	n := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Transport: Transport{Network: NetTCP},
		Security:  Security{Type: SecReality, ServerName: "www.apple.com", Reality: &Reality{PublicKey: "pk", ShortID: "", ShortIDs: []string{""}}}}
	if err := n.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	// REALITY over a bare (unset) network is legal too.
	bare := &Node{Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Security: Security{Type: SecReality, ServerName: "www.apple.com", Reality: &Reality{PrivateKey: "sk"}}}
	if err := bare.Validate(); err != nil {
		t.Fatalf("Validate() on an unset network = %v, want nil", err)
	}
}

func TestValidateAllowsOpenSocksAndHTTP(t *testing.T) {
	for _, p := range []Protocol{ProtoSOCKS, ProtoHTTP} {
		n := &Node{Protocol: p, Address: "a", Port: 1080}
		if err := n.Validate(); err != nil {
			t.Errorf("%s: an open proxy is legal, got %v", p, err)
		}
	}
}

// ---------------------------------------------------------------------------
// small accessors
// ---------------------------------------------------------------------------

func TestSNIPrecedence(t *testing.T) {
	cases := []struct {
		name string
		node Node
		want string
	}{
		{"explicit sni wins", Node{Address: "1.2.3.4", Security: Security{ServerName: "sni.example"}, Transport: Transport{Host: "host.example"}}, "sni.example"},
		{"host is the fallback", Node{Address: "1.2.3.4", Transport: Transport{Host: "host.example"}}, "host.example"},
		{"address is the last resort", Node{Address: "1.2.3.4"}, "1.2.3.4"},
	}
	for _, c := range cases {
		if got := c.node.SNI(); got != c.want {
			t.Errorf("%s: SNI() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestUsesTransportAndIsQUICBased(t *testing.T) {
	transportProtos := map[Protocol]bool{
		ProtoVLESS: true, ProtoVMess: true, ProtoTrojan: true,
		ProtoShadowsocks: true, ProtoSOCKS: true, ProtoHTTP: true,
	}
	for _, p := range append(AllProtocols(), ProtoAmneziaWG) {
		if got := p.UsesTransport(); got != transportProtos[p] {
			t.Errorf("%s.UsesTransport() = %v, want %v", p, got, transportProtos[p])
		}
		wantQUIC := p == ProtoHysteria2 || p == ProtoTUIC
		if got := p.IsQUICBased(); got != wantQUIC {
			t.Errorf("%s.IsQUICBased() = %v, want %v", p, got, wantQUIC)
		}
	}
}

func TestIsPlaintextOnlyForCleartextTransportProtocols(t *testing.T) {
	if !(&Node{Protocol: ProtoVLESS, Security: Security{Type: SecNone}}).IsPlaintext() {
		t.Error("vless with security=none is plaintext")
	}
	if (&Node{Protocol: ProtoVLESS, Security: Security{Type: SecTLS}}).IsPlaintext() {
		t.Error("vless with TLS is not plaintext")
	}
	// Hysteria2 carries its own encryption, so security=none is not "plaintext".
	if (&Node{Protocol: ProtoHysteria2, Security: Security{Type: SecNone}}).IsPlaintext() {
		t.Error("hysteria2 must not be reported as plaintext")
	}
}

func TestEffectiveClientAddressPrefersDomain(t *testing.T) {
	n := &Node{Address: "203.0.113.5", Domain: "  vpn.example.com  "}
	if got := n.EffectiveClientAddress(); got != "vpn.example.com" {
		t.Errorf("EffectiveClientAddress() = %q, want the trimmed domain", got)
	}
	n.Domain = "   "
	if got := n.EffectiveClientAddress(); got != "203.0.113.5" {
		t.Errorf("EffectiveClientAddress() = %q, want the node address", got)
	}
}

func TestApplyDomainCascadeCoversEveryHostBearingTransport(t *testing.T) {
	for _, net := range []Network{NetWS, NetHTTPUpgrade, NetH2, NetGRPC, NetXHTTP} {
		n := &Node{Protocol: ProtoVLESS, Address: "0.0.0.0", Port: 443, Domain: "vpn.example.com",
			Transport: Transport{Network: net}, Security: Security{Type: SecTLS}}
		if !n.ApplyDomainCascade() {
			t.Fatalf("%s: cascade returned false", net)
		}
		if n.Transport.Host != "vpn.example.com" {
			t.Errorf("%s: Host = %q, want the domain", net, n.Transport.Host)
		}
	}
	// TCP has no virtual-host concept, so the cascade leaves it alone.
	tcp := &Node{Protocol: ProtoVLESS, Domain: "vpn.example.com", Transport: Transport{Network: NetTCP}, Security: Security{Type: SecTLS}}
	tcp.ApplyDomainCascade()
	if tcp.Transport.Host != "" {
		t.Errorf("tcp Host = %q, want untouched", tcp.Transport.Host)
	}
	if tcp.Domain != "vpn.example.com" {
		t.Errorf("domain = %q, want stored trimmed", tcp.Domain)
	}
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

func TestCloneIsDeep(t *testing.T) {
	orig := &Node{
		Protocol: ProtoVLESS, Address: "a", Port: 443, UUID: "u",
		Transport: Transport{Network: NetWS, Headers: map[string]string{"X": "1"}, H2Hosts: []string{"h1"},
			HeaderObfs: &Header{Type: "http"}, XMux: &XMux{MaxConcurrency: "8"}},
		Security: Security{Type: SecReality, ALPN: []string{"h2"}, PinSHA256: []string{"pin"},
			Reality: &Reality{PublicKey: "pk", ServerNames: []string{"s"}, ShortIDs: []string{"00"}}, ECH: &ECH{Enabled: true}},
		Multiplex: &Multiplex{Enabled: true, Brutal: &Brutal{Enabled: true, UpMbps: 50}},
		Hysteria2: &Hysteria2Options{UpMbps: 1}, TUIC: &TUICOptions{HeartbeatSeconds: 1},
		AnyTLS:    &AnyTLSOptions{PaddingScheme: []string{"a"}},
		WireGuard: &WireGuardOptions{LocalAddress: []string{"10.0.0.1/24"}, AllowedIPs: []string{"0.0.0.0/0"}, Reserved: []int{1, 2, 3}},
		AmneziaWG: &AmneziaWGOptions{WireGuardOptions: WireGuardOptions{LocalAddress: []string{"10.1.0.1/24"}, AllowedIPs: []string{"::/0"}, Reserved: []int{4, 5, 6}}, Jc: 8},
		ShadowTLS: &ShadowTLSOptions{Password: "hs"}, SSH: &SSHOptions{User: "root", HostKeyAlgorithms: []string{"ssh-ed25519"}},
		Brook: &BrookOptions{Mode: "server"}, ForgeDNS: &ForgeDNSOptions{Zone: "z"},
		SSPlugin: &SSPluginOptions{Name: "obfs-local"},
	}
	c := orig.Clone()
	if !reflect.DeepEqual(orig, c) {
		t.Fatal("Clone() is not equal to the original")
	}

	// Mutate every independently-allocated part of the clone.
	c.Transport.Headers["X"] = "mutated"
	c.Transport.H2Hosts[0] = "mutated"
	c.Transport.HeaderObfs.Type = "mutated"
	c.Transport.XMux.MaxConcurrency = "mutated"
	c.Security.ALPN[0] = "mutated"
	c.Security.PinSHA256[0] = "mutated"
	c.Security.Reality.ServerNames[0] = "mutated"
	c.Security.Reality.ShortIDs[0] = "ff"
	c.Security.Reality.PublicKey = "mutated"
	c.Security.ECH.Enabled = false
	c.Multiplex.Brutal.UpMbps = 999
	c.Hysteria2.UpMbps = 999
	c.TUIC.HeartbeatSeconds = 999
	c.AnyTLS.PaddingScheme[0] = "mutated"
	c.WireGuard.LocalAddress[0] = "mutated"
	c.WireGuard.AllowedIPs[0] = "mutated"
	c.WireGuard.Reserved[0] = 9
	c.AmneziaWG.LocalAddress[0] = "mutated"
	c.AmneziaWG.AllowedIPs[0] = "mutated"
	c.AmneziaWG.Reserved[0] = 9
	c.AmneziaWG.Jc = 999
	c.ShadowTLS.Password = "mutated"
	c.SSH.HostKeyAlgorithms[0] = "mutated"
	c.Brook.Mode = "mutated"
	c.ForgeDNS.Zone = "mutated"
	c.SSPlugin.Name = "mutated"

	// None of it may have reached the original.
	if orig.Transport.Headers["X"] != "1" || orig.Transport.H2Hosts[0] != "h1" ||
		orig.Transport.HeaderObfs.Type != "http" ||
		orig.Transport.XMux.MaxConcurrency != "8" {
		t.Error("Clone aliased the transport")
	}
	if orig.Security.ALPN[0] != "h2" || orig.Security.PinSHA256[0] != "pin" ||
		orig.Security.Reality.ServerNames[0] != "s" || orig.Security.Reality.ShortIDs[0] != "00" ||
		orig.Security.Reality.PublicKey != "pk" || !orig.Security.ECH.Enabled {
		t.Error("Clone aliased the security block")
	}
	if orig.Multiplex.Brutal.UpMbps != 50 || orig.Hysteria2.UpMbps != 1 || orig.TUIC.HeartbeatSeconds != 1 ||
		orig.AnyTLS.PaddingScheme[0] != "a" {
		t.Error("Clone aliased a protocol extension block")
	}
	if orig.WireGuard.LocalAddress[0] != "10.0.0.1/24" || orig.WireGuard.AllowedIPs[0] != "0.0.0.0/0" || orig.WireGuard.Reserved[0] != 1 {
		t.Error("Clone aliased the wireguard block")
	}
	if orig.AmneziaWG.LocalAddress[0] != "10.1.0.1/24" || orig.AmneziaWG.AllowedIPs[0] != "::/0" ||
		orig.AmneziaWG.Reserved[0] != 4 || orig.AmneziaWG.Jc != 8 {
		t.Error("Clone aliased the amneziawg block")
	}
	if orig.ShadowTLS.Password != "hs" || orig.SSH.HostKeyAlgorithms[0] != "ssh-ed25519" ||
		orig.Brook.Mode != "server" || orig.ForgeDNS.Zone != "z" || orig.SSPlugin.Name != "obfs-local" {
		t.Error("Clone aliased a leaf options block")
	}
}

func TestCloneNil(t *testing.T) {
	var n *Node
	if n.Clone() != nil {
		t.Fatal("Clone() of a nil node must be nil")
	}
}

func TestCloneKeepsNilCollectionsNil(t *testing.T) {
	// Clone must not turn a nil header map into an empty one; that would break
	// reflect.DeepEqual in the round-trip property test.
	orig := &Node{Protocol: ProtoVLESS, Address: "a", Port: 1, UUID: "u"}
	c := orig.Clone()
	if c.Transport.Headers != nil {
		t.Error("nil Headers became non-nil after Clone")
	}
	if c.Transport.H2Hosts != nil {
		t.Error("nil H2Hosts became non-nil after Clone")
	}
	if c.Security.ALPN != nil {
		t.Error("nil ALPN became non-nil after Clone")
	}
}

// ---------------------------------------------------------------------------
// low-level helpers
// ---------------------------------------------------------------------------

func TestIsHex(t *testing.T) {
	for _, s := range []string{"0", "abcdef", "ABCDEF", "0123456789"} {
		if !isHex(s) {
			t.Errorf("isHex(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "g", "0x1", "ab cd", "zz"} {
		if isHex(s) {
			t.Errorf("isHex(%q) = true, want false", s)
		}
	}
}

func TestContainsStr(t *testing.T) {
	hay := []string{"a", "b", "c"}
	if !containsStr(hay, "b") {
		t.Error("containsStr should find an existing element")
	}
	if containsStr(hay, "z") {
		t.Error("containsStr should not find a missing element")
	}
	if containsStr(nil, "a") {
		t.Error("containsStr on nil must be false")
	}
}

// REALITY decides on the SERVER's terms: the inbound accepts a ClientHello only
// if its SNI is one of reality.serverNames. A share link built from
// Security.ServerName when that name is not in the list advertises an SNI the
// server refuses, and the client reports "reality verification failed" while the
// inbound is perfectly healthy.
//
// Measured on a live panel: an imported inbound carried
// server_name=slashdot.org with serverNames=[www.cloudflare.com]. The link the
// panel handed out could not connect; the same client with www.cloudflare.com
// connected immediately.
func TestRealitySNIComesFromWhatTheServerWillAccept(t *testing.T) {
	n := &Node{
		Protocol: ProtoVLESS, Address: "203.0.113.5", Port: 443,
		Security: Security{
			Type: SecReality, ServerName: "slashdot.org",
			Reality: &Reality{ServerNames: []string{"www.cloudflare.com"}, PublicKey: "pk"},
		},
	}
	if got := n.SNI(); got != "www.cloudflare.com" {
		t.Errorf("SNI() = %q; the server only accepts %v, so that link cannot connect",
			got, n.Security.Reality.ServerNames)
	}

	// An SNI that IS in the list is the operator's choice and must be kept —
	// several borrowed names is the normal REALITY setup.
	n.Security.ServerName = "www.microsoft.com"
	n.Security.Reality.ServerNames = []string{"www.cloudflare.com", "www.microsoft.com"}
	if got := n.SNI(); got != "www.microsoft.com" {
		t.Errorf("SNI() = %q, want the operator's own choice when the server accepts it", got)
	}

	// Non-REALITY is untouched: TLS has no serverNames list to disagree with.
	tls := &Node{Protocol: ProtoVLESS, Address: "203.0.113.5", Port: 443,
		Security: Security{Type: SecTLS, ServerName: "panel.example.com"}}
	if got := tls.SNI(); got != "panel.example.com" {
		t.Errorf("a TLS node's SNI became %q", got)
	}
}
