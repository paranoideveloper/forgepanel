package model

import "testing"

func TestApplyFrontSNI_realityXHTTP(t *testing.T) {
	n := &Node{
		Protocol:  ProtoVLESS,
		Address:   "203.0.113.13",
		Port:      8443,
		Transport: Transport{Network: NetXHTTP},
		Security:  Security{Type: SecReality, ServerName: "www.datadoghq.com"},
	}
	ApplyFront(n, "nobat.com", FrontSNI)
	if n.Security.ServerName != "nobat.com" {
		t.Fatalf("SNI not fronted: got %q", n.Security.ServerName)
	}
	if n.Transport.Host != "nobat.com" {
		t.Fatalf("Host header not fronted: got %q", n.Transport.Host)
	}
	if n.Address != "203.0.113.13" {
		t.Fatalf("real dial address must not change: got %q", n.Address)
	}
}

func TestApplyFrontCDN_plaintextVMessWS(t *testing.T) {
	n := &Node{
		Protocol:  ProtoVMess,
		Address:   "s3.example.org",
		Port:      2053,
		Transport: Transport{Network: NetWS, Path: "/vm"},
		Security:  Security{Type: SecNone},
	}
	ApplyFront(n, "taskulu.com", FrontCDN)
	if n.Transport.Host != "taskulu.com" {
		t.Fatalf("Host header not fronted: got %q", n.Transport.Host)
	}
	if n.Security.Type != SecNone || n.Security.ServerName != "" {
		t.Fatalf("CDN mode must not add TLS/SNI: type=%v sni=%q", n.Security.Type, n.Security.ServerName)
	}
	if n.Address != "s3.example.org" {
		t.Fatalf("real dial address must not change: got %q", n.Address)
	}
}

func TestApplyFrontSNI_visionTCPHasNoHost(t *testing.T) {
	n := &Node{
		Protocol:  ProtoVLESS,
		Address:   "91.99.20.251",
		Port:      443,
		Flow:      "xtls-rprx-vision",
		Transport: Transport{Network: NetTCP},
		Security:  Security{Type: SecReality, ServerName: "www.speedtest.net"},
	}
	ApplyFront(n, "aparat.com", FrontSNI)
	if n.Security.ServerName != "aparat.com" {
		t.Fatalf("SNI not fronted: got %q", n.Security.ServerName)
	}
	if n.Transport.Host != "" {
		t.Fatalf("tcp transport must not carry a Host header: got %q", n.Transport.Host)
	}
}

func TestApplyFrontNoneAndBlankAreNoops(t *testing.T) {
	mk := func() *Node {
		return &Node{Protocol: ProtoShadowsocks, Address: "91.99.20.251", Port: 9988,
			Transport: Transport{Network: NetWS, Host: "orig.example"}, Security: Security{Type: SecTLS, ServerName: "orig.example"}}
	}
	unchanged := func(n *Node, why string) {
		if n.Transport.Host != "orig.example" || n.Security.ServerName != "orig.example" {
			t.Fatalf("%s must be a no-op: host=%q sni=%q", why, n.Transport.Host, n.Security.ServerName)
		}
	}
	n1 := mk()
	ApplyFront(n1, "aparat.com", FrontNone)
	unchanged(n1, "FrontNone")
	n2 := mk()
	ApplyFront(n2, "", FrontSNI)
	unchanged(n2, "blank domain")
}

func TestParseFrontMode(t *testing.T) {
	cases := map[string]FrontMode{
		"": FrontNone, "none": FrontNone, "off": FrontNone,
		"cdn": FrontCDN, "domain-front": FrontCDN,
		"sni": FrontSNI, "anything-else": FrontSNI,
	}
	for in, want := range cases {
		if got := ParseFrontMode(in); got != want {
			t.Errorf("ParseFrontMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFancyThemesCatalogue(t *testing.T) {
	themes := FancyThemes()
	if len(themes) < 10 {
		t.Fatalf("expected a real catalogue, got %d", len(themes))
	}
	seen := map[string]bool{}
	for _, th := range themes {
		if th.ID == "" || th.Template == "" || th.Sample == "" {
			t.Errorf("theme %q has an empty field", th.ID)
		}
		if seen[th.ID] {
			t.Errorf("duplicate theme id %q", th.ID)
		}
		seen[th.ID] = true
		if want := "s3"; !contains(th.Sample, want) {
			t.Errorf("theme %q sample %q did not expand {NAME}", th.ID, th.Sample)
		}
	}
	if _, ok := FancyThemeByID("aparat-line"); !ok {
		t.Errorf("FancyThemeByID lost a known theme")
	}
	if _, ok := FancyThemeByID("nope"); ok {
		t.Errorf("FancyThemeByID returned an unknown theme")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
