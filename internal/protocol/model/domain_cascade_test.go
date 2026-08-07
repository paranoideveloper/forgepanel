package model

import "testing"

func TestApplyDomainCascadeFillsBlanks(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "0.0.0.0", Port: 443, Domain: "vpn.example.com",
		Transport: Transport{Network: NetWS}, Security: Security{Type: SecTLS}}
	if !n.ApplyDomainCascade() {
		t.Fatal("cascade returned false for a domain-bearing node")
	}
	if n.Security.ServerName != "vpn.example.com" {
		t.Errorf("SNI not cascaded: %q", n.Security.ServerName)
	}
	if n.Transport.Host != "vpn.example.com" {
		t.Errorf("WS Host not cascaded: %q", n.Transport.Host)
	}
	if n.EffectiveClientAddress() != "vpn.example.com" {
		t.Errorf("client address should be the domain, got %q", n.EffectiveClientAddress())
	}
}

func TestApplyDomainCascadeRespectsOverrides(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Domain: "vpn.example.com",
		Transport: Transport{Network: NetWS, Host: "cdn.example.net"},
		Security:  Security{Type: SecTLS, ServerName: "sni.example.org"}}
	n.ApplyDomainCascade()
	if n.Security.ServerName != "sni.example.org" {
		t.Errorf("cascade overwrote an explicit SNI: %q", n.Security.ServerName)
	}
	if n.Transport.Host != "cdn.example.net" {
		t.Errorf("cascade overwrote an explicit Host: %q", n.Transport.Host)
	}
}

func TestApplyDomainCascadeLeavesRealityAlone(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Domain: "vpn.example.com",
		Transport: Transport{Network: NetTCP},
		Security:  Security{Type: SecReality, Reality: &Reality{ServerNames: []string{"www.microsoft.com"}}}}
	n.ApplyDomainCascade()
	if n.Security.ServerName == "vpn.example.com" {
		t.Error("cascade set an SNI on a REALITY inbound; REALITY borrows a foreign chain and must stay domain-free")
	}
	if len(n.Security.Reality.ServerNames) != 1 || n.Security.Reality.ServerNames[0] != "www.microsoft.com" {
		t.Errorf("cascade disturbed REALITY serverNames: %v", n.Security.Reality.ServerNames)
	}
}

func TestNoDomainReturnsFalseAndIsPlaintextDetected(t *testing.T) {
	n := &Node{Protocol: ProtoVLESS, Address: "203.0.113.5", Transport: Transport{Network: NetTCP}, Security: Security{Type: SecNone}}
	if n.ApplyDomainCascade() {
		t.Error("cascade returned true for a domain-free node")
	}
	if n.EffectiveClientAddress() != "203.0.113.5" {
		t.Errorf("client address should fall back to node address: %q", n.EffectiveClientAddress())
	}
	if !n.IsPlaintext() {
		t.Error("security=none over TCP must be detected as plaintext so the UI never shows it as secure")
	}
}
