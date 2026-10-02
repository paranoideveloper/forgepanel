package model

import (
	"net/netip"
	"strings"
)

// Xray v26.7.11 refuses, at config load, a VLESS or Trojan OUTBOUND that carries
// no transport security to a public address (infra/conf/xray.go
// validateOutboundTransportSecurity). It is a whole-config failure: one such
// outbound and the core starts nothing. These are its exact private lists
// (common/geodata/consts.go); anything outside them is "public".
var (
	xrayPrivatePrefixes = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::/127", "fc00::/7", "fe80::/10", "ff00::/8",
	)
	xrayPrivateDomains = []string{
		"lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal",
	}
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

// xrayPrivateAddress mirrors Xray's requiresTransportSecurity, inverted.
func xrayPrivateAddress(addr string) bool {
	addr = strings.Trim(addr, "[]")
	if ip, err := netip.ParseAddr(addr); err == nil {
		ip = ip.Unmap()
		for _, p := range xrayPrivatePrefixes {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	d := strings.TrimSuffix(strings.ToLower(addr), ".")
	for _, p := range xrayPrivateDomains {
		if d == p || strings.HasSuffix(d, "."+p) {
			return true
		}
	}
	return false
}

// XrayRefusesAsOutbound reports whether Xray v26.7.11+ would refuse n as an
// outbound: VLESS without TLS, REALITY or VLESS encryption, or Trojan without
// TLS, pointed at a public address. The same node is fine as an INBOUND.
func XrayRefusesAsOutbound(n *Node) bool {
	if n.Security.Type == SecTLS || n.Security.Type == SecReality {
		return false
	}
	switch n.Protocol {
	case ProtoVLESS:
		if n.Encryption != "" && n.Encryption != "none" {
			return false
		}
	case ProtoTrojan:
	default:
		return false
	}
	return !xrayPrivateAddress(n.Address)
}
