package porthop

import (
	"testing"
)

func TestPorthop_ManagerAndBackend(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatalf("New returned nil")
	}

	backend := m.Backend()
	if backend != BackendNFT && backend != BackendIptables && backend != BackendNone {
		t.Fatalf("unexpected backend: %s", backend)
	}

	netAdmin := HasNetAdmin()
	_ = netAdmin

	spec, err := ParseSpec("10000-10010,20000")
	if err != nil || len(spec) == 0 {
		t.Fatalf("ParseSpec failed: %v", err)
	}

	if spec[0].String() == "" {
		t.Fatalf("empty PortRange.String()")
	}

	rules := m.Rules()
	_ = rules

	cmds := ManualCommands(BackendIptables, 443, "10000-10010")
	if len(cmds) == 0 {
		t.Fatalf("ManualCommands returned empty slice")
	}
}

func TestPorthop_ChainName(t *testing.T) {
	cn := chainName(443)
	if cn != "hop_443" {
		t.Fatalf("expected 'hop_443', got %q", cn)
	}
}
