package porthop

import "testing"

func TestParseSpec(t *testing.T) {
	ok := map[string]int{"20000-50000": 1, "443": 1, "20000-50000,60000-61000": 2, "1-65535": 1}
	for spec, n := range ok {
		r, err := ParseSpec(spec)
		if err != nil || len(r) != n {
			t.Errorf("ParseSpec(%q) = %v, %v; want %d ranges", spec, r, err, n)
		}
	}
	for _, bad := range []string{"", "50000-20000", "0-100", "100-70000", "abc", "10-", "-10"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Errorf("ParseSpec(%q) should have errored", bad)
		}
	}
}

func TestRuleHasOwnedCommentRequiresExactCommentField(t *testing.T) {
	good := `-A PREROUTING -p udp -m comment --comment "forgepanel-porthop-443" -j REDIRECT --to-ports 443`
	if !ruleHasOwnedComment(good, "forgepanel-porthop-") {
		t.Fatal("managed rule was not recognized")
	}
	bad := `-A PREROUTING -m comment --comment "unrelated-forgepanel-porthop-443" -j ACCEPT`
	if ruleHasOwnedComment(bad, "forgepanel-porthop-") {
		t.Fatal("substring match must not claim an unrelated rule")
	}
}

func TestConflicts(t *testing.T) {
	ranges, _ := ParseSpec("20000-30000")
	// listener 25000 is inside but excluded; 2053/443 outside; 22000 inside -> conflict.
	got := Conflicts(ranges, 25000, []int{443, 2053, 22000, 25000})
	if len(got) != 1 || got[0] != 22000 {
		t.Errorf("Conflicts = %v; want [22000]", got)
	}
}

func TestManualCommands(t *testing.T) {
	nft := ManualCommands(BackendNFT, 443, "20000-50000")
	if len(nft) < 3 {
		t.Fatalf("nft manual commands too short: %v", nft)
	}
	ipt := ManualCommands(BackendIptables, 443, "20000-50000")
	found := false
	for _, c := range ipt {
		if len(c) > 0 && c[0:8] == "iptables" {
			found = true
		}
	}
	if !found {
		t.Errorf("iptables manual commands missing: %v", ipt)
	}
}

func TestManagerAndBackend(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}

	backend := m.Backend()
	if backend != BackendNFT && backend != BackendIptables && backend != BackendNone {
		t.Fatalf("unexpected backend: %s", backend)
	}

	_ = HasNetAdmin()
	_ = m.ownedPorts()
	_ = m.Rules()
}

func TestPortRangeString(t *testing.T) {
	r1 := PortRange{Lo: 100, Hi: 200}
	if r1.String() != "100-200" {
		t.Fatalf("r1.String() = %q", r1.String())
	}

	r2 := PortRange{Lo: 443, Hi: 443}
	if r2.String() != "443" {
		t.Fatalf("r2.String() = %q", r2.String())
	}
}

func TestCleanAllAndSyncEdgeCases(t *testing.T) {
	m := New()
	_ = m.CleanupOwned()
	_ = m.Remove(9999)
	_ = m.Sync(map[int]string{9999: "20000-20005"})
}
