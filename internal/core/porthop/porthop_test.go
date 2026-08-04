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
