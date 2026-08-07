package firewall

import "testing"

func TestParseAllowed(t *testing.T) {
	out := `Status: active

To                         Action      From
--                         ------      ----
22                         ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
3443/tcp                   ALLOW       Anywhere
3443/udp                   ALLOW       Anywhere
9999                       DENY        Anywhere
2053 (v6)                  ALLOW       Anywhere (v6)
`
	got := parseAllowed(out)
	for _, p := range []int{22, 443, 3443, 2053} {
		if !got[p] {
			t.Errorf("port %d should be parsed as allowed", p)
		}
	}
	if got[9999] {
		t.Error("port 9999 is DENY, must not be allowed")
	}
}

func TestReachabilityWithoutUFW(t *testing.T) {
	// On a host without ufw active, everything is reported reachable (we cannot
	// tell, and there is no ufw blocking) — never a false "blocked".
	if !ufwActive() {
		reach := Reachability()
		if !reach(12345) {
			t.Error("with no active ufw, ports must be reported reachable")
		}
	}
}
