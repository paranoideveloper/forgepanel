package connkill

import (
	"strings"
	"testing"
)

func TestArgsFilterByRemoteAddressAndLocalPort(t *testing.T) {
	got, err := Args(Target{IPs: []string{"198.51.100.7", "[2001:db8::1]", "::ffff:203.0.113.9"}, Ports: []int{8443, 443, 443}})
	if err != nil {
		t.Fatal(err)
	}
	want := "-K -t -n state established ( dst 198.51.100.7 or dst 2001:db8::1 or dst 203.0.113.9 ) and ( sport = :443 or sport = :8443 )"
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
}

// Both halves are required: an address alone would cut the administrator's own
// SSH session from the same address, and a port alone would cut every user.
func TestArgsRefuseAnIncompleteTarget(t *testing.T) {
	for _, tg := range []Target{
		{IPs: []string{"198.51.100.7"}},
		{Ports: []int{443}},
		{IPs: []string{"not-an-ip"}, Ports: []int{443}},
		{IPs: []string{"198.51.100.7"}, Ports: []int{0, 70000}},
	} {
		if _, err := Args(tg); err == nil {
			t.Errorf("accepted %+v", tg)
		}
	}
}

func TestCountClosedReadsSSOutput(t *testing.T) {
	out := "Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n" +
		"0      0          127.0.0.1:31701    127.0.0.1:48850\n" +
		"0      0      [::ffff:10.0.0.1]:443  [::ffff:198.51.100.7]:51000\n"
	if n := countClosed(out); n != 2 {
		t.Fatalf("countClosed = %d, want 2", n)
	}
	if n := countClosed("Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"); n != 0 {
		t.Fatalf("header only counted as %d", n)
	}
}
