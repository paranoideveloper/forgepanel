package api

import (
	"net/url"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func TestApplyPattern(t *testing.T) {
	in := "vless://u@1.2.3.4:443?security=tls&type=ws&encryption=none#Berlin"
	out := applyPattern(in)
	// The three unsafe-uTLS params must be present and correctly decodable.
	q, _ := url.ParseQuery(out[strings.IndexByte(out, '?')+1 : strings.IndexByte(out, '#')])
	if q.Get("fp") != "unsafe" {
		t.Fatalf("fp = %q", q.Get("fp"))
	}
	if !strings.Contains(q.Get("cs"), "TLS_AES_256_GCM_SHA384") || strings.Count(q.Get("cs"), ":") != 12 {
		t.Fatalf("cs wrong: %q", q.Get("cs"))
	}
	if !strings.Contains(q.Get("fm"), `"maxSplit":"355"`) {
		t.Fatalf("fm did not round-trip: %q", q.Get("fm"))
	}
	if !strings.HasSuffix(out, "#Berlin") {
		t.Fatalf("remark lost: %s", out)
	}

	// A non-TLS link is left exactly as-is (fp=unsafe without a TLS layer is
	// meaningless and would break older clients).
	noTLS := "vless://u@1.2.3.4:80?security=none&type=tcp#x"
	if applyPattern(noTLS) != noTLS {
		t.Fatal("non-tls link must be untouched")
	}
	// base64 VMess (no query) is skipped.
	if applyPattern("vmess://eyJ2IjoiMiJ9") != "vmess://eyJ2IjoiMiJ9" {
		t.Fatal("base64 vmess must be untouched")
	}
}

func TestPlainLinksMode(t *testing.T) {
	nodes := []*model.Node{{
		Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: "u-1",
		Remark: "n1", Transport: model.Transport{Network: "ws", Path: "/x"},
		Security: model.Security{Type: model.SecTLS, ServerName: "a.example"},
	}}
	if n := strings.Count(plainLinksMode(nodes, patternOff), "fp=unsafe"); n != 0 {
		t.Fatalf("off: unexpected pattern (%d)", n)
	}
	if n := strings.Count(plainLinksMode(nodes, patternOnly), "fp=unsafe"); n != 1 {
		t.Fatalf("only: want 1 patterned link, got %d", n)
	}
	both := plainLinksMode(nodes, patternBoth)
	if lines := strings.Count(strings.TrimSpace(both), "\n") + 1; lines != 2 {
		t.Fatalf("both: want 2 links, got %d", lines)
	}
	if !strings.Contains(both, "Patt") || strings.Count(both, "fp=unsafe") != 1 {
		t.Fatalf("both: want one normal + one patterned tagged link:\n%s", both)
	}
}

func TestParsePatternMode(t *testing.T) {
	cases := map[string]patternMode{"1": patternOnly, "on": patternOnly, "both": patternBoth, "off": patternOff, "": patternOff}
	for in, want := range cases {
		if got := parsePatternMode(in, patternOff); got != want {
			t.Errorf("parsePatternMode(%q) = %v, want %v", in, got, want)
		}
	}
}
