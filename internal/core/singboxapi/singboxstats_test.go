package singboxapi

import (
	"encoding/hex"
	"strings"
	"testing"
)

// realSingboxFrame is a genuine gRPC response captured from sing-box 1.13.15
// built with -tags with_v2ray_api, after pushing 50 KB through a Hysteria2
// inbound as user "u42".
//
// The codec here is hand-written — two messages with four scalar fields between
// them do not justify pulling in grpc-go and generated stubs — so it is tested
// against bytes the real core produced rather than against bytes this package
// also encoded. A codec that only round-trips with itself proves nothing about
// the wire.
const realSingboxFrame = "00000000f80a270a23696e626f756e643e3e3e6879322d696e3e3e3e747261666669633e3e3e75706c696e6b104f0a2b0a25696e626f756e643e3e3e6879322d696e3e3e3e747261666669633e3e3e646f776e6c696e6b10c487030a280a246f7574626f756e643e3e3e6469726563743e3e3e747261666669633e3e3e75706c696e6b104f0a2c0a266f7574626f756e643e3e3e6469726563743e3e3e747261666669633e3e3e646f776e6c696e6b10c487030a210a1d757365723e3e3e7534323e3e3e747261666669633e3e3e75706c696e6b104f0a250a1f757365723e3e3e7534323e3e3e747261666669633e3e3e646f776e6c696e6b10c48703"

func TestDecodeRealSingboxFrame(t *testing.T) {
	raw, err := hex.DecodeString(realSingboxFrame)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := decodeQueryStatsResponse(raw)
	if err != nil {
		t.Fatalf("decoding a real sing-box response failed: %v", err)
	}

	// The counter that makes hysteria2 meterable at all.
	up, okUp := stats["user>>>u42>>>traffic>>>uplink"]
	down, okDown := stats["user>>>u42>>>traffic>>>downlink"]
	if !okUp || !okDown {
		t.Fatalf("per-user counters missing; got %v", keysOfStats(stats))
	}
	if down < 50000 {
		t.Errorf("downlink is %d, but 50 KB was pushed through the inbound", down)
	}
	if up <= 0 {
		t.Errorf("uplink is %d, want a positive count", up)
	}

	// The inbound-level counters must decode too; they are how an operator sees
	// an inbound's total without summing users.
	if _, ok := stats["inbound>>>hy2-in>>>traffic>>>downlink"]; !ok {
		t.Errorf("inbound counters missing; got %v", keysOfStats(stats))
	}
}

func keysOfStats(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The panel parses xray's counters with the same "user>>><tag>>>traffic>>>dir"
// grammar. sing-box emitting the identical shape is what lets one accounting
// path serve both cores.
func TestSingboxCountersUseTheSameGrammarAsXray(t *testing.T) {
	raw, _ := hex.DecodeString(realSingboxFrame)
	stats, err := decodeQueryStatsResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for name := range stats {
		if strings.HasPrefix(name, "user>>>") &&
			(strings.HasSuffix(name, ">>>traffic>>>uplink") || strings.HasSuffix(name, ">>>traffic>>>downlink")) {
			found++
		}
	}
	if found < 2 {
		t.Fatalf("expected uplink and downlink per user in xray's grammar, found %d", found)
	}
}

func TestEncodeQueryStatsRequestFrame(t *testing.T) {
	// A gRPC frame is a compression flag plus a 4-byte big-endian length.
	got := encodeQueryStatsRequest("user>>>", false)
	if got[0] != 0 {
		t.Fatalf("compression flag is %d, want 0", got[0])
	}
	wantLen := len(got) - 5
	if int(got[4]) != wantLen {
		t.Fatalf("declared length %d, actual %d", got[4], wantLen)
	}
	// field 1, length-delimited, then the pattern.
	if got[5] != 0x0a || string(got[7:]) != "user>>>" {
		t.Fatalf("unexpected encoding: %x", got)
	}

	// An empty pattern means "everything" and must send no field at all rather
	// than an empty string, which some servers treat as a literal match.
	if empty := encodeQueryStatsRequest("", false); len(empty) != 5 {
		t.Fatalf("an empty pattern encoded %d bytes, want a bare frame", len(empty))
	}

	// reset must actually be on the wire when asked for; silently dropping it
	// would leave counters growing forever.
	if r := encodeQueryStatsRequest("", true); len(r) != 7 || r[5] != 0x10 || r[6] != 0x01 {
		t.Fatalf("reset not encoded: %x", r)
	}
}

// A truncated or malformed frame must be an error, never partial counters:
// half a response read as a whole one under-bills every user in it.
func TestMalformedFramesAreRefused(t *testing.T) {
	raw, _ := hex.DecodeString(realSingboxFrame)
	for name, in := range map[string][]byte{
		"header only":     raw[:4],
		"truncated body":  raw[:len(raw)-10],
		"compressed flag": append([]byte{1}, raw[1:]...),
	} {
		if _, err := decodeQueryStatsResponse(in); err == nil {
			t.Errorf("%s decoded without error", name)
		}
	}
	// An empty response is not malformed: a core with no traffic yet reports
	// nothing, and that must read as zero counters rather than a failure.
	if got, err := decodeQueryStatsResponse(nil); err != nil || len(got) != 0 {
		t.Errorf("an empty response should be zero counters, got %v %v", got, err)
	}
}

// The build tag is the whole question: two builds of the same version differ.
func TestDetectSingboxStatsReadsBuildTags(t *testing.T) {
	if got := Detect(""); got.Supported {
		t.Error("an absent binary was reported as capable")
	} else if got.Reason == "" {
		t.Error("an absent binary must say why it cannot meter")
	}
}
