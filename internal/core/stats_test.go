package core

import "testing"

func TestParseStatsQueryNumericAndString(t *testing.T) {
	// Modern Xray emits numeric "value"; older builds emit a string. Both, plus
	// zero / large / null / missing / malformed, must parse without losing data.
	js := []byte(`{"stat":[
		{"name":"user>>>alice>>>traffic>>>uplink","value":12345},
		{"name":"user>>>alice>>>traffic>>>downlink","value":"67890"},
		{"name":"user>>>bob>>>traffic>>>uplink","value":9223372036854775807},
		{"name":"user>>>bob>>>traffic>>>downlink","value":0},
		{"name":"user>>>carol>>>traffic>>>uplink"},
		{"name":"user>>>carol>>>traffic>>>downlink","value":null},
		{"name":"user>>>dave>>>traffic>>>uplink","value":"not-a-number"},
		{"name":"user>>>dave>>>traffic>>>downlink","value":"99999999999999999999999999"},
		{"name":"user>>>eve>>>traffic>>>uplink","value":500}
	]}`)
	res, skipped := parseStatsQuery(js)
	if skipped != 2 {
		t.Fatalf("dave's two malformed counters should be reported as skipped, got %d", skipped)
	}
	if res["alice"].Uplink != 12345 || res["alice"].Downlink != 67890 {
		t.Fatalf("alice: %+v", res["alice"])
	}
	if res["bob"].Uplink != 9223372036854775807 || res["bob"].Downlink != 0 {
		t.Fatalf("bob large/zero: %+v", res["bob"])
	}
	if res["carol"].Uplink != 0 || res["carol"].Downlink != 0 {
		t.Fatalf("carol null/missing should be 0: %+v", res["carol"])
	}
	// dave's malformed + overflow values are skipped, but the rest of the doc
	// still parsed (regression: the whole document used to be discarded).
	if res["dave"] != nil && (res["dave"].Uplink != 0 || res["dave"].Downlink != 0) {
		t.Fatalf("dave malformed should not set values: %+v", res["dave"])
	}
	if res["eve"].Uplink != 500 {
		t.Fatalf("eve after malformed entry should still parse: %+v", res["eve"])
	}
}

// TestStatsRejectsNegativeCounters: Xray traffic counters are monotonic byte
// totals. A negative value is corruption, and applying it would credit bytes
// back to the user and silently weaken quota enforcement.
func TestStatsRejectsNegativeCounters(t *testing.T) {
	for _, doc := range []string{
		`{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":-5}]}`,
		`{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":"-5"}]}`,
		`{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":-1e6}]}`,
	} {
		res, skipped := parseStatsQuery([]byte(doc))
		if skipped == 0 {
			t.Errorf("negative counter accepted: %s", doc)
		}
		if ut, ok := res["u1"]; ok && ut.Uplink < 0 {
			t.Errorf("negative counter applied (%d): %s", ut.Uplink, doc)
		}
	}
}

// TestStatsRejectsStructuredValues: an object or array where a counter belongs
// is malformed input, not a zero.
func TestStatsRejectsStructuredValues(t *testing.T) {
	for _, doc := range []string{
		`{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":{"n":1}}]}`,
		`{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":[1,2]}]}`,
	} {
		res, skipped := parseStatsQuery([]byte(doc))
		if skipped == 0 {
			t.Errorf("structured value accepted: %s", doc)
		}
		if ut, ok := res["u1"]; ok && ut.Uplink != 0 {
			t.Errorf("structured value produced %d: %s", ut.Uplink, doc)
		}
	}
}

// TestStatsPreservesExactInt64 guards against float64 rounding mis-billing a
// heavy user: 2^53+1 is not representable as a float64.
func TestStatsPreservesExactInt64(t *testing.T) {
	res, _ := parseStatsQuery([]byte(
		`{"stat":[{"name":"user>>>u1>>>traffic>>>uplink","value":9007199254740993}]}`))
	if got := res["u1"].Uplink; got != 9007199254740993 {
		t.Fatalf("large counter mangled: got %d", got)
	}
}

// TestStatsIgnoresNonUserCounters keeps inbound/outbound counters out of the
// per-user map.
func TestStatsIgnoresNonUserCounters(t *testing.T) {
	res, _ := parseStatsQuery([]byte(`{"stat":[
		{"name":"inbound>>>in-1>>>traffic>>>uplink","value":10},
		{"name":"user>>>u1>>>traffic>>>uplink","value":20}
	]}`))
	if len(res) != 1 || res["u1"] == nil {
		t.Fatalf("non-user counters leaked into per-user stats: %+v", res)
	}
}
