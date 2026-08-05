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
	res := parseStatsQuery(js)
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
