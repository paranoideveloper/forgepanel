package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/diag"
)

func TestValidateInboundReportsFindings(t *testing.T) {
	s := dbServerT(t)
	r := gin.New()
	r.POST("/api/admin/inbounds/validate", s.handleValidateInbound)
	// A plaintext-as-secure inbound (security none over tcp) must be flagged.
	rec := dreq(t, r, "POST", "/api/admin/inbounds/validate",
		`{"protocol":"vless","port":80,"transport":{"network":"tcp"},"security":{"type":"none"}}`)
	if rec.Code != 200 {
		t.Fatalf("validate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK       bool `json:"ok"`
		Findings []struct {
			Code    string `json:"code"`
			TitleFA string `json:"title_fa"`
		} `json:"findings"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	found := false
	for _, f := range out.Findings {
		if f.Code == "FP-TLS-002" {
			found = true
			if f.TitleFA == "" {
				t.Error("finding missing Farsi text")
			}
		}
	}
	if !found {
		t.Fatalf("plaintext-as-secure not flagged: %+v", out.Findings)
	}
}

func TestDoctorRunsBattery(t *testing.T) {
	s := dbServerT(t)
	r := gin.New()
	r.GET("/api/admin/doctor", s.handleDoctor)
	rec := dreq(t, r, "GET", "/api/admin/doctor", "")
	if rec.Code != 200 {
		t.Fatalf("doctor: %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"system_findings", "inbounds", "health", "ok"} {
		if _, present := out[k]; !present {
			t.Fatalf("doctor report missing %q", k)
		}
	}
}

// --- host clock discipline -------------------------------------------------

// fakeNTPServer answers SNTP requests with a clock that is `offset` away from
// this machine's, so the skew the doctor reports is a value the test chose.
func fakeNTPServer(t *testing.T, offset time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			resp := make([]byte, 48)
			resp[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
			resp[1] = 2    // stratum 2 — anything but 0, which is kiss-o'-death
			now := timeToNTP(time.Now().Add(offset))
			copy(resp[24:32], buf[40:48]) // origin = the client's transmit stamp
			binary.BigEndian.PutUint64(resp[32:40], now)
			binary.BigEndian.PutUint64(resp[40:48], now)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// TestDoctorReportsClockSkew is the regression guard for FP-OBS-016: clockSkew()
// was a hardcoded `return 0`, so the `skew > 5s` branch in handleDoctor could
// never be taken and FP-CLOCK-001 was dead code that reported clock health it
// had never measured. With a time source 45s ahead the doctor must say so.
func TestDoctorReportsClockSkew(t *testing.T) {
	srv := fakeNTPServer(t, 45*time.Second)
	old := ntpServers
	ntpServers = []string{srv}
	t.Cleanup(func() { ntpServers = old })

	s := dbServerT(t)
	r := gin.New()
	r.GET("/api/admin/doctor", s.handleDoctor)
	rec := dreq(t, r, "GET", "/api/admin/doctor", "")
	if rec.Code != 200 {
		t.Fatalf("doctor: %d", rec.Code)
	}
	var out struct {
		OK       bool `json:"ok"`
		Findings []struct {
			Code     string `json:"code"`
			Detail   string `json:"detail"`
			TitleFA  string `json:"title_fa"`
			Severity string `json:"severity"`
		} `json:"system_findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	var got *string
	for i, f := range out.Findings {
		if f.Code == "FP-CLOCK-001" {
			got = &out.Findings[i].Detail
			if f.TitleFA == "" {
				t.Error("FP-CLOCK-001 shipped without Farsi text")
			}
		}
	}
	if got == nil {
		t.Fatalf("45s of clock skew did not raise FP-CLOCK-001: %+v", out.Findings)
	}
	if !strings.Contains(*got, srv) {
		t.Errorf("finding does not name the time source it measured against: %q", *got)
	}
	if out.OK {
		t.Error("doctor reported ok=true with a critical clock finding")
	}
}

// TestDoctorStaysQuietWhenClockIsGood: the check must not cry wolf. A time
// source that agrees with us produces no clock finding at all.
func TestDoctorStaysQuietWhenClockIsGood(t *testing.T) {
	srv := fakeNTPServer(t, 0)
	old := ntpServers
	ntpServers = []string{srv}
	t.Cleanup(func() { ntpServers = old })

	for _, f := range clockFindings(context.Background()) {
		if f.Code == "FP-CLOCK-001" || f.Code == "FP-CLOCK-003" {
			t.Fatalf("a synchronised clock raised %s: %+v", f.Code, f)
		}
	}
}

// TestClockUnreachableSourceIsReportedAsUnknown: with no reachable time source
// and no local daemon to vouch for the clock, the doctor must say it could not
// check rather than stay silent — silence reads as a pass, which is the exact
// lie the `return 0` stub told.
func TestClockUnreachableSourceIsReportedAsUnknown(t *testing.T) {
	// A port nothing is listening on: the UDP read times out.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	pc.Close()

	oldServers, oldSync := ntpServers, timeSyncProbe
	ntpServers = []string{dead}
	timeSyncProbe = func(context.Context) (bool, bool) { return false, false }
	t.Cleanup(func() { ntpServers, timeSyncProbe = oldServers, oldSync })

	fs := clockFindings(context.Background())
	if !hasCode(fs, "FP-CLOCK-003") {
		t.Fatalf("unmeasurable clock did not raise FP-CLOCK-003: %+v", fs)
	}
	if hasCode(fs, "FP-CLOCK-001") {
		t.Fatalf("an unmeasurable clock must not be reported as skewed: %+v", fs)
	}
}

// TestClockUnsyncedDaemonIsReported: the host itself saying "NTPSynchronized=no"
// is enough to warn, even while the current offset is still inside tolerance —
// an undisciplined clock is tomorrow's FP-CLOCK-001.
func TestClockUnsyncedDaemonIsReported(t *testing.T) {
	srv := fakeNTPServer(t, 0)
	oldServers, oldSync := ntpServers, timeSyncProbe
	ntpServers = []string{srv}
	timeSyncProbe = func(context.Context) (bool, bool) { return false, true }
	t.Cleanup(func() { ntpServers, timeSyncProbe = oldServers, oldSync })

	fs := clockFindings(context.Background())
	if !hasCode(fs, "FP-CLOCK-002") {
		t.Fatalf("NTPSynchronized=no did not raise FP-CLOCK-002: %+v", fs)
	}
}

func TestParseNTPSynchronized(t *testing.T) {
	cases := []struct {
		in           string
		want, wantOK bool
	}{
		{"NTPSynchronized=yes\n", true, true},
		{"NTPSynchronized=no\n", false, true},
		{"Timezone=UTC\nNTPSynchronized=yes\n", true, true},
		// Older systemd omits the property entirely rather than answering "no";
		// reading that absence as "not synced" would warn on every such host.
		{"Timezone=UTC\n", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		got, ok := parseNTPSynchronized(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("parseNTPSynchronized(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// TestNTPTimestampRoundTrip guards the wire encoding: a sign or shift error here
// would manufacture a skew of decades and fire FP-CLOCK-001 on healthy hosts.
func TestNTPTimestampRoundTrip(t *testing.T) {
	want := time.Unix(1735689600, 500_000_000)
	got := ntpToTime(timeToNTP(want))
	if d := got.Sub(want); d > time.Millisecond || d < -time.Millisecond {
		t.Fatalf("NTP timestamp round trip drifted by %s (%s -> %s)", d, want, got)
	}
	if !ntpToTime(0).IsZero() {
		t.Error("an all-zero NTP timestamp must decode as the zero time, not 1900")
	}
}

func hasCode(fs []diag.Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}
