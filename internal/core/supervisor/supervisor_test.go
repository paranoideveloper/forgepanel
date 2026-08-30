package supervisor

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The ring buffer holds an engine's recent output and is the only source for the
// crash hint the panel shows. It had a wraparound bug: snapshot sliced the
// backing array by INDEX, which is the newest window only until the buffer wraps
// — after that add overwrites from the start, the newest lines live at the low
// indices, and the slice returns a window from some arbitrary earlier moment.
//
// The symptom is a crash hint quoting a line unrelated to the crash, which is
// worse than no hint at all: it sends the operator after the wrong problem.

func TestRingReturnsTheNewestLinesAfterWraparound(t *testing.T) {
	r := newRing(8)
	// 22, deliberately NOT a multiple of 8.
	//
	// This number matters. An exact multiple wraps back to index 0, so the newest
	// entries land at the high indices and a naive index slice returns the right
	// answer by luck — the first version of this test used 24 and PASSED against
	// the bug it was written to catch. With 22 the newest four entries sit at
	// indices 2..5, and buf[4:8] returns two current lines followed by two that
	// are a whole lap old, in the wrong order.
	for i := 0; i < 22; i++ {
		r.add(fmt.Sprintf("line-%d", i))
	}
	got := r.snapshotN(4)
	want := []string{"line-18", "line-19", "line-20", "line-21"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (oldest first, newest last)", got, want)
		}
	}
}

func TestRingBeforeItIsFull(t *testing.T) {
	r := newRing(100)
	for i := 0; i < 5; i++ {
		r.add(fmt.Sprintf("l%d", i))
	}
	got := r.snapshotN(20)
	if len(got) != 5 {
		t.Fatalf("got %d lines, want the 5 that exist", len(got))
	}
	if got[0] != "l0" || got[4] != "l4" {
		t.Fatalf("got %v, want l0..l4 in order", got)
	}
}

func TestRingIsEmptyWhenNothingWasLogged(t *testing.T) {
	r := newRing(10)
	if got := r.snapshotN(20); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}

func TestRingSizeZeroDoesNotDivideByZero(t *testing.T) {
	// add does `r.n % r.size`. A zero size panics on the goroutine draining the
	// engine's output, taking the process's logs with it.
	r := newRing(0)
	r.add("x")
	r.add("y")
	if got := r.snapshotN(5); len(got) == 0 {
		t.Fatal("a minimum-size ring stored nothing")
	}
}

func TestRingIsSafeUnderConcurrentUse(t *testing.T) {
	// stdout and stderr are pumped on two goroutines while Status reads.
	r := newRing(64)
	var wg sync.WaitGroup
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r.add(fmt.Sprintf("g%d-%d", g, i))
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = r.snapshot()
		}
	}()
	wg.Wait()
}

// --- diagnosis -------------------------------------------------------------

// These are REAL messages, captured from a failing Xray 26 rather than written
// from memory. A signature that does not match what the core actually prints is
// worse than none: the panel looks like it has diagnostics and quietly falls
// back to raw text.

const (
	realPortInUse = "Failed to start: app/proxyman/inbound: failed to listen TCP on 52497 > " +
		"transport/internet: failed to listen on address: 127.0.0.1:52497 > " +
		"transport/internet/tcp: failed to listen TCP on 127.0.0.1:52497 > " +
		"listen tcp 127.0.0.1:52497: bind: address already in use"
	realPermissionDenied = "Failed to start: app/proxyman/inbound: failed to listen TCP on 80 > " +
		"transport/internet: failed to listen on address: 0.0.0.0:80 > " +
		"transport/internet/tcp: failed to listen TCP on 0.0.0.0:80 > " +
		"listen tcp 0.0.0.0:80: bind: permission denied"
	realMissingCert = "Failed to start: main: failed to load config files: [/tmp/cert.json] > " +
		"infra/conf: failed to build inbound config with tag in > infra/conf: Failed to build TLS config. > " +
		"infra/conf: failed to parse certificate > open /nonexistent/a.crt: no such file or directory"
	realBadGeosite = "Failed to start: main: failed to load config files: [/tmp/c.json] > " +
		"infra/conf: failed to build routing configuration > infra/conf: invalid field rule > " +
		"infra/conf: failed to parse domain rule: geosite:category-bittorrent > " +
		"infra/conf: failed to load geosite: CATEGORY-BITTORRENT > " +
		"code not found in geosite.dat: CATEGORY-BITTORRENT"
)

func TestDiagnosesRealFailures(t *testing.T) {
	cases := map[string]string{
		realPortInUse:        "already listening",
		realPermissionDenied: "not permitted to bind",
		realMissingCert:      "does not exist",
		realBadGeosite:       "geosite category",
	}
	for line, want := range cases {
		d, ok := Diagnose([]string{"Xray 26.2.6 started", line})
		if !ok {
			t.Errorf("no diagnosis for a real failure:\n%s", line)
			continue
		}
		if !strings.Contains(d.Cause, want) {
			t.Errorf("cause = %q, want something containing %q", d.Cause, want)
		}
	}
}

func TestDiagnosisPrefersTheMostRecentFailure(t *testing.T) {
	// A process that failed, restarted and failed again has several matching
	// lines. The current failure is the last one; reporting the oldest describes
	// a problem that may already be fixed.
	d, ok := Diagnose([]string{realPortInUse, "restarting", realPermissionDenied})
	if !ok {
		t.Fatal("no diagnosis")
	}
	if !strings.Contains(d.Cause, "not permitted to bind") {
		t.Fatalf("cause = %q, want the most recent failure", d.Cause)
	}
}

func TestUnrecognisedOutputIsNotDiagnosed(t *testing.T) {
	// Inventing a diagnosis for output nobody has seen is how an operator ends
	// up debugging the wrong thing.
	if d, ok := Diagnose([]string{"Xray started", "everything is fine"}); ok {
		t.Fatalf("diagnosed healthy output as %q", d.Cause)
	}
	if _, ok := Diagnose(nil); ok {
		t.Fatal("diagnosed an empty log")
	}
}

func TestLogHintPrefersADiagnosisAndFallsBackToTheRawLine(t *testing.T) {
	r := newRing(50)
	r.add("Xray 26.2.6 started")
	r.add(realPermissionDenied)
	hint := logHint(r)
	if !strings.Contains(hint, "CAP_NET_BIND_SERVICE") {
		t.Errorf("hint = %q; a five-clause chained error makes the operator do the reading", hint)
	}

	// Unrecognised output still yields the engine's own words: a real message
	// beats a generic one.
	r2 := newRing(50)
	r2.add("something nobody has a signature for")
	if hint := logHint(r2); !strings.Contains(hint, "nobody has a signature") {
		t.Errorf("fallback hint = %q, want the raw line", hint)
	}

	if got := logHint(newRing(10)); got != "" {
		t.Errorf("empty log produced %q, want no hint", got)
	}
}

func TestLogHintLooksPastTheVeryLastLine(t *testing.T) {
	// The cause is often logged several lines before the process gives up, and a
	// window of one line misses it.
	r := newRing(200)
	r.add(realPortInUse)
	for i := 0; i < 30; i++ {
		r.add(fmt.Sprintf("[Info] shutting down %d", i))
	}
	if hint := logHint(r); !strings.Contains(hint, "already listening") {
		t.Errorf("hint = %q; the cause was 30 lines back and was missed", hint)
	}
}

// since is what makes a bounded buffer resumable: the node agent re-sends
// anything the panel did not acknowledge, so it asks the ring for everything
// after the position it last had accepted. Same wraparound trap as snapshotN,
// with the added hazard that the caller's cursor can be older than anything the
// ring still holds.
func TestRingSinceReturnsEverythingAfterACursorAcrossAWrap(t *testing.T) {
	r := newRing(8)
	// 22 again, and for the same reason: an exact multiple of the size wraps
	// back to index 0 and a naive slice is right by luck.
	for i := 0; i < 22; i++ {
		r.add(fmt.Sprintf("line-%d", i))
	}

	// A cursor inside the window: exactly the lines after it, in order.
	got, next := r.since(19)
	want := []string{"line-19", "line-20", "line-21"}
	if next != 22 {
		t.Fatalf("next = %d, want 22 — the caller would re-send accepted lines forever", next)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("since(19) = %v, want %v", got, want)
	}

	// A cursor older than the window: everything still held, not nothing and not
	// a slice from some arbitrary earlier lap.
	old, _ := r.since(0)
	if len(old) != 8 || old[0] != "line-14" || old[7] != "line-21" {
		t.Fatalf("since(0) = %v, want the eight lines the ring still holds", old)
	}

	// A cursor ahead of the ring — the process restarted under the reader. It
	// gets what is there rather than silently nothing forever.
	ahead, _ := r.since(99)
	if len(ahead) != 8 {
		t.Fatalf("since(99) = %v, want the whole window", ahead)
	}

	// Caught up: nothing to send.
	if none, _ := r.since(22); len(none) != 0 {
		t.Fatalf("since(22) = %v, want nothing", none)
	}
}
