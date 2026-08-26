package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fastVerify probes without waiting, so a test that needs several attempts does
// not take the real backoff.
func fastVerify(attempts int) VerifyOptions {
	return VerifyOptions{Attempts: attempts, Interval: time.Millisecond, Sleep: func(time.Duration) {}}
}

// worker1101 is Cloudflare's response when a Worker's isolate throws.
func worker1101(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("error code: 1101"))
}

func TestVerifyAcceptsAWorkerThatServesThePanel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sp123456/panel" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<title>ForgeEdge</title>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := VerifyWorker(context.Background(), srv.URL, "sp123456", fastVerify(3))
	if !h.OK {
		t.Fatalf("a serving Worker was reported unhealthy: %+v", h)
	}
	if h.Threw {
		t.Error("Threw set on a healthy Worker")
	}
}

func TestVerifyDetectsTheWorkerThrowing(t *testing.T) {
	// The exact failure a real account produced: 1101 on every request, while
	// the deploy had reported success.
	srv := httptest.NewServer(http.HandlerFunc(worker1101))
	defer srv.Close()

	h := VerifyWorker(context.Background(), srv.URL, "sp123456", fastVerify(5))
	if h.OK {
		t.Fatal("a Worker throwing 1101 was reported healthy")
	}
	if !h.Threw {
		t.Fatal("a 1101 was not recognised as the Worker throwing")
	}
	// Deterministic: it will not fix itself, so probing must stop rather than
	// burn the whole attempt budget.
	if h.Attempts != 1 {
		t.Errorf("probed %d times; a 1101 is deterministic and should stop at the first one", h.Attempts)
	}
}

func TestVerifyRetriesWhileTheWorkerIsStillPropagating(t *testing.T) {
	// A new Worker is not live everywhere the instant the upload returns. A
	// single probe would report healthy deploys as broken more often than it
	// caught a real fault.
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		attempt := n
		mu.Unlock()
		if attempt < 3 {
			w.WriteHeader(http.StatusNotFound) // route not published yet
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := VerifyWorker(context.Background(), srv.URL, "sp123456", fastVerify(6))
	if !h.OK {
		t.Fatalf("gave up on a Worker that came up on the third probe: %+v", h)
	}
	if h.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", h.Attempts)
	}
}

func TestAnUnreachableEdgeIsNotBlamedOnTheWorker(t *testing.T) {
	// This distinction decides whether a Worker gets DELETED. A probe that
	// cannot reach Cloudflare says nothing about the Worker, and treating it as
	// a fault would turn a network blip on the panel host into someone's outage.
	srv := httptest.NewServer(http.HandlerFunc(worker1101))
	url := srv.URL
	srv.Close() // nothing is listening now

	h := VerifyWorker(context.Background(), url, "sp123456", fastVerify(2))
	if h.OK {
		t.Fatal("an unreachable endpoint was reported healthy")
	}
	if h.Threw {
		t.Fatal("an unreachable endpoint was blamed on the Worker — this would delete it")
	}
}

func TestAPlainFiveHundredIsNotTreatedAsTheWorkerThrowing(t *testing.T) {
	// Recreating a script is destructive enough that it must key off the 1101
	// signature specifically, not off "something returned 5xx" — plenty of 500s
	// are the destination's fault, not the isolate's.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("upstream database unavailable"))
	}))
	defer srv.Close()

	h := VerifyWorker(context.Background(), srv.URL, "sp123456", fastVerify(2))
	if h.Threw {
		t.Fatal("an unrelated 500 was classified as the Worker throwing; this would delete a Worker over someone else's outage")
	}
	if h.OK {
		t.Fatal("a 500 was reported healthy")
	}
}

func TestVerifyProbesThePanelPathNotTheRoot(t *testing.T) {
	// "/" answers 404 by design, which is indistinguishable from Cloudflare
	// answering 404 because the route is not published yet. A 200 on the panel
	// proves the isolate starts, the KV binding resolves and the Worker renders.
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	VerifyWorker(context.Background(), srv.URL, "sp123456", fastVerify(1))
	if got != "/sp123456/panel" {
		t.Fatalf("probed %q, want the panel path", got)
	}
}

func TestVerifyStopsWhenTheContextIsCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := VerifyWorker(ctx, srv.URL, "sp123456", fastVerify(50))
	if h.Attempts > 1 {
		t.Fatalf("kept probing after cancellation (%d attempts)", h.Attempts)
	}
}
