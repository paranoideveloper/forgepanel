package edge

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// edgeStub stands in for the deployed Worker's public origin. Deploy derives
// that origin from the account subdomain, so probes are routed here by a
// transport rather than by rewriting the URL.
type edgeStub struct {
	mu sync.Mutex
	// throwUntil makes the Worker return 1101 until it has been recreated this
	// many times.
	throwUntilRecreate int
	recreates          int
	hits               int
	srv                *httptest.Server
}

func newEdgeStub(t *testing.T) *edgeStub {
	t.Helper()
	e := &edgeStub{}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.hits++
		throwing := e.recreates < e.throwUntilRecreate
		e.mu.Unlock()
		if throwing {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error code: 1101"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<title>ForgeEdge</title>"))
	}))
	t.Cleanup(e.srv.Close)
	return e
}

// client routes every probe to the stub regardless of hostname.
func (e *edgeStub) client() *http.Client {
	target, _ := url.Parse(e.srv.URL)
	return &http.Client{Timeout: 5 * time.Second, Transport: &redirectTransport{to: target}}
}

type redirectTransport struct{ to *url.URL }

func (rt *redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = rt.to.Scheme, rt.to.Host
	return http.DefaultTransport.RoundTrip(r)
}

func (e *edgeStub) noteRecreate() {
	e.mu.Lock()
	e.recreates++
	e.mu.Unlock()
}

func verifyVia(e *edgeStub) VerifyOptions {
	return VerifyOptions{Attempts: 3, Interval: time.Millisecond,
		Sleep: func(time.Duration) {}, HTTP: e.client()}
}

func TestDeployReportsHealthOnASuccessfulDeploy(t *testing.T) {
	m := newCFMock(t)
	e := newEdgeStub(t)
	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: verifyVia(e),
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.Health == nil || !res.Health.OK {
		t.Fatalf("health = %+v, want a passing probe", res.Health)
	}
	if res.Health.Recreated {
		t.Error("a healthy first deploy was reported as recreated")
	}
}

func TestDeployRecreatesAWorkerThatThrows(t *testing.T) {
	// The failure this exists for: the upload succeeds, the URLs are built, and
	// the Worker throws 1101 on every request. Before this, that was returned to
	// the user as a success with a dead panel link.
	m := newCFMock(t)
	e := newEdgeStub(t)
	e.throwUntilRecreate = 1

	// The mock records a delete; recreating is what clears the fault.
	m.OnDeleteScript = func(string) { e.noteRecreate() }

	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: verifyVia(e),
	})
	if err != nil {
		t.Fatalf("Deploy did not recover a throwing Worker: %v", err)
	}
	if res.Health == nil || !res.Health.OK {
		t.Fatalf("health = %+v, want OK after the recreate", res.Health)
	}
	if !res.Health.Recreated {
		t.Error("the deploy recovered but did not report that it had to recreate the Worker")
	}
	if e.recreates != 1 {
		t.Errorf("recreated %d times, want exactly 1", e.recreates)
	}
	// The KV namespace must survive: it holds the secure path, the VLESS UUID
	// and the trojan password, so recreating must not cost the Worker its
	// identity or invalidate configs people already hold.
	if len(m.snapshot().KV) == 0 {
		t.Fatal("the KV namespace was destroyed by the recreate — every existing config would break")
	}
}

func TestDeployFailsLoudlyWhenTheWorkerStaysBroken(t *testing.T) {
	// Handing someone a panel URL that 500s is worse than an error: they have no
	// way to tell it from a Worker that is still propagating.
	m := newCFMock(t)
	e := newEdgeStub(t)
	e.throwUntilRecreate = 99 // never recovers
	m.OnDeleteScript = func(string) { e.noteRecreate() }

	_, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: verifyVia(e),
	})
	if err == nil {
		t.Fatal("a Worker that never serves was reported as a successful deploy")
	}
	if !IsUnhealthy(err) {
		t.Fatalf("error %v is not recognisable as a failed verification", err)
	}
	if !strings.Contains(err.Error(), "not serving") {
		t.Errorf("error %q does not say what is wrong", err)
	}
}

func TestDeployDoesNotDeleteAWorkerOverAnUnreachableEdge(t *testing.T) {
	// The distinction that decides whether someone's Worker gets deleted. A
	// probe that cannot reach Cloudflare says nothing about the Worker, and
	// deleting one over a network blip on the panel host would turn a
	// non-problem into an outage.
	m := newCFMock(t)
	deleted := false
	m.OnDeleteScript = func(string) { deleted = true }

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target, _ := url.Parse(dead.URL)
	dead.Close() // nothing listening

	_, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		Verify: VerifyOptions{Attempts: 2, Interval: time.Millisecond, Sleep: func(time.Duration) {},
			HTTP: &http.Client{Timeout: 2 * time.Second, Transport: &redirectTransport{to: target}}},
	})
	if err == nil {
		t.Fatal("an unverifiable deploy was reported as success")
	}
	if deleted {
		t.Fatal("the Worker was DELETED because the probe could not reach the edge")
	}
}

func TestSkipVerifyLeavesTheOldBehaviour(t *testing.T) {
	m := newCFMock(t)
	res, err := Deploy(ctx(t), m.client(), DeploySpec{
		Name: "w", Bundle: []byte("x"), SecurePath: "p23456789abcdefghijklmno",
		SkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if res.Health != nil {
		t.Errorf("health = %+v, want nil when verification is skipped", res.Health)
	}
}
