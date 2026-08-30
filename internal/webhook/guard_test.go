package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The delivery path, not the save path.
//
// A loopback httptest server is the WRONG target here: PolicyNoMetadata permits
// loopback on purpose, because an internal receiver is the documented case for
// a webhook. So this aims at the address that actually matters — the cloud
// instance-metadata service, which answers anything on the box with the hosting
// account's credentials — and checks the refusal happens before the dial.
func TestADeliveryToTheCloudMetadataServiceIsRefusedBeforeItIsDialled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	res := (&Dispatcher{}).Deliver(ctx,
		Endpoint{ID: 1, URL: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
		Event{Type: "node-down", Subject: "edge-1"})
	elapsed := time.Since(start)

	if res.Err == "" || res.Status != 0 {
		t.Fatalf("a delivery to the metadata service returned %+v; it was allowed out", res)
	}
	if !strings.Contains(res.Err, "link-local") {
		t.Fatalf("delivery error = %q, want the guard's refusal, not a dial failure", res.Err)
	}
	// The load-bearing assertion: a guard that refuses before dialling returns
	// instantly. A packet that actually left burns the whole attempt window —
	// and on a host that HAS a metadata service it comes back with a real
	// answer, which is the whole problem.
	if elapsed > 100*time.Millisecond {
		t.Fatalf("the refusal took %v; the guard must refuse before the dial, not after it times out", elapsed)
	}
}

// The other half of the policy split. If this goes red, the guard was made
// strict and the documented feature — alerting an internal service — is gone.
func TestADeliveryToAnInternalReceiverStillArrives(t *testing.T) {
	got := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- struct{}{}
	}))
	defer srv.Close()

	res := (&Dispatcher{}).Deliver(context.Background(),
		Endpoint{ID: 1, URL: srv.URL}, Event{Type: "node-down", Subject: "edge-1"})
	if res.Status != http.StatusOK || res.Err != "" {
		t.Fatalf("delivery to an internal receiver returned %+v; the guard is too strict", res)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the internal receiver was never reached")
	}
}

// The case the dial-time hook inside the client CANNOT cover.
//
// An endpoint with its own proxy is a deliberate hop, so the guarded client
// dials the PROXY and installs no address hook — inspecting the proxy's own
// address would refuse the common socks5://127.0.0.1:1080 deployment and take
// every delivery down. That leaves the destination unchecked unless send()
// validates ep.URL itself, and the request would go out as a CONNECT/absolute
// URI asking the proxy to fetch the metadata service on the panel's behalf.
func TestADeliveryThroughAPerEndpointProxyIsStillRefusedForTheMetadataService(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.RequestURI)
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer proxy.Close()

	res := (&Dispatcher{}).Deliver(context.Background(), Endpoint{
		ID:       1,
		URL:      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		ProxyURL: proxy.URL,
	}, Event{Type: "node-down", Subject: "edge-1"})

	mu.Lock()
	got := append([]string(nil), asked...)
	mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("the proxy was asked to fetch %v on the panel's behalf", got)
	}
	if !strings.Contains(res.Err, "link-local") {
		t.Fatalf("delivery through a proxy returned %+v, want the guard's refusal", res)
	}
}
