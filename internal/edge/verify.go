package edge

// Proving a freshly deployed Worker actually answers, before anyone is handed
// its URL.
//
// Deploy used to upload the script, enable the subdomain, build the panel and
// subscription URLs and return them — without ever asking the Worker whether it
// runs. Every caller (the Telegram bot's /deploy, the panel wizard, the web
// wizard) reported success and handed over links. Measured on a real account
// 2026-08-26: a Worker whose script, bindings, KV and compatibility date were
// all byte-identical to a healthy twin threw Cloudflare error 1101 — "Worker
// threw an exception" — on EVERY request, including routes that should 404. The
// deploy had reported success. The person on the other end got a panel link and
// a subscription link that were dead from the moment they were issued, and no
// way to tell that from a Worker that was merely still propagating.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"strings"
	"time"
)

// Health is the outcome of probing a deployed Worker.
type Health struct {
	// OK is true when the Worker answered without throwing.
	OK bool `json:"ok"`
	// Status is the last HTTP status observed.
	Status int `json:"status,omitempty"`
	// Threw is true when Cloudflare reported error 1101 — the Worker's isolate
	// raised an exception. This is the deterministic failure that recreating the
	// script fixes; it is deliberately kept apart from "could not reach
	// Cloudflare at all", which recreating would not fix and must never trigger
	// deleting a Worker that is probably fine.
	Threw bool `json:"threw,omitempty"`
	// Attempts is how many probes were made.
	Attempts int `json:"attempts"`
	// Recreated is true when the Worker had to be deleted and re-uploaded to
	// make it serve. Surfaced so an operator can see that a deploy needed a
	// second go, rather than it looking like a clean first-time success.
	Recreated bool `json:"recreated,omitempty"`
	// Detail explains a failure in the operator's terms.
	Detail string `json:"detail,omitempty"`
}

// VerifyOptions bound the probe.
type VerifyOptions struct {
	// Attempts is how many times to probe before giving up. Zero means 8.
	//
	// More than one because a new Worker is not instantly live everywhere: the
	// subdomain route and the script propagate over a few seconds, and a probe
	// that ran once immediately after upload would report a healthy deploy as
	// broken more often than it caught a real fault.
	Attempts int
	// Interval between probes. Zero means 3s.
	Interval time.Duration
	// HTTP is the client used for probes.
	HTTP *http.Client
	// Sleep is the delay hook; tests replace it so they do not wait.
	Sleep func(time.Duration)
}

func (o *VerifyOptions) withDefaults() {
	if o.Attempts <= 0 {
		o.Attempts = 8
	}
	if o.Interval <= 0 {
		o.Interval = 3 * time.Second
	}
	if o.HTTP == nil {
		o.HTTP = netegress.Client(20 * time.Second)
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
}

// cloudflareThrew reports whether a response is Cloudflare's "Worker threw an
// exception" page.
//
// Matched on the body, not the status: 1101 is served as a 500, and so are
// plenty of things that are the destination's fault rather than the Worker's.
// Recreating a script is destructive enough that it must key off the specific
// signal, never off "something returned 5xx".
func cloudflareThrew(status int, body string) bool {
	if status != http.StatusInternalServerError {
		return false
	}
	return strings.Contains(body, "error code: 1101") || strings.Contains(body, "Error 1101")
}

// VerifyWorker probes a deployed Worker until it answers or the attempts run
// out.
//
// The probe asks for the panel path, because a 200 there proves the whole chain
// an operator is about to rely on: the isolate starts, the KV binding resolves,
// the secrets bootstrap and the Worker renders. A bare "/" would only prove the
// isolate starts — it answers 404 by design, which is indistinguishable from
// Cloudflare answering 404 because the route is not published yet.
func VerifyWorker(ctx context.Context, origin, securePath string, opts VerifyOptions) Health {
	opts.withDefaults()
	h := Health{}
	target := strings.TrimRight(origin, "/") + "/" + strings.Trim(securePath, "/") + "/panel"

	for i := 0; i < opts.Attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				h.Detail = "verification was cancelled"
				return h
			default:
			}
			opts.Sleep(opts.Interval)
		}
		h.Attempts++

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			h.Detail = err.Error()
			return h
		}
		resp, err := opts.HTTP.Do(req)
		if err != nil {
			// Could not reach Cloudflare. NOT a Worker fault: keep Threw false so
			// nothing downstream deletes a script over a network blip.
			h.Detail = "could not reach " + target + ": " + err.Error()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		h.Status = resp.StatusCode

		if cloudflareThrew(resp.StatusCode, string(body)) {
			h.Threw = true
			h.Detail = "the Worker threw an exception on every request (Cloudflare error 1101)"
			// Deterministic: it will not fix itself. Stop probing.
			return h
		}
		if resp.StatusCode == http.StatusOK {
			h.OK = true
			h.Threw = false
			h.Detail = ""
			return h
		}
		h.Threw = false
		h.Detail = fmt.Sprintf("%s answered HTTP %d", target, resp.StatusCode)
	}
	return h
}

// ErrWorkerUnhealthy is returned when a deploy produced a Worker that does not
// answer. It carries the health so a caller can show why.
type ErrWorkerUnhealthy struct {
	Health Health
	Name   string
}

func (e *ErrWorkerUnhealthy) Error() string {
	return fmt.Sprintf("the Worker %q was uploaded but is not serving: %s", e.Name, e.Health.Detail)
}

// IsUnhealthy reports whether err is a failed post-deploy verification.
func IsUnhealthy(err error) bool {
	var e *ErrWorkerUnhealthy
	return errors.As(err, &e)
}
