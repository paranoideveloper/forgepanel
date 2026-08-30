package apierr

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/telegram"
)

// The adapters are the whole reason this package is not a fourth copy of the
// same switch, and they are the part with nothing else watching them: the panel
// exercises them only through handlers that would still answer *something* if a
// branch here were dropped.

func TestFromDNSKeepsTheActionableHalf(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &dns.Error{
		Provider:     "cloudflare",
		Op:           "find-zone",
		Kind:         dns.KindPermission,
		Status:       403, // the PROVIDER's status, which must not become ours
		Message:      "your token cannot read zones",
		MissingScope: "Zone → Zone → Read",
		Remediation:  "mint a token with that permission",
	})

	e := From(err)
	if e.Kind != KindPermission {
		t.Errorf("kind = %q, want %q", e.Kind, KindPermission)
	}
	if e.HTTPStatus() != http.StatusForbidden {
		t.Errorf("status = %d, want %d", e.HTTPStatus(), http.StatusForbidden)
	}
	if e.MissingScope != "Zone → Zone → Read" {
		t.Errorf("missing scope dropped: %q", e.MissingScope)
	}
	if e.Remediation == "" {
		t.Error("remediation dropped")
	}
	if got := e.Body()["provider"]; got != "cloudflare" {
		t.Errorf("provider = %v, want cloudflare — the DNS layer's own writer emits it", got)
	}
	if !errors.Is(err, dns.ErrPermission) {
		t.Error("the chain no longer matches dns.ErrPermission")
	}
}

// A provider 403 on a request the browser made correctly is not the browser's
// 403. This is the specific confusion the panel had: it forwarded upstream
// statuses as its own.
func TestFromDoesNotForwardProviderStatus(t *testing.T) {
	e := From(&dns.Error{Op: "create-record", Kind: dns.KindRateLimit, Status: 429,
		Message: "slow down"})
	if e.Status != 0 {
		t.Errorf("Status = %d, want 0 so the kind decides", e.Status)
	}
	if e.HTTPStatus() != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 from the kind", e.HTTPStatus())
	}
}

func TestFromEdgeNoCredentialsIs428(t *testing.T) {
	e := From(edge.ErrNoCredentials("deploy"))
	if e.Kind != KindNoCredentials {
		t.Errorf("kind = %q, want %q", e.Kind, KindNoCredentials)
	}
	if e.HTTPStatus() != http.StatusPreconditionRequired {
		t.Errorf("status = %d, want %d (what edge_routes.go answered before)",
			e.HTTPStatus(), http.StatusPreconditionRequired)
	}
	if e.Remediation == "" {
		t.Error("the sentinel's remediation — the whole reason it exists — was dropped")
	}
}

// Telegram answers everything the same way; the three failures below need three
// different fixes, so they must not arrive as one kind.
func TestFromTelegramClassifies(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *telegram.SendError
		want Kind
	}{
		{"dead token", &telegram.SendError{Code: 401, Description: "Unauthorized"}, KindAuth},
		{"never started", &telegram.SendError{Code: 400, Description: "chat not found"}, KindNotFound},
		{"blocked", &telegram.SendError{Code: 403, Description: "bot was blocked by the user"}, KindPermission},
		{"throttled", &telegram.SendError{Code: 429, Description: "Too Many Requests"}, KindRateLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := From(tc.err)
			if e.Kind != tc.want {
				t.Errorf("kind = %q, want %q", e.Kind, tc.want)
			}
			if e.Remediation == "" {
				t.Errorf("no remediation for %q; the operator is told only that it failed",
					tc.err.Description)
			}
			if e.Details["chat_id"] != tc.err.ChatID {
				t.Errorf("chat_id = %v, want %d", e.Details["chat_id"], tc.err.ChatID)
			}
		})
	}
}

// Coerce is what lets 386 converted handlers keep the status their tests pin
// while a typed error still overrides it.
func TestCoerce(t *testing.T) {
	plain := Coerce(errors.New("disk is full"), http.StatusBadRequest)
	if plain.HTTPStatus() != http.StatusBadRequest || plain.Kind != KindValidation {
		t.Errorf("untyped: got %d/%q, want 400/validation", plain.HTTPStatus(), plain.Kind)
	}
	typed := Coerce(&dns.Error{Kind: dns.KindNotFound, Message: "no such zone"}, http.StatusBadRequest)
	if typed.HTTPStatus() != http.StatusNotFound {
		t.Errorf("typed: got %d, want 404 — the caller's fallback must not win", typed.HTTPStatus())
	}
	if Coerce(nil, http.StatusBadRequest) != nil {
		t.Error("Coerce(nil) must be nil so a handler can test it")
	}
}

// Details must not be able to redefine the envelope, or an endpoint could ship
// a "kind" the rest of the API does not mean.
func TestBodyReservedKeysWin(t *testing.T) {
	e := &Error{Kind: KindConflict, Code: "group_in_use", Message: "in use",
		Details: map[string]any{"kind": "not_found", "members": 3}}
	b := e.Body()
	if b["kind"] != "conflict" {
		t.Errorf("kind = %v, want conflict", b["kind"])
	}
	if b["members"] != 3 {
		t.Errorf("members = %v, want 3 — extras must still reach the top level", b["members"])
	}
}

func TestStatusForCoversEveryKind(t *testing.T) {
	all := []Kind{KindValidation, KindAuth, KindPermission, KindNotFound, KindConflict,
		KindStaleWrite, KindQuotaExceeded, KindRateLimit, KindPreflight, KindNoCredentials,
		KindNetwork, KindUnsupported, KindNotImplemented, KindUnavailable, KindServer}
	for _, k := range all {
		if got := StatusFor(k); got < 400 || got > 599 {
			t.Errorf("StatusFor(%q) = %d, not an error status", k, got)
		}
	}
	// An unmapped kind is a 500, not a panic and not a 200.
	if got := StatusFor(Kind("invented_yesterday")); got != http.StatusInternalServerError {
		t.Errorf("unknown kind = %d, want 500", got)
	}
}

// A handler that returns an uninitialised typed pointer hands us a non-nil
// interface wrapping a nil pointer. That must be a 500, not a panic inside the
// writer — a panic here takes the request down with no body at all.
func TestFromSurvivesNilTypedPointers(t *testing.T) {
	var d *dns.Error
	var e *edge.Error
	var s *telegram.SendError
	var a *Error
	var b *backup.S3Error
	for _, err := range []error{error(d), error(e), error(s), error(a), error(b)} {
		got := From(err)
		if got == nil {
			t.Fatalf("From(%T(nil)) returned nil", err)
		}
		if got.HTTPStatus() < 400 {
			t.Errorf("From(%T(nil)) status = %d, want an error status", err, got.HTTPStatus())
		}
		if IsTyped(err) {
			t.Errorf("IsTyped(%T(nil)) = true; a nil pointer classifies nothing", err)
		}
		if c := Coerce(err, http.StatusBadRequest); c == nil || c.HTTPStatus() != http.StatusBadRequest {
			t.Errorf("Coerce(%T(nil)) did not fall back to the caller's status", err)
		}
	}
}

// A bucket refusal has to arrive as something an operator can act on. All three
// of "your key is wrong", "there is no such bucket" and "slow down" used to be
// one sentence in a log line, and each needs a different fix.
func TestS3RefusalsAreClassified(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *backup.S3Error
		want Kind
	}{
		{"bad signature", &backup.S3Error{Status: 403, Code: "SignatureDoesNotMatch"}, KindAuth},
		{"no such bucket", &backup.S3Error{Status: 404, Code: "NoSuchBucket"}, KindNotFound},
		{"throttled", &backup.S3Error{Status: 503, Code: "SlowDown"}, KindRateLimit},
		{"service down", &backup.S3Error{Status: 500}, KindUnavailable},
		{"never reached", &backup.S3Error{Message: "dial tcp: no route to host"}, KindNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := From(tc.err)
			if got.Kind != tc.want {
				t.Errorf("kind = %q, want %q", got.Kind, tc.want)
			}
			if got.Op != "backup-s3" {
				t.Errorf("op = %q, want backup-s3", got.Op)
			}
			if got.Remediation == "" {
				t.Error("no remediation; the operator is told what failed and not what to change")
			}
			if got.HTTPStatus() < 400 {
				t.Errorf("status = %d, want an error status", got.HTTPStatus())
			}
		})
	}
}
