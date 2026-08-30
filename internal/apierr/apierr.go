// Package apierr is the panel's one description of a failed request.
//
// It exists because there were three. internal/dns grew a typed error with a
// kind, an operation, a remediation and the exact API-token permission that was
// missing, plus a kind->status switch to write it. internal/edge grew the same
// thing again, with a slightly different kind set and a second switch. And
// internal/api — the package that actually answers the browser — grew neither:
// 386 handlers wrote `c.JSON(400, gin.H{"error": err.Error()})` by hand, and
// the two adapters that did understand typed errors covered 23 of them.
//
// The cost was not tidiness. A Cloudflare refusal that says "your token needs
// Zone -> DNS -> Edit" reached the operator as a 400 with the remediation
// deleted, because the only thing that survived the trip was err.Error(). This
// package is the third and last copy: kinds, one authoritative status map, and
// one writer, with adapters (adapt.go) so the two existing typed errors flow
// through it unchanged rather than becoming a fourth switch.
package apierr

import (
	"errors"
	"net/http"
	"strings"
)

// Kind classifies a failure. It is the union of internal/dns's and
// internal/edge's kind sets plus the two the panel already invented by hand as
// bare "code" strings (stale_write in usergroup.go, quota_exceeded in admin.go),
// so nothing that already crossed the wire loses its name here.
type Kind string

const (
	KindValidation     Kind = "validation"      // the caller sent something malformed
	KindAuth           Kind = "auth"            // credential missing, wrong or expired
	KindPermission     Kind = "permission"      // authenticated but not allowed
	KindNotFound       Kind = "not_found"       // no such object
	KindConflict       Kind = "conflict"        // collides with something that exists
	KindStaleWrite     Kind = "stale_write"     // optimistic-concurrency loss
	KindQuotaExceeded  Kind = "quota_exceeded"  // an admin's allowance is spent
	KindRateLimit      Kind = "rate_limit"      // throttled, here or upstream
	KindPreflight      Kind = "preflight"       // readiness check says this cannot work yet
	KindNoCredentials  Kind = "no_credentials"  // the operation needs an authorisation nobody gave
	KindNetwork        Kind = "network"         // could not reach an upstream
	KindUnsupported    Kind = "unsupported"     // this backend cannot do it at all
	KindNotImplemented Kind = "not_implemented" // registered but not built in this binary
	KindUnavailable    Kind = "unavailable"     // a dependency is down right now
	KindServer         Kind = "server"          // our fault
)

// Error is what every refused request in this panel is, on the way out.
//
// Message is the sentence shown to a human. Everything else is for the UI to
// act on: Kind to branch, Code for a machine-readable reason the browser
// already switches on (port_hop_conflict, group_in_use), Fields to put a
// message under the input that caused it, Remediation and MissingScope to say
// what to go and change.
type Error struct {
	Op           string
	Code         string
	Kind         Kind
	Status       int
	Message      string
	Remediation  string
	MissingScope string
	Fields       map[string]string
	// Details carries the per-endpoint extras that already cross the wire —
	// totp_required, members, limit, profiles. They are merged at the TOP level
	// of the body, not nested, because that is where the UI and the existing
	// handler tests already read them; nesting would have been tidier and would
	// have silently broken every one of those readers.
	Details map[string]any
	Cause   error
}

func (e *Error) Error() string {
	var b strings.Builder
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	if e.Message != "" {
		b.WriteString(e.Message)
	} else {
		b.WriteString(string(e.Kind))
	}
	if e.MissingScope != "" {
		b.WriteString("\nmissing permission: ")
		b.WriteString(e.MissingScope)
	}
	if e.Remediation != "" {
		b.WriteString("\nfix: ")
		b.WriteString(e.Remediation)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Cause }

// HTTPStatus is the status to answer with. An explicit Status wins so a handler
// that has already decided (and whose tests pin it) keeps its answer; otherwise
// the kind decides, which is the whole point of having kinds.
func (e *Error) HTTPStatus() int {
	if e.Status != 0 {
		return e.Status
	}
	return StatusFor(e.Kind)
}

// Body is the JSON envelope. Empty fields are omitted rather than sent as ""
// so a client can test presence, and the key names are the ones the SvelteKit
// client already parses in frontend/src/lib/api.ts.
func (e *Error) Body() map[string]any {
	b := map[string]any{"error": e.Message}
	// Details first: the reserved keys below must win a collision, so that no
	// endpoint can accidentally redefine what "kind" or "remediation" mean.
	for k, v := range e.Details {
		b[k] = v
	}
	if e.Kind != "" {
		b["kind"] = string(e.Kind)
	}
	if e.Op != "" {
		b["op"] = e.Op
	}
	if e.Code != "" {
		b["code"] = e.Code
	}
	if e.Remediation != "" {
		b["remediation"] = e.Remediation
	}
	if e.MissingScope != "" {
		b["missing_scope"] = e.MissingScope
	}
	if len(e.Fields) > 0 {
		b["fields"] = e.Fields
	}
	return b
}

// StatusFor maps a kind to its HTTP status. This is the one authoritative copy;
// it started as internal/dns/routes.go's switch (the more complete of the two
// that existed) and gained the three kinds that switch had never heard of.
func StatusFor(k Kind) int {
	switch k {
	case KindValidation:
		return http.StatusBadRequest
	case KindAuth:
		return http.StatusUnauthorized
	case KindPermission:
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindConflict, KindStaleWrite, KindQuotaExceeded:
		return http.StatusConflict
	case KindPreflight:
		return http.StatusUnprocessableEntity
	// 428 is what internal/api/edge_routes.go already answered for a missing
	// Cloudflare authorisation: the request is fine, a precondition is not met.
	case KindNoCredentials:
		return http.StatusPreconditionRequired
	case KindRateLimit:
		return http.StatusTooManyRequests
	case KindUnsupported, KindNotImplemented:
		return http.StatusNotImplemented
	case KindNetwork:
		return http.StatusBadGateway
	case KindUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// KindForStatus is the reverse: the kind a handler that has only picked a status
// means. It exists for the mechanical conversion of the handlers that hard-code
// a number, so those answers gain a kind without anyone having to re-decide the
// status of 386 call sites and get one of them wrong.
func KindForStatus(status int) Kind {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return KindValidation
	case http.StatusUnauthorized:
		return KindAuth
	case http.StatusForbidden:
		return KindPermission
	case http.StatusNotFound:
		return KindNotFound
	case http.StatusConflict:
		return KindConflict
	case http.StatusPreconditionRequired:
		return KindNoCredentials
	case http.StatusTooManyRequests:
		return KindRateLimit
	case http.StatusNotImplemented:
		return KindNotImplemented
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return KindNetwork
	case http.StatusServiceUnavailable:
		return KindUnavailable
	}
	if status >= 400 && status < 500 {
		return KindValidation
	}
	return KindServer
}

// New builds an error whose status the caller has already decided.
func New(status int, msg string) *Error {
	return &Error{Kind: KindForStatus(status), Status: status, Message: msg}
}

// Validation is a rejected request body or parameter.
func Validation(op, msg, remedy string) *Error {
	return &Error{Op: op, Kind: KindValidation, Message: msg, Remediation: remedy}
}

// NotFound is a missing object.
func NotFound(op, msg string) *Error {
	return &Error{Op: op, Kind: KindNotFound, Message: msg}
}

// Conflict is a collision, carrying the machine-readable reason the UI branches
// on (group_in_use, port_hop_conflict, stale_write).
func Conflict(op, code, msg string) *Error {
	return &Error{Op: op, Kind: KindConflict, Code: code, Message: msg}
}

// Permission is a refusal that names the scope or role that would have allowed it.
func Permission(op, msg, scope string) *Error {
	return &Error{Op: op, Kind: KindPermission, Message: msg, MissingScope: scope}
}

// Server is our own fault, with the cause kept for errors.Is/As upstream.
func Server(op string, err error) *Error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return &Error{Op: op, Kind: KindServer, Message: msg, Cause: err}
}

// FieldErrors rejects specific inputs, so the UI can put each message under the
// input that caused it instead of showing one toast for the whole form.
func FieldErrors(op string, fields map[string]string) *Error {
	return &Error{Op: op, Kind: KindValidation, Status: http.StatusUnprocessableEntity,
		Message: "validation failed", Fields: fields}
}

// As extracts an *Error from a chain.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
