package dns

import (
	"errors"
	"fmt"
	"strings"
)

// Kind classifies a failure so callers (and the HTTP layer) can react without
// string-matching provider prose.
type Kind string

// Failure kinds. Every error this package returns carries exactly one.
const (
	KindAuth           Kind = "auth"            // credential rejected outright
	KindPermission     Kind = "permission"      // credential valid but under-scoped
	KindNotFound       Kind = "not_found"       // zone or record does not exist
	KindConflict       Kind = "conflict"        // record already exists / collides
	KindValidation     Kind = "validation"      // caller sent something malformed
	KindRateLimit      Kind = "rate_limit"      // provider or ACME throttled us
	KindNetwork        Kind = "network"         // could not reach the provider
	KindUnsupported    Kind = "unsupported"     // provider cannot do this at all
	KindNotImplemented Kind = "not_implemented" // provider is registered but has no backend yet
	KindServer         Kind = "server"          // provider 5xx
	KindPreflight      Kind = "preflight"       // ACME readiness check failed
)

// Error is the single error type this package returns. It always names the
// provider and operation, and — this is the point of it — carries a concrete
// Remediation string rather than leaving the operator with a raw API message.
type Error struct {
	Provider string `json:"provider,omitempty"`
	Op       string `json:"op,omitempty"`
	Kind     Kind   `json:"kind"`
	// Status is the HTTP status the provider returned, 0 for local failures.
	Status int `json:"status,omitempty"`
	// Code is the provider's own numeric error code (Cloudflare populates this).
	Code    int    `json:"code,omitempty"`
	Message string `json:"message"`
	// MissingScope names the exact API-token permission that has to be added,
	// in the wording the provider's own token editor uses.
	MissingScope string `json:"missing_scope,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	Cause        error  `json:"-"`
}

func (e *Error) Error() string {
	var b strings.Builder
	if e.Provider != "" {
		b.WriteString(e.Provider)
		b.WriteString(": ")
	}
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	if e.Message != "" {
		b.WriteString(e.Message)
	} else {
		b.WriteString(string(e.Kind))
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.Status)
		if e.Code != 0 {
			fmt.Fprintf(&b, ", code %d", e.Code)
		}
		b.WriteString(")")
	}
	if e.MissingScope != "" {
		b.WriteString("\nmissing API token permission: ")
		b.WriteString(e.MissingScope)
	}
	if e.Remediation != "" {
		b.WriteString("\nfix: ")
		b.WriteString(e.Remediation)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Cause }

// Is lets errors.Is match on kind alone via the sentinel helpers below.
func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	// A bare sentinel carries only a Kind; match on that.
	if other.Provider == "" && other.Op == "" && other.Message == "" {
		return other.Kind == e.Kind
	}
	return other.Kind == e.Kind && other.Message == e.Message
}

// Sentinels for errors.Is. They compare on Kind only.
var (
	ErrAuth           = &Error{Kind: KindAuth}
	ErrPermission     = &Error{Kind: KindPermission}
	ErrNotFound       = &Error{Kind: KindNotFound}
	ErrConflict       = &Error{Kind: KindConflict}
	ErrValidation     = &Error{Kind: KindValidation}
	ErrRateLimit      = &Error{Kind: KindRateLimit}
	ErrNetwork        = &Error{Kind: KindNetwork}
	ErrUnsupported    = &Error{Kind: KindUnsupported}
	ErrNotImplemented = &Error{Kind: KindNotImplemented}
	ErrPreflight      = &Error{Kind: KindPreflight}
)

// KindOf returns the classification of err, or "" when err is not from this
// package.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// AsError extracts the typed error, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// IsPermission reports whether err is an under-scoped-credential failure.
func IsPermission(err error) bool { return KindOf(err) == KindPermission }

// IsNotImplemented reports whether err came from a registered-but-unbuilt provider.
func IsNotImplemented(err error) bool { return KindOf(err) == KindNotImplemented }

// IsNotFound reports whether err is a missing zone or record.
func IsNotFound(err error) bool { return KindOf(err) == KindNotFound }

// IsRetryable reports whether retrying the same call could plausibly succeed.
func IsRetryable(err error) bool {
	switch KindOf(err) {
	case KindRateLimit, KindNetwork, KindServer:
		return true
	}
	return false
}

// notImplemented builds the typed error the registry hands back for providers
// that exist as an entry but have no backend.
func notImplemented(provider, docs string) *Error {
	return &Error{
		Provider: provider,
		Op:       "new-provider",
		Kind:     KindNotImplemented,
		Message:  fmt.Sprintf("the %s DNS backend is registered but not available in this build", provider),
		Remediation: "use one of the implemented providers (cloudflare, arvancloud, desec), or create the records by hand at " +
			docs + " and register the resulting domain with `forgectl provision --skip-dns`",
	}
}
