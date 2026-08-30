package apierr

import (
	"errors"
	"net/http"
	"strings"

	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/telegram"
)

// From translates any error this panel can produce into the one envelope.
//
// This function is the reason the package is worth having. Without it the HTTP
// layer needs a switch per typed-error package, which is exactly how internal/dns
// and internal/edge each ended up with their own copy of the same kind->status
// table. Adding another typed error means adding a case here and nowhere else.
//
// apierr imports dns, edge, telegram and netegress; none of the four imports
// internal/api, so the dependency runs one way and there is no cycle to design
// around. netegress is already a transitive dependency here (through dns),
// which is also why netegress must not import this package back.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	// A handler that returns an uninitialised typed pointer hands us a non-nil
	// interface wrapping a nil pointer. errors.As walks such a chain through
	// Unwrap with a nil receiver and panics — which takes the request down with
	// no body at all, strictly worse than the 500 this becomes instead. Catch it
	// before the extraction below rather than after.
	switch v := err.(type) {
	case *Error:
		if v == nil {
			return Unspecified()
		}
	case *dns.Error:
		if v == nil {
			return Unspecified()
		}
	case *edge.Error:
		if v == nil {
			return Unspecified()
		}
	case *telegram.SendError:
		if v == nil {
			return Unspecified()
		}
	case *backup.S3Error:
	case *netegress.BlockedError:
		if v == nil {
			return Unspecified()
		}
	}
	if e, ok := As(err); ok && e != nil {
		return e
	}
	if e, ok := dns.AsError(err); ok && e != nil {
		out := &Error{
			Op:           e.Op,
			Kind:         Kind(e.Kind),
			Message:      e.Message,
			Remediation:  e.Remediation,
			MissingScope: e.MissingScope,
			Cause:        err,
		}
		// e.Status is the PROVIDER's HTTP status, not ours — copying it into
		// Status would answer the browser with Cloudflare's 403 for a request
		// the browser made correctly. The kind decides our status.
		if e.Provider != "" {
			out.Details = map[string]any{"provider": e.Provider}
		}
		if out.Message == "" {
			out.Message = err.Error()
		}
		return out
	}
	if e, ok := edge.AsError(err); ok && e != nil {
		out := &Error{
			Op:           e.Op,
			Kind:         Kind(e.Kind),
			Message:      e.Message,
			Remediation:  e.Remediation,
			MissingScope: e.MissingScope,
			Cause:        err,
		}
		if out.Message == "" {
			out.Message = err.Error()
		}
		return out
	}
	var se *telegram.SendError
	if errors.As(err, &se) && se != nil {
		return fromTelegram(se, err)
	}
	var s3e *backup.S3Error
	if errors.As(err, &s3e) && s3e != nil {
		return fromS3(s3e, err)
	}
	// The egress guard refused a target the OPERATOR typed, so it is their
	// input that is wrong, not the panel — without this it arrives as a 500,
	// or as the 502 the egress test button uses for "your proxy is broken",
	// and the operator goes off to fix a proxy that is working fine.
	var be *netegress.BlockedError
	if errors.As(err, &be) && be != nil {
		return &Error{
			Op:      "egress-guard",
			Kind:    KindValidation,
			Message: be.Error(),
			Remediation: "Point this at a public address. The panel refuses to fetch its own host, " +
				"a private network, or the cloud instance-metadata endpoint.",
			Details: map[string]any{"address": be.Addr},
			Cause:   err,
		}
	}
	// An untyped error is our fault until a handler says otherwise; handlers
	// that already know better pass a fallback through Coerce.
	return &Error{Kind: KindServer, Message: err.Error(), Cause: err}
}

// fromTelegram classifies a Bot API refusal. Telegram answers everything with
// its own code, and the three that matter each need a different fix — a dead
// token, a chat that was never started, and a bot that was blocked all arrive
// as "the message could not be sent" otherwise.
func fromTelegram(se *telegram.SendError, cause error) *Error {
	d := strings.ToLower(se.Description)
	kind := KindNetwork
	switch {
	case se.Code == 401 || strings.Contains(d, "unauthorized"):
		kind = KindAuth
	case strings.Contains(d, "chat not found"):
		kind = KindNotFound
	case se.Code == 403 || strings.Contains(d, "forbidden") || strings.Contains(d, "blocked"):
		kind = KindPermission
	case se.Code == 429 || strings.Contains(d, "too many requests"):
		kind = KindRateLimit
	}
	return &Error{
		Op:          "telegram-send",
		Kind:        kind,
		Message:     se.Error(),
		Remediation: se.Remediation(),
		Details:     map[string]any{"chat_id": se.ChatID},
		Cause:       cause,
	}
}

// fromS3 classifies a bucket's refusal of a backup upload.
//
// The three an operator can actually act on need opposite fixes and used to be
// one line in the log: a key the bucket does not accept, a bucket that is not
// there, and a service asking to be slowed down. A status of 0 means the
// endpoint was never reached at all, which is a different problem again and the
// one most likely to be the egress proxy rather than the bucket.
func fromS3(e *backup.S3Error, cause error) *Error {
	code := strings.ToLower(e.Code)
	kind := KindNetwork
	remediation := "Check the endpoint URL and that this panel can reach it; if an egress proxy is configured, this upload goes through it too."
	switch {
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden ||
		strings.Contains(code, "signature") || strings.Contains(code, "accesskey") ||
		strings.Contains(code, "accessdenied") || strings.Contains(code, "invalidaccesskeyid"):
		kind = KindAuth
		remediation = "Check the access key and secret key, and that the key is allowed to PutObject in this bucket. A wrong region also signs wrongly on services that enforce one."
	case e.Status == http.StatusNotFound || strings.Contains(code, "nosuchbucket"):
		kind = KindNotFound
		remediation = "Create the bucket first, or correct its name. The panel never creates a bucket: doing so silently would put the panel's whole state somewhere nobody chose."
	case e.Status == http.StatusTooManyRequests || strings.Contains(code, "slowdown"):
		kind = KindRateLimit
		remediation = "The service is throttling. The next scheduled backup retries on its own."
	case e.Status >= 500:
		kind = KindUnavailable
		remediation = "The storage service reported its own failure. The next scheduled backup retries on its own."
	}
	out := &Error{
		Op:          "backup-s3",
		Kind:        kind,
		Message:     e.Error(),
		Remediation: remediation,
		Cause:       cause,
	}
	if e.Code != "" {
		out.Details = map[string]any{"s3_code": e.Code}
	}
	return out
}

// Unspecified is the answer when there is no usable error to describe. It is
// never a 200: a writer called with nothing to report is a bug in the caller,
// and hiding it behind an empty success body is how it stays one.
func Unspecified() *Error {
	return &Error{Kind: KindServer, Message: "an unspecified error occurred"}
}

// IsTyped reports whether err carries one of the panel's typed errors, and so
// already knows its own kind, status and remediation.
func IsTyped(err error) bool {
	if err == nil {
		return false
	}
	// Same nil-pointer trap as From, and the same reason to spring it here: a
	// typed pointer that is nil carries no classification, so it is not typed.
	switch v := err.(type) {
	case *Error:
		return v != nil
	case *dns.Error:
		return v != nil
	case *edge.Error:
		return v != nil
	case *telegram.SendError:
		return v != nil
	case *backup.S3Error:
	case *netegress.BlockedError:
		return v != nil
	}
	if e, ok := As(err); ok && e != nil {
		return true
	}
	if e, ok := dns.AsError(err); ok && e != nil {
		return true
	}
	if e, ok := edge.AsError(err); ok && e != nil {
		return true
	}
	var se *telegram.SendError
	if errors.As(err, &se) && se != nil {
		return true
	}
	var s3e *backup.S3Error
	if errors.As(err, &s3e) && s3e != nil {
		return true
	}
	// Both halves matter: registering *BlockedError in From alone still lets
	// Coerce flatten a guard refusal back onto the caller's fallback status,
	// and the classification above becomes cosmetic.
	var be *netegress.BlockedError
	return errors.As(err, &be) && be != nil
}

// Coerce is From for a handler that has already chosen a status.
//
// A typed error keeps its own kind and status: that is the whole point — a
// handler flattening a Cloudflare "no such zone" into its own 400 was the bug.
// An untyped error takes the caller's status, because "the handler looked at
// this and decided it was a 404" is better information than "we could not
// classify it, so 500".
func Coerce(err error, fallbackStatus int) *Error {
	e := From(err)
	if e == nil || IsTyped(err) || fallbackStatus == 0 {
		return e
	}
	e.Kind = KindForStatus(fallbackStatus)
	e.Status = fallbackStatus
	return e
}
