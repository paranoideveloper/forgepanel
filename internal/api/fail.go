package api

import (
	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/gin-gonic/gin"
)

// The three writers every refused request in this package goes through.
//
// They are thin on purpose. Their job is not to add behaviour but to remove a
// choice: before them, 386 handlers each decided for themselves what an error
// body looks like, so `kind` existed on two endpoints, `remediation` on those
// same two, and a Cloudflare refusal that named the exact missing token scope
// arrived at the browser as a 400 with one sentence. Routing everything through
// apierr means the envelope is defined once and extending it reaches all of it.
//
// The status argument stays because these handlers have already decided, often
// with a test pinning the number. A TYPED error overrides it — that is the fix,
// not a side effect: a *dns.Error saying not_found must not be answered 400
// merely because the handler that called the DNS layer assumed the worst case
// was a bad request.

// fail writes a refusal the handler itself diagnosed, with prose for the operator.
func fail(c *gin.Context, status int, msg string) {
	apierr.Fail(c, apierr.New(status, msg))
}

// failErr writes an error from further down. If it is typed, its own kind,
// status and remediation win over status.
func failErr(c *gin.Context, status int, err error) {
	apierr.FailStatus(c, status, err)
}

// abortFail is fail for middleware: it stops the handler chain as well as
// answering, which is the difference between rejecting a request and merely
// commenting on it.
func abortFail(c *gin.Context, status int, msg string) {
	c.Abort()
	fail(c, status, msg)
}

// abortFailWith is abortFail for an error that already knows its own kind.
func abortFailWith(c *gin.Context, err error) {
	c.Abort()
	apierr.Fail(c, err)
}

// failFields refuses with a message AND per-input detail, so the UI can put each
// message under the input that caused it instead of one toast for the whole
// form. It keeps the caller's own status rather than forcing 422: a refusal that
// is a 400 for a reason should stay a 400.
func failFields(c *gin.Context, status int, msg string, fields map[string]string) {
	e := apierr.New(status, msg)
	e.Fields = fields
	apierr.Fail(c, e)
}
