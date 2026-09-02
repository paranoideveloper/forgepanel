package apierr

import "github.com/gin-gonic/gin"

// Fail is the single place an error becomes an HTTP response.
//
// Every refused request in the panel goes through here, which is what makes the
// envelope worth extending: adding a field to Error.Body reaches all of them at
// once, instead of reaching the two handlers somebody remembered.
func Fail(c *gin.Context, err error) {
	e := From(err)
	if e == nil {
		e = Unspecified()
	}
	c.JSON(e.HTTPStatus(), e.Body())
}

// FailStatus writes err with a status the caller has already decided, for the
// handlers that predate typed errors. A typed error still wins; see Coerce.
func FailStatus(c *gin.Context, status int, err error) {
	Fail(c, Coerce(err, status))
}
