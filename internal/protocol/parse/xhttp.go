package parse

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// applyXHTTPExtended decodes the extended XHTTP knobs a share link can carry.
//
// There are two competing conventions in the wild and a link may use either or
// both: the whole xhttpSettings object packed into `extra=<json>` (what the
// panels emit, and what carries the nested xmux / downloadSettings objects), and
// individual camelCase query parameters. Both are read, with the explicit
// parameters applied LAST so a link that carries a stale `extra` blob plus a
// corrected parameter imports as the operator sees it.
//
// A malformed `extra` payload is ignored rather than fatal: the rest of the link
// is still a working tunnel, and refusing to import a whole subscription because
// one node has a truncated blob is the worse failure.
func applyXHTTPExtended(t *model.Transport, q url.Values) {
	_ = t.ApplyXHTTPExtra(q.Get("extra"))

	// x_padding_bytes is the snake_case spelling some panels emit; the
	// camelCase key below wins when both are present.
	setXHTTPString(&t.XPaddingB, q, "x_padding_bytes")
	setXHTTPString(&t.XPaddingB, q, "xPaddingBytes")
	setXHTTPBool(&t.XPaddingObfsMode, q, "xPaddingObfsMode")
	setXHTTPString(&t.XPaddingKey, q, "xPaddingKey")
	setXHTTPString(&t.XPaddingHeader, q, "xPaddingHeader")
	setXHTTPString(&t.XPaddingPlacement, q, "xPaddingPlacement")
	setXHTTPString(&t.XPaddingMethod, q, "xPaddingMethod")

	setXHTTPBool(&t.NoGRPCHeader, q, "noGRPCHeader")
	setXHTTPBool(&t.NoSSEHeader, q, "noSSEHeader")

	setXHTTPString(&t.SCMaxEachPostBytes, q, "scMaxEachPostBytes")
	setXHTTPString(&t.SCMinPostsIntervalMs, q, "scMinPostsIntervalMs")
	setXHTTPInt(&t.SCMaxBufferedPosts, q, "scMaxBufferedPosts")
	setXHTTPString(&t.SCStreamUpServerSecs, q, "scStreamUpServerSecs")

	// Links minted before the core renamed the session parameters carry
	// sessionIDPlacement/sessionIDKey; accept them so an old link still imports.
	setXHTTPString(&t.SessionPlacement, q, "sessionIDPlacement")
	setXHTTPString(&t.SessionKey, q, "sessionIDKey")
	setXHTTPString(&t.SessionPlacement, q, "sessionPlacement")
	setXHTTPString(&t.SessionKey, q, "sessionKey")
	setXHTTPString(&t.SeqPlacement, q, "seqPlacement")
	setXHTTPString(&t.SeqKey, q, "seqKey")

	setXHTTPString(&t.UplinkDataPlacement, q, "uplinkDataPlacement")
	setXHTTPString(&t.UplinkDataKey, q, "uplinkDataKey")
	setXHTTPString(&t.UplinkHTTPMethod, q, "uplinkHTTPMethod")
	setXHTTPInt(&t.UplinkChunkSize, q, "uplinkChunkSize")
	setXHTTPInt(&t.ServerMaxHeaderBytes, q, "serverMaxHeaderBytes")
}

// setXHTTPString overwrites dst only when the parameter is present and
// non-empty, so a later key never blanks a value an earlier one supplied.
func setXHTTPString(dst *string, q url.Values, key string) {
	if v := strings.TrimSpace(q.Get(key)); v != "" {
		*dst = v
	}
}

func setXHTTPInt(dst *int, q url.Values, key string) {
	v := strings.TrimSpace(q.Get(key))
	if v == "" {
		return
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		*dst = n
	}
}

// setXHTTPBool accepts every truthy spelling share links use in practice.
func setXHTTPBool(dst *bool, q url.Values, key string) {
	v := strings.TrimSpace(strings.ToLower(q.Get(key)))
	switch v {
	case "1", "true", "yes", "on":
		*dst = true
	case "0", "false", "no", "off":
		*dst = false
	}
}
