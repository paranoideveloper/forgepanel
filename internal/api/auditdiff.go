package api

// Recording WHAT CHANGED in an audit entry.
//
// AuditLog carries a Diff column. It is stored, it is served, and no handler
// ever wrote it — so every entry said that someone changed an inbound and
// nothing at all about what they changed. That is the difference between a trail
// you can investigate with and a list of timestamps: "alice edited inbound 7" is
// not an answer to "who opened port 443 to the world".
//
// The diff is deliberately FIELD-LEVEL and compact rather than a full before/
// after dump. Two reasons, and the second matters more:
//
//   * a whole config in every row makes the table enormous and the UI unusable;
//   * a full dump would copy CREDENTIALS into the audit trail — private keys,
//     passwords, tokens — which turns an access-control record into a second
//     place secrets live, readable by anyone who can read the trail.
//
// So secret-bearing fields are recorded as "changed" without their values.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// maxDiffLen bounds one entry. A pathological change (a huge rule list, a
// pasted certificate) must not put an unbounded blob in every row.
const maxDiffLen = 2000

// secretFieldHints are substrings that mark a field as credential-bearing.
//
// Matched on the KEY, not the value, and matched loosely on purpose: a new
// secret field added to the model should default to redacted rather than
// default to leaked. The cost of over-redacting is an audit entry that says
// "password changed" instead of naming it; the cost of under-redacting is
// secrets in a table people are encouraged to read.
var secretFieldHints = []string{
	"password", "secret", "key", "token", "uuid", "credential",
	"seed", "psk", "auth", "cert", "pem",
}

func isSecretField(name string) bool {
	l := strings.ToLower(name)
	for _, h := range secretFieldHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// diffJSON compares two JSON documents and returns a compact field-level
// summary, or "" when nothing changed.
//
// Nested objects are walked with dotted paths, so "security.reality.dest" reads
// the way an operator refers to it rather than as a nested blob.
func diffJSON(before, after []byte) string {
	var b, a map[string]any
	// A document that does not parse is not a reason to lose the audit entry;
	// the entry is still worth having without a diff.
	if len(before) > 0 && json.Unmarshal(before, &b) != nil {
		return ""
	}
	if len(after) > 0 && json.Unmarshal(after, &a) != nil {
		return ""
	}
	var out []string
	walkDiff("", b, a, &out)
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	s := strings.Join(out, "; ")
	if len(s) > maxDiffLen {
		s = s[:maxDiffLen] + " …(truncated)"
	}
	return s
}

func walkDiff(prefix string, before, after map[string]any, out *[]string) {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, k := range names {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		bv, hadB := before[k]
		av, hadA := after[k]

		bm, bIsMap := bv.(map[string]any)
		am, aIsMap := av.(map[string]any)
		if bIsMap || aIsMap {
			if bm == nil {
				bm = map[string]any{}
			}
			if am == nil {
				am = map[string]any{}
			}
			walkDiff(path, bm, am, out)
			continue
		}

		bs, as := scalarString(bv), scalarString(av)
		if hadB && hadA && bs == as {
			continue
		}
		if !hadB && !hadA {
			continue
		}
		switch {
		case isSecretField(k):
			// Named, never valued.
			if bs != as {
				*out = append(*out, path+": changed")
			}
		case !hadB:
			*out = append(*out, fmt.Sprintf("%s: set to %s", path, clip(as)))
		case !hadA:
			*out = append(*out, path+": removed")
		default:
			*out = append(*out, fmt.Sprintf("%s: %s → %s", path, clip(bs), clip(as)))
		}
	}
}

// scalarString renders a leaf value stably, so an unchanged field never looks
// changed because a number formatted differently between two reads.
func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers are float64; render integers without a decimal tail so
		// port 443 does not read as "443 → 443".
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}

// clip keeps one field's value short. A pasted certificate should not push the
// three fields that actually changed off the end of the entry.
func clip(s string) string {
	const max = 80
	if len(s) <= max {
		if s == "" {
			return "(empty)"
		}
		return s
	}
	return s[:max] + "…"
}

// auditWithDiff records an action together with what changed.
func (s *Server) auditWithDiff(c *gin.Context, action, target string, before, after []byte) {
	if s.db == nil {
		return
	}
	claims, _ := auth.ClaimsFrom(c)
	al := &store.AuditLog{
		IP: c.ClientIP(), Action: action, Target: target,
		Diff: diffJSON(before, after),
	}
	if claims != nil {
		al.AdminID = claims.AdminID
		al.Actor = claims.Username
	}
	s.db.Audit(al)
}

// auditNote records an action with a plain-language note in the Diff column.
//
// For mutations where a before/after comparison says nothing useful but the
// SHAPE of the change matters. A credential rotation is the example: the values
// must never be recorded, and "credentials reset" alone cannot answer whether
// someone handed out a fresh subscription link or invalidated every config the
// user held — three very different blast radii.
func (s *Server) auditNote(c *gin.Context, action, target, note string) {
	if s.db == nil {
		return
	}
	claims, _ := auth.ClaimsFrom(c)
	al := &store.AuditLog{IP: c.ClientIP(), Action: action, Target: target, Diff: note}
	if claims != nil {
		al.AdminID = claims.AdminID
		al.Actor = claims.Username
	}
	s.db.Audit(al)
}
