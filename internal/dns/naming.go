package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// DefaultNameTemplate is the shipped subdomain pattern. It keeps the protocol
// visible (so an operator reading a DNS list knows what a name is for), the
// node identifiable, and a random tail so a burned name is replaceable without
// collisions.
const DefaultNameTemplate = "{proto}-{node}-{rand}"

// nameAlphabet excludes vowels and look-alike characters. Generated labels end
// up in QR codes and get read aloud over the phone, and a random label must
// never accidentally spell a word that a keyword filter would match.
const nameAlphabet = "bcdfghjkmnpqrstvwxz23456789"

// TemplateVars are the substitutions available to a NameTemplate.
type TemplateVars struct {
	// Proto is the inbound protocol or transport, e.g. "ws", "reality", "hy2".
	Proto string
	// Node identifies the server, e.g. "fra1".
	Node string
	// Region is an optional geographic tag.
	Region string
	// Seq is the 1-based index within a bulk run.
	Seq int
	// Now supplies {date}; zero means time.Now.
	Now time.Time
	// Extra holds arbitrary {key} substitutions.
	Extra map[string]string
	// RandFn generates the {rand} tail; nil means crypto/rand.
	RandFn func(n int) (string, error)
}

// NameTemplate renders subdomain labels from a pattern.
//
// Placeholders: {proto} {node} {region} {seq} {date} {rand} {rand:N} and any
// key in Extra. Unknown placeholders are an error rather than being left
// literal, because a stray "{nodee}" would otherwise become a real DNS label
// containing braces and fail much later at the provider.
type NameTemplate struct {
	Pattern string
}

// NewNameTemplate builds a template, defaulting an empty pattern.
func NewNameTemplate(pattern string) NameTemplate {
	if strings.TrimSpace(pattern) == "" {
		pattern = DefaultNameTemplate
	}
	return NameTemplate{Pattern: strings.TrimSpace(pattern)}
}

// RandomLabel returns n characters from the reduced alphabet using crypto/rand.
func RandomLabel(n int) (string, error) {
	if n <= 0 {
		n = 6
	}
	if n > 32 {
		n = 32
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(nameAlphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", &Error{Op: "random-label", Kind: KindServer,
				Message: "could not read cryptographic randomness: " + err.Error(), Cause: err}
		}
		out[i] = nameAlphabet[idx.Int64()]
	}
	return string(out), nil
}

// Render substitutes the placeholders and returns a sanitised DNS label.
func (t NameTemplate) Render(vars TemplateVars) (string, error) {
	pattern := t.Pattern
	if strings.TrimSpace(pattern) == "" {
		pattern = DefaultNameTemplate
	}
	randFn := vars.RandFn
	if randFn == nil {
		randFn = RandomLabel
	}
	now := vars.Now
	if now.IsZero() {
		now = time.Now()
	}

	var out strings.Builder
	for i := 0; i < len(pattern); {
		ch := pattern[i]
		if ch != '{' {
			out.WriteByte(ch)
			i++
			continue
		}
		end := strings.IndexByte(pattern[i:], '}')
		if end < 0 {
			return "", &Error{Op: "render-template", Kind: KindValidation,
				Message:     fmt.Sprintf("template %q has an unclosed '{'", pattern),
				Remediation: "close every placeholder, e.g. {proto}-{node}-{rand}"}
		}
		key := pattern[i+1 : i+end]
		i += end + 1

		value, err := resolvePlaceholder(key, vars, now, randFn)
		if err != nil {
			return "", err
		}
		out.WriteString(value)
	}

	label := sanitizeLabel(out.String())
	if label == "" {
		return "", &Error{Op: "render-template", Kind: KindValidation,
			Message:     fmt.Sprintf("template %q rendered to an empty label", pattern),
			Remediation: "the substituted values were all empty or non-DNS characters; set --node/--proto or add a literal prefix to the template"}
	}
	if len(label) > 63 {
		return "", &Error{Op: "render-template", Kind: KindValidation,
			Message:     fmt.Sprintf("template %q rendered %q, which is %d characters and over the 63-character DNS label limit", pattern, label, len(label)),
			Remediation: "shorten the node name or drop a component from the template"}
	}
	return label, nil
}

func resolvePlaceholder(key string, vars TemplateVars, now time.Time, randFn func(int) (string, error)) (string, error) {
	lower := strings.ToLower(strings.TrimSpace(key))
	if strings.HasPrefix(lower, "rand") {
		n := 6
		if rest, ok := strings.CutPrefix(lower, "rand:"); ok {
			parsed, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil || parsed <= 0 {
				return "", &Error{Op: "render-template", Kind: KindValidation,
					Message:     fmt.Sprintf("placeholder {%s} needs a positive length, e.g. {rand:8}", key),
					Remediation: "use {rand} for the 6-character default or {rand:N} for N characters"}
			}
			n = parsed
		} else if lower != "rand" {
			return "", unknownPlaceholder(key, vars)
		}
		return randFn(n)
	}
	switch lower {
	case "proto", "protocol":
		return vars.Proto, nil
	case "node":
		return vars.Node, nil
	case "region":
		return vars.Region, nil
	case "seq":
		return strconv.Itoa(vars.Seq), nil
	case "date":
		return now.UTC().Format("20060102"), nil
	}
	if v, ok := vars.Extra[lower]; ok {
		return v, nil
	}
	if v, ok := vars.Extra[key]; ok {
		return v, nil
	}
	return "", unknownPlaceholder(key, vars)
}

func unknownPlaceholder(key string, vars TemplateVars) error {
	known := []string{"proto", "node", "region", "seq", "date", "rand", "rand:N"}
	for k := range vars.Extra {
		known = append(known, k)
	}
	return &Error{Op: "render-template", Kind: KindValidation,
		Message:     fmt.Sprintf("unknown template placeholder {%s}", key),
		Remediation: "available placeholders: {" + strings.Join(known, "} {") + "}"}
}

// sanitizeLabel forces a rendered string into a legal DNS label: lower-case,
// alphanumerics and hyphens, no doubled or edge hyphens.
func sanitizeLabel(s string) string {
	var b strings.Builder
	lastHyphen := true // suppress a leading hyphen
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastHyphen = false
		case r == '-' || r == '_' || r == ' ' || r == '.' || r == '/':
			if !lastHyphen {
				b.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// GenerateNames renders count unique fully-qualified names under domain. It
// retries a collision within the run rather than returning duplicates, which
// would make the subsequent bulk create silently produce fewer records than
// asked for.
func (t NameTemplate) GenerateNames(domain string, count int, vars TemplateVars) ([]string, error) {
	if count <= 0 {
		return nil, &Error{Op: "generate-names", Kind: KindValidation,
			Message: fmt.Sprintf("count must be positive, got %d", count), Remediation: "pass --count 1 or higher"}
	}
	if count > 500 {
		return nil, &Error{Op: "generate-names", Kind: KindValidation,
			Message:     fmt.Sprintf("count %d exceeds the 500-record safety cap", count),
			Remediation: "create fewer names per run; provider rate limits make larger batches fail partway through anyway"}
	}
	base := NormalizeDomain(domain)
	if err := ValidateFQDN(base); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		v := vars
		v.Seq = i + 1
		var name string
		// The template may be fully deterministic ({proto}-{node} with no
		// {rand}), in which case a second name is impossible; say so instead of
		// spinning.
		var lastLabel string
		for attempt := 0; attempt < 20; attempt++ {
			label, err := t.Render(v)
			if err != nil {
				return nil, err
			}
			lastLabel = label
			candidate := label + "." + base
			if !seen[candidate] {
				name = candidate
				break
			}
		}
		if name == "" {
			return nil, &Error{Op: "generate-names", Kind: KindValidation,
				Message:     fmt.Sprintf("template %q cannot produce %d distinct names — it keeps rendering %q", t.Pattern, count, lastLabel),
				Remediation: "add {rand} or {seq} to the template so each name is unique"}
		}
		if err := ValidateFQDN(name); err != nil {
			return nil, err
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// BulkSpec describes a batch of identical records under generated names.
type BulkSpec struct {
	// ZoneRef is the provider zone handle to write into.
	ZoneRef string
	// Domain is the parent the generated labels hang off; it may be a
	// subdomain of the zone.
	Domain   string
	Template string
	Type     RecordType
	Content  string
	TTL      int
	Proxied  bool
	Count    int
	Comment  string
	Vars     TemplateVars
}

// BulkResult reports one record from a bulk run.
type BulkResult struct {
	Name   string `json:"name"`
	Action string `json:"action,omitempty"`
	Record Record `json:"record,omitempty"`
	Error  string `json:"error,omitempty"`
	// Remediation is set when Error is.
	Remediation string `json:"remediation,omitempty"`
}

// BulkCreate generates names and upserts a record for each. It does not abort
// on the first failure: a rate limit partway through a 50-record batch should
// still leave the operator with the 30 records that landed and an exact reason
// for the rest.
func BulkCreate(ctx context.Context, p Provider, spec BulkSpec) ([]BulkResult, error) {
	rtype := spec.Type
	if rtype == "" {
		rtype = TypeA
	}
	if _, err := NormalizeType(string(rtype)); err != nil {
		return nil, err
	}
	tpl := NewNameTemplate(spec.Template)
	names, err := tpl.GenerateNames(spec.Domain, spec.Count, spec.Vars)
	if err != nil {
		return nil, err
	}
	ttl := spec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	results := make([]BulkResult, 0, len(names))
	for _, name := range names {
		rec := Record{
			Type: rtype, Name: name, Content: spec.Content,
			TTL: ttl, Proxied: spec.Proxied, Comment: spec.Comment,
		}
		res, err := EnsureRecord(ctx, p, spec.ZoneRef, rec)
		if err != nil {
			br := BulkResult{Name: name, Error: err.Error()}
			if e, ok := AsError(err); ok {
				br.Error = e.Message
				br.Remediation = e.Remediation
			}
			results = append(results, br)
			// A rejected credential will reject every remaining name too;
			// stopping keeps the operator from reading the same error 50 times.
			if KindOf(err) == KindAuth || KindOf(err) == KindPermission {
				return results, err
			}
			continue
		}
		results = append(results, BulkResult{Name: name, Action: res.Action, Record: res.Record})
	}
	return results, nil
}
