package api

// Cross-language guard: every JSON key the SvelteKit UI posts to the API must
// actually exist as a json tag the Go side binds.
//
// Three separate features were completely dead in shipped code because nobody
// checked this, and each failed in a way that looked like something else:
//
//   change-password    UI sent {old_password,new_password}, handler binds
//                      {old,new} -> both empty -> 400 with a misleading
//                      "at least 8 characters" error. Changing the admin
//                      password was impossible from the panel.
//   certs/import       UI sent {cert_pem,key_pem}, handler binds {cert,key} ->
//                      X509KeyPair got two empty buffers -> no certificate
//                      could ever be imported.
//   reset-credentials  UI posted NO body; the handler refuses a request that
//                      names nothing to rotate -> credential rotation, the most
//                      urgent action after a leak, was unavailable.
//
// The Svelte unit tests did not catch any of it because they mock fetch and
// assert only that a call happened, never the shape of the body. Nothing else
// crosses the language boundary, so nothing else could catch it.
//
// This test reads the real frontend source, extracts the keys of every
// JSON.stringify body sent to an /admin or /api path, and fails if a key
// appears nowhere in internal/api as a bound json tag. It is intentionally a
// containment check rather than a per-endpoint schema: a typo, a rename on
// either side, or a field the backend never learned about all fail here, with
// no per-endpoint table to keep up to date.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// keysSentByUI finds JSON.stringify({...}) bodies in the frontend and returns
// the top-level keys, mapped to the file that sends them.
func keysSentByUI(t *testing.T, root string) map[string][]string {
	t.Helper()
	// JSON.stringify({ a: x, b: y }) — non-greedy to the first closing brace,
	// which is correct for the flat request bodies the UI actually sends.
	call := regexp.MustCompile(`JSON\.stringify\(\{([^{}]*)\}\)`)
	// key: value  /  'key': value  /  "key": value
	keyRe := regexp.MustCompile(`(?m)(?:^|,)\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*:`)

	out := map[string][]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".svelte" && ext != ".ts" {
			return nil
		}
		// Test files legitimately fabricate payloads to drive mocks.
		if strings.HasSuffix(path, ".test.ts") || strings.Contains(path, "__tests__") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, m := range call.FindAllStringSubmatch(string(src), -1) {
			for _, k := range keyRe.FindAllStringSubmatch(m[1], -1) {
				out[k[1]] = append(out[k[1]], filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// tagsBoundByGo collects every json tag declared anywhere in internal/api, which
// is the set of keys the API can actually receive.
func tagsBoundByGo(t *testing.T) map[string]bool {
	t.Helper()
	tag := regexp.MustCompile(`json:"([A-Za-z_][A-Za-z0-9_]*)`)
	out := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			continue
		}
		for _, m := range tag.FindAllStringSubmatch(string(src), -1) {
			out[m[1]] = true
		}
	}
	// The model, store and settings packages are bound through the API too.
	for _, pkg := range []string{
		"../protocol/model", "../store", "../settings", "../dns", "../forgedns", "../config",
	} {
		entries, err := os.ReadDir(pkg)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
				continue
			}
			src, err := os.ReadFile(filepath.Join(pkg, e.Name()))
			if err != nil {
				continue
			}
			for _, m := range tag.FindAllStringSubmatch(string(src), -1) {
				out[m[1]] = true
			}
		}
	}
	if len(out) < 50 {
		t.Fatalf("only found %d json tags — the scan is broken, not the UI", len(out))
	}
	return out
}

// uiOnlyKeys are keys the UI sends inside bodies that are NOT API request
// payloads (third-party APIs, or nested objects the backend receives under a
// different name). Each needs a reason; an unexplained entry here is how this
// guard would get quietly neutered.
var uiOnlyKeys = map[string]string{
	"query":            "GraphQL/third-party payloads, not the ForgePanel API",
	"variables":        "GraphQL variables",
	"jsonrpc":          "JSON-RPC envelope to an external service",
	"method":           "JSON-RPC envelope field",
	"params":           "JSON-RPC envelope field",
	"chat_id":          "Telegram Bot API, called directly by the browser in some flows",
	"text":             "Telegram Bot API message body",
	"purge_everything": "Cloudflare API cache purge, not ForgePanel",
}

func TestUIRequestKeysExistInTheAPI(t *testing.T) {
	sent := keysSentByUI(t, filepath.Join("..", "..", "frontend", "src"))
	if len(sent) == 0 {
		t.Skip("no frontend sources found; nothing to check")
	}
	bound := tagsBoundByGo(t)

	var bad []string
	for key, files := range sent {
		if bound[key] || uiOnlyKeys[key] != "" {
			continue
		}
		sort.Strings(files)
		bad = append(bad, key+"  (sent by "+strings.Join(uniqueStrings(files), ", ")+")")
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("the UI posts %d key(s) the API never binds — these silently arrive empty and the "+
			"feature fails in a way that looks like a validation bug:\n  - %s\n\n"+
			"Fix the UI to send the name the handler binds, add the field to the Go struct, or (only if "+
			"it is genuinely not a ForgePanel API call) document it in uiOnlyKeys.",
			len(bad), strings.Join(bad, "\n  - "))
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
