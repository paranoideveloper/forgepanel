package model

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every protocol the panel enumerates must resolve to a real engine. Without
// this, a protocol added without an engine mapping silently becomes
// EngineUnknown and fails much later, at reload time, as "nothing happened".
func TestEveryProtocolHasAnEngine(t *testing.T) {
	for _, p := range AllProtocols() {
		if e := EngineFor(p); e == EngineUnknown || e == "" {
			t.Errorf("protocol %q has no engine mapping — add it to engineByProtocol", p)
		}
	}
}

// declaredProtocols scrapes the package's own source for Protocol constants.
//
// Go cannot reflect over constants, and this guard is worth the scrape: the
// AmneziaWG bug was exactly this shape — the constant and its full kernel-mode
// implementation existed, but AllProtocols() omitted it, so every consumer that
// asks "which protocols exist" (API metadata, UI pickers, test matrices) could
// not see it. A declared-but-unlisted protocol is invisible, not broken, which
// is why nothing caught it.
func declaredProtocols(t *testing.T) []string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s*(Proto[A-Za-z0-9]+)\s+Protocol\s*=\s*"([a-z0-9-]+)"`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || regexp.MustCompile(`_test\.go$`).MatchString(name) {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			out = append(out, m[2])
		}
	}
	if len(out) == 0 {
		t.Fatal("scraped zero Protocol constants — the regex or layout changed, fix this guard")
	}
	return out
}

func TestAllProtocolsListsEveryDeclaredProtocol(t *testing.T) {
	listed := map[string]bool{}
	for _, p := range AllProtocols() {
		listed[string(p)] = true
	}
	for _, declared := range declaredProtocols(t) {
		if !listed[declared] {
			t.Errorf("protocol %q is declared as a constant but missing from AllProtocols() — "+
				"it will be invisible to the API, the UI and every test matrix", declared)
		}
	}
}

// The reverse direction: AllProtocols must not name something that no longer
// exists, which would surface as an empty picker entry.
func TestAllProtocolsHasNoPhantoms(t *testing.T) {
	declared := map[string]bool{}
	for _, d := range declaredProtocols(t) {
		declared[d] = true
	}
	for _, p := range AllProtocols() {
		if !declared[string(p)] {
			t.Errorf("AllProtocols() lists %q which is not a declared Protocol constant", p)
		}
	}
}

// ProtocolsForEngine must partition AllProtocols exactly: every protocol lands
// in exactly one engine bucket, and the buckets sum to the whole set.
func TestProtocolsForEnginePartitionsAllProtocols(t *testing.T) {
	engines := []string{EngineXray, EngineSingBox, EngineAmneziaWG, EngineBrook, EngineForgeDNS}
	seen := map[Protocol]int{}
	for _, e := range engines {
		for _, p := range ProtocolsForEngine(e) {
			seen[p]++
		}
	}
	for _, p := range AllProtocols() {
		switch seen[p] {
		case 1: // exactly right
		case 0:
			t.Errorf("protocol %q belongs to no engine bucket", p)
		default:
			t.Errorf("protocol %q claimed by %d engines", p, seen[p])
		}
	}
}

// The specific drift this refactor removed, pinned so it cannot come back.
func TestForgeDNSAndAmneziaWGResolveToTheirOwnEngines(t *testing.T) {
	if got := EngineFor(ProtoForgeDNS); got != EngineForgeDNS {
		t.Errorf("forgedns -> %q, want %q (core.engineFor used to return \"\" here)", got, EngineForgeDNS)
	}
	if got := EngineFor(ProtoAmneziaWG); got != EngineAmneziaWG {
		t.Errorf("amneziawg -> %q, want %q — routing it to sing-box selects the userspace implementation", got, EngineAmneziaWG)
	}
	if got := EngineFor(Protocol("nonsense")); got != EngineUnknown {
		t.Errorf("unmapped protocol -> %q, want %q", got, EngineUnknown)
	}
	if got := EngineForNode(nil); got != EngineUnknown {
		t.Errorf("nil node -> %q, want %q", got, EngineUnknown)
	}
}
