package cfedge

import (
	"strings"
	"testing"
)

func TestEmbeddedWorkerIsPresent(t *testing.T) {
	if len(WorkerJS) < 2000 {
		t.Fatalf("embedded worker.js looks too small (%d bytes)", len(WorkerJS))
	}
	// Sanity: it must be the VLESS edge worker, not some stub.
	for _, marker := range []string{"cloudflare:sockets", "parseVlessHeader", "vlessOverWS", "buildConfigs"} {
		if !strings.Contains(WorkerJS, marker) {
			t.Fatalf("embedded worker.js missing marker %q", marker)
		}
	}
}

func TestOptionsScriptDefault(t *testing.T) {
	if (Options{}).script() != "forgeedge" {
		t.Fatal("empty script name should default to forgeedge")
	}
	if (Options{ScriptName: "  custom "}).script() != "custom" {
		t.Fatal("script name should be trimmed")
	}
}

func TestCredentialsValidation(t *testing.T) {
	if err := (Credentials{}).valid(); err == nil {
		t.Fatal("empty credentials must be rejected")
	}
	if err := (Credentials{AccountID: "a"}).valid(); err == nil {
		t.Fatal("account id without any auth must be rejected")
	}
	if err := (Credentials{AccountID: "a", APIToken: "t"}).valid(); err != nil {
		t.Fatalf("account id + token should be valid: %v", err)
	}
	if err := (Credentials{AccountID: "a", Email: "e", GlobalKey: "k"}).valid(); err != nil {
		t.Fatalf("account id + email + global key should be valid: %v", err)
	}
	if err := (Credentials{AccountID: "a", Email: "e"}).valid(); err == nil {
		t.Fatal("email without global key must be rejected")
	}
}
