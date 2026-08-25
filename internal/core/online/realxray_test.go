package online

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// End-to-end against a REAL Xray: generate a config the way the panel does,
// run it, make a connection through it, and confirm the presence tracker sees
// the user. Everything else in this package is a unit test against captured
// lines; this is the one that proves the captured lines are still what the
// binary emits.
func TestAgainstRealXray(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes and needs outbound network")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl to drive a connection through the proxy")
	}
	dir := t.TempDir()

	uuid := "8f1c9e4a-0d3b-4c7a-9f21-6b5d8e2a1c47"
	srv := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": ""},
		"inbounds": []any{map[string]any{
			"tag": "vless-in", "listen": "127.0.0.1", "port": 24443, "protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": uuid, "email": "u.42"}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{"network": "tcp"},
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	cli := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "s", "listen": "127.0.0.1", "port": 24081, "protocol": "socks",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": 24443,
				"users": []any{map[string]any{"id": uuid, "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{"network": "tcp"},
		}},
	}
	write := func(name string, v any) string {
		p := filepath.Join(dir, name)
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srvPath, cliPath := write("srv.json", srv), write("cli.json", cli)

	tr := NewTracker(time.Minute)

	scmd := exec.Command(bin, "run", "-c", srvPath)
	stdout, err := scmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := scmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scmd.Process.Kill(); _ = scmd.Wait() }()

	// Exactly what the supervisor's pump does.
	hook := tr.ObserveLine("local")
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			hook(sc.Text())
		}
	}()

	ccmd := exec.Command(bin, "run", "-c", cliPath)
	if err := ccmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ccmd.Process.Kill(); _ = ccmd.Wait() }()

	time.Sleep(2 * time.Second)

	ok := false
	for i := 0; i < 8; i++ {
		c := exec.Command("curl", "-s", "--max-time", "8", "--socks5", "127.0.0.1:24081",
			"http://example.com/", "-o", "/dev/null")
		_ = c.Run()
		time.Sleep(600 * time.Millisecond)
		if snap := tr.Snapshot(); len(snap) > 0 {
			if snap[0].User != "u.42" {
				t.Fatalf("tracked user = %q, want u.42", snap[0].User)
			}
			if len(snap[0].Sessions) == 0 || snap[0].Sessions[0].IP != "127.0.0.1" {
				t.Fatalf("sessions = %+v, want a 127.0.0.1 session", snap[0].Sessions)
			}
			if snap[0].Sessions[0].Inbound != "vless-in" {
				t.Fatalf("inbound = %q, want vless-in", snap[0].Sessions[0].Inbound)
			}
			ok = true
			break
		}
	}
	if !ok {
		t.Fatal("a real connection through a real Xray produced no presence: the access log format this package parses has changed")
	}
}
