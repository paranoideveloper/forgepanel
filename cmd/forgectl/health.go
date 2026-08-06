package main

// forgectl healthcheck — the probe used by the container HEALTHCHECK and by any
// external monitor.
//
// Why this lives in forgectl instead of being a curl one-liner: the runtime
// image is distroless, so there is no shell, no curl and no wget to probe with.
// Docker's exec-form HEALTHCHECK can only run a binary that is already in the
// image, and forgectl is already there.
//
// It is deliberately scheme-agnostic and does NOT verify the certificate: the
// panel may serve plain HTTP, HTTPS with an operator certificate, or HTTPS with
// a self-signed one, and all three are supported configurations. This probe
// answers "is the panel alive", not "is its chain trusted" -- treating a
// self-signed cert as unhealthy would take a working panel offline.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// healthPath is the panel's unauthenticated liveness endpoint.
const healthPath = "/healthz"

// defaultPanelPort mirrors the config package's default. It is the last resort:
// the env var and the persisted panel settings both win over it.
const defaultPanelPort = 2053

func cmdHealth(args []string) error {
	target := ""
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	var lastErr error
	for _, u := range healthURLs(target) {
		if err := probe(u); err != nil {
			lastErr = err
			continue
		}
		fmt.Println("ok", u)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address to probe")
	}
	return fmt.Errorf("healthcheck failed: %w", lastErr)
}

// healthURLs turns the argument (a full URL, a port, or nothing) into the list
// of candidates to try, HTTPS first because that is the target configuration.
func healthURLs(target string) []string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{strings.TrimSuffix(target, "/") + healthPath}
	}
	port := healthPort(target)
	hostport := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	return []string{
		"https://" + hostport + healthPath,
		"http://" + hostport + healthPath,
	}
}

// healthPort resolves which port the panel is listening on: an explicit
// argument, then the persisted panel settings (an operator can change the port
// from the UI, and the probe must follow it), then a legacy bootstrap
// environment value, then the compiled-in default. Every lookup failure falls through silently -- a
// health probe must never fail because a config file was unreadable.
func healthPort(arg string) int {
	if n, err := strconv.Atoi(arg); err == nil && n > 0 && n < 65536 {
		return n
	}
	if dir := os.Getenv("FORGEPANEL_DATA"); dir != "" {
		raw, err := os.ReadFile(filepath.Join(dir, "panel.json"))
		if err == nil {
			var panel struct {
				Port int `json:"port"`
			}
			if json.Unmarshal(raw, &panel) == nil && panel.Port > 0 && panel.Port < 65536 {
				return panel.Port
			}
		}
	}
	if n, err := strconv.Atoi(os.Getenv("FORGEPANEL_PANEL_PORT")); err == nil && n > 0 && n < 65536 {
		return n
	}
	return defaultPanelPort
}

func probe(url string) error {
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			// See the file comment: a self-signed panel certificate is a
			// supported setup, so the probe pins liveness, not trust.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return nil
}
