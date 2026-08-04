// Command forgenode is the lightweight remote node agent (spec §10). It enrolls
// with the panel using a one-time token, then heartbeats on an interval,
// receiving the engine config to run locally. Transport here is token-
// authenticated HTTPS; the hardening upgrade is mTLS gRPC with a panel-issued
// per-node client certificate (documented in docs/DECISIONS.md).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	panel := os.Getenv("PANEL")
	token := os.Getenv("TOKEN")
	if panel == "" || token == "" {
		fmt.Fprintln(os.Stderr, "forgenode: set PANEL and TOKEN environment variables")
		os.Exit(2)
	}
	if err := register(panel, token); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: register:", err)
		os.Exit(1)
	}
	fmt.Println("forgenode: enrolled with", panel)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cfg, err := heartbeat(panel, token)
		if err != nil {
			fmt.Fprintln(os.Stderr, "forgenode: heartbeat:", err)
			continue
		}
		if cfg != "" {
			_ = os.WriteFile("/tmp/forgenode-xray.json", []byte(cfg), 0o600)
		}
	}
}

func register(panel, token string) error {
	body, _ := json.Marshal(map[string]string{"token": token, "core_version": "xray"})
	return post(panel+"/api/node/register", body, nil)
}

func heartbeat(panel, token string) (string, error) {
	body, _ := json.Marshal(map[string]any{"token": token, "cpu": 0.0, "mem_mb": 0})
	var resp struct {
		XrayConfig string `json:"xray_config"`
	}
	if err := post(panel+"/api/node/heartbeat", body, &resp); err != nil {
		return "", err
	}
	return resp.XrayConfig, nil
}

func post(url string, body []byte, out any) error {
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	r, err := client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		b, _ := io.ReadAll(r.Body)
		return fmt.Errorf("status %d: %s", r.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(r.Body).Decode(out)
	}
	return nil
}
