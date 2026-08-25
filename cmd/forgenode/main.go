// Command forgenode is the lightweight remote node agent (spec §10). It enrolls
// with the panel using a one-time token, then heartbeats on an interval,
// receiving the engine config to run locally and supervising the proxy core.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/version"
)

type NodeAgent struct {
	panel string
	token string
	// pin is the panel's certificate SHA-256, hex. Empty means "use the system
	// trust store", which is correct once the panel has a real certificate.
	pin       string
	client    *http.Client
	dataDir   string
	binMgr    *binmgr.Manager
	xrayBin   string
	lastCfg   string
	mu        sync.Mutex
	activeCmd *exec.Cmd
}

func main() {
	if nodeVersionRequested(os.Args[1:]) {
		fmt.Println(version.String("forgenode"))
		return
	}
	panel := os.Getenv("PANEL")
	token := os.Getenv("TOKEN")
	pin := os.Getenv("PANEL_FINGERPRINT")
	if panel == "" || token == "" {
		fmt.Fprintln(os.Stderr, "forgenode: set PANEL and TOKEN environment variables")
		os.Exit(2)
	}

	dataDir := os.Getenv("FORGEPANEL_DATA")
	if dataDir == "" {
		dataDir = "/var/lib/forgepanel"
	}
	_ = os.MkdirAll(dataDir, 0o700)

	bm := binmgr.New(dataDir)
	xrayPath, err := bm.Ensure(binmgr.EngineXray)
	if err != nil {
		// Fallback to path lookup if binmgr download fails in offline test environments
		xrayPath, _ = exec.LookPath("xray")
	}

	agent := &NodeAgent{
		panel:   panel,
		token:   token,
		pin:     pin,
		dataDir: dataDir,
		binMgr:  bm,
		xrayBin: xrayPath,
	}

	if err := agent.register(); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: register error:", err)
		os.Exit(1)
	}
	fmt.Println("forgenode: enrolled successfully with", panel)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Initial heartbeat immediately
	agent.step()

	for range ticker.C {
		agent.step()
	}
}

func nodeVersionRequested(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version")
}

func (a *NodeAgent) step() {
	cfg, err := a.heartbeat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: heartbeat error:", err)
		return
	}
	if cfg != "" && cfg != a.lastCfg {
		a.applyConfig(cfg)
	}
}

func (a *NodeAgent) applyConfig(cfg string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	tmpConfigPath := filepath.Join(a.dataDir, "node-xray.tmp.json")
	configPath := filepath.Join(a.dataDir, "node-xray.json")

	if err := os.WriteFile(tmpConfigPath, []byte(cfg), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: failed to write temp config:", err)
		return
	}

	if a.xrayBin != "" {
		// Validate config before touching active process or committing config
		testCmd := exec.Command(a.xrayBin, "run", "-test", "-config", tmpConfigPath)
		if out, err := testCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "forgenode: invalid xray config rejected: %v: %s\n", err, string(out))
			_ = os.Remove(tmpConfigPath)
			return
		}
	}

	if err := os.Rename(tmpConfigPath, configPath); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: failed to commit config:", err)
		_ = os.Remove(tmpConfigPath)
		return
	}

	a.lastCfg = cfg

	// Stop existing process if running
	if a.activeCmd != nil && a.activeCmd.Process != nil {
		_ = a.activeCmd.Process.Kill()
		_ = a.activeCmd.Wait()
		a.activeCmd = nil
	}

	if a.xrayBin == "" {
		fmt.Println("forgenode: config updated (xray binary not available to launch)")
		return
	}

	// Launch xray core with validated config
	cmd := exec.Command(a.xrayBin, "run", "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "forgenode: failed to start xray:", err)
		return
	}

	a.activeCmd = cmd
	fmt.Println("forgenode: successfully started xray engine with new config")
}

func (a *NodeAgent) register() error {
	body, _ := json.Marshal(map[string]string{"token": a.token, "core_version": "xray"})
	return a.post("/api/node/register", body, nil)
}

func (a *NodeAgent) heartbeat() (string, error) {
	body, _ := json.Marshal(map[string]any{"token": a.token, "cpu": 0.1, "mem_mb": 128})
	var resp struct {
		XrayConfig string `json:"xray_config"`
	}
	if err := a.post("/api/node/heartbeat", body, &resp); err != nil {
		return "", err
	}
	return resp.XrayConfig, nil
}

// httpClient returns the client used for every panel call.
//
// A fresh panel serves HTTPS with a self-signed certificate, because a domain
// is optional and most installs start life reachable only by IP. A remote node
// cannot verify that certificate against the system trust store — measured on
// live servers, forgenode crash-looped on "certificate signed by unknown
// authority" and a multi-node install simply could not complete.
//
// Disabling verification outright would be the easy fix and the wrong one: the
// node ships its enrolment token on this connection, so an unverified transport
// hands that token to anyone who can intercept it. Instead the node PINS the
// panel's certificate by SHA-256 fingerprint, supplied at enrolment time
// alongside the token. Verification still happens; the trust anchor is just the
// pin rather than a public CA. With no pin configured the system trust store is
// used unchanged, which is what a panel with a real certificate wants.
func (a *NodeAgent) httpClient() *http.Client {
	if a.client != nil {
		return a.client
	}
	c := &http.Client{Timeout: 10 * time.Second}
	if a.pin != "" {
		want := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(a.pin))
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			// The pin IS the verification, so the default chain check is
			// bypassed and replaced below rather than simply switched off.
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				for _, raw := range rawCerts {
					sum := sha256.Sum256(raw)
					if hex.EncodeToString(sum[:]) == want {
						return nil
					}
				}
				return fmt.Errorf("panel certificate does not match the pinned fingerprint %s; "+
					"re-run enrolment to get the current pin, or the connection is being intercepted", want)
			},
		}}
	}
	a.client = c
	return c
}

func (a *NodeAgent) post(path string, body []byte, out any) error {
	url := a.panel + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := a.httpClient().Do(req)
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
