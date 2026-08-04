// Package config holds runtime configuration and first-boot secret generation
// (spec §0.10, §12). Panel-address and ACME settings live in a persisted,
// upgrade-safe panel.json (atomic writes, 0600, unknown keys preserved); the
// master key + legacy admin path live in secrets.json. Nothing here is
// hardcoded and existing installs migrate forward without losing data.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ACMESettings is the automatic-certificate configuration persisted in
// panel.json. Private key material is never stored here — only paths and status.
type ACMESettings struct {
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider"`  // letsencrypt
	Email        string `json:"email"`     // ACME account email
	Challenge    string `json:"challenge"` // http-01 | tls-alpn-01 | dns-01
	Staging      bool   `json:"staging"`
	CertPath     string `json:"certificate_path,omitempty"`
	PrivateKey   string `json:"private_key_path,omitempty"`
	LastRenewal  string `json:"last_renewal,omitempty"`
	RenewalError string `json:"renewal_error,omitempty"`
}

// PanelSettings is the operator-editable panel address + setup state. It is the
// source of truth for how the panel is reached (domain/port/https) and whether
// first-run administrator setup is still pending.
type PanelSettings struct {
	Domain         string       `json:"domain"`
	BindAddress    string       `json:"bind_address"`
	Port           int          `json:"port"`
	PublicURL      string       `json:"public_url"`
	AdminPath      string       `json:"admin_path"`
	HTTPSEnabled   bool         `json:"https_enabled"`
	SetupCompleted bool         `json:"setup_completed"`
	SetupToken     string       `json:"setup_token,omitempty"`
	SetupExpires   string       `json:"setup_token_expires,omitempty"`
	ACME           ACMESettings `json:"acme"`

	// extra preserves any unknown/forward-compat keys so a rewrite by an older
	// binary never silently drops fields written by a newer one.
	extra map[string]json.RawMessage
}

// Config is the resolved runtime configuration.
type Config struct {
	DataDir        string `json:"data_dir"`
	PanelPort      int    `json:"panel_port"`
	SubPort        int    `json:"sub_port"`
	APIPort        int    `json:"api_port"`
	DNSPort        int    `json:"dns_port"`
	AdminPath      string `json:"admin_path"` // randomized secret path, printed once
	AdminUser      string `json:"admin_user"`
	MasterKey      string `json:"master_key"` // AES key material for at-rest secret encryption
	TelegramToken  string `json:"-"`
	TelegramAdmins string `json:"-"`

	panel     *PanelSettings
	firstBoot bool
}

// envInt reads an int from the environment with a default.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean-ish env var ("1", "true", "yes", "on").
func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	}
	return false
}

// Load resolves configuration from env + the persisted state under DataDir.
// secrets.json holds the master key (and, for legacy installs, the admin path);
// panel.json holds the panel address, ACME and first-run setup state. On a
// brand-new data dir both are minted and marked FirstBoot.
func Load() (*Config, error) {
	dataDir := envStr("FORGEPANEL_DATA", defaultDataDir())
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	cfg := &Config{
		DataDir:        dataDir,
		SubPort:        envInt("FORGEPANEL_SUB_PORT", 2096),
		APIPort:        envInt("FORGEPANEL_API_PORT", 2054),
		DNSPort:        envInt("FORGEPANEL_DNS_PORT", 53),
		AdminUser:      envStr("FORGEPANEL_ADMIN_USER", "admin"),
		TelegramToken:  envStr("FORGEPANEL_TELEGRAM_TOKEN", ""),
		TelegramAdmins: envStr("FORGEPANEL_TELEGRAM_ADMINS", ""),
	}

	// --- secrets.json: master key + legacy admin path/user ---
	statePath := filepath.Join(dataDir, "secrets.json")
	var legacyAdminPath string
	if raw, err := os.ReadFile(statePath); err == nil {
		var persisted Config
		if err := json.Unmarshal(raw, &persisted); err == nil {
			cfg.MasterKey = persisted.MasterKey
			legacyAdminPath = persisted.AdminPath
			if persisted.AdminUser != "" {
				cfg.AdminUser = persisted.AdminUser
			}
		}
	}
	secretsFresh := cfg.MasterKey == ""
	if secretsFresh {
		cfg.MasterKey = randToken(32)
		save := Config{AdminPath: legacyAdminPath, MasterKey: cfg.MasterKey, AdminUser: cfg.AdminUser}
		raw, _ := json.MarshalIndent(save, "", "  ")
		if err := os.WriteFile(statePath, raw, 0o600); err != nil {
			return nil, fmt.Errorf("persist secrets: %w", err)
		}
	}

	// --- panel.json: address, ACME, setup state (migrate on first sight) ---
	panelPath := filepath.Join(dataDir, "panel.json")
	panel, panelExisted, err := loadPanel(panelPath)
	if err != nil {
		return nil, err
	}
	if !panelExisted {
		// Migrate: seed from legacy secrets + env. An upgrade (legacy admin path
		// present, or secrets.json already existed) is NOT a fresh panel — the
		// server reconciles SetupCompleted against the admin table so existing
		// operators keep their credentials (spec: upgrade compatibility).
		panel = &PanelSettings{
			BindAddress:    "0.0.0.0",
			Port:           envInt("FORGEPANEL_PANEL_PORT", 2053),
			AdminPath:      legacyAdminPath,
			SetupCompleted: false,
			ACME: ACMESettings{
				Provider:  "letsencrypt",
				Challenge: "http-01",
				Email:     envStr("FORGEPANEL_ACME_EMAIL", ""),
			},
		}
		if d := envStr("FORGEPANEL_DOMAIN", ""); d != "" {
			panel.Domain = d
			if envBool("FORGEPANEL_HTTPS") {
				panel.HTTPSEnabled = true
				panel.ACME.Enabled = true
			}
		}
		cfg.firstBoot = secretsFresh && legacyAdminPath == ""
	}
	// Mint the randomized admin path if this is a genuinely fresh install.
	if panel.AdminPath == "" {
		panel.AdminPath = "/panel/" + randToken(6)
	}
	if panel.Port == 0 {
		panel.Port = 2053
	}
	if panel.BindAddress == "" {
		panel.BindAddress = "0.0.0.0"
	}
	if panel.ACME.Provider == "" {
		panel.ACME.Provider = "letsencrypt"
	}
	if panel.ACME.Challenge == "" {
		panel.ACME.Challenge = "http-01"
	}

	// Env overrides always win at runtime (installer/systemd may pass them).
	if v := envInt("FORGEPANEL_PANEL_PORT", 0); v != 0 {
		panel.Port = v
	}
	if v := envStr("FORGEPANEL_DOMAIN", ""); v != "" {
		panel.Domain = v
		if envBool("FORGEPANEL_HTTPS") {
			panel.HTTPSEnabled = true
			panel.ACME.Enabled = true
		}
	}
	if v := envStr("FORGEPANEL_ACME_EMAIL", ""); v != "" {
		panel.ACME.Email = v
	}

	cfg.panel = panel
	cfg.AdminPath = panel.AdminPath
	cfg.PanelPort = panel.Port
	if err := savePanel(panelPath, panel); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Panel returns the mutable panel settings (address, ACME, setup state).
func (c *Config) Panel() *PanelSettings { return c.panel }

// RestoreRollback promotes panel.json.bak (the pre-change snapshot written before
// a panel-address edit) back to panel.json. It is invoked when the panel fails
// to bind with the new settings, so a bad port/bind change can never permanently
// lock the administrator out. Reports whether a rollback file was applied.
func RestoreRollback(dataDir string) bool {
	bak := filepath.Join(dataDir, "panel.json.bak")
	if _, err := os.Stat(bak); err != nil {
		return false
	}
	if err := os.Rename(bak, filepath.Join(dataDir, "panel.json")); err != nil {
		return false
	}
	return true
}

// ClearRollback removes a stale rollback snapshot after a successful bind, so a
// later failure can't restore a much older configuration by mistake.
func ClearRollback(dataDir string) {
	_ = os.Remove(filepath.Join(dataDir, "panel.json.bak"))
}

// SavePanel atomically persists the panel settings to panel.json (0600),
// preserving any unknown keys. Safe to call concurrently with reads.
func (c *Config) SavePanel() error {
	if c.panel == nil {
		return nil
	}
	c.AdminPath = c.panel.AdminPath
	c.PanelPort = c.panel.Port
	return savePanel(filepath.Join(c.DataDir, "panel.json"), c.panel)
}

// FirstBoot reports whether this Load initialized a brand-new panel (no prior
// secrets and no prior admin path) — i.e. first-run setup has never happened.
func (c *Config) FirstBoot() bool { return c.firstBoot }

// loadPanel reads panel.json, capturing unknown keys for round-trip safety.
func loadPanel(path string) (*PanelSettings, bool, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &PanelSettings{}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read panel.json: %w", err)
	}
	var known PanelSettings
	if err := json.Unmarshal(raw, &known); err != nil {
		return nil, false, fmt.Errorf("parse panel.json: %w", err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err == nil {
		for _, k := range panelKnownKeys() {
			delete(all, k)
		}
		if len(all) > 0 {
			known.extra = all
		}
	}
	return &known, true, nil
}

// savePanel writes panel.json atomically (temp file + rename) with 0600 perms,
// merging back any preserved unknown keys.
func savePanel(path string, p *PanelSettings) error {
	// Marshal known fields, then splice unknown keys back in.
	base, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return err
	}
	for k, v := range p.extra {
		if _, taken := merged[k]; !taken {
			merged[k] = v
		}
	}
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("write panel.json: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit panel.json: %w", err)
	}
	return nil
}

// panelKnownKeys lists the JSON keys PanelSettings owns, so loadPanel can tell
// unknown (preserve) from known (parsed) keys.
func panelKnownKeys() []string {
	return []string{"domain", "bind_address", "port", "public_url", "admin_path",
		"https_enabled", "setup_completed", "setup_token", "setup_token_expires", "acme"}
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".forgepanel")
	}
	return "./forgepanel-data"
}

// randToken returns nBytes of hex-encoded entropy.
func randToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
