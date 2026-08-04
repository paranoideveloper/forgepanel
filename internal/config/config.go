// Package config holds runtime configuration and first-boot secret generation
// (spec §0.10, §12): secrets are generated at first boot, printed once, and the
// randomized admin path is minted then. Nothing here is hardcoded.
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
	firstBoot      bool
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

// Load resolves configuration from env + the persisted state file under
// DataDir. On first boot it generates the admin path, admin user and master
// key, persists them, and marks FirstBoot so the caller can print credentials
// once.
func Load() (*Config, error) {
	dataDir := envStr("FORGEPANEL_DATA", defaultDataDir())
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	cfg := &Config{
		DataDir:        dataDir,
		PanelPort:      envInt("FORGEPANEL_PANEL_PORT", 2053),
		SubPort:        envInt("FORGEPANEL_SUB_PORT", 2096),
		APIPort:        envInt("FORGEPANEL_API_PORT", 2054),
		DNSPort:        envInt("FORGEPANEL_DNS_PORT", 53),
		AdminUser:      envStr("FORGEPANEL_ADMIN_USER", "admin"),
		TelegramToken:  envStr("FORGEPANEL_TELEGRAM_TOKEN", ""),
		TelegramAdmins: envStr("FORGEPANEL_TELEGRAM_ADMINS", ""),
	}
	statePath := filepath.Join(dataDir, "secrets.json")
	if raw, err := os.ReadFile(statePath); err == nil {
		var persisted Config
		if err := json.Unmarshal(raw, &persisted); err == nil {
			cfg.AdminPath = persisted.AdminPath
			cfg.MasterKey = persisted.MasterKey
			if persisted.AdminUser != "" {
				cfg.AdminUser = persisted.AdminUser
			}
		}
	}
	if cfg.AdminPath == "" || cfg.MasterKey == "" {
		cfg.firstBoot = true
		cfg.AdminPath = "/panel/" + randToken(6)
		cfg.MasterKey = randToken(32)
		save := Config{AdminPath: cfg.AdminPath, MasterKey: cfg.MasterKey, AdminUser: cfg.AdminUser}
		raw, _ := json.MarshalIndent(save, "", "  ")
		if err := os.WriteFile(statePath, raw, 0o600); err != nil {
			return nil, fmt.Errorf("persist secrets: %w", err)
		}
	}
	return cfg, nil
}

// FirstBoot reports whether this Load generated fresh secrets.
func (c *Config) FirstBoot() bool { return c.firstBoot }

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
