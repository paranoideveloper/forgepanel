package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
	"github.com/forgepanel/forgepanel/internal/store"
)

// zoneKey is the shared secret the test zone is created with. Every response
// this file asserts on is checked for it: the config surface must never hand
// back key material, whichever layer holds it.
const zoneKey = "5eeded5eeded5eeded5eeded5eeded5e"

// configRoutes registers the exact route set the lead will add to server.go,
// alongside the forgedns routes that are already there. Registering both in one
// engine is also the cheapest proof that the new paths do not collide with the
// existing /forgedns/upstream/adapters and /forgedns/zones/:id/* patterns.
func configRoutes(s *Server) *gin.Engine {
	r := gin.New()
	r.GET("/forgedns/upstream/adapters", s.handleForgeDNSUpstreamAdapters)
	r.GET("/forgedns/zones/:id/client", s.handleForgeDNSClientConfig)
	r.GET("/forgedns/zones/:id/bundle", s.handleForgeDNSBundle)

	r.GET("/forgedns/upstream/adapters/:adapter/options", s.handleForgeDNSAdapterOptions)
	r.GET("/forgedns/zones/:id/config", s.handleForgeDNSZoneConfig)
	r.PUT("/forgedns/zones/:id/config", s.handleForgeDNSZoneOverride)
	r.POST("/forgedns/zones/:id/config/import", s.handleForgeDNSZoneImport)
	return r
}

func configTestServer(t *testing.T) (*Server, *gin.Engine, *store.ForgeDNSZone) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "forgepanel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := &Server{db: db, router: gin.New()}
	z := &store.ForgeDNSZone{
		Zone: "v.example.com", Adapter: upstream.AdapterCottenDNS, Enabled: true,
		EncryptKey: zoneKey, Cipher: 3, TCPListener: true, AutoDetect: true,
		QueryTypes: "TXT",
	}
	if err := db.CreateZone(z); err != nil {
		t.Fatalf("create zone: %v", err)
	}
	return s, configRoutes(s), z
}

func do(t *testing.T, r *gin.Engine, method, path, body string) (int, string) {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestAdapterOptionsEndpoint(t *testing.T) {
	_, r, _ := configTestServer(t)
	code, body := do(t, r, http.MethodGet, "/forgedns/upstream/adapters/cottendns/options", "")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	var out struct {
		Manifest upstream.Manifest `json:"manifest"`
		Layers   []string          `json:"layers"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Manifest.ConfigVersion != "14" || len(out.Manifest.Server) == 0 || len(out.Manifest.Client) == 0 {
		t.Fatalf("manifest looks empty: %+v", out.Manifest)
	}
	if len(out.Layers) != 4 || out.Layers[3] != string(upstream.LayerRuntime) {
		t.Errorf("layers = %v, want the four merge layers with runtime last", out.Layers)
	}
	// The UI needs the per-key facts a boolean capability table cannot carry.
	var domain upstream.Option
	for _, o := range out.Manifest.Server {
		if o.Key == "UDP_PORT" {
			domain = o
		}
	}
	if domain.Type != upstream.TypeInt || domain.Max == nil || *domain.Max != 65535 || !domain.Restart {
		t.Errorf("UDP_PORT option = %+v", domain)
	}

	if code, _ := do(t, r, http.MethodGet, "/forgedns/upstream/adapters/nope/options", ""); code != 404 {
		t.Errorf("unknown adapter status = %d, want 404", code)
	}
}

func TestZoneConfigMasksSecrets(t *testing.T) {
	_, r, z := configTestServer(t)
	code, body := do(t, r, http.MethodGet, "/forgedns/zones/1/config", "")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if strings.Contains(body, zoneKey) {
		t.Fatalf("the zone's shared key leaked into the config response:\n%s", body)
	}
	if !strings.Contains(body, upstream.MaskedValue) {
		t.Fatalf("nothing was masked; the client config must carry a masked key:\n%s", body)
	}
	var out struct {
		Adapter string `json:"adapter"`
		Server  struct {
			TOML string `json:"toml"`
			Keys []struct {
				Key    string `json:"key"`
				Layer  string `json:"layer"`
				Secret bool   `json:"secret"`
			} `json:"keys"`
		} `json:"server"`
		Client struct {
			TOML string `json:"toml"`
		} `json:"client"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Adapter != upstream.AdapterCottenDNS {
		t.Errorf("adapter = %q", out.Adapter)
	}
	layers := map[string]string{}
	for _, k := range out.Server.Keys {
		layers[k.Key] = k.Layer
	}
	if layers["UDP_PORT"] != string(upstream.LayerManaged) {
		t.Errorf("UDP_PORT layer = %q, want managed", layers["UDP_PORT"])
	}
	if layers["CONFIG_VERSION"] != string(upstream.LayerRuntime) {
		t.Errorf("CONFIG_VERSION layer = %q, want runtime", layers["CONFIG_VERSION"])
	}
	if !strings.Contains(out.Client.TOML, "ENCRYPTION_KEY = \""+upstream.MaskedValue+"\"") {
		t.Errorf("client TOML should carry a masked key:\n%s", out.Client.TOML)
	}
	if z.OverrideTOML != "" {
		t.Errorf("a fresh zone should have no override, got %q", z.OverrideTOML)
	}
}

func TestZoneOverridePutAndEffect(t *testing.T) {
	s, r, z := configTestServer(t)
	code, body := do(t, r, http.MethodPut, "/forgedns/zones/1/config",
		`{"scope":"server","toml":"UDP_PORT = 5353\nEXPERIMENTAL_KNOB = \"keep me\"\n"}`)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if !strings.Contains(body, "EXPERIMENTAL_KNOB") {
		t.Errorf("response should report the preserved unknown key: %s", body)
	}

	saved, err := s.db.ZoneByID(z.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(saved.OverrideTOML, "UDP_PORT = 5353") ||
		!strings.Contains(saved.OverrideTOML, "EXPERIMENTAL_KNOB") {
		t.Fatalf("override was not stored: %q", saved.OverrideTOML)
	}

	// It must show up as an override in the effective view AND in the file the
	// supervised process would read.
	code, body = do(t, r, http.MethodGet, "/forgedns/zones/1/config", "")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if !strings.Contains(body, `"key":"UDP_PORT","layer":"override"`) {
		t.Errorf("UDP_PORT should now resolve at the override layer: %s", body)
	}
	d, _ := upstream.Lookup(saved.Adapter)
	rendered, err := upstream.RenderServer(d, upstreamConfig(saved))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "UDP_PORT = 5353") || !strings.Contains(rendered, "EXPERIMENTAL_KNOB") {
		t.Errorf("the override did not reach the rendered server config:\n%s", rendered)
	}
}

func TestZoneOverrideRejectsInvalid(t *testing.T) {
	s, r, z := configTestServer(t)
	for name, payload := range map[string]string{
		"bad type":      `{"toml":"UDP_PORT = \"nope\"\n"}`,
		"out of range":  `{"toml":"DATA_ENCRYPTION_METHOD = 9\n"}`,
		"not toml":      `{"toml":"= = =\n"}`,
		"wrong dialect": `{"toml":"PROTOCOL_TYPE = \"socks5\"\n"}`,
	} {
		code, body := do(t, r, http.MethodPut, "/forgedns/zones/1/config", payload)
		if code != 400 {
			t.Errorf("%s: status %d, want 400 (%s)", name, code, body)
		}
	}
	saved, _ := s.db.ZoneByID(z.ID)
	if saved.OverrideTOML != "" {
		t.Errorf("a rejected override must not be stored, got %q", saved.OverrideTOML)
	}
}

func TestZoneImportEndpoint(t *testing.T) {
	s, r, z := configTestServer(t)
	const body = `{"scope":"server","apply":true,"toml":"DOMAIN = [\"v.example.com\"]\nUDP_PORT = 5353\nLOG_LEVEL = \"DEBUG\"\nEXPERIMENTAL_KNOB = \"hold on\"\nCONFIG_VERSION = \"14\"\n"}`
	code, out := do(t, r, http.MethodPost, "/forgedns/zones/1/config/import", body)
	if code != 200 {
		t.Fatalf("status %d: %s", code, out)
	}
	if !strings.Contains(out, `"applied":true`) {
		t.Errorf("import should report that it applied: %s", out)
	}
	saved, err := s.db.ZoneByID(z.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.BindPort != 5353 {
		t.Errorf("recognised setting not adopted: BindPort = %d", saved.BindPort)
	}
	if !strings.Contains(saved.OverrideTOML, "EXPERIMENTAL_KNOB") {
		t.Errorf("the unknown key was lost on import: %q", saved.OverrideTOML)
	}
	if saved.EncryptKey != zoneKey {
		t.Errorf("importing a server config must not disturb the zone key, got %q", saved.EncryptKey)
	}

	// Without apply, nothing is written — an operator can see the split first.
	code, out = do(t, r, http.MethodPost, "/forgedns/zones/1/config/import",
		`{"toml":"DOMAIN = [\"other.example.com\"]\nUDP_PORT = 5454\nCONFIG_VERSION = \"14\"\n"}`)
	if code != 200 || !strings.Contains(out, `"applied":false`) {
		t.Fatalf("dry-run import: status %d body %s", code, out)
	}
	saved, _ = s.db.ZoneByID(z.ID)
	if saved.BindPort != 5353 {
		t.Errorf("a dry-run import must not write, BindPort = %d", saved.BindPort)
	}
}

// TestConfigSurfaceRejectsNativeZones: the panel-native codec has no upstream
// TOML, so the editor must say so instead of rendering a meaningless file.
func TestConfigSurfaceRejectsNativeZones(t *testing.T) {
	s, r, _ := configTestServer(t)
	if err := s.db.CreateZone(&store.ForgeDNSZone{Zone: "n.example.com", Adapter: "forge", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, r, http.MethodGet, "/forgedns/zones/2/config", ""); code != 400 {
		t.Errorf("status %d, want 400: %s", code, body)
	}
	if code, _ := do(t, r, http.MethodGet, "/forgedns/zones/99/config", ""); code != 404 {
		t.Errorf("missing zone should 404, got %d", code)
	}
}
