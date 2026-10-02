package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

var railwayDesync = config.Desync{Profile: "Custom", Args: config.DefaultDesyncArgs}

// pingngQuery reads a link's query the way PingNG does (FmtBase.getQueryParam):
// split on '&', take the text between a field's first and second '=' as its
// value, and decode it with '+' kept as a literal plus. Asserting through this
// instead of url.ParseQuery is the point: Go's parser would happily accept the
// '+'-for-space encoding that PingNG hands to ByeDPI as one broken argument.
func pingngQuery(t *testing.T, uri string) map[string]string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("unparseable link %q: %v", uri, err)
	}
	out := map[string]string{}
	for _, field := range strings.Split(u.RawQuery, "&") {
		parts := strings.Split(field, "=")
		if len(parts) < 2 {
			t.Fatalf("field %q has no '=' — PingNG's destructuring throws on it", field)
		}
		v, err := url.QueryUnescape(strings.ReplaceAll(parts[1], "+", "%2B"))
		if err != nil {
			t.Fatalf("field %q does not decode: %v", field, err)
		}
		out[parts[0]] = v
	}
	return out
}

const tlsVLESS = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@forge-test.up.railway.app:443" +
	"?encryption=none&host=forge-test.up.railway.app&path=%2Ftunnel&security=tls" +
	"&sni=forge-test.up.railway.app&type=ws#ws1"

// The appended fields are byte-for-byte what PingNG itself writes for this
// profile, and they decode back to the exact ByeDPI command line.
func TestADesyncLinkIsWhatPingNGWritesAndReads(t *testing.T) {
	got := stampDesync(tlsVLESS, railwayDesync)
	want := "&png=Custom&pngargs=--proto%3Dtls%20--split%201%2Bs%20--tlsrec%202%2Bs" +
		"%20--timeout%203%20--cache-ttl%203600%20--delay-range%201-5#ws1"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("got  %s\nwant suffix %s", got, want)
	}
	q := pingngQuery(t, got)
	if q["png"] != "Custom" || q["pngargs"] != config.DefaultDesyncArgs {
		t.Fatalf("PingNG would read png=%q pngargs=%q", q["png"], q["pngargs"])
	}
	// Nothing already in the link moved.
	if q["path"] != "/tunnel" || q["security"] != "tls" || q["sni"] != "forge-test.up.railway.app" {
		t.Fatalf("existing fields changed: %v", q)
	}
	if !strings.HasSuffix(got, "#ws1") {
		t.Fatalf("remark lost: %s", got)
	}
}

func TestABuiltInProfileCarriesNoArguments(t *testing.T) {
	got := stampDesync(tlsVLESS, config.Desync{Profile: "Balanced"})
	q := pingngQuery(t, got)
	if q["png"] != "Balanced" {
		t.Fatalf("png=%q", q["png"])
	}
	if _, ok := q["pngargs"]; ok {
		t.Fatalf("a built-in profile must not carry pngargs: %s", got)
	}
}

func TestDesyncLeavesOtherLinksAlone(t *testing.T) {
	trojan := "trojan://pw@forge-test.up.railway.app:443?security=tls&type=ws&path=%2Ft#t"
	if got := stampDesync(trojan, railwayDesync); pingngQuery(t, got)["png"] != "Custom" {
		t.Fatalf("a TLS Trojan link is one PingNG reads Desync from: %s", got)
	}
	for _, uri := range []string{
		"vless://id@203.0.113.5:80?encryption=none&security=none&type=ws#plain", // no TLS hello to act on
		"vmess://eyJ2IjoiMiJ9",                                 // base64 JSON: no query
		"ss://YWVzLTEyOC1nY206cGFzcw@203.0.113.5:8388#ss",      // not a profile type PingNG reads here
		strings.Replace(tlsVLESS, "#ws1", "&png=Light#ws1", 1), // already chosen — never overridden
	} {
		if got := stampDesync(uri, railwayDesync); got != uri {
			t.Errorf("changed %s\n     to %s", uri, got)
		}
	}
	if got := stampDesync(tlsVLESS, config.Desync{}); got != tlsVLESS {
		t.Errorf("the zero setting (not Railway) changed a link: %s", got)
	}
	once := stampDesync(tlsVLESS, railwayDesync)
	if twice := stampDesync(once, railwayDesync); twice != once {
		t.Errorf("stamping twice is not a no-op:\n%s\n%s", once, twice)
	}
}

// The pattern variant re-encodes the whole query, and url.Values writes a space
// as '+'. Stamping after it is what keeps pngargs readable; this fails if the
// order is ever swapped.
func TestDesyncSurvivesThePatternVariant(t *testing.T) {
	n := &model.Node{
		Remark: "ws1", Protocol: model.ProtoVLESS, Address: "forge-test.up.railway.app", Port: 443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS, Path: "/tunnel"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "forge-test.up.railway.app"},
	}
	for _, mode := range []patternMode{patternOff, patternOnly, patternBoth} {
		lines := strings.Fields(plainLinksMode([]*model.Node{n}, mode, railwayDesync))
		if len(lines) == 0 {
			t.Fatalf("mode %d: no links", mode)
		}
		for _, l := range lines {
			if got := pingngQuery(t, l)["pngargs"]; got != config.DefaultDesyncArgs {
				t.Errorf("mode %d: PingNG would run %q\n  from %s", mode, got, l)
			}
		}
	}
}

// End to end on a panel that detected Railway from its environment: the
// subscription and the inbound's own share link both carry Desync.
func TestARailwayPanelHandsOutDesyncLinks(t *testing.T) {
	s := paasServer(t)
	in := wsInbound(t, s, "ws1", "/tunnel")
	g := &store.Group{Name: "g1", InboundIDs: []uint{in.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "alice", GroupID: g.ID, SubToken: "subtok123456",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)
	r.GET("/inbounds/:id/config", s.handleInboundConfig)
	s.router = r

	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "forge-test.up.railway.app"
		req.Header.Set("User-Agent", "v2rayNG/1.10.0")
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	b64, err := base64.StdEncoding.DecodeString(get("/sub/" + u.SubToken))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct{ URI string }
	if err := json.Unmarshal([]byte(get("/inbounds/"+strconv.FormatUint(uint64(in.ID), 10)+"/config")), &cfg); err != nil {
		t.Fatal(err)
	}
	for name, link := range map[string]string{
		"v2ray sub": strings.TrimSpace(string(b64)),
		"links sub": strings.TrimSpace(get("/sub/" + u.SubToken + "/links")),
		"share":     cfg.URI,
	} {
		q := pingngQuery(t, link)
		if q["png"] != "Custom" || q["pngargs"] != config.DefaultDesyncArgs {
			t.Errorf("%s: png=%q pngargs=%q in %s", name, q["png"], q["pngargs"], link)
		}
	}
}
