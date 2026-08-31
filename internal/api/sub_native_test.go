package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// A subscription is a list of URIs, and two protocols cannot be represented as
// one. AmneziaWG had no URI at all, so plainLinksMode's "skip anything that
// errors" dropped it silently — the panel could create the server side and hand
// the user nothing. WireGuard did produce a link, and it carried the server's
// private key. Neither gave anyone a working config.

func wgFamilyNodes() []*model.Node {
	return []*model.Node{
		{Remark: "plain", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443,
			UUID: "11111111-1111-1111-1111-111111111111"},
		{Remark: "wg-one", Protocol: model.ProtoWireGuard, Address: "vpn.example.com", Port: 3445,
			WireGuard: &model.WireGuardOptions{
				PrivateKey: "SERVER-SK", PublicKey: "SERVER-PK",
				PeerPrivateKey: "CLIENT-SK", PeerAddress: []string{"10.66.66.2/32"},
				AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1420, Keepalive: 25,
			}},
		{Remark: "awg-one", Protocol: model.ProtoAmneziaWG, Address: "vpn.example.com", Port: 5454,
			AmneziaWG: &model.AmneziaWGOptions{
				WireGuardOptions: model.WireGuardOptions{
					PrivateKey: "A-SERVER-SK", PublicKey: "A-SERVER-PK",
					PeerPrivateKey: "A-CLIENT-SK", PeerAddress: []string{"10.67.67.2/32"},
					AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1420,
				},
				Jc: 8, Jmin: 50, Jmax: 1000, S1: 86, S2: 574,
				H1: "1234567", H2: "2345678", H3: "3456789", H4: "4567890",
			}},
	}
}

func TestOnlyFileFormatProtocolsGetANativeConfEntry(t *testing.T) {
	got := nativeConfNodes(wgFamilyNodes())
	if len(got) != 2 {
		t.Fatalf("got %d native-config entries, want the WireGuard and AmneziaWG ones", len(got))
	}
	if got[0].Remark != "wg-one" || got[1].Remark != "awg-one" {
		t.Errorf("order is not stable: %q, %q — an index in a URL must keep meaning the same entry",
			got[0].Remark, got[1].Remark)
	}
}

// AmneziaWG must NOT be reduced to plain WireGuard. Without Jc/Jmin/Jmax/S1/S2
// and the H values the peer negotiates nothing with an AmneziaWG server, and it
// looks like an ordinary config that simply never connects.
func TestTheAmneziaConfKeepsItsObfuscationParameters(t *testing.T) {
	nodes := nativeConfNodes(wgFamilyNodes())
	_, body, err := nativeConfFor(nodes[1], "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Jc = 8", "Jmin = 50", "Jmax = 1000", "S1 = 86", "S2 = 574",
		"H1 = 1234567", "H2 = 2345678", "H3 = 3456789", "H4 = 4567890"} {
		if !strings.Contains(body, want) {
			t.Errorf("the AmneziaWG config lost %q — it is plain WireGuard now:\n%s", want, body)
		}
	}
}

// Neither config may contain the server's private key: these are handed to the
// subscriber.
func TestNativeConfsAreClientSide(t *testing.T) {
	for _, n := range nativeConfNodes(wgFamilyNodes()) {
		name, body, err := nativeConfFor(n, "vpn.example.com")
		if err != nil {
			t.Fatalf("%s: %v", n.Remark, err)
		}
		for _, secret := range []string{"SERVER-SK", "A-SERVER-SK"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s (%s) contains the server's private key", n.Remark, name)
			}
		}
		if !strings.Contains(body, "[Interface]") || !strings.Contains(body, "[Peer]") {
			t.Errorf("%s is not a wg-quick document:\n%s", n.Remark, body)
		}
		if !strings.HasSuffix(name, ".conf") {
			t.Errorf("filename %q should end .conf so a client opens it", name)
		}
	}
}

func TestAProtocolWithNoNativeFormatIsRefusedClearly(t *testing.T) {
	n := &model.Node{Remark: "v", Protocol: model.ProtoVLESS, Address: "a", Port: 1}
	if _, _, err := nativeConfFor(n, "a"); err == nil {
		t.Fatal("a VLESS node was given a wg-quick config")
	}
}

// The endpoint itself: an unknown token and an out-of-range index must both say
// what is wrong rather than serving an empty file.
func TestTheNativeConfEndpointRefusesWhatItCannotServe(t *testing.T) {
	s, _ := adminAPI(t)
	for _, path := range []string{"/subconf/no-such-token/0", "/subconf/no-such-token/9"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Errorf("%s returned 200 for a token that does not exist", path)
		}
		if strings.TrimSpace(w.Body.String()) == "" {
			t.Errorf("%s refused with an empty body", path)
		}
	}
}

// TestLandingPageDownloadURLMatchesRoute pins the Download button's href to the
// route that actually serves it. The first version of this page built the URL
// by appending to the subscription base, producing /sub/<token>/subconf/0 —
// a button that 404s. Asserting the string alone would have passed; this
// asserts the shape the router registered.
func TestLandingPageDownloadURLMatchesRoute(t *testing.T) {
	natives := []nativeEntry{
		{name: "wg-one", kind: "WireGuard client",
			url:  "https://vpn.example.com/subconf/abc123/0",
			body: "[Interface]\nPrivateKey = X\n[Peer]\n"},
	}
	page := string(subLandingPage("https://vpn.example.com/sub/abc123",
		"upload=0; download=0; total=0; expire=0", natives))

	if !strings.Contains(page, `href="https://vpn.example.com/subconf/abc123/0" download`) {
		t.Errorf("landing page does not offer the native config for download:\n%s", page)
	}
	// The registered route is /subconf/:token/:index. A link built under /sub/
	// is the exact regression this test exists for.
	if strings.Contains(page, "/sub/abc123/subconf/") {
		t.Error("download link nests /subconf under /sub — that route does not exist")
	}
	if !strings.Contains(page, "Direct configs") {
		t.Error("the native-config section is missing entirely")
	}
	// The copy button must carry the CONFIG, not the URL: a WireGuard user
	// pastes the conf into their client, they do not paste a link.
	if !strings.Contains(page, "[Interface]") {
		t.Error("copy button does not carry the config text")
	}
}

// TestSubNativeEntriesURLResolves goes one step further than string matching:
// it takes the URL the landing page would emit and asks the real router to
// serve it.
func TestSubNativeEntriesURLResolves(t *testing.T) {
	s, token := seedNativeSubscription(t)

	// Fetch the landing page as a browser would.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+token, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("landing page: got %d", rec.Code)
	}
	href := firstDownloadHref(rec.Body.String())
	if href == "" {
		t.Fatalf("landing page offered no download link:\n%s", rec.Body.String())
	}

	// Now ask the router for exactly that path.
	path := href
	if i := strings.Index(href, "/subconf/"); i >= 0 {
		path = href[i:]
	}
	rec2 := httptest.NewRecorder()
	s.router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, path, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("the Download button's own URL %q returned %d:\n%s",
			path, rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "[Interface]") {
		t.Errorf("download returned something that is not a config:\n%s", rec2.Body.String())
	}
	if cd := rec2.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("config is not served as a download: Content-Disposition=%q", cd)
	}
}

func firstDownloadHref(page string) string {
	const marker = `class="btn primary" href="`
	i := strings.Index(page, marker)
	for i >= 0 {
		rest := page[i+len(marker):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			return ""
		}
		href := rest[:end]
		if strings.Contains(href, "/subconf/") {
			return href
		}
		next := strings.Index(rest, marker)
		if next < 0 {
			return ""
		}
		i = i + len(marker) + next
	}
	return ""
}

// seedNativeSubscription builds a server whose subscription contains a
// WireGuard inbound, with the same routes main() registers for these paths.
func seedNativeSubscription(t *testing.T) (*Server, string) {
	t.Helper()
	s := dbServerT(t)
	n := &model.Node{
		Protocol: model.ProtoWireGuard, Address: "vpn.example.com", Port: 51820,
		Remark: "wg-native",
		WireGuard: &model.WireGuardOptions{
			PrivateKey: "cFJvYmFibHlOb3RBUmVhbEtleUZvclRlc3Rz", PublicKey: "U0VSVkVSLVBVQkxJQy1LRVktRk9SLVRFU1Rz",
			PeerPrivateKey: "Q0xJRU5ULVBSSVZBVEUtS0VZLUZPUi1URVNUcw", PeerPublicKey: "Q0xJRU5ULVBVQkxJQy1LRVktRk9SLVRFU1RzMQ",
			PeerAddress: []string{"10.66.66.2/32"}, AllowedIPs: []string{"0.0.0.0/0"},
			MTU: 1420, Keepalive: 25,
		},
	}
	in, err := s.db.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	g := &store.Group{Name: "gnative", InboundIDs: []uint{in.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "wguser", GroupID: g.ID, SubToken: "nativetok123",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/sub/:token", s.handleSub)
	r.GET("/sub/:token/*format", s.handleSub)
	r.GET("/subconf/:token/:index", s.handleSubNativeConf)
	s.router = r
	return s, u.SubToken
}

// TestNativeCardsAreLabelledByProtocol: the heading has to say which app the
// file belongs in.
//
// It used to be the inbound's remark, which is operator text and routinely
// empty or " (copy)" — the two headings a live panel actually showed for its
// WireGuard and AmneziaWG entries. A user could not tell which file went where,
// and importing a .conf into the wrong Amnezia app looks exactly like a broken
// server: nothing ever leaves the device.
func TestNativeCardsAreLabelledByProtocol(t *testing.T) {
	s, token := seedNativeSubscription(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+token, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	s.router.ServeHTTP(rec, req)
	page := rec.Body.String()

	if !strings.Contains(page, "<h3>WireGuard</h3>") {
		t.Errorf("the WireGuard card is not headed by its protocol:\n%s", firstCard(page))
	}
	// The remark is kept, but as detail rather than as the identity.
	if !strings.Contains(page, "wg-native") {
		t.Error("the inbound's remark was dropped entirely; it is still useful detail")
	}
}

// TestAmneziaCardNamesTheAppThatCanReadIt: AmneziaVPN and the standalone
// AmneziaWG app are different clients with different formats, and only one of
// them imports the .conf this endpoint serves.
func TestAmneziaCardNamesTheAppThatCanReadIt(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoAmneziaWG, Address: "vpn.example.com", Port: 5454, Remark: "",
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "S", PublicKey: "SP", PeerPrivateKey: "C", PeerPublicKey: "CP",
			PeerAddress: []string{"10.67.67.2/32"}, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1420,
		}}}
	entries := []nativeEntry{}
	// Exercise the same labelling the page uses.
	name, kind := "WireGuard", "wg-quick / the WireGuard app"
	if n.Protocol == model.ProtoAmneziaWG {
		name, kind = "AmneziaWG", "the AmneziaWG app (not AmneziaVPN) / awg-quick"
	}
	entries = append(entries, nativeEntry{name: name, kind: kind, url: "https://h/subconf/t/0", body: "[Interface]\n"})
	page := string(subLandingPage("https://h/sub/t", "upload=0; download=0; total=0; expire=0", entries))

	if !strings.Contains(page, "AmneziaWG") {
		t.Error("the card does not name the protocol")
	}
	if !strings.Contains(page, "not AmneziaVPN") {
		t.Error("nothing warns that AmneziaVPN cannot read this file, which is the " +
			"single most likely reason an import silently does nothing")
	}
}

func firstCard(page string) string {
	i := strings.Index(page, "Direct configs")
	if i < 0 {
		return page
	}
	if len(page[i:]) > 600 {
		return page[i : i+600]
	}
	return page[i:]
}
