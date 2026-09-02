package api

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/gin-gonic/gin"
)

// The fancy wizard writes three settings (name template + front domain + front
// mode); this proves they flow all the way through subscriptionNodes into the
// rendered links: every config is renamed with the theme and fronted behind the
// camouflage domain, while still dialling the real server address.
func TestFancyWizard_FrontsAndRenamesSubscription(t *testing.T) {
	s := dbServerT(t)

	spec := &model.Node{
		Protocol: model.ProtoVLESS, Port: 8443, Remark: "s7", Address: "203.0.113.13",
		UUID:      "11111111-1111-1111-1111-111111111111",
		Transport: model.Transport{Network: model.NetWS, Path: "/aux"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "real-cert.example"},
	}
	ib, err := s.db.CreateInbound(spec)
	if err != nil {
		t.Fatal(err)
	}
	g := &store.Group{Name: "fancy-g", InboundIDs: []uint{ib.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "vael", GroupID: g.ID, SubToken: "fancytok", UUID: "11111111-1111-1111-1111-111111111111", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	// Simulate the wizard: apply a theme (name template + front mode) + domain.
	th, ok := model.FancyThemeByID("aparat-line")
	if !ok {
		t.Fatal("theme missing")
	}
	_ = s.db.SetSetting("sub_name_template", th.Template)
	_ = s.db.SetSetting("sub_front_mode", string(th.Front)) // sni
	_ = s.db.SetSetting("sub_front_domain", "aparat.com")

	r := gin.New()
	r.GET("/sub/:token/*format", s.handleSub)
	s.router = r

	rec := subGet(t, s, "/sub/fancytok/links", "")
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	// Fronted: host + sni now carry the camouflage domain, not the real cert name.
	if !strings.Contains(body, "host=aparat.com") || !strings.Contains(body, "sni=aparat.com") {
		t.Fatalf("subscription not fronted behind aparat.com:\n%s", body)
	}
	if strings.Contains(body, "real-cert.example") {
		t.Fatalf("real cert SNI leaked instead of the camouflage domain:\n%s", body)
	}
	// Real dial address preserved so the client still reaches the server.
	if !strings.Contains(body, "@203.0.113.13:8443") {
		t.Fatalf("real dial address lost:\n%s", body)
	}
	// Renamed with the fancy theme (the styled brand + the node name s7).
	if !strings.Contains(body, "s7") || !strings.Contains(body, "%D8%A2%D9%BE%D8%A7%D8%B1%D8%A7%D8%AA") {
		// آپارات (url-encoded) — the Persian brand from the aparat-line theme.
		t.Fatalf("subscription not renamed with the fancy theme:\n%s", body)
	}
}
