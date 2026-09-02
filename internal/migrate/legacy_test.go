package migrate

import (
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"testing"
)

func TestImportPanelDB(t *testing.T) {
	dir := t.TempDir() + "/xui.db"
	db, _ := gorm.Open(sqlite.Open(dir), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	db.Exec(`CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT)`)
	// a VLESS-REALITY inbound with two clients (mirrors a real inbound from an existing panel box)
	db.Exec(`INSERT INTO inbounds (remark,port,protocol,settings,stream_settings) VALUES (?,?,?,?,?)`,
		"Batman vless", 58504, "vless",
		`{"clients":[{"id":"11111111-2222-3333-4444-555555555555","email":"alice","flow":"xtls-rprx-vision"},{"id":"66666666-7777-8888-9999-000000000000","email":"bob"}]}`,
		`{"network":"tcp","security":"reality","realitySettings":{"privateKey":"pk","serverNames":["aparat.ir"],"shortIds":["0123abcd"],"dest":"aparat.ir:443"}}`)
	// an SS inbound
	db.Exec(`INSERT INTO inbounds (remark,port,protocol,settings,stream_settings) VALUES (?,?,?,?,?)`,
		"ss", 42836, "shadowsocks", `{"method":"chacha20-ietf-poly1305","password":"sspw"}`, `{"network":"tcp","security":"none"}`)
	res, err := ImportPanelDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d (%v)", len(res.Inbounds), res.Warnings)
	}
	// vless reality inbound
	var vless *ImportedInbound
	for i := range res.Inbounds {
		if res.Inbounds[i].Node.Protocol == model.ProtoVLESS {
			vless = &res.Inbounds[i]
		}
	}
	if vless == nil {
		t.Fatal("vless inbound missing")
	}
	if vless.Node.Security.Type != model.SecReality {
		t.Fatal("reality not mapped")
	}
	if len(vless.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(vless.Users))
	}
	if vless.Users[0].UUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatal("client uuid not lifted")
	}
}
