// Package migrate imports foreign panel databases into ForgePanel's canonical
// model (spec §13). This build ships the an existing panel importer, which is the most
// widely deployed panel; other panels/ importers follow the same shape (read
// their inbound rows, map each into a model.Node, and lift each client to a
// user). Every mapping is derived from the real an existing panel schema.
package migrate

import (
	"encoding/json"
	"fmt"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// ImportedInbound is one migrated inbound template plus its users.
type ImportedInbound struct {
	Node  *model.Node    `json:"node"`
	Users []ImportedUser `json:"users"`
	// SourceID is the row id this inbound had in the foreign panel.
	//
	// Matching a re-import on the REMARK was the obvious approach and is wrong:
	// rename an inbound on either side and the next import creates a duplicate
	// rather than recognising it. The source id does not change when a human
	// edits a label.
	SourceID uint `json:"source_id"`
}

// ImportedUser is a client lifted out of a foreign inbound.
type ImportedUser struct {
	Email    string `json:"email"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
}

// Result is the outcome of a migration.
type Result struct {
	Inbounds []ImportedInbound `json:"inbounds"`
	Warnings []string          `json:"warnings"`
}

// panelInbound mirrors the columns of the an existing panel `inbounds` table we consume.
type panelInbound struct {
	ID             uint
	Remark         string
	Port           int
	Protocol       string
	Settings       string
	StreamSettings string
}

// ImportPanelDB opens a an existing panel SQLite database and converts its inbounds (and their
// clients) into canonical nodes. It is read-only.
func ImportPanelDB(dbPath string) (*Result, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("migrate: open an existing panel db: %w", err)
	}
	var rows []panelInbound
	if err := db.Table("inbounds").
		Select("id, remark, port, protocol, settings, stream_settings").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("migrate: read inbounds: %w", err)
	}
	res := &Result{}
	for _, r := range rows {
		n, users, warns := mapPanelInbound(r)
		res.Warnings = append(res.Warnings, warns...)
		if n == nil {
			continue
		}
		res.Inbounds = append(res.Inbounds, ImportedInbound{Node: n, Users: users, SourceID: r.ID})
	}
	if len(res.Inbounds) == 0 {
		res.Warnings = append(res.Warnings, "no importable inbounds found")
	}
	return res, nil
}

func mapPanelInbound(r panelInbound) (*model.Node, []ImportedUser, []string) {
	var warns []string
	n := &model.Node{
		Protocol: model.Protocol(r.Protocol), Address: "0.0.0.0", Port: r.Port, Remark: r.Remark,
	}
	// stream settings → transport + security.
	var ss map[string]any
	_ = json.Unmarshal([]byte(r.StreamSettings), &ss)
	applyStream(n, ss)

	// settings → clients.
	var st struct {
		Clients []struct {
			ID       string `json:"id"`
			Password string `json:"password"`
			Email    string `json:"email"`
			Flow     string `json:"flow"`
		} `json:"clients"`
		Method   string `json:"method"`
		Password string `json:"password"`
	}
	_ = json.Unmarshal([]byte(r.Settings), &st)

	var users []ImportedUser
	switch n.Protocol {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan:
		for _, cl := range st.Clients {
			users = append(users, ImportedUser{Email: cl.Email, UUID: cl.ID, Password: cl.Password})
		}
		if len(st.Clients) > 0 {
			n.UUID = st.Clients[0].ID
			n.Password = st.Clients[0].Password
			n.Flow = st.Clients[0].Flow
		}
	case model.ProtoShadowsocks:
		n.Method = st.Method
		n.Password = st.Password
	default:
		warns = append(warns, fmt.Sprintf("inbound %d: protocol %q not mapped, skipped", r.ID, r.Protocol))
		return nil, nil, warns
	}
	n.Normalize()
	return n, users, warns
}

// applyStream maps a an existing panel streamSettings object onto the canonical transport +
// security. an existing panel stores raw Xray streamSettings.
func applyStream(n *model.Node, ss map[string]any) {
	if ss == nil {
		n.Transport.Network = model.NetTCP
		return
	}
	net, _ := ss["network"].(string)
	switch net {
	case "ws":
		n.Transport.Network = model.NetWS
		if w, ok := ss["wsSettings"].(map[string]any); ok {
			n.Transport.Path, _ = w["path"].(string)
			if h, ok := w["headers"].(map[string]any); ok {
				n.Transport.Host, _ = h["Host"].(string)
			}
		}
	case "grpc":
		n.Transport.Network = model.NetGRPC
		if g, ok := ss["grpcSettings"].(map[string]any); ok {
			n.Transport.ServiceName, _ = g["serviceName"].(string)
		}
	case "xhttp", "splithttp":
		n.Transport.Network = model.NetXHTTP
		if x, ok := ss["xhttpSettings"].(map[string]any); ok {
			n.Transport.Path, _ = x["path"].(string)
		}
	default:
		n.Transport.Network = model.NetTCP
	}
	sec, _ := ss["security"].(string)
	switch sec {
	case "tls":
		n.Security.Type = model.SecTLS
		if t, ok := ss["tlsSettings"].(map[string]any); ok {
			n.Security.ServerName, _ = t["serverName"].(string)
		}
	case "reality":
		n.Security.Type = model.SecReality
		if rr, ok := ss["realitySettings"].(map[string]any); ok {
			r := &model.Reality{}
			r.PrivateKey, _ = rr["privateKey"].(string)
			if sn, ok := rr["serverNames"].([]any); ok && len(sn) > 0 {
				for _, v := range sn {
					if str, ok := v.(string); ok {
						r.ServerNames = append(r.ServerNames, str)
					}
				}
			}
			if sids, ok := rr["shortIds"].([]any); ok {
				for _, v := range sids {
					if str, ok := v.(string); ok {
						r.ShortIDs = append(r.ShortIDs, str)
					}
				}
			}
			if s, ok := rr["dest"].(string); ok {
				r.Dest = s
			}
			n.Security.Reality = r
		}
	default:
		n.Security.Type = model.SecNone
	}
}
