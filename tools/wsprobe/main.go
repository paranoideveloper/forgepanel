package main

// Generate a VLESS + WebSocket + TLS pair from the panel's own renderers, the
// shape used behind a CDN, so the thing under test is what the panel ships.

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

func main() {
	host := os.Args[1] // the CDN hostname clients dial
	port := 8443
	uuid := keygen.UUID()

	// The panel's model: Address is what the core BINDS, Domain is what clients
	// dial. Behind a CDN those differ, and conflating them is how a CDN-fronted
	// inbound ends up either unbindable or advertising the raw origin IP.
	n := &model.Node{
		Remark:   "ws-cdn-test",
		Protocol: model.ProtoVLESS,
		Address:  "0.0.0.0",
		Domain:   host,
		Port:     port,
		UUID:     uuid,
		Transport: model.Transport{
			Network: model.NetWS,
			Path:    "/wscdn",
			Host:    host,
		},
		Security: model.Security{
			Type:       model.SecTLS,
			ServerName: host,
		},
	}

	in, err := render.XrayInbound(n)
	must(err)
	// The ORIGIN terminates TLS with its own certificate; Cloudflare is in
	// "full" mode, which does not validate it.
	ss, _ := in["streamSettings"].(map[string]any)
	if ts, ok := ss["tlsSettings"].(map[string]any); ok {
		ts["certificates"] = []any{map[string]any{
			"certificateFile": "/tmp/ws.crt", "keyFile": "/tmp/ws.key",
		}}
	}
	srv := map[string]any{
		"log":       map[string]any{"loglevel": "debug"},
		"inbounds":  []any{in},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	b, _ := json.MarshalIndent(srv, "", " ")
	must(os.WriteFile("/tmp/ws-server.json", b, 0o644))

	// What the panel hands the client: the same node with the advertised address
	// substituted, which is what substituteAddr does in the real subscription
	// path.
	cn := n.Clone()
	cn.Address = host
	link, err := export.URI(cn)
	must(err)
	fmt.Println("LINK:", link)

	out, err := render.XrayOutbound(cn)
	must(err)
	cli := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"tag": "s", "protocol": "socks", "port": 13960,
			"listen": "127.0.0.1", "settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{out},
	}
	b, _ = json.MarshalIndent(cli, "", " ")
	must(os.WriteFile("/tmp/ws-client.json", b, 0o644))
	fmt.Println("wrote /tmp/ws-server.json /tmp/ws-client.json")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
