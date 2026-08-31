package api

// Native client configuration for the protocols a URI cannot carry.
//
// WireGuard and AmneziaWG are configured by a FILE, not a link. The
// subscription pipeline is a list of URIs, and both protocols fall off it:
//
//   - AmneziaWG has no URI at all. export.URI refuses it, plainLinksMode skips
//     anything that errors, and the inbound vanishes from the subscription
//     without a word. The panel can create the server side and hand the user
//     nothing.
//   - WireGuard does produce a URI, and it was worse than nothing: it carried
//     the SERVER's private key and no client address. (Fixed in export/uri.go;
//     this endpoint exists because a link is still not what these clients
//     import.)
//
// So the subscription serves the real thing: a wg-quick / AmneziaWG config, the
// exact text every client in that ecosystem opens, with the Amnezia obfuscation
// parameters preserved rather than quietly reduced to plain WireGuard.
//
// ShadowTLS is the third case, and the one the panel offered nothing at all
// for. It has no share-link scheme (export.URI refuses it) and Clash.Meta
// models it as a Shadowsocks plugin rather than a proxy (export.Clash refuses
// it too), so an operator who created a ShadowTLS inbound could copy nothing,
// scan nothing, and download nothing. Its native format is a sing-box client
// config, because ShadowTLS is a PAIR: the inner Shadowsocks that carries the
// traffic and the shadowtls camouflage it detours through. Emitting the bare
// shadowtls outbound produces a config that connects and carries nothing, so
// this reuses render.SingboxOutbounds, the one place that knows to build both.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// nativeConfNodes returns the subscription entries whose client format is a
// file, in a stable order so an index in a URL keeps meaning the same entry.
func nativeConfNodes(nodes []*model.Node) []*model.Node {
	var out []*model.Node
	for _, n := range nodes {
		if n == nil {
			continue
		}
		switch n.Protocol {
		case model.ProtoWireGuard, model.ProtoAmneziaWG, model.ProtoShadowTLS:
			out = append(out, n)
		}
	}
	return out
}

// nativeConfFor renders one entry, choosing the format by protocol.
func nativeConfFor(n *model.Node, host string) (filename, body string, err error) {
	switch n.Protocol {
	case model.ProtoWireGuard:
		body, err = export.WireGuardConf(n, host)
	case model.ProtoAmneziaWG:
		// AmneziaWGConf, not WireGuardConf: reducing an AmneziaWG peer to plain
		// WireGuard drops Jc/Jmin/Jmax/S1/S2/H1-H4, and a config without them
		// negotiates nothing with an AmneziaWG server — it looks like an
		// ordinary peer that simply never connects.
		body, err = export.AmneziaWGConf(n, host)
	case model.ProtoShadowTLS:
		return shadowTLSClientConf(n)
	default:
		return "", "", fmt.Errorf("%s has no native config format", n.Protocol)
	}
	if err != nil {
		return "", "", err
	}
	name := strings.TrimSpace(n.Remark)
	if name == "" {
		name = string(n.Protocol)
	}
	return safeName(name, n.Port) + ".conf", body, nil
}

// shadowTLSClientConf renders a complete, importable sing-box client config for
// one ShadowTLS inbound: the outbound pair plus the minimum a client needs to
// actually run it (a mixed inbound to point a browser at, and DNS).
func shadowTLSClientConf(n *model.Node) (string, string, error) {
	outs, err := render.SingboxOutbounds(n)
	if err != nil {
		return "", "", fmt.Errorf("render shadowtls: %w", err)
	}
	if len(outs) < 2 {
		// One outbound means the camouflage without the carrier. That config
		// completes a TLS handshake and then moves no traffic, which is the
		// failure this whole file exists to stop shipping.
		return "", "", fmt.Errorf("shadowtls rendered %d outbound(s); expected the "+
			"shadowtls+shadowsocks pair", len(outs))
	}
	tag, _ := outs[0]["tag"].(string)
	if tag == "" {
		tag = "shadowtls"
		render.RetagOutbounds(outs, tag)
	}
	body := map[string]any{
		"log": map[string]any{"level": "warn"},
		// Deliberately no "dns" block: sing-box changed the DNS server schema in
		// 1.12 and rejects the old shape outright, so a config that hard-codes
		// either form is valid on one side of that line and fatal on the other.
		// Omitting it uses the client's own defaults and parses on both.
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "mixed-in",
			"listen": "127.0.0.1", "listen_port": 2080,
		}},
		"outbounds": append(toAnySlice(outs),
			map[string]any{"type": "direct", "tag": "direct"}),
		"route": map[string]any{
			"rules": []any{map[string]any{"action": "sniff"}},
			"final": tag,
		},
	}
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return "", "", err
	}
	name := strings.TrimSpace(n.Remark)
	if name == "" {
		name = string(n.Protocol)
	}
	return safeName(name, n.Port) + ".json", string(raw), nil
}

func toAnySlice[T any](in []T) []any {
	out := make([]any, 0, len(in)+1)
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

// handleSubNativeConf serves one subscription entry as its native config file.
//
// Indexed rather than keyed by inbound id: the subscription is the user's view,
// and an id from the panel's database is not something a subscriber has or
// should be able to probe.
func (s *Server) handleSubNativeConf(c *gin.Context) {
	token := c.Param("token")
	nodes := s.subscriptionNodes(token, hostOnly(c.Request.Host))
	if nodes == nil {
		c.String(http.StatusNotFound, "unknown subscription")
		return
	}
	confs := nativeConfNodes(nodes)
	if len(confs) == 0 {
		c.String(http.StatusNotFound, "this subscription has no entry with a native config format")
		return
	}
	idx, err := strconv.Atoi(strings.TrimPrefix(c.Param("index"), "/"))
	if err != nil || idx < 0 || idx >= len(confs) {
		c.String(http.StatusNotFound, "no entry %s; this subscription has %d",
			c.Param("index"), len(confs))
		return
	}
	n := confs[idx]
	filename, body, err := nativeConfFor(n, n.Address)
	if err != nil {
		c.String(http.StatusUnprocessableEntity, "%v", err)
		return
	}
	// Content-Disposition so a browser saves it, and text/plain so a phone that
	// previews it shows the config rather than downloading a blob it cannot open.
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	ctype := "text/plain; charset=utf-8"
	if strings.HasSuffix(filename, ".json") {
		ctype = "application/json; charset=utf-8"
	}
	c.Data(http.StatusOK, ctype, []byte(body))
}

// subNativeEntries builds the landing-page cards for the entries a subscription
// URL cannot carry. It renders each config here rather than linking blindly, so
// a config that fails to render is left off the page instead of shown as a
// download button that returns an error.
func (s *Server) subNativeEntries(token string, c *gin.Context, base string) []nativeEntry {
	// The download route is /subconf/<token>/<index>, a sibling of /sub — NOT a
	// child of it. base is ".../sub/<token>", so appending to it would produce
	// /sub/<token>/subconf/0 and a 404: a Download button that downloads
	// nothing. Cut back to the origin and build the real path.
	root := strings.TrimSuffix(strings.TrimSuffix(base, "/"), "/sub/"+token)
	nodes := nativeConfNodes(s.subscriptionNodes(token, hostOnly(c.Request.Host)))
	out := make([]nativeEntry, 0, len(nodes))
	for i, n := range nodes {
		_, body, err := nativeConfFor(n, n.Address)
		if err != nil {
			continue
		}
		kind := "WireGuard client"
		switch n.Protocol {
		case model.ProtoAmneziaWG:
			kind = "AmneziaWG client (obfuscated)"
		case model.ProtoShadowTLS:
			kind = "sing-box client config"
		}
		name := strings.TrimSpace(n.Remark)
		if name == "" {
			name = string(n.Protocol)
		}
		out = append(out, nativeEntry{
			name: name, kind: kind,
			url:  fmt.Sprintf("%s/subconf/%s/%d", root, token, i),
			body: body,
		})
	}
	return out
}
