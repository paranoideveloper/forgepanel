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

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// nativeConfNodes returns the subscription entries whose client format is a
// file, in a stable order so an index in a URL keeps meaning the same entry.
func nativeConfNodes(nodes []*model.Node) []*model.Node {
	var out []*model.Node
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if n.Protocol == model.ProtoWireGuard || n.Protocol == model.ProtoAmneziaWG {
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
		c.String(http.StatusNotFound, "this subscription has no WireGuard or AmneziaWG entry")
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
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(body))
}
