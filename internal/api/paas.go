package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// PaaS mode: every inbound behind ONE plain-HTTP port.
//
// On a platform like Railway the container is given a single port, reached
// through an edge that terminates TLS on :443 of a hostname the platform owns.
// There is no second port to put an inbound on and no way to bind the address
// clients dial. What there IS, is a URL path — so the panel and every inbound
// share the one port and are told apart by the path the client requests.
//
// That splits an inbound in two, and keeping the halves straight is the whole
// job of this file:
//
//	stored node  →  what the CLIENT is told: platform hostname, :443, TLS
//	engine node  →  what the CORE binds:     127.0.0.1, a local port, no TLS
//
// The stored node is never rewritten. A subscription, a QR code and the link in
// the inbound drawer all keep describing the connection the client actually
// makes — through the edge, over TLS, on 443 — because that is the truth from
// where the client sits. Only the copy handed to the core is rewritten, because
// what the core can bind is a different truth on the inside of the edge.

// paasPortBase is where locally-bound inbound ports start. High, ephemeral-range
// and above anything the panel itself uses, so an assignment can never collide
// with the panel port, the core API ports, or a port the platform assigned.
const paasPortBase = 39000

// paasRoute is one inbound reachable through the shared public port.
type paasRoute struct {
	// Prefix is the URL path that selects this inbound. Matching is by prefix,
	// not equality, because XHTTP appends its session id and packet sequence to
	// the configured path ("/path/<uuid>/1") and an exact match would route the
	// first request and drop every one after it.
	Prefix string
	// Addr is the loopback address:port the core was told to bind.
	Addr string
	// Remark identifies the inbound in diagnostics.
	Remark string
}

// paasRoutable reports whether an inbound can be served through a shared HTTP
// port, and why not when it cannot.
//
// The reason strings are the operator-facing explanation of an inbound that
// exists, is enabled, and carries nothing. Without them the panel would accept
// a Hysteria2 inbound on Railway, show it green, and never say that the
// platform does not route UDP at all — which is exactly the failure the
// not-serving column was added to end.
func paasRoutable(n *model.Node) (string, string) {
	if n == nil {
		return "", "no configuration"
	}
	switch n.Transport.Network {
	case model.NetWS, model.NetHTTPUpgrade, model.NetXHTTP:
		p := strings.TrimSpace(n.Transport.Path)
		if p == "" {
			// Every inbound sharing the port needs something to be told apart
			// by. Without a path this one would either capture the panel or be
			// captured by another inbound, so it is refused rather than served
			// ambiguously.
			return "", "needs a transport path to share the platform's single port"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return p, ""
	case model.NetGRPC, model.NetH2:
		// Both require end-to-end HTTP/2. A PaaS edge terminates the client's
		// connection and re-issues it to the container over HTTP/1.1, so the
		// stream multiplexing these transports are built on never arrives.
		return "", "needs end-to-end HTTP/2, which the platform edge does not forward"
	case model.NetQUIC:
		return "", "needs UDP, which the platform does not route"
	case model.NetMKCP:
		return "", "needs UDP, which the platform does not route"
	}
	// Everything left is a raw-TCP or UDP protocol: Hysteria2, TUIC, AnyTLS,
	// ShadowTLS, WireGuard, Shadowsocks-on-tcp, Brook, plain VLESS/Trojan on
	// tcp. The platform gives out one HTTP port and nothing else, so there is
	// no honest way to serve any of them.
	if isUDPProtocol(n.Protocol) {
		return "", "needs UDP, which the platform does not route"
	}
	return "", "needs its own TCP port, which the platform does not give out — use ws, httpupgrade or xhttp"
}

// isUDPProtocol reports whether the protocol is UDP-only at the wire level.
func isUDPProtocol(p model.Protocol) bool {
	switch p {
	case model.ProtoHysteria2, model.ProtoTUIC, model.ProtoWireGuard, model.ProtoAmneziaWG:
		return true
	}
	return false
}

// paasEngineNode returns the copy of n the CORE is given: bound on loopback at
// port, with the TLS layer removed.
//
// Removing TLS is not an omission, it is the point. The platform's edge already
// performed the handshake the client's link describes; what reaches the
// container is the plaintext inside it. A core still configured for TLS would
// answer that plaintext HTTP request with a ServerHello and every connection
// would fail — with a certificate error on a connection that never needed a
// certificate here.
func paasEngineNode(n *model.Node, port int) *model.Node {
	c := n.Clone()
	c.Address = "127.0.0.1"
	c.Port = port
	c.Security = model.Security{Type: model.SecNone}
	return c
}

// paasSpecs rewrites the enabled inbounds for a shared-port deployment and
// returns the specs to hand the cores alongside the routing table the front
// proxy needs and the inbounds that cannot be served here at all.
func (s *Server) paasSpecs() ([]engine.InboundSpec, []paasRoute, []engine.SkippedInbound) {
	all := s.enabledInboundSpecs()
	var (
		specs   []engine.InboundSpec
		routes  []paasRoute
		skipped []engine.SkippedInbound
	)
	// Sorting by prefix length, longest first, makes a nested path ("/a/b")
	// win over the shorter one that contains it ("/a"). Registration order is
	// whatever the database returned, so without this the winner between two
	// overlapping inbounds would depend on their row order.
	taken := map[string]string{}
	for i, sp := range all {
		if sp.Node == nil {
			continue
		}
		prefix, why := paasRoutable(sp.Node)
		if why != "" {
			skipped = append(skipped, engine.SkippedInbound{Remark: sp.Node.Remark, Reason: why})
			continue
		}
		if other, dup := taken[prefix]; dup {
			skipped = append(skipped, engine.SkippedInbound{
				Remark: sp.Node.Remark,
				Reason: fmt.Sprintf("path %s is already served by %q — each inbound needs its own path here", prefix, other),
			})
			continue
		}
		taken[prefix] = sp.Node.Remark
		port := paasPortBase + i
		out := sp
		out.Node = paasEngineNode(sp.Node, port)
		// The certificate belongs to the edge. Handing the core one it must not
		// present would only give it something to fail on.
		out.CertPath, out.KeyPath = "", ""
		specs = append(specs, out)
		routes = append(routes, paasRoute{
			Prefix: prefix,
			Addr:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			Remark: sp.Node.Remark,
		})
	}
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Prefix) > len(routes[j].Prefix)
	})
	return specs, routes, skipped
}

// setPaaSRoutes publishes the routing table the front proxy reads.
func (s *Server) setPaaSRoutes(routes []paasRoute) {
	s.paasMu.Lock()
	s.paasRoutes = routes
	s.paasMu.Unlock()
}

// PaaSRoutes returns the current shared-port routing table.
func (s *Server) PaaSRoutes() []paasRoute {
	s.paasMu.RLock()
	defer s.paasMu.RUnlock()
	return append([]paasRoute(nil), s.paasRoutes...)
}

// paasMatch finds the inbound serving a request path, if any.
func (s *Server) paasMatch(path string) (paasRoute, bool) {
	s.paasMu.RLock()
	defer s.paasMu.RUnlock()
	for _, r := range s.paasRoutes {
		if path == r.Prefix || strings.HasPrefix(path, strings.TrimSuffix(r.Prefix, "/")+"/") {
			return r, true
		}
	}
	return paasRoute{}, false
}

// paasFront wraps the panel handler so requests whose path belongs to an
// inbound are passed to the core instead.
//
// It is a plain reverse proxy rather than a raw connection splice because the
// two transports that survive here are HTTP: a WebSocket inbound needs the 101
// upgrade forwarded (ReverseProxy hands the hijacked connection over once the
// core answers 101), and an XHTTP inbound needs its POST bodies streamed
// without buffering, which FlushInterval -1 does. Splicing the raw socket would
// mean re-implementing both.
func (s *Server) paasFront(next http.Handler) http.Handler {
	if !s.cfg.PaaS().Enabled {
		return next
	}
	proxy := &httputil.ReverseProxy{
		// A DEDICATED transport, with pooling off.
		//
		// Not http.DefaultTransport, which the panel shares with ACME, Telegram
		// and the node control plane: a stalled tunnel must not be able to hold
		// an idle slot the control plane needs, and tunnel traffic has no
		// business in the same pool as the panel's own calls.
		//
		// Keep-alives are off because a pooled connection is worth nothing here
		// and is a hazard. Every WebSocket this carries is hijacked after its
		// 101 and can never return to the pool anyway, and an XHTTP session's
		// requests belong to one tunnel — handing a later, unrelated session a
		// connection an earlier one left behind is a correctness question, not a
		// performance one. Measured cost: none that showed up. A 5 MB transfer
		// through the front proxy runs at 20 MB/s, and 20 consecutive tunnels
		// each completed a full request/response with no reuse.
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		// FlushInterval -1 flushes each write straight through. XHTTP's
		// download leg is a long-lived streaming response, and buffering it —
		// the default — holds the tunnel's data in this process until a buffer
		// fills, which stalls the connection instead of carrying it.
		FlushInterval: -1,
		Director: func(r *http.Request) {
			route, ok := paasRouteFrom(r)
			if !ok {
				return
			}
			r.URL.Scheme = "http"
			r.URL.Host = route.Addr
			// The client's Host header is preserved deliberately. An inbound may
			// be configured to check it (transport host / domain fronting), and
			// rewriting it to "127.0.0.1:39000" would make every such inbound
			// reject its own traffic.
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A core that is down or restarting must not look like a panel
			// error. 502 with no body is what a plain reverse proxy in front of
			// a dead upstream gives, and it tells a probing client nothing.
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if route, ok := s.paasMatch(r.URL.Path); ok {
			proxy.ServeHTTP(w, withPaaSRoute(r, route))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// paasRouteKey carries the matched route from the handler to the Director,
// which is the only hook ReverseProxy gives for choosing an upstream.
type paasRouteKey struct{}

func withPaaSRoute(r *http.Request, route paasRoute) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), paasRouteKey{}, route))
}

func paasRouteFrom(r *http.Request) (paasRoute, bool) {
	route, ok := r.Context().Value(paasRouteKey{}).(paasRoute)
	return route, ok
}

// applyPaaSAddressing fixes the stored node's PUBLIC identity to what the
// platform actually serves: its hostname, the edge's port, and TLS.
//
// On a normal install the address and port are the operator's to choose, and
// the panel must not overrule them. Here they are not a choice. There is one
// hostname, it is the platform's; there is one public port, the edge's 443; and
// TLS is terminated there whatever the inbound thinks. An operator who types
// their own address into the form is not expressing a preference, they are
// describing a server that does not exist — and the link built from it fails
// with a connection error that says nothing about why.
//
// Only path-routable inbounds are touched. A Hysteria2 or raw-TCP inbound is
// left exactly as entered, because rewriting it to the platform's address would
// dress up an inbound that cannot be served here as one that can; it is
// reported in the not-serving column instead, with the reason.
func (s *Server) applyPaaSAddressing(n *model.Node) {
	pa := s.cfg.PaaS()
	if !pa.Enabled || pa.Domain == "" || n == nil {
		return
	}
	if _, why := paasRoutable(n); why != "" {
		// One exception: a routable transport that simply has no path yet. That
		// is a form the operator left blank, not an unservable protocol, and a
		// path is something the panel can supply.
		if !paasNeedsPath(n) {
			return
		}
		n.Transport.Path = "/" + randHex(8)
	}
	n.Address = pa.Domain
	n.Port = pa.PublicPort
	n.Domain = pa.Domain
	// TLS in the LINK, none in the engine config (see paasEngineNode). The
	// client really does speak TLS — to the edge — so the link must say so or
	// the client sends plaintext into an HTTPS listener and is rejected.
	n.Security = model.Security{Type: model.SecTLS, ServerName: pa.Domain}
	if n.Transport.Host == "" {
		n.Transport.Host = pa.Domain
	}
}

// paasSharesPublicPort reports whether n will end up sharing the platform's one
// public port, judged on TRANSPORT ALONE.
//
// paasRoutable is the wrong question in the request pipeline, and getting that
// wrong is what made the collision guard keep refusing inbounds after the
// exemption was added: paasRoutable also requires a path, and the path is minted
// later, by applyPaaSAddressing in the handler. The guard runs first, saw a
// path-less node, judged it unroutable, and fell through to the ordinary
// one-port-one-listener rule it was meant to skip.
//
// What the guard actually needs to know is "will this inbound be served by path
// on the shared port", and the transport settles that on its own.
func paasSharesPublicPort(n *model.Node) bool {
	if n == nil {
		return false
	}
	switch n.Transport.Network {
	case model.NetWS, model.NetHTTPUpgrade, model.NetXHTTP:
		return true
	}
	return false
}

// paasNeedsPath reports whether n uses a path-carrying transport but has no
// path set — the one repairable reason paasRoutable rejects an inbound.
func paasNeedsPath(n *model.Node) bool {
	switch n.Transport.Network {
	case model.NetWS, model.NetHTTPUpgrade, model.NetXHTTP:
		return strings.TrimSpace(n.Transport.Path) == ""
	}
	return false
}

// ReconcilePaaSAddresses corrects stored inbounds that carry an address the
// platform does not serve.
//
// A Railway service has no public hostname until somebody clicks "Generate
// Domain", and RAILWAY_PUBLIC_DOMAIN does not exist before that. So the panel's
// first boot is routinely in a state where PaaS mode is on and the domain is
// unknown — and an inbound created in that window is stored with whatever
// address the form defaulted to, which is not reachable from anywhere.
//
// Generating the domain afterwards used to fix nothing: the platform's variable
// appeared, every NEW inbound came out right, and the ones made in the first ten
// minutes kept pointing at an address that never worked, with nothing anywhere
// saying so. The operator's own conclusion is that the panel is broken, and they
// are not wrong.
//
// This runs at every start, so the deploy that first sees the domain is the one
// that repairs them. It only ever rewrites the public identity — address, port,
// TLS, host — and only for inbounds the platform can actually serve; it never
// touches credentials, paths, or an inbound that is unservable here anyway.
func (s *Server) ReconcilePaaSAddresses() int {
	pa := s.cfg.PaaS()
	if !pa.Enabled || pa.Domain == "" || s.db == nil {
		return 0
	}
	ins, err := s.db.ListInbounds()
	if err != nil {
		return 0
	}
	fixed := 0
	for i := range ins {
		in := &ins[i]
		n, err := in.Node()
		if err != nil {
			continue
		}
		if _, why := paasRoutable(n); why != "" {
			continue // not servable here; leave it exactly as entered
		}
		if n.Address == pa.Domain && n.Port == pa.PublicPort && n.Security.Type == model.SecTLS {
			continue // already correct
		}
		was := fmt.Sprintf("%s:%d", n.Address, n.Port)
		s.applyPaaSAddressing(n)
		if err := in.SetNode(n); err != nil {
			continue
		}
		if err := s.db.SaveInbound(in); err != nil {
			continue
		}
		fixed++
		fmt.Printf("forgepanel: inbound %q pointed at %s, which this platform does not serve — corrected to %s:%d\n",
			n.Remark, was, n.Address, n.Port)
	}
	if fixed > 0 {
		s.startBackground(s.reloadEngines)
	}
	return fixed
}

// learnPaaSDomain records the hostname the panel is actually reached on, when
// the platform did not tell it.
//
// The panel cannot write a usable client link, or even print its own URL,
// without knowing its public hostname — and on Railway that hostname exists
// (the operator is looking at it in the browser) while the variable that would
// carry it does not, because the service has not restarted since the domain was
// generated. Every request arriving through the edge carries it in Host.
//
// It learns only from an AUTHENTICATED ADMIN request. Host is client-supplied,
// and a hostname learned from any passer-by is a hostname an outsider chooses:
// it would end up in every link and QR code the panel hands out. An admin
// necessarily reached the login page on the right hostname, so their session is
// both the earliest trustworthy signal and a hard one to forge.
//
// Once stored it is ordinary panel configuration — visible on the panel-address
// page and editable there — not hidden state.
func (s *Server) learnPaaSDomain() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		pa := s.cfg.PaaS()
		if !pa.Enabled || pa.Domain != "" || c.Writer.Status() >= 400 {
			return
		}
		host := c.Request.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		// A hostname, not an address: the container's own private IP is exactly
		// what this is here to stop the panel from advertising.
		if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
			return
		}
		if err := s.setPanelDomain(host); err != nil {
			return
		}
		fmt.Printf("forgepanel: learned this service's public hostname from an administrator request: %s\n", host)
		// Inbounds created while the hostname was unknown carry a placeholder
		// address. Now that it is known they can be repaired, which is the whole
		// point of learning it.
		s.ReconcilePaaSAddresses()
	}
}

// setPanelDomain persists the panel's domain and refreshes the running config.
func (s *Server) setPanelDomain(host string) error {
	p := s.cfg.Panel()
	if p == nil {
		return fmt.Errorf("no panel settings")
	}
	p.Domain = host
	if err := config.SavePanelSettings(s.cfg.DataDir, p); err != nil {
		return err
	}
	return s.cfg.ReloadPanel()
}
