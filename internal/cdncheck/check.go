// Package cdncheck asks Cloudflare what it thinks of an origin, and turns its
// answer into something an operator can act on.
//
// A CDN-fronted inbound fails in a way that is almost impossible to debug from
// the origin side: the operator tests the port directly, gets a clean answer,
// and concludes the server is fine — while every client gets a Cloudflare error
// page. The panel created the record and the inbound, reported success, and had
// no idea.
//
// MEASURED, on a live Cloudflare zone with a proxied record on port 8443:
//
//	origin directly (plain HTTP on 8443)  -> 200
//	through Cloudflare, same port         -> 525
//
// Cloudflare speaks HTTPS to the origin on every proxied HTTPS port, so a
// plain-HTTP origin behind one is a 525 no matter how healthy it looks locally.
// That single fact accounts for a large share of "the CDN config does not work"
// reports.
//
// The 5xx codes below are Cloudflare's own, returned by its edge rather than by
// the origin, and each one names a different thing to fix. Reporting the number
// alone would leave the operator searching; reporting the fix is the point of
// this package.
package cdncheck

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"strconv"
	"time"
)

// ProxiedHTTPSPorts are the only HTTPS ports Cloudflare will proxy. An inbound
// on any other port is simply not reachable through the CDN, and the record
// looks perfectly correct in the dashboard.
var ProxiedHTTPSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

// ProxiedHTTPPorts are the plain-HTTP equivalents.
var ProxiedHTTPPorts = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}

// PortIsProxied reports whether Cloudflare routes a proxied record on this port.
func PortIsProxied(port int) bool {
	for _, p := range ProxiedHTTPSPorts {
		if p == port {
			return true
		}
	}
	return false
}

// Result is what the edge said, and what to do about it.
type Result struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Reached is true when the request got past Cloudflare to the origin. It
	// does NOT mean the tunnel works — a 404 from the origin still counts,
	// because the origin answered.
	Reached bool `json:"reached"`
	Status  int  `json:"status"`
	// Problem names the fault in one phrase, empty when there is none.
	Problem string `json:"problem,omitempty"`
	// Fix is the actionable sentence.
	Fix string `json:"fix,omitempty"`
	// EdgeServed reports whether Cloudflare answered at all.
	EdgeServed bool          `json:"edge_served"`
	Elapsed    time.Duration `json:"-"`
}

// Checker performs the request. Client is a seam for tests, which stand up a
// throwaway TLS server whose certificate no public root signs; production
// leaves it nil and gets the panel's proxied client.
type Checker struct {
	Client *http.Client
}

// Check makes one request to a proxied host:port and interprets the answer.
//
// It deliberately does NOT follow redirects and does not care what the body is:
// the question is only whether Cloudflare could reach the origin, which its own
// 5xx codes answer precisely.
func Check(ctx context.Context, host string, port int) Result {
	return Checker{}.Check(ctx, host, port)
}

// Check is the same, with a caller-supplied client.
func (ck Checker) Check(ctx context.Context, host string, port int) Result {
	r := Result{Host: host, Port: port}

	if !PortIsProxied(port) {
		r.Problem = "port " + strconv.Itoa(port) + " is not one Cloudflare proxies"
		r.Fix = fmt.Sprintf("A proxied record only carries HTTPS on %v. Move the inbound to one of "+
			"those ports, or turn the proxy off for this record and serve it directly.", ProxiedHTTPSPorts)
		return r
	}

	start := time.Now()
	// netegress, not a bare client: the panel's egress may be proxied, and a
	// diagnosis that dials direct would report the CDN as unreachable on exactly
	// the network the proxy exists for. The wiring guard in internal/netegress
	// enforces this, and it caught this file.
	cl := ck.Client
	if cl == nil {
		cl = netegress.Client(20 * time.Second)
	}
	// The edge's own error pages are the answer; a redirect to a login or a
	// parked page is not, and following it would turn a diagnosis into whatever
	// the redirect target happens to return.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	url := "https://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Problem = "could not build a request for " + url
		return r
	}
	resp, err := cl.Do(req)
	r.Elapsed = time.Since(start)
	if err != nil {
		r.Problem = "the CDN hostname could not be reached: " + err.Error()
		r.Fix = "Check that the DNS record exists and is proxied, and that this server has outbound HTTPS."
		return r
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	r.EdgeServed = resp.Header.Get("Server") == "cloudflare" || resp.Header.Get("CF-RAY") != ""

	switch resp.StatusCode {
	case 521:
		r.Problem = "Cloudflare reached the origin and the connection was refused"
		r.Fix = "Nothing is listening on port " + strconv.Itoa(port) + ". Check the inbound is enabled and the core is running."
	case 522:
		r.Problem = "Cloudflare could not connect to the origin before timing out"
		r.Fix = "The port is filtered. Open " + strconv.Itoa(port) + "/tcp to Cloudflare's ranges in the firewall."
	case 523:
		r.Problem = "Cloudflare cannot route to the origin address"
		r.Fix = "The record points at an address Cloudflare cannot reach. Check it holds this server's public IP."
	case 525:
		r.Problem = "the TLS handshake between Cloudflare and the origin failed"
		r.Fix = "Cloudflare speaks HTTPS to the origin on every proxied HTTPS port, so the inbound must serve TLS " +
			"on " + strconv.Itoa(port) + ". Either give it a certificate (self-signed is fine) or set the zone's " +
			"SSL mode to Full — Flexible cannot work on a port other than 443."
	case 526:
		r.Problem = "Cloudflare rejected the origin's certificate"
		r.Fix = "The zone is on Full (Strict), which requires a certificate a public CA signed. Switch it to Full, " +
			"or install a real certificate on the origin."
	default:
		// Anything else means the origin answered — including a 404, which is
		// exactly what a proxy endpoint returns for a bare GET.
		r.Reached = true
	}
	return r
}
