package webhook

// How a delivery actually leaves the box.
//
// Deliveries default to the panel-wide egress proxy (internal/netegress), which
// is the one place every outbound call the panel makes is built. An endpoint
// may override it, and that override is the point: the panel-wide proxy exists
// to get OUT of a censored network, while a webhook receiver is very often an
// internal service on the other side of a different hop entirely. Forcing both
// through one proxy breaks whichever of the two was configured second.
//
// That is also why deliveries use netegress.PolicyNoMetadata and not
// PolicyStrict: an internal receiver is the intended case, so loopback and
// RFC1918 stay reachable, while the cloud instance-metadata endpoints — which
// nobody ever legitimately posts a webhook to, and which hand out the hosting
// account's credentials — are refused. A stored endpoint is retried by a
// background goroutine, so this is the one delivery path with no operator
// watching it.

import (
	"net/http"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/netegress"
)

// newClient builds the client for one endpoint.
//
// PER ATTEMPT rather than cached on the endpoint: the proxy can be edited in
// the panel between two retries of the same delivery, and a cached transport
// would keep dialling the old one until the panel restarted.
func newClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return netegress.GuardedClient(netegress.PolicyNoMetadata, timeout), nil
	}
	return netegress.GuardedClientVia(netegress.PolicyNoMetadata, proxyURL, timeout)
}

// ValidateProxy reports whether a per-endpoint proxy can be used at all, so an
// operator learns it is wrong when they save it rather than from deliveries
// that silently never arrive.
func ValidateProxy(proxyURL string) error {
	_, err := newClient(proxyURL, attemptTimeout)
	return err
}
