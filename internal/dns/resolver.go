package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Resolver is the DNS query surface this package needs. It is an interface so
// preflight and delegation logic are unit-testable without real DNS, and so a
// deployment can pin the recursive resolvers it trusts.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]string, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// PublicResolvers are the recursive resolvers used when none are configured.
// Two independent operators, so one operator's stale cache does not decide a
// provisioning outcome.
var PublicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// NetResolver queries public recursive resolvers through the standard library.
// With Servers empty it uses the host's own resolver.
type NetResolver struct {
	Servers []string
	Timeout time.Duration
}

// NewResolver builds a NetResolver over the given servers ("1.1.1.1:53" form).
// Passing none uses PublicResolvers.
func NewResolver(servers ...string) *NetResolver {
	if len(servers) == 0 {
		servers = PublicResolvers
	}
	return &NetResolver{Servers: servers, Timeout: 5 * time.Second}
}

func (r *NetResolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 5 * time.Second
}

// resolvers returns one *net.Resolver per configured server, or the system
// resolver when none are configured.
func (r *NetResolver) resolvers() []*net.Resolver {
	if len(r.Servers) == 0 {
		return []*net.Resolver{net.DefaultResolver}
	}
	out := make([]*net.Resolver, 0, len(r.Servers))
	for _, server := range r.Servers {
		addr := server
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		out = append(out, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: r.timeout()}
				// Honour the transport the resolver picked (it retries over TCP
				// when a UDP answer is truncated).
				if !strings.HasPrefix(network, "tcp") {
					network = "udp"
				}
				return d.DialContext(ctx, network, addr)
			},
		})
	}
	return out
}

// query runs fn against each configured resolver and returns the first
// non-empty answer. A "no such host" from every resolver is returned as-is so
// callers can distinguish NXDOMAIN from a transport failure.
func (r *NetResolver) query(ctx context.Context, fn func(context.Context, *net.Resolver) ([]string, error)) ([]string, error) {
	var lastErr error
	for _, res := range r.resolvers() {
		qctx, cancel := context.WithTimeout(ctx, r.timeout())
		vals, err := fn(qctx, res)
		cancel()
		if err == nil && len(vals) > 0 {
			return vals, nil
		}
		if err != nil {
			lastErr = err
			continue
		}
		// Success with zero answers: keep the empty result if nothing better turns up.
		lastErr = nil
	}
	return nil, lastErr
}

// LookupIP returns the A and AAAA addresses for host.
func (r *NetResolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	return r.query(ctx, func(c context.Context, res *net.Resolver) ([]string, error) {
		addrs, err := res.LookupHost(c, NormalizeDomain(host))
		return addrs, err
	})
}

// LookupNS returns the nameserver hostnames for host.
func (r *NetResolver) LookupNS(ctx context.Context, host string) ([]string, error) {
	return r.query(ctx, func(c context.Context, res *net.Resolver) ([]string, error) {
		ns, err := res.LookupNS(c, NormalizeDomain(host))
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(ns))
		for _, n := range ns {
			out = append(out, NormalizeDomain(n.Host))
		}
		return out, nil
	})
}

// LookupTXT returns the TXT strings for host.
func (r *NetResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return r.query(ctx, func(c context.Context, res *net.Resolver) ([]string, error) {
		return res.LookupTXT(c, NormalizeDomain(host))
	})
}

// LookupCNAME returns the canonical name for host.
func (r *NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	vals, err := r.query(ctx, func(c context.Context, res *net.Resolver) ([]string, error) {
		cname, err := res.LookupCNAME(c, NormalizeDomain(host))
		if err != nil {
			return nil, err
		}
		return []string{NormalizeDomain(cname)}, nil
	})
	if err != nil {
		return "", err
	}
	if len(vals) == 0 {
		return "", nil
	}
	return vals[0], nil
}

// IsNXDOMAIN reports whether err is an authoritative "name does not exist",
// as opposed to a resolver that could not be reached. The distinction decides
// whether preflight says "create the record" or "your resolver is broken".
func IsNXDOMAIN(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

var _ Resolver = (*NetResolver)(nil)
