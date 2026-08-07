package dns

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// SampleIPs draws n random addresses from the given CIDRs, spread evenly
// across them so one enormous /13 does not swamp the sample. Network and
// broadcast addresses are skipped.
func SampleIPs(cidrs []string, n int) ([]string, error) {
	if len(cidrs) == 0 {
		cidrs = CloudflareIPv4Ranges
	}
	if n <= 0 {
		n = 256
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, &Error{Op: "sample-ips", Kind: KindValidation,
				Message:     fmt.Sprintf("%q is not a valid CIDR: %v", c, err),
				Remediation: "use CIDR notation such as 104.16.0.0/13"}
		}
		if ipnet.IP.To4() == nil {
			return nil, &Error{Op: "sample-ips", Kind: KindUnsupported,
				Message:     fmt.Sprintf("%q is IPv6; the scanner samples IPv4 space only", c),
				Remediation: "pass IPv4 CIDRs, or scan specific IPv6 addresses with --scan-addresses"}
		}
		nets = append(nets, ipnet)
	}
	// A range small enough to exhaust is enumerated and shuffled rather than
	// sampled: random draws from a tiny CIDR collide constantly, and giving up
	// on a collision would silently return fewer addresses than asked for.
	pools := make([][]string, len(nets))
	for i, ipnet := range nets {
		if size := usableSize(ipnet); size > 0 && size <= smallRangeLimit {
			pool, err := enumerateUsable(ipnet)
			if err != nil {
				return nil, err
			}
			pools[i] = pool
		}
	}

	seen := map[string]bool{}
	out := make([]string, 0, n)
	// Round-robin the ranges so the sample is spread rather than clustered in
	// whichever range happens to be enormous.
	for len(out) < n {
		progress := false
		for i, ipnet := range nets {
			if len(out) >= n {
				break
			}
			var ip string
			if pools[i] != nil {
				if len(pools[i]) == 0 {
					continue
				}
				ip = pools[i][0]
				pools[i] = pools[i][1:]
			} else {
				// Retry a few times: a collision in a large range is rare, and
				// one unlucky draw must not end the sampling.
				for attempt := 0; attempt < 8; attempt++ {
					candidate, err := randomIPIn(ipnet)
					if err != nil {
						return nil, err
					}
					if candidate != "" && !seen[candidate] {
						ip = candidate
						break
					}
				}
			}
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
			progress = true
		}
		if !progress {
			// Every range is exhausted; stop rather than spin.
			break
		}
	}
	return out, nil
}

// smallRangeLimit is the size below which a range is enumerated exhaustively.
const smallRangeLimit = 4096

// usableSize is how many addresses a range offers, excluding the network and
// broadcast addresses on anything wider than a /31. It returns -1 for ranges
// too large to count in an int.
func usableSize(ipnet *net.IPNet) int {
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return 1
	}
	if hostBits > 20 {
		return -1
	}
	size := 1 << uint(hostBits)
	if hostBits >= 2 {
		size -= 2
	}
	return size
}

// enumerateUsable lists every usable address in a small range, shuffled.
func enumerateUsable(ipnet *net.IPNet) ([]string, error) {
	base := ipnet.IP.To4()
	if base == nil {
		return nil, nil
	}
	size := usableSize(ipnet)
	if size <= 0 {
		return nil, nil
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	start := 0
	if hostBits >= 2 {
		start = 1 // skip the network address
	}
	baseInt := new(big.Int).SetBytes(base)
	out := make([]string, 0, size)
	for i := 0; i < size; i++ {
		ipInt := new(big.Int).Add(baseInt, big.NewInt(int64(start+i)))
		buf := ipInt.Bytes()
		for len(buf) < 4 {
			buf = append([]byte{0}, buf...)
		}
		out = append(out, net.IP(buf[len(buf)-4:]).String())
	}
	// Fisher-Yates with crypto/rand so an exhaustive range is still sampled in
	// an unpredictable order.
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, &Error{Op: "sample-ips", Kind: KindServer,
				Message: "could not read cryptographic randomness: " + err.Error(), Cause: err}
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return out, nil
}

// randomIPIn picks a uniformly random usable address inside ipnet.
func randomIPIn(ipnet *net.IPNet) (string, error) {
	base := ipnet.IP.To4()
	if base == nil {
		return "", nil
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return base.String(), nil
	}
	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	// A /31 or /32 has no network/broadcast convention worth honouring.
	if hostBits >= 2 {
		size = new(big.Int).Sub(size, big.NewInt(2))
	}
	if size.Sign() <= 0 {
		return base.String(), nil
	}
	offset, err := rand.Int(rand.Reader, size)
	if err != nil {
		return "", &Error{Op: "sample-ips", Kind: KindServer,
			Message: "could not read cryptographic randomness: " + err.Error(), Cause: err}
	}
	if hostBits >= 2 {
		offset = new(big.Int).Add(offset, big.NewInt(1)) // skip the network address
	}
	baseInt := new(big.Int).SetBytes(base)
	ipInt := new(big.Int).Add(baseInt, offset)
	buf := ipInt.Bytes()
	for len(buf) < 4 {
		buf = append([]byte{0}, buf...)
	}
	return net.IP(buf[len(buf)-4:]).String(), nil
}
