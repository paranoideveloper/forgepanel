package singboxapi

// Per-user traffic accounting for the sing-box protocols.
//
// Hysteria2, TUIC, AnyTLS, ShadowTLS and WireGuard are served by sing-box, and
// until now NOTHING metered them. Only Xray was polled, so a user could exhaust
// their plan entirely on those protocols and stay active forever: the quota
// system guarded traffic it could not see. That fails quietly and always in the
// customer's favour, which is why it survived.
//
// WHAT IS ACTUALLY AVAILABLE, measured against sing-box 1.13.15 rather than
// assumed:
//
//	clash_api   present in official builds, and useless for this. Connection
//	            metadata carries no user field (destinationIP, host, network,
//	            sourceIP, type … and no identity), and /connections lists only
//	            LIVE connections — a short request opens and closes between two
//	            polls and is never counted at all.
//	ssm_api     present, and Shadowsocks-only: attaching it to a Hysteria2
//	            inbound is refused with "is not a SSM server".
//	v2ray_api   exactly what is needed — user>>><name>>>traffic>>>uplink counters,
//	            the same shape Xray emits — but the OFFICIAL release archives are
//	            not built with it. A binary built with `-tags with_v2ray_api`
//	            reports per-user Hysteria2 traffic correctly; verified end to end.
//
// So the capability depends on which sing-box binary is installed. This file
// detects that from the binary itself and uses the counters when they exist. The
// alternative — assuming and failing silently — is what produced the original
// gap.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// singboxStatsService is the gRPC service sing-box registers for its v2ray API.
//
// It is NOT the name Xray uses (xray.app.stats.command.StatsService), which is
// why `xray api statsquery` against a sing-box endpoint fails with UNIMPLEMENTED
// rather than with anything that hints at the cause.
const singboxStatsService = "v2ray.core.app.stats.command.StatsService"

// singboxV2RayTag is the build tag that decides whether any of this is possible.
const singboxV2RayTag = "with_v2ray_api"

// SingboxStatsSupport reports whether a sing-box binary can report per-user
// traffic, and why not when it cannot.
type Support struct {
	Supported bool   `json:"supported"`
	Version   string `json:"version,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// detectSingboxStats reads the binary's own build tags.
//
// `sing-box version` prints a Tags: line listing exactly what was compiled in,
// so the binary is asked rather than guessed at from a version number — two
// builds of the same version can differ here, and that difference is the whole
// question.
func Detect(bin string) Support {
	if strings.TrimSpace(bin) == "" {
		return Support{Reason: "sing-box is not installed"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return Support{Reason: "could not run sing-box: " + err.Error()}
	}
	sup := Support{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "sing-box version "); ok {
			sup.Version = strings.TrimSpace(v)
		}
		if tags, ok := strings.CutPrefix(line, "Tags:"); ok {
			for _, t := range strings.Split(strings.TrimSpace(tags), ",") {
				if strings.TrimSpace(t) == singboxV2RayTag {
					sup.Supported = true
				}
			}
		}
	}
	if !sup.Supported {
		sup.Reason = "this sing-box is built without " + singboxV2RayTag + ", so it cannot report " +
			"per-user traffic. Inbounds it serves (hysteria2, tuic, anytls, shadowtls, wireguard) " +
			"are NOT metered, and their users' quotas will not be enforced from this host. " +
			"Install a sing-box built with that tag to meter them."
	}
	return sup
}

// querySingboxStats reads counters from a sing-box v2ray API endpoint.
//
// reset=true zeroes each counter as it is read. The scheduler does NOT use that:
// a destructive read makes the in-flight value the only copy, and a panel killed
// between the read and the write loses that traffic for good. It exists because
// the wire format has the field and omitting it would silently send false.
func Query(ctx context.Context, addr, pattern string, reset bool) (map[string]int64, error) {
	body := encodeQueryStatsRequest(pattern, reset)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+addr+"/"+singboxStatsService+"/QueryStats", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/grpc")
	req.Header.Set("te", "trailers")

	resp, err := singboxGRPCClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sing-box stats: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("sing-box stats: read: %w", err)
	}
	// gRPC reports failure in a trailer, not the HTTP status, so a 200 with
	// grpc-status 12 is what an unimplemented service looks like.
	if st := firstNonEmptyStr(resp.Trailer.Get("grpc-status"), resp.Header.Get("grpc-status")); st != "" && st != "0" {
		msg := firstNonEmptyStr(resp.Trailer.Get("grpc-message"), resp.Header.Get("grpc-message"))
		return nil, fmt.Errorf("sing-box stats: grpc-status %s %s", st, msg)
	}
	return decodeQueryStatsResponse(raw)
}

var (
	singboxGRPCOnce   sync.Once
	singboxGRPCShared *http.Client
)

// singboxGRPCClient speaks h2c: HTTP/2 over a plain connection, which is what a
// loopback gRPC listener without TLS expects. Go's default transport will not
// do that on its own.
func singboxGRPCClient() *http.Client {
	singboxGRPCOnce.Do(func() {
		singboxGRPCShared = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
				},
			},
		}
	})
	return singboxGRPCShared
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- the two messages -------------------------------------------------------
//
// QueryStatsRequest { 1: string pattern, 2: bool reset }
// QueryStatsResponse{ 1: repeated Stat }, Stat { 1: string name, 2: int64 value }
//
// Encoded by hand rather than by pulling in grpc-go and generated stubs: two
// messages with four scalar fields between them do not justify the dependency,
// and the codec is covered by round-trip tests against bytes the real sing-box
// produced.

func encodeQueryStatsRequest(pattern string, reset bool) []byte {
	var msg []byte
	if pattern != "" {
		msg = append(msg, 0x0a) // field 1, length-delimited
		msg = binary.AppendUvarint(msg, uint64(len(pattern)))
		msg = append(msg, pattern...)
	}
	if reset {
		msg = append(msg, 0x10, 0x01) // field 2, varint, true
	}
	// gRPC frame: 1 byte compression flag + 4 byte big-endian length.
	frame := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg)))
	return append(frame, msg...)
}

var errShortStats = errors.New("sing-box stats: truncated response")

func decodeQueryStatsResponse(frame []byte) (map[string]int64, error) {
	out := map[string]int64{}
	if len(frame) == 0 {
		return out, nil // no counters yet is not an error
	}
	if len(frame) < 5 {
		return nil, errShortStats
	}
	if frame[0] != 0 {
		// A compressed frame would need the negotiated codec; sing-box does not
		// send one, and guessing would corrupt counters rather than fail.
		return nil, fmt.Errorf("sing-box stats: compressed responses are not supported")
	}
	n := binary.BigEndian.Uint32(frame[1:5])
	body := frame[5:]
	if uint32(len(body)) < n {
		return nil, errShortStats
	}
	body = body[:n]

	for len(body) > 0 {
		key, used := binary.Uvarint(body)
		if used <= 0 {
			return nil, errShortStats
		}
		body = body[used:]
		if key != 0x0a { // field 1, length-delimited (repeated Stat)
			var skipErr error
			if body, skipErr = skipField(key, body); skipErr != nil {
				return nil, skipErr
			}
			continue
		}
		l, used := binary.Uvarint(body)
		if used <= 0 || uint64(len(body[used:])) < l {
			return nil, errShortStats
		}
		body = body[used:]
		name, value, err := decodeStat(body[:l])
		if err != nil {
			return nil, err
		}
		body = body[l:]
		if name != "" {
			out[name] = value
		}
	}
	return out, nil
}

func decodeStat(b []byte) (name string, value int64, err error) {
	for len(b) > 0 {
		key, used := binary.Uvarint(b)
		if used <= 0 {
			return "", 0, errShortStats
		}
		b = b[used:]
		switch key {
		case 0x0a: // name
			l, used := binary.Uvarint(b)
			if used <= 0 || uint64(len(b[used:])) < l {
				return "", 0, errShortStats
			}
			b = b[used:]
			name = string(b[:l])
			b = b[l:]
		case 0x10: // value
			v, used := binary.Uvarint(b)
			if used <= 0 {
				return "", 0, errShortStats
			}
			b = b[used:]
			value = int64(v)
		default:
			if b, err = skipField(key, b); err != nil {
				return "", 0, err
			}
		}
	}
	return name, value, nil
}

// skipField steps over a field this decoder does not read, so a future sing-box
// that adds one does not turn every counter into a parse error.
func skipField(key uint64, b []byte) ([]byte, error) {
	switch key & 7 {
	case 0: // varint
		_, used := binary.Uvarint(b)
		if used <= 0 {
			return nil, errShortStats
		}
		return b[used:], nil
	case 1: // 64-bit
		if len(b) < 8 {
			return nil, errShortStats
		}
		return b[8:], nil
	case 2: // length-delimited
		l, used := binary.Uvarint(b)
		if used <= 0 || uint64(len(b[used:])) < l {
			return nil, errShortStats
		}
		return b[used+int(l):], nil
	case 5: // 32-bit
		if len(b) < 4 {
			return nil, errShortStats
		}
		return b[4:], nil
	default:
		return nil, fmt.Errorf("sing-box stats: unsupported wire type %d", key&7)
	}
}
