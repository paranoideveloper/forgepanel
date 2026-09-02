package bridge

// Rendering the two halves of a bridge.
//
// Every template here produces a config that the tool's OWN binary accepted on
// 2026-08-26. The exact commands and their output are in backends_verified.md;
// the golden tests compare against these bytes, so a change to a template that
// would be rejected at startup fails in CI instead of on a bridge nobody can
// reach to debug.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Role is which half of the tunnel a config is for.
type Role string

const (
	// RoleExit runs on the server ABROAD. It accepts the tunnel.
	RoleExit Role = "exit"
	// RoleBridge runs on the machine reachable from inside Iran. It dials out
	// to the exit and accepts users.
	RoleBridge Role = "bridge"
)

// Service is one forwarded port.
type Service struct {
	// Name identifies the service in the config. Must be stable: it is the key
	// both halves agree on.
	Name string `json:"name"`
	// Protocol is "tcp" or "udp". A Hysteria2/TUIC/WireGuard inbound needs udp,
	// and getting this wrong produces a bridge that looks healthy and carries
	// nothing.
	Protocol string `json:"protocol"`
	// BridgePort is the port users connect to on the bridge.
	BridgePort int `json:"bridge_port"`
	// ExitHost/ExitPort are where the exit forwards to — normally the inbound's
	// own listener on 127.0.0.1.
	ExitHost string `json:"exit_host"`
	ExitPort int    `json:"exit_port"`
}

// Spec describes a whole bridge.
type Spec struct {
	Backend string `json:"backend"`
	// ExitAddr is the exit server's public address, which the bridge dials.
	ExitAddr string `json:"exit_addr"`
	// TunnelPort is the port the tunnel itself runs on.
	TunnelPort int `json:"tunnel_port"`
	// Token authenticates the two halves to each other.
	Token string `json:"token"`
	// Transport is backend-specific ("tcp", "ws", "wss", …). Empty takes the
	// backend's default.
	Transport string    `json:"transport"`
	Services  []Service `json:"services"`
}

// Validate checks a spec before anything is rendered from it.
func (s Spec) Validate() error {
	b, err := Get(s.Backend)
	if err != nil {
		return err
	}
	if strings.TrimSpace(s.ExitAddr) == "" {
		return errors.New("bridge: the exit server's address is required — it is what the bridge dials")
	}
	if s.TunnelPort <= 0 || s.TunnelPort > 65535 {
		return fmt.Errorf("bridge: tunnel port %d is out of range", s.TunnelPort)
	}
	if len(strings.TrimSpace(s.Token)) < 8 {
		// The token is the only thing standing between the exit and anyone who
		// finds its tunnel port. A short one is worse than none, because it
		// looks like protection.
		return errors.New("bridge: the shared token must be at least 8 characters")
	}
	if len(s.Services) == 0 {
		return errors.New("bridge: a bridge with no services forwards nothing")
	}
	seen := map[string]bool{}
	for _, svc := range s.Services {
		if strings.TrimSpace(svc.Name) == "" {
			return errors.New("bridge: every service needs a name; it is the key both halves agree on")
		}
		if seen[svc.Name] {
			return fmt.Errorf("bridge: two services are both called %q", svc.Name)
		}
		seen[svc.Name] = true
		switch strings.ToLower(svc.Protocol) {
		case "tcp":
		case "udp":
			if !b.CarriesUDP {
				return fmt.Errorf("bridge: %s cannot carry UDP, so %q would look healthy and move nothing "+
					"— Hysteria2, TUIC and WireGuard all need UDP", b.Title, svc.Name)
			}
		default:
			return fmt.Errorf("bridge: service %q has protocol %q; use tcp or udp", svc.Name, svc.Protocol)
		}
		if svc.BridgePort <= 0 || svc.BridgePort > 65535 {
			return fmt.Errorf("bridge: service %q has an out-of-range bridge port %d", svc.Name, svc.BridgePort)
		}
		if svc.ExitPort <= 0 || svc.ExitPort > 65535 {
			return fmt.Errorf("bridge: service %q has an out-of-range exit port %d", svc.Name, svc.ExitPort)
		}
	}
	return nil
}

// sortedServices returns the services in a stable order, so a rendered config
// does not churn between runs and a diff means something changed.
func (s Spec) sortedServices() []Service {
	out := append([]Service(nil), s.Services...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	for i := range out {
		out[i].Protocol = strings.ToLower(out[i].Protocol)
		if strings.TrimSpace(out[i].ExitHost) == "" {
			out[i].ExitHost = "127.0.0.1"
		}
	}
	return out
}

// Render produces the config for one half of the bridge.
//
// For an args-only backend the result is the command line, one argument per
// line, which is what a systemd unit's ExecStart needs anyway.
func Render(s Spec, role Role) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	switch s.Backend {
	case "backhaul":
		return renderBackhaul(s, role), nil
	case "rathole":
		return renderRathole(s, role), nil
	case "frp":
		return renderFRP(s, role), nil
	case "wstunnel":
		return renderWstunnel(s, role), nil
	}
	return "", fmt.Errorf("bridge: no renderer for %q", s.Backend)
}

func renderBackhaul(s Spec, role Role) string {
	transport := s.Transport
	if transport == "" {
		transport = "tcp"
	}
	var b strings.Builder
	if role == RoleExit {
		b.WriteString("[server]\n")
		fmt.Fprintf(&b, "bind_addr = \"0.0.0.0:%d\"\n", s.TunnelPort)
	} else {
		b.WriteString("[client]\n")
		fmt.Fprintf(&b, "remote_addr = \"%s:%d\"\n", s.ExitAddr, s.TunnelPort)
	}
	fmt.Fprintf(&b, "transport = %q\n", transport)
	fmt.Fprintf(&b, "token = %q\n", s.Token)
	if role == RoleExit {
		// backhaul's server declares the forwarded ports as "local=remote"
		// pairs; the client learns them from the server.
		ports := make([]string, 0, len(s.Services))
		for _, svc := range s.sortedServices() {
			ports = append(ports, fmt.Sprintf("%q", strconv.Itoa(svc.BridgePort)+"="+strconv.Itoa(svc.ExitPort)))
		}
		fmt.Fprintf(&b, "ports = [%s]\n", strings.Join(ports, ", "))
	}
	return b.String()
}

func renderRathole(s Spec, role Role) string {
	var b strings.Builder
	if role == RoleExit {
		b.WriteString("[server]\n")
		fmt.Fprintf(&b, "bind_addr = \"0.0.0.0:%d\"\n", s.TunnelPort)
		fmt.Fprintf(&b, "default_token = %q\n", s.Token)
		for _, svc := range s.sortedServices() {
			fmt.Fprintf(&b, "\n[server.services.%s]\n", svc.Name)
			fmt.Fprintf(&b, "type = %q\n", svc.Protocol)
			fmt.Fprintf(&b, "bind_addr = \"0.0.0.0:%d\"\n", svc.BridgePort)
		}
		return b.String()
	}
	b.WriteString("[client]\n")
	fmt.Fprintf(&b, "remote_addr = \"%s:%d\"\n", s.ExitAddr, s.TunnelPort)
	fmt.Fprintf(&b, "default_token = %q\n", s.Token)
	for _, svc := range s.sortedServices() {
		fmt.Fprintf(&b, "\n[client.services.%s]\n", svc.Name)
		fmt.Fprintf(&b, "type = %q\n", svc.Protocol)
		fmt.Fprintf(&b, "local_addr = \"%s:%d\"\n", svc.ExitHost, svc.ExitPort)
	}
	return b.String()
}

func renderFRP(s Spec, role Role) string {
	var b strings.Builder
	if role == RoleExit {
		// frps runs on the EXIT and accepts the tunnel.
		fmt.Fprintf(&b, "bindPort = %d\n", s.TunnelPort)
		b.WriteString("auth.method = \"token\"\n")
		fmt.Fprintf(&b, "auth.token = %q\n", s.Token)
		return b.String()
	}
	fmt.Fprintf(&b, "serverAddr = %q\n", s.ExitAddr)
	fmt.Fprintf(&b, "serverPort = %d\n", s.TunnelPort)
	b.WriteString("auth.method = \"token\"\n")
	fmt.Fprintf(&b, "auth.token = %q\n", s.Token)
	for _, svc := range s.sortedServices() {
		b.WriteString("\n[[proxies]]\n")
		fmt.Fprintf(&b, "name = %q\n", svc.Name)
		fmt.Fprintf(&b, "type = %q\n", svc.Protocol)
		fmt.Fprintf(&b, "localIP = %q\n", svc.ExitHost)
		fmt.Fprintf(&b, "localPort = %d\n", svc.ExitPort)
		fmt.Fprintf(&b, "remotePort = %d\n", svc.BridgePort)
	}
	return b.String()
}

func renderWstunnel(s Spec, role Role) string {
	// wstunnel has no config file; the "config" is the command line, which is
	// what a systemd ExecStart needs anyway.
	scheme := "ws"
	if s.Transport == "wss" || s.Transport == "https" {
		scheme = "wss"
	}
	var b strings.Builder
	if role == RoleExit {
		b.WriteString("server\n")
		fmt.Fprintf(&b, "%s://0.0.0.0:%d\n", scheme, s.TunnelPort)
		fmt.Fprintf(&b, "--restrict-http-upgrade-path-prefix\n%s\n", s.Token)
		return b.String()
	}
	b.WriteString("client\n")
	for _, svc := range s.sortedServices() {
		// -L <proto>://<bind-port>:<host>:<port> — the form the binary's own
		// --help documents, including for udp.
		fmt.Fprintf(&b, "-L\n%s://%d:%s:%d\n", svc.Protocol, svc.BridgePort, svc.ExitHost, svc.ExitPort)
	}
	fmt.Fprintf(&b, "--http-upgrade-path-prefix\n%s\n", s.Token)
	fmt.Fprintf(&b, "%s://%s:%d\n", scheme, s.ExitAddr, s.TunnelPort)
	return b.String()
}

// Args splits an args-format render into an argv slice.
func Args(rendered string) []string {
	var out []string
	for _, line := range strings.Split(rendered, "\n") {
		if v := strings.TrimSpace(line); v != "" {
			out = append(out, v)
		}
	}
	return out
}
