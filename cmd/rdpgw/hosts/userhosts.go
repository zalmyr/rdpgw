package hosts

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
)

// UserHostPolicy decides which destinations a user may type in themselves
// (instead of picking a configured entry). The operator lists patterns:
//
//	*.corp.local:3389     hostname glob with a fixed port
//	*.corp.local          hostname glob, port must be in the allowed ports
//	10.20.0.0/16:3389     CIDR; hostnames must resolve entirely inside it
//	[fd00::/8]:3389       IPv6 needs brackets when a port is given
//	rdp-*.corp.local:*    any port
//
// Patterns are explicit operator intent, so private ranges are allowed when
// a pattern covers them.
type UserHostPolicy struct {
	patterns     []hostPattern
	defaultPorts map[int]struct{}
}

type hostPattern struct {
	raw     string
	glob    string
	cidr    *net.IPNet
	port    int // 0 = use defaultPorts
	anyPort bool
}

// NewUserHostPolicy parses patterns. It returns nil (disabled) when there
// are none.
func NewUserHostPolicy(patterns []string, defaultPorts []int) (*UserHostPolicy, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	p := &UserHostPolicy{defaultPorts: portSet(defaultPorts)}
	for _, raw := range patterns {
		hp, err := parsePattern(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		p.patterns = append(p.patterns, hp)
	}
	return p, nil
}

func parsePattern(raw string) (hostPattern, error) {
	hp := hostPattern{raw: raw}
	if raw == "" {
		return hp, fmt.Errorf("empty user host pattern")
	}
	host, port := raw, ""
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end < 0 {
			return hp, fmt.Errorf("user host pattern %q: missing ']'", raw)
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return hp, fmt.Errorf("user host pattern %q: expected ':port' after ']'", raw)
			}
			port = rest[1:]
		}
	} else if i := strings.LastIndex(raw, ":"); i >= 0 && isPortSpec(raw[i+1:]) && !strings.Contains(raw[:i], ":") {
		// unbracketed IPv6 (more than one ':') never carries a port
		host, port = raw[:i], raw[i+1:]
	}

	switch port {
	case "":
	case "*":
		hp.anyPort = true
	default:
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return hp, fmt.Errorf("user host pattern %q: invalid port", raw)
		}
		hp.port = n
	}

	if strings.Contains(host, "/") {
		_, n, err := net.ParseCIDR(host)
		if err != nil {
			return hp, fmt.Errorf("user host pattern %q: %s", raw, err)
		}
		hp.cidr = n
		return hp, nil
	}
	host = strings.ToLower(host)
	if host == "" || strings.ContainsAny(host, " \t\r\n?#@\\") {
		return hp, fmt.Errorf("user host pattern %q: invalid host", raw)
	}
	if _, err := path.Match(host, "x"); err != nil {
		return hp, fmt.Errorf("user host pattern %q: %s", raw, err)
	}
	if host == "*" {
		return hp, fmt.Errorf("user host pattern %q matches every host; use hostselection: any instead", raw)
	}
	hp.glob = host
	return hp, nil
}

func isPortSpec(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (hp hostPattern) portOK(port int, defaults map[int]struct{}) bool {
	switch {
	case hp.anyPort:
		return true
	case hp.port != 0:
		return port == hp.port
	default:
		_, ok := defaults[port]
		return ok
	}
}

func (hp hostPattern) hostOK(host string) bool {
	if hp.cidr == nil {
		ok, _ := path.Match(hp.glob, strings.ToLower(host))
		return ok
	}
	if ip := net.ParseIP(host); ip != nil {
		return hp.cidr.Contains(ip)
	}
	addrs, err := lookupIP(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, ip := range addrs {
		if !hp.cidr.Contains(ip) {
			return false
		}
	}
	return true
}

// Allow reports whether hostport matches at least one pattern.
func (p *UserHostPolicy) Allow(hostport string) error {
	if p == nil {
		return fmt.Errorf("user supplied hosts are disabled")
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return err
	}
	for _, hp := range p.patterns {
		if hp.portOK(port, p.defaultPorts) && hp.hostOK(host) {
			return nil
		}
	}
	return fmt.Errorf("destination %q does not match any allowed pattern", hostport)
}

// Patterns returns the configured patterns, for display.
func (p *UserHostPolicy) Patterns() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.patterns))
	for i, hp := range p.patterns {
		out[i] = hp.raw
	}
	return out
}
