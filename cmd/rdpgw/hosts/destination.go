package hosts

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DefaultRDPPort is assumed when a destination has no explicit port.
const DefaultRDPPort = 3389

// resolver is swapped out in tests.
var lookupIP = net.LookupIP

// splitHostPort splits host[:port], defaulting the port to 3389, and rejects
// strings that could not be a plain destination.
func splitHostPort(hostport string) (string, int, error) {
	if hostport == "" || strings.ContainsAny(hostport, " \t\r\n/?#@\\") {
		return "", 0, fmt.Errorf("invalid destination %q", hostport)
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// no port present -- assume the protocol default
		host = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
		port = strconv.Itoa(DefaultRDPPort)
	}
	if host == "" {
		return "", 0, fmt.Errorf("invalid destination %q", hostport)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", 0, fmt.Errorf("invalid port %q in %q", port, hostport)
	}
	return host, portNum, nil
}

// DestinationPolicy gates the host strings accepted in `any` host-selection
// mode. With the curated modes the operator picks the hosts; with `any` the
// value comes from the request, so the gateway must ensure it isn't being
// asked to act as a TCP relay against an internal-only target.
type DestinationPolicy struct {
	allowedPorts             map[int]struct{}
	allowPrivateDestinations bool
}

// NewDestinationPolicy builds a policy. An empty port list means {3389}.
func NewDestinationPolicy(allowedPorts []int, allowPrivate bool) DestinationPolicy {
	return DestinationPolicy{
		allowedPorts:             portSet(allowedPorts),
		allowPrivateDestinations: allowPrivate,
	}
}

func portSet(ports []int) map[int]struct{} {
	if len(ports) == 0 {
		ports = []int{DefaultRDPPort}
	}
	set := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		set[p] = struct{}{}
	}
	return set
}

// Allow validates a host:port (or bare host) string against the policy.
// The zero-value policy is treated as the secure default ({3389},
// public-only).
func (p DestinationPolicy) Allow(hostport string) error {
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return err
	}
	allowedPorts := p.allowedPorts
	if len(allowedPorts) == 0 {
		allowedPorts = portSet(nil)
	}
	if _, ok := allowedPorts[port]; !ok {
		return fmt.Errorf("port %d not in allow-list", port)
	}

	if p.allowPrivateDestinations {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		return checkPublicIP(host, ip)
	}
	addrs, err := lookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %q: %s", host, err)
	}
	for _, ip := range addrs {
		if err := checkPublicIP(host, ip); err != nil {
			return err
		}
	}
	return nil
}

func checkPublicIP(host string, ip net.IP) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("destination %q (%s) is loopback", host, ip)
	case ip.IsPrivate():
		return fmt.Errorf("destination %q (%s) is in a private range", host, ip)
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("destination %q (%s) is link-local", host, ip)
	case ip.IsUnspecified():
		return fmt.Errorf("destination %q (%s) is unspecified", host, ip)
	case ip.IsMulticast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("destination %q (%s) is multicast", host, ip)
	}
	return nil
}
