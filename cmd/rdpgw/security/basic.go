package security

import (
	"context"
	"errors"
	"log"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
)

// HostPolicy decides which destinations a tunnel may be opened to. It is
// shared with the web frontend so both apply the same rules.
var HostPolicy *hosts.Policy

// CheckHost verifies a destination for tunnels that were not issued a PAA
// token (basic, NTLM, Kerberos): the client names the host itself, so the
// catalog, access rules and destination policy are applied here.
func CheckHost(ctx context.Context, host string) (bool, error) {
	if HostPolicy == nil {
		return false, errors.New("no host policy configured")
	}
	s := getTunnel(ctx)
	if s == nil || s.User == nil {
		return false, errors.New("no valid session info found in context")
	}

	subject := hosts.SubjectFrom(s.User)
	log.Printf("Checking host %s for user %s", host, subject.UserName)
	if err := HostPolicy.Authorize(subject, host); err != nil {
		return false, err
	}
	return true, nil
}

// CheckPinnedHost verifies a destination for tunnels authenticated with a PAA
// token. CheckSession has already matched the host against the one pinned in
// the token, which /connect chose under the host policy.
func CheckPinnedHost(ctx context.Context, host string) (bool, error) {
	if HostPolicy == nil {
		return false, errors.New("no host policy configured")
	}
	if err := HostPolicy.AuthorizePinned(host); err != nil {
		return false, err
	}
	return true, nil
}
