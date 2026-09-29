package hosts

import (
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Host selection modes.
const (
	// SelectionRoundRobin picks a random entry the user may use.
	SelectionRoundRobin = "roundrobin"
	// SelectionUnsigned lets the user pick an entry (by id or address) and,
	// when UserHostPatterns are configured, type in a matching host.
	SelectionUnsigned = "unsigned"
	// SelectionSigned expects a host signed by an external portal.
	SelectionSigned = "signed"
	// SelectionAny accepts any public destination on an allowed port.
	SelectionAny = "any"
)

// Config configures a Policy.
type Config struct {
	Selection string
	// Entries come from the main configuration file / environment.
	Entries []Entry
	// HostsFile optionally holds more entries under a top-level `hosts:`
	// key. It is re-read by Reload.
	HostsFile string
	// AllowedDestinationPorts is used by `any` mode and by user host
	// patterns that don't name a port. Empty means {3389}.
	AllowedDestinationPorts []int
	// AllowPrivateDestinations lifts the public-only restriction of `any`.
	AllowPrivateDestinations bool
	// UserHostPatterns enables user supplied hosts in unsigned mode.
	UserHostPatterns []string
}

// Policy is the host decision point shared by the web frontend and the
// gateway. It is safe for concurrent use; the catalog can be swapped at
// runtime with Reload.
type Policy struct {
	selection string
	static    []Entry
	hostsFile string
	dest      DestinationPolicy
	userHosts *UserHostPolicy

	catalog  atomic.Pointer[Catalog]
	reloadMu sync.Mutex
	fileMod  time.Time
}

// NewPolicy validates cfg and loads the hosts file, if any.
func NewPolicy(cfg Config) (*Policy, error) {
	switch cfg.Selection {
	case "":
		cfg.Selection = SelectionRoundRobin
	case SelectionRoundRobin, SelectionUnsigned, SelectionSigned, SelectionAny:
	default:
		return nil, fmt.Errorf("unknown host selection %q (valid: roundrobin, unsigned, signed, any)", cfg.Selection)
	}
	p := &Policy{
		selection: cfg.Selection,
		static:    cfg.Entries,
		hostsFile: cfg.HostsFile,
		dest:      NewDestinationPolicy(cfg.AllowedDestinationPorts, cfg.AllowPrivateDestinations),
	}
	uh, err := NewUserHostPolicy(cfg.UserHostPatterns, cfg.AllowedDestinationPorts)
	if err != nil {
		return nil, err
	}
	if uh != nil && cfg.Selection != SelectionUnsigned {
		return nil, fmt.Errorf("user host patterns require hostselection: unsigned (got %q)", cfg.Selection)
	}
	p.userHosts = uh

	if err := p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

// Reload rebuilds the catalog from the static entries plus the hosts file.
// On error the previous catalog stays active.
func (p *Policy) Reload() error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	entries := append([]Entry(nil), p.static...)
	if p.hostsFile != "" {
		st, err := os.Stat(p.hostsFile)
		if err != nil {
			return fmt.Errorf("hosts file: %w", err)
		}
		// remember this version even if it turns out invalid, so the
		// poller reports a broken file once instead of every interval
		p.fileMod = st.ModTime()
		fromFile, err := LoadFile(p.hostsFile)
		if err != nil {
			return err
		}
		entries = append(entries, fromFile...)
	}

	c, err := NewCatalog(entries)
	if err != nil {
		return err
	}
	if c.Len() == 0 && p.selection != SelectionAny && p.userHosts == nil {
		return errors.New("no hosts configured")
	}
	p.catalog.Store(c)
	return nil
}

// ReloadIfChanged reloads when the hosts file modification time changed.
func (p *Policy) ReloadIfChanged() (bool, error) {
	if p.hostsFile == "" {
		return false, nil
	}
	st, err := os.Stat(p.hostsFile)
	if err != nil {
		return false, err
	}
	p.reloadMu.Lock()
	same := st.ModTime().Equal(p.fileMod)
	p.reloadMu.Unlock()
	if same {
		return false, nil
	}
	return true, p.Reload()
}

// Watch polls the hosts file every interval until stop is closed, logging
// reload results. It is a no-op without a hosts file.
func (p *Policy) Watch(interval time.Duration, stop <-chan struct{}) {
	if p.hostsFile == "" {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			changed, err := p.ReloadIfChanged()
			if err != nil {
				log.Printf("hosts: keeping previous host list, reload of %s failed: %s", p.hostsFile, err)
			} else if changed {
				log.Printf("hosts: reloaded %d entries from %s", p.Catalog().Len(), p.hostsFile)
			}
		}
	}
}

// Selection returns the host selection mode.
func (p *Policy) Selection() string { return p.selection }

// Catalog returns the active catalog.
func (p *Policy) Catalog() *Catalog { return p.catalog.Load() }

// UserHosts returns the user host policy, nil when disabled.
func (p *Policy) UserHosts() *UserHostPolicy { return p.userHosts }

// Visible returns the entries s may pick from.
func (p *Policy) Visible(s Subject) []Resolved {
	return p.Catalog().ForSubject(s)
}

// Select decides the destination for a /connect request. requested is the
// `host` query parameter ("" when absent). verifySigned decodes a signed
// host token and is only used in signed mode.
func (p *Policy) Select(s Subject, requested string, verifySigned func(string) (string, error)) (string, error) {
	switch p.selection {
	case SelectionRoundRobin:
		visible := p.Visible(s)
		if len(visible) == 0 {
			return "", errors.New("no hosts available for this user")
		}
		return visible[rand.IntN(len(visible))].Address, nil

	case SelectionUnsigned:
		if requested == "" {
			return "", errors.New("missing host parameter")
		}
		if r, ok := p.Catalog().Lookup(s, requested); ok {
			return r.Address, nil
		}
		if p.userHosts != nil {
			if err := p.userHosts.Allow(requested); err != nil {
				log.Printf("rejecting user supplied host %q for %s: %s", requested, s.UserName, err)
				return "", errors.New("host not allowed")
			}
			return requested, nil
		}
		log.Printf("Invalid host %q requested by %s", requested, s.UserName)
		return "", errors.New("invalid host specified in query parameter")

	case SelectionSigned:
		if requested == "" {
			return "", errors.New("missing host parameter")
		}
		if verifySigned == nil {
			return "", errors.New("signed host selection is not configured")
		}
		ref, err := verifySigned(requested)
		if err != nil {
			return "", err
		}
		if r, ok := p.Catalog().Lookup(s, ref); ok {
			return r.Address, nil
		}
		log.Printf("Invalid host %q specified in token for %s", ref, s.UserName)
		return "", errors.New("invalid host specified in query token")

	case SelectionAny:
		if requested == "" {
			return "", errors.New("missing host parameter")
		}
		// configured entries are offered as suggestions and may be
		// referenced by id; they still go through the destination policy
		if r, ok := p.Catalog().Lookup(s, requested); ok {
			requested = r.Address
		}
		if err := p.dest.Allow(requested); err != nil {
			log.Printf("rejecting `any` destination %q: %s", requested, err)
			return "", fmt.Errorf("destination not allowed: %s", err)
		}
		return requested, nil
	}
	return "", errors.New("unrecognized host selection")
}

// Authorize is the gateway-side check for tunnels that were not issued a
// PAA token (basic, NTLM, Kerberos): the client names the destination
// itself, so apply the same rules /connect would.
func (p *Policy) Authorize(s Subject, address string) error {
	switch p.selection {
	case SelectionAny:
		return p.dest.Allow(address)
	case SelectionSigned:
		return errors.New("signed host selection requires token authentication")
	case SelectionRoundRobin, SelectionUnsigned:
		if s.UserName == "" {
			return errors.New("no user in session")
		}
		if p.Catalog().Allows(s, address) {
			return nil
		}
		if p.selection == SelectionUnsigned && p.userHosts != nil {
			return p.userHosts.Allow(address)
		}
		return fmt.Errorf("host %s not allowed for %s", address, s.UserName)
	}
	return errors.New("unrecognized host selection")
}

// AuthorizePinned is the gateway-side check for tunnels whose destination
// was pinned by a PAA token issued by /connect, which already applied the
// catalog and access rules. Only `any` re-validates, since DNS may have
// changed since the token was issued.
func (p *Policy) AuthorizePinned(address string) error {
	if p.selection == SelectionAny {
		return p.dest.Allow(address)
	}
	return nil
}

// LoadFile reads entries from a YAML file with a top-level `hosts:` list.
func LoadFile(path string) ([]Entry, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("hosts file %s: %w", path, err)
	}
	var doc struct {
		Hosts []Entry `koanf:"hosts"`
	}
	if err := k.UnmarshalWithConf("", &doc, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return nil, fmt.Errorf("hosts file %s: %w", path, err)
	}
	return doc.Hosts, nil
}
