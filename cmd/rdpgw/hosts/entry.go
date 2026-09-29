// Package hosts owns the set of RDP destinations a user may be sent to. It
// is the single place where host templates are expanded, access rules are
// evaluated and user supplied destinations are validated, so the web
// frontend (/connect, /api/v1/hosts) and the gateway protocol handler make
// the same decision for the same user.
package hosts

import (
	"fmt"
	"regexp"
	"strings"
)

// Entry is one operator-defined destination. In YAML it can be written as a
// plain "host:port" string (the legacy format) or as a mapping:
//
//   - id: finance
//     name: Finance terminal server
//     address: fin-ts01.corp.local:3389
//     description: Shared finance desktop
//     groups: [finance]
//     users: [alice]
//     default: true
type Entry struct {
	// ID identifies the entry in /connect?host=<id>. Derived from Address
	// when empty.
	ID string `koanf:"id"`
	// Name is shown in the web interface. Defaults to the expanded address.
	Name string `koanf:"name"`
	// Address is host:port, optionally containing placeholders such as
	// {{ username }}; see Subject.expand.
	Address     string `koanf:"address"`
	Description string `koanf:"description"`
	// Groups and Users restrict who may use the entry. When both are empty
	// every authenticated user may use it; otherwise the user must be
	// listed in Users or be a member of one of Groups.
	Groups []string `koanf:"groups"`
	Users  []string `koanf:"users"`
	// Default marks the entry that is preselected in the web interface.
	Default bool `koanf:"default"`
}

// UnmarshalText lets a bare string in the configuration stand for an entry
// with only an address, keeping `hosts: [a:3389, b:3389]` and the
// space-separated RDPGW_SERVER__HOSTS environment variable working.
func (e *Entry) UnmarshalText(b []byte) error {
	*e = Entry{Address: strings.TrimSpace(string(b))}
	return nil
}

var (
	validID    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	nonIDChars = regexp.MustCompile(`[^a-z0-9]+`)
)

// slug derives a stable identifier from an address, e.g.
// "my-{{ username }}-host:3389" -> "my-username-host-3389".
func slug(address string) string {
	s := nonIDChars.ReplaceAllString(strings.ToLower(address), "-")
	s = strings.Trim(s, "-")
	if len(s) > 60 {
		s = strings.TrimRight(s[:60], "-")
	}
	if s == "" {
		s = "host"
	}
	return s
}

// normalize validates the entries and fills in derived IDs. IDs must be
// unique; derived IDs get a numeric suffix on collision.
func normalize(entries []Entry) ([]Entry, error) {
	out := make([]Entry, 0, len(entries))
	seen := make(map[string]bool, len(entries))

	// explicit IDs first so derived IDs never steal them
	for _, e := range entries {
		if e.ID == "" {
			continue
		}
		if !validID.MatchString(e.ID) {
			return nil, fmt.Errorf("host id %q: only letters, digits, '.', '_' and '-' are allowed (max 64)", e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("duplicate host id %q", e.ID)
		}
		seen[e.ID] = true
	}

	for i, e := range entries {
		e.Address = strings.TrimSpace(e.Address)
		if e.Address == "" {
			return nil, fmt.Errorf("host entry %d (%q) has no address", i, e.ID)
		}
		if e.ID == "" {
			base := slug(e.Address)
			id := base
			for n := 2; seen[id]; n++ {
				id = fmt.Sprintf("%s-%d", base, n)
			}
			e.ID = id
			seen[id] = true
		}
		e.Groups = trimAll(e.Groups)
		e.Users = trimAll(e.Users)
		out = append(out, e)
	}
	return out, nil
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
