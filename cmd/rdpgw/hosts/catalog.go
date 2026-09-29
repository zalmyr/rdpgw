package hosts

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// Subject is the user a host decision is made for.
type Subject struct {
	UserName string
	Groups   []string
}

// SubjectFrom builds a Subject from an authenticated identity.
func SubjectFrom(id identity.Identity) Subject {
	if id == nil {
		return Subject{}
	}
	return Subject{UserName: id.UserName(), Groups: id.Groups()}
}

var (
	placeholder = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)
	// values substituted into an address must not be able to change its
	// structure (add a port, path, userinfo, whitespace ...)
	safeValue = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// placeholders supported in Entry.Address and Entry.Name:
//
//	{{ username }} / {{ preferred_username }}  the full user name
//	{{ user }}                                 the part before '@'
//	{{ domain }}                               the part after '@' (empty if none)
var knownPlaceholders = map[string]bool{
	"username": true, "preferred_username": true, "user": true, "domain": true,
}

func (s Subject) value(name string) string {
	switch name {
	case "username", "preferred_username":
		return s.UserName
	case "user":
		u, _, _ := strings.Cut(s.UserName, "@")
		return u
	case "domain":
		_, d, _ := strings.Cut(s.UserName, "@")
		return d
	}
	return ""
}

// expand substitutes placeholders. It reports false when a placeholder
// would expand to an empty or unsafe value, in which case the entry is not
// usable for this subject.
func (s Subject) expand(tmpl string, strict bool) (string, bool) {
	ok := true
	out := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := placeholder.FindStringSubmatch(m)[1]
		v := s.value(name)
		if strict && !safeValue.MatchString(v) {
			ok = false
		}
		return v
	})
	return out, ok
}

func validateTemplate(addr string) error {
	for _, m := range placeholder.FindAllStringSubmatch(addr, -1) {
		if !knownPlaceholders[m[1]] {
			return fmt.Errorf("host %q: unknown placeholder {{ %s }}", addr, m[1])
		}
	}
	stripped := placeholder.ReplaceAllString(addr, "x")
	if strings.Contains(stripped, "{{") || strings.Contains(stripped, "}}") {
		return fmt.Errorf("host %q: malformed placeholder", addr)
	}
	if strings.ContainsAny(stripped, " \t\r\n/?#@\\") {
		return fmt.Errorf("host %q: invalid characters in address", addr)
	}
	return nil
}

// Resolved is an entry expanded for one subject.
type Resolved struct {
	ID          string
	Name        string
	Address     string
	Description string
	Default     bool
	// template is the unexpanded address, kept to accept legacy requests
	// that send the raw configured string.
	template string
}

// Catalog is an immutable, validated list of entries.
type Catalog struct {
	entries []Entry
	groups  map[string]bool
}

// NewCatalog validates entries and returns a catalog.
func NewCatalog(entries []Entry) (*Catalog, error) {
	for _, e := range entries {
		if err := validateTemplate(strings.TrimSpace(e.Address)); err != nil {
			return nil, err
		}
	}
	norm, err := normalize(entries)
	if err != nil {
		return nil, err
	}
	c := &Catalog{entries: norm, groups: map[string]bool{}}
	for _, e := range norm {
		for _, g := range e.Groups {
			c.groups[g] = true
		}
	}
	return c, nil
}

// Len returns the number of configured entries.
func (c *Catalog) Len() int { return len(c.entries) }

// Entries returns a copy of the normalized entries.
func (c *Catalog) Entries() []Entry {
	return append([]Entry(nil), c.entries...)
}

// ReferencesGroup reports whether any entry is restricted to group g.
func (c *Catalog) ReferencesGroup(g string) bool { return c.groups[g] }

func (e Entry) allows(s Subject) bool {
	if len(e.Groups) == 0 && len(e.Users) == 0 {
		return true
	}
	for _, u := range e.Users {
		if strings.EqualFold(u, s.UserName) {
			return true
		}
	}
	for _, g := range e.Groups {
		for _, sg := range s.Groups {
			if g == sg {
				return true
			}
		}
	}
	return false
}

// ForSubject returns the entries s may use, with placeholders expanded.
// Entries whose placeholders cannot be safely expanded for s are omitted.
// If no entry is marked Default the first one is.
func (c *Catalog) ForSubject(s Subject) []Resolved {
	out := make([]Resolved, 0, len(c.entries))
	hasDefault := false
	for _, e := range c.entries {
		if !e.allows(s) {
			continue
		}
		addr, ok := s.expand(e.Address, true)
		if !ok {
			continue
		}
		name := e.Name
		if name == "" {
			name = addr
		} else {
			name, _ = s.expand(name, false)
		}
		desc, _ := s.expand(e.Description, false)
		out = append(out, Resolved{
			ID:          e.ID,
			Name:        name,
			Address:     addr,
			Description: desc,
			Default:     e.Default && !hasDefault,
			template:    e.Address,
		})
		hasDefault = hasDefault || e.Default
	}
	if !hasDefault && len(out) > 0 {
		out[0].Default = true
	}
	return out
}

// Lookup finds the entry s may use that matches ref, which may be an entry
// ID, the expanded address, or the raw configured address (legacy clients
// send that). It returns the expanded entry.
func (c *Catalog) Lookup(s Subject, ref string) (Resolved, bool) {
	visible := c.ForSubject(s)
	for _, r := range visible {
		if r.ID == ref {
			return r, true
		}
	}
	for _, r := range visible {
		if strings.EqualFold(r.Address, ref) || r.template == ref {
			return r, true
		}
	}
	return Resolved{}, false
}

// Allows reports whether address is one of the expanded addresses s may use.
func (c *Catalog) Allows(s Subject, address string) bool {
	for _, r := range c.ForSubject(s) {
		if strings.EqualFold(r.Address, address) {
			return true
		}
	}
	return false
}
