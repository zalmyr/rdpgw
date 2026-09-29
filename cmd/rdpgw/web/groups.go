package web

import (
	"log"
	"strings"
)

// maxSessionGroups caps the groups kept in the session so an identity
// provider that sends hundreds of groups can't overflow the session cookie.
const maxSessionGroups = 64

// GroupFilter reports whether a group is worth keeping in the session,
// typically whether any host entry references it. nil keeps every group.
type GroupFilter func(string) bool

// claimValue looks up a possibly nested claim, e.g. "realm_access.roles".
func claimValue(claims map[string]interface{}, name string) interface{} {
	var cur interface{} = claims
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// groupsFromClaim accepts a JSON array of strings or a single string.
func groupsFromClaim(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return splitGroups(t, ",")
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, g := range t {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}

func splitGroups(s, sep string) []string {
	var out []string
	for _, g := range strings.Split(s, sep) {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func filterGroups(user string, in []string, keep GroupFilter) []string {
	out := make([]string, 0, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" || (keep != nil && !keep(g)) {
			continue
		}
		if len(out) == maxSessionGroups {
			log.Printf("user %s: keeping only the first %d relevant groups", user, maxSessionGroups)
			break
		}
		out = append(out, g)
	}
	return out
}
