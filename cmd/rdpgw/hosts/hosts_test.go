package hosts

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

func fakeDNS(t *testing.T, table map[string][]string) {
	t.Helper()
	orig := lookupIP
	lookupIP = func(host string) ([]net.IP, error) {
		addrs, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}
	t.Cleanup(func() { lookupIP = orig })
}

func mustCatalog(t *testing.T, entries ...Entry) *Catalog {
	t.Helper()
	c, err := NewCatalog(entries)
	if err != nil {
		t.Fatalf("NewCatalog: %s", err)
	}
	return c
}

func TestEntryDecodesFromStringsAndMaps(t *testing.T) {
	src := []byte(`
server:
  hosts:
    - legacy:3389
    - id: fin
      name: Finance
      address: fin-ts01:3389
      groups: [finance]
`)
	path := filepath.Join(t.TempDir(), "rdpgw.yaml")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	k := koanf.New(".")
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Hosts []Entry `koanf:"hosts"`
	}
	if err := k.UnmarshalWithConf("server", &out, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		t.Fatal(err)
	}
	if len(out.Hosts) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(out.Hosts), out.Hosts)
	}
	if out.Hosts[0].Address != "legacy:3389" {
		t.Errorf("legacy string entry decoded as %+v", out.Hosts[0])
	}
	if out.Hosts[1].ID != "fin" || out.Hosts[1].Address != "fin-ts01:3389" || out.Hosts[1].Groups[0] != "finance" {
		t.Errorf("map entry decoded as %+v", out.Hosts[1])
	}
}

func TestEntryDecodesFromSingleString(t *testing.T) {
	// what RDPGW_SERVER__HOSTS=xrdp:3389 produces
	k := koanf.New(".")
	k.Set("Server.Hosts", "xrdp:3389")
	var out struct {
		Hosts []Entry `koanf:"hosts"`
	}
	if err := k.UnmarshalWithConf("Server", &out, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		t.Fatal(err)
	}
	if len(out.Hosts) != 1 || out.Hosts[0].Address != "xrdp:3389" {
		t.Fatalf("got %+v", out.Hosts)
	}
}

func TestCatalogValidation(t *testing.T) {
	bad := [][]Entry{
		{{Address: ""}},
		{{ID: "a b", Address: "x:3389"}},
		{{ID: "dup", Address: "a:3389"}, {ID: "dup", Address: "b:3389"}},
		{{Address: "evil/path:3389"}},
		{{Address: "{{ nope }}:3389"}},
		{{Address: "{{ username :3389"}},
	}
	for _, entries := range bad {
		if _, err := NewCatalog(entries); err == nil {
			t.Errorf("NewCatalog(%+v) accepted invalid input", entries)
		}
	}
}

func TestCatalogDerivesUniqueIDs(t *testing.T) {
	c := mustCatalog(t,
		Entry{Address: "host-3389"},
		Entry{Address: "host:3389"},
		Entry{ID: "host-3389-2", Address: "other:3389"},
	)
	ids := map[string]bool{}
	for _, e := range c.Entries() {
		if ids[e.ID] {
			t.Fatalf("duplicate id %q in %+v", e.ID, c.Entries())
		}
		ids[e.ID] = true
	}
}

func TestForSubjectFiltersAndExpands(t *testing.T) {
	c := mustCatalog(t,
		Entry{ID: "shared", Address: "shared:3389"},
		Entry{ID: "fin", Address: "fin:3389", Groups: []string{"finance"}, Default: true},
		Entry{ID: "bob", Address: "bob-only:3389", Users: []string{"Bob@corp.com"}},
		Entry{ID: "vm", Name: "{{ user }}'s VM", Address: "vm-{{ user }}.{{ domain }}:3389"},
	)

	alice := Subject{UserName: "alice@corp.com", Groups: []string{"finance"}}
	got := map[string]Resolved{}
	for _, r := range c.ForSubject(alice) {
		got[r.ID] = r
	}
	if _, ok := got["bob"]; ok {
		t.Error("alice can see bob's entry")
	}
	if !got["fin"].Default || got["shared"].Default {
		t.Errorf("explicit default not honoured: %+v", got)
	}
	if got["vm"].Address != "vm-alice.corp.com:3389" || got["vm"].Name != "alice's VM" {
		t.Errorf("vm expanded to %+v", got["vm"])
	}

	bob := Subject{UserName: "bob@corp.com"}
	ids := []string{}
	for _, r := range c.ForSubject(bob) {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "shared,bob,vm" {
		t.Errorf("bob sees %v", ids)
	}
	if !c.ForSubject(bob)[0].Default {
		t.Error("first entry should become default when the explicit default is hidden")
	}

	// no domain -> {{ domain }} can't expand -> entry hidden
	for _, r := range c.ForSubject(Subject{UserName: "carol"}) {
		if r.ID == "vm" {
			t.Errorf("entry with empty placeholder value is visible: %+v", r)
		}
	}
}

func TestPlaceholderInjectionIsRejected(t *testing.T) {
	c := mustCatalog(t, Entry{ID: "vm", Address: "vm-{{ username }}:3389"})
	for _, name := range []string{"evil.com:22 #", "a/b", "x@y:1", "a b"} {
		if got := c.ForSubject(Subject{UserName: name}); len(got) != 0 {
			t.Errorf("username %q expanded into %+v", name, got)
		}
	}
}

func TestLookup(t *testing.T) {
	c := mustCatalog(t,
		Entry{ID: "vm", Address: "my-{{ preferred_username }}-host:3389"},
		Entry{ID: "fin", Address: "fin:3389", Groups: []string{"finance"}},
	)
	s := Subject{UserName: "alice"}
	for _, ref := range []string{"vm", "my-alice-host:3389", "MY-ALICE-HOST:3389", "my-{{ preferred_username }}-host:3389"} {
		r, ok := c.Lookup(s, ref)
		if !ok || r.Address != "my-alice-host:3389" {
			t.Errorf("Lookup(%q) = %+v, %v", ref, r, ok)
		}
	}
	if _, ok := c.Lookup(s, "fin"); ok {
		t.Error("Lookup returned an entry the subject may not use")
	}
	if _, ok := c.Lookup(s, "my-bob-host:3389"); ok {
		t.Error("Lookup matched another user's expansion")
	}
}

func TestDestinationPolicy(t *testing.T) {
	fakeDNS(t, map[string][]string{
		"public.example": {"203.0.113.9"},
		"internal.corp":  {"10.1.2.3"},
	})
	p := NewDestinationPolicy(nil, false)
	allow := []string{"203.0.113.5:3389", "203.0.113.5", "public.example:3389"}
	deny := []string{"127.0.0.1:3389", "10.0.0.5:3389", "[::1]:3389", "[fc00::1]:3389",
		"169.254.169.254:80", "203.0.113.5:22", "internal.corp:3389", "unknown.example:3389",
		"a b:3389", "host:0", "host:99999"}
	for _, h := range allow {
		if err := p.Allow(h); err != nil {
			t.Errorf("Allow(%q) = %s", h, err)
		}
	}
	for _, h := range deny {
		if err := p.Allow(h); err == nil {
			t.Errorf("Allow(%q) accepted", h)
		}
	}

	private := NewDestinationPolicy([]int{3389, 5985}, true)
	if err := private.Allow("10.0.0.1:5985"); err != nil {
		t.Errorf("opt-in policy rejected private destination: %s", err)
	}
}

func TestUserHostPolicy(t *testing.T) {
	fakeDNS(t, map[string][]string{
		"inside.lab":  {"10.20.1.1"},
		"outside.lab": {"10.20.1.1", "8.8.8.8"},
	})
	p, err := NewUserHostPolicy([]string{
		"*.corp.local",
		"jump.corp.local:2222",
		"10.20.0.0/16:3389",
		"[fd00::/8]:3389",
		"rdp-*.lab:*",
	}, []int{3389})
	if err != nil {
		t.Fatal(err)
	}
	allow := []string{"pc1.corp.local:3389", "PC1.Corp.Local", "jump.corp.local:2222",
		"10.20.3.4:3389", "inside.lab:3389", "[fd00::1]:3389", "rdp-7.lab:40000"}
	deny := []string{"pc1.corp.local:22", "corp.local.evil.com:3389", "10.21.0.1:3389",
		"outside.lab:3389", "[fe80::1]:3389", "rdp-7.lab/x:1", "10.20.3.4:3390"}
	for _, h := range allow {
		if err := p.Allow(h); err != nil {
			t.Errorf("Allow(%q) = %s", h, err)
		}
	}
	for _, h := range deny {
		if err := p.Allow(h); err == nil {
			t.Errorf("Allow(%q) accepted", h)
		}
	}

	for _, bad := range []string{"*", "[fd00::/8", "10.0.0.0/33", "host:70000", "a[:3389"} {
		if _, err := NewUserHostPolicy([]string{bad}, nil); err == nil {
			t.Errorf("pattern %q accepted", bad)
		}
	}
	if p, _ := NewUserHostPolicy(nil, nil); p != nil {
		t.Error("empty pattern list should disable user hosts")
	}
}

func TestPolicySelectAndAuthorize(t *testing.T) {
	entries := []Entry{
		{ID: "shared", Address: "shared:3389"},
		{ID: "fin", Address: "fin:3389", Groups: []string{"finance"}},
	}
	alice := Subject{UserName: "alice", Groups: []string{"finance"}}
	bob := Subject{UserName: "bob"}

	rr, err := NewPolicy(Config{Selection: SelectionRoundRobin, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if h, err := rr.Select(bob, "", nil); err != nil || h != "shared:3389" {
			t.Fatalf("roundrobin for bob picked %q, %v", h, err)
		}
	}
	if err := rr.Authorize(bob, "fin:3389"); err == nil {
		t.Error("gateway allowed bob to reach a group restricted host")
	}
	if err := rr.Authorize(alice, "fin:3389"); err != nil {
		t.Errorf("gateway rejected alice: %s", err)
	}
	if err := rr.Authorize(Subject{}, "shared:3389"); err == nil {
		t.Error("gateway allowed a tunnel without a user")
	}

	un, err := NewPolicy(Config{Selection: SelectionUnsigned, Entries: entries,
		UserHostPatterns: []string{"*.lab"}})
	if err != nil {
		t.Fatal(err)
	}
	if h, err := un.Select(alice, "fin", nil); err != nil || h != "fin:3389" {
		t.Errorf("select by id: %q %v", h, err)
	}
	if _, err := un.Select(bob, "fin", nil); err == nil {
		t.Error("bob selected a group restricted host")
	}
	if h, err := un.Select(bob, "pc.lab:3389", nil); err != nil || h != "pc.lab:3389" {
		t.Errorf("user host: %q %v", h, err)
	}
	if _, err := un.Select(bob, "pc.other:3389", nil); err == nil {
		t.Error("user host outside the patterns accepted")
	}
	if err := un.Authorize(bob, "pc.lab:3389"); err != nil {
		t.Errorf("gateway rejected a pattern-matching user host: %s", err)
	}
	if _, err := un.Select(bob, "", nil); err == nil {
		t.Error("unsigned accepted a missing host")
	}

	signed, err := NewPolicy(Config{Selection: SelectionSigned, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(tok string) (string, error) {
		if tok == "good" {
			return "shared:3389", nil
		}
		return "", errors.New("bad token")
	}
	if h, err := signed.Select(bob, "good", verify); err != nil || h != "shared:3389" {
		t.Errorf("signed select: %q %v", h, err)
	}
	if _, err := signed.Select(bob, "bad", verify); err == nil {
		t.Error("signed accepted a bad token")
	}
	if err := signed.Authorize(bob, "shared:3389"); err == nil {
		t.Error("signed mode must not authorize tunnels without a PAA token")
	}
	if err := signed.AuthorizePinned("shared:3389"); err != nil {
		t.Errorf("pinned host rejected: %s", err)
	}

	anyMode, err := NewPolicy(Config{Selection: SelectionAny})
	if err != nil {
		t.Fatalf("any mode without entries: %s", err)
	}
	if err := anyMode.Authorize(bob, "127.0.0.1:3389"); err == nil {
		t.Error("gateway allowed loopback in any mode")
	}
	if err := anyMode.AuthorizePinned("10.0.0.1:3389"); err == nil {
		t.Error("pinned any-mode host skipped the destination policy")
	}
	if err := anyMode.Authorize(bob, "203.0.113.7:3389"); err != nil {
		t.Errorf("gateway rejected a public host in any mode: %s", err)
	}
}

func TestPolicyConfigErrors(t *testing.T) {
	if _, err := NewPolicy(Config{Selection: "bogus", Entries: []Entry{{Address: "a:1"}}}); err == nil {
		t.Error("unknown selection accepted")
	}
	if _, err := NewPolicy(Config{Selection: SelectionRoundRobin}); err == nil {
		t.Error("roundrobin without hosts accepted")
	}
	if _, err := NewPolicy(Config{Selection: SelectionRoundRobin, Entries: []Entry{{Address: "a:1"}},
		UserHostPatterns: []string{"*.lab"}}); err == nil {
		t.Error("user host patterns accepted outside unsigned mode")
	}
	if _, err := NewPolicy(Config{Selection: SelectionUnsigned, UserHostPatterns: []string{"*.lab"}}); err != nil {
		t.Errorf("unsigned with only user hosts rejected: %s", err)
	}
}

func TestHostsFileReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yaml")
	write := func(body string, mod time.Time) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Now().Add(-time.Hour)
	write("hosts:\n  - id: a\n    address: a:3389\n", t0)

	p, err := NewPolicy(Config{Selection: SelectionUnsigned, Entries: []Entry{{ID: "static", Address: "s:3389"}}, HostsFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.Catalog().Len() != 2 {
		t.Fatalf("want static + file entry, got %+v", p.Catalog().Entries())
	}

	if changed, err := p.ReloadIfChanged(); changed || err != nil {
		t.Fatalf("unchanged file reloaded: %v %v", changed, err)
	}

	write("Hosts:\n  - a:3389\n  - b:3389\n", t0.Add(time.Minute))
	if changed, err := p.ReloadIfChanged(); !changed || err != nil {
		t.Fatalf("changed file not reloaded: %v %v", changed, err)
	}
	if p.Catalog().Len() != 3 {
		t.Fatalf("after reload: %+v", p.Catalog().Entries())
	}

	// a broken file keeps the previous catalog
	write("hosts:\n  - id: 'bad id'\n    address: x:1\n", t0.Add(2*time.Minute))
	if _, err := p.ReloadIfChanged(); err == nil {
		t.Fatal("invalid hosts file accepted")
	}
	if p.Catalog().Len() != 3 {
		t.Fatalf("failed reload replaced the catalog: %+v", p.Catalog().Entries())
	}
	// ...and is reported once, not on every poll
	if changed, err := p.ReloadIfChanged(); changed || err != nil {
		t.Fatalf("unchanged broken file retried: %v %v", changed, err)
	}
}
