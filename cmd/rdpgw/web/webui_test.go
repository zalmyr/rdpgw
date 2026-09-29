package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

func authedRequest(method, target, user string, groups ...string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	id := identity.NewUser()
	id.SetUserName(user)
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now())
	id.SetGroups(groups)
	id.SetAttribute(identity.AttrClientIp, "192.0.2.10")
	return identity.AddToRequestCtx(id, req)
}

func catalogHandler(t *testing.T, cfg hosts.Config) *Handler {
	t.Helper()
	p, err := hosts.NewPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{
		policy:         p,
		gatewayAddress: &url.URL{Host: "gateway.example.com"},
		paaTokenGenerator: func(ctx context.Context, user, host string) (string, error) {
			return "token-for-" + host, nil
		},
	}
}

var catalogEntries = []hosts.Entry{
	{ID: "shared", Name: "Shared desktop", Address: "shared.corp:3389"},
	{ID: "fin", Name: "Finance", Address: "fin.corp:3389", Groups: []string{"finance"}, Default: true},
	{ID: "vm", Name: "{{ user }}'s VM", Address: "vm-{{ user }}.corp:3389"},
}

func hostList(t *testing.T, h *Handler, user string, groups ...string) []Host {
	t.Helper()
	w := httptest.NewRecorder()
	h.HandleHostList(w, authedRequest("GET", "/api/v1/hosts", user, groups...))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out []Host
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHostListIsPerUser(t *testing.T) {
	h := catalogHandler(t, hosts.Config{Selection: hosts.SelectionUnsigned, Entries: catalogEntries})

	alice := hostList(t, h, "alice@corp", "finance")
	if len(alice) != 3 {
		t.Fatalf("alice sees %+v", alice)
	}
	byID := map[string]Host{}
	for _, x := range alice {
		byID[x.ID] = x
	}
	if byID["vm"].Name != "alice's VM" || byID["vm"].Address != "vm-alice.corp:3389" {
		t.Errorf("templated entry not expanded: %+v", byID["vm"])
	}
	if byID["fin"].ConnectURL != "/connect?host=fin" || !byID["fin"].IsDefault {
		t.Errorf("fin entry: %+v", byID["fin"])
	}

	bob := hostList(t, h, "bob@corp")
	for _, x := range bob {
		if x.ID == "fin" {
			t.Errorf("bob can see the finance host")
		}
	}
	if len(bob) != 2 || !bob[0].IsDefault {
		t.Errorf("bob sees %+v", bob)
	}
}

func TestConnectByIDRespectsAccessRules(t *testing.T) {
	h := catalogHandler(t, hosts.Config{Selection: hosts.SelectionUnsigned, Entries: catalogEntries})

	w := httptest.NewRecorder()
	h.HandleDownload(w, authedRequest("GET", "/connect?host=fin", "alice", "finance"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "full address:s:fin.corp:3389") {
		t.Fatalf("alice could not connect to fin: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "token-for-fin.corp:3389") {
		t.Errorf("PAA token not pinned to the resolved host")
	}

	w = httptest.NewRecorder()
	h.HandleDownload(w, authedRequest("GET", "/connect?host=fin", "bob"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bob connected to fin: %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.HandleDownload(w, authedRequest("GET", "/connect?host=vm", "carol@corp"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "full address:s:vm-carol.corp:3389") {
		t.Fatalf("templated host: %d %s", w.Code, w.Body.String())
	}
}

func TestSettings(t *testing.T) {
	cases := []struct {
		cfg     hosts.Config
		custom  bool
		message bool
	}{
		{hosts.Config{Selection: hosts.SelectionRoundRobin, Entries: catalogEntries}, false, false},
		{hosts.Config{Selection: hosts.SelectionUnsigned, Entries: catalogEntries}, false, false},
		{hosts.Config{Selection: hosts.SelectionUnsigned, Entries: catalogEntries, UserHostPatterns: []string{"*.lab"}}, true, false},
		{hosts.Config{Selection: hosts.SelectionAny}, true, false},
		{hosts.Config{Selection: hosts.SelectionSigned, Entries: catalogEntries}, false, true},
	}
	for _, tc := range cases {
		h := catalogHandler(t, tc.cfg)
		w := httptest.NewRecorder()
		h.HandleSettings(w, authedRequest("GET", "/api/v1/settings", "alice"))
		var s Settings
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		if s.HostSelection != tc.cfg.Selection || s.AllowCustomHost != tc.custom || (s.Message != "") != tc.message {
			t.Errorf("%+v: settings %+v", tc.cfg, s)
		}
	}

	w := httptest.NewRecorder()
	h := catalogHandler(t, hosts.Config{Selection: hosts.SelectionAny})
	h.HandleSettings(w, httptest.NewRequest("GET", "/api/v1/settings", nil).WithContext(
		context.WithValue(context.Background(), identity.CTXKey, identity.NewUser())))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated settings request: %d", w.Code)
	}
}

func TestRoundRobinListHidesUnavailable(t *testing.T) {
	h := catalogHandler(t, hosts.Config{Selection: hosts.SelectionRoundRobin, Entries: []hosts.Entry{
		{Address: "fin.corp:3389", Groups: []string{"finance"}},
	}})
	if got := hostList(t, h, "bob"); len(got) != 0 {
		t.Errorf("bob has no hosts but got %+v", got)
	}
	got := hostList(t, h, "alice", "finance")
	if len(got) != 1 || got[0].ConnectURL != "/connect" {
		t.Errorf("alice: %+v", got)
	}
}

func TestStaticHandlerAndTemplateOverride(t *testing.T) {
	builtin := fstest.MapFS{
		"index.html": {Data: []byte(`<title>{{.Title}}</title><style>:root{--primary: {{.PrimaryColor}}}</style>`)},
		"style.css":  {Data: []byte("builtin-css")},
		"app.js":     {Data: []byte("builtin-js")},
		"README.md":  {Data: []byte("docs")},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("custom-css"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Config{
		HostPolicy:    mustPolicy(t, "roundrobin", "a:3389"),
		Templates:     builtin,
		TemplatesPath: dir,
		Web:           WebConfig{Title: "Acme", PrimaryColor: "#123456"},
	}
	h := c.NewHandler()
	static := h.StaticHandler("/static/")

	get := func(p string) (int, string) {
		w := httptest.NewRecorder()
		static.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		return w.Code, w.Body.String()
	}
	if code, body := get("/static/style.css"); code != 200 || body != "custom-css" {
		t.Errorf("override not served: %d %q", code, body)
	}
	if code, body := get("/static/app.js"); code != 200 || body != "builtin-js" {
		t.Errorf("builtin not served: %d %q", code, body)
	}
	for _, p := range []string{"/static/README.md", "/static/index.html", "/static/../web.go", "/static/"} {
		if code, _ := get(p); code != http.StatusNotFound {
			t.Errorf("%s served with %d", p, code)
		}
	}

	w := httptest.NewRecorder()
	h.HandleWebInterface(w, authedRequest("GET", "/", "alice"))
	body := w.Body.String()
	if !strings.Contains(body, "<title>Acme</title>") || !strings.Contains(body, "--primary: #123456") {
		t.Errorf("branding not applied: %s", body)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing framing protection")
	}

	bad := WebConfig{PrimaryColor: "red;} body{display:none"}.withDefaults()
	if bad.PrimaryColor != "" {
		t.Errorf("unsafe color accepted: %q", bad.PrimaryColor)
	}
}

func TestGroupExtraction(t *testing.T) {
	claims := map[string]interface{}{
		"groups":       []interface{}{"finance", "staff", 7},
		"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}},
		"single":       "a, b",
	}
	if got := groupsFromClaim(claimValue(claims, "groups")); len(got) != 2 {
		t.Errorf("groups claim: %v", got)
	}
	if got := groupsFromClaim(claimValue(claims, "realm_access.roles")); len(got) != 1 || got[0] != "admin" {
		t.Errorf("nested claim: %v", got)
	}
	if got := groupsFromClaim(claimValue(claims, "single")); len(got) != 2 || got[1] != "b" {
		t.Errorf("string claim: %v", got)
	}
	if got := groupsFromClaim(claimValue(claims, "missing.path")); got != nil {
		t.Errorf("missing claim: %v", got)
	}

	keep := func(g string) bool { return g == "finance" }
	if got := filterGroups("u", []string{"finance", "staff"}, keep); len(got) != 1 {
		t.Errorf("filter: %v", got)
	}
	many := make([]string, 200)
	for i := range many {
		many[i] = "g" + string(rune('a'+i%26)) + strings.Repeat("x", i)
	}
	if got := filterGroups("u", many, nil); len(got) != maxSessionGroups {
		t.Errorf("cap: %d", len(got))
	}
}

func TestHeaderAuthSetsGroups(t *testing.T) {
	cfg := &HeaderConfig{
		UserHeader:     "X-User",
		GroupsHeader:   "X-Groups",
		TrustedProxies: []string{"192.0.2.0/24"},
		KeepGroup:      func(g string) bool { return g != "ignored" },
	}
	InitStore([]byte("0123456789abcdef0123456789abcdef"), []byte("0123456789abcdef0123456789abcdef"), "cookie", 0)

	var seen []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = identity.FromRequestCtx(r).Groups()
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-User", "alice")
	req.Header.Set("X-Groups", "finance, ignored ,staff")
	req = identity.AddToRequestCtx(identity.NewUser(), req)

	cfg.New().Authenticated(next).ServeHTTP(httptest.NewRecorder(), req)
	if strings.Join(seen, ",") != "finance,staff" {
		t.Errorf("groups = %v", seen)
	}
}
