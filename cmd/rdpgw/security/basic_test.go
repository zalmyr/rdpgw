package security

import (
	"context"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
)

var (
	info = protocol.Tunnel{
		RDGId:        "myid",
		TargetServer: "my.remote.server",
		RemoteAddr:   "10.0.0.1",
	}

	hostEntries = []hosts.Entry{
		{Address: "localhost:3389"},
		{Address: "my-{{ preferred_username }}-host:3389"},
		{Address: "finance:3389", Groups: []string{"finance"}},
	}
)

func usePolicy(t *testing.T, selection string) {
	t.Helper()
	p, err := hosts.NewPolicy(hosts.Config{Selection: selection, Entries: hostEntries})
	if err != nil {
		t.Fatal(err)
	}
	orig := HostPolicy
	HostPolicy = p
	t.Cleanup(func() { HostPolicy = orig })
}

func TestCheckHost(t *testing.T) {
	info.User = identity.NewUser()
	info.User.SetUserName("MYNAME")

	ctx := context.WithValue(context.Background(), protocol.CtxTunnel, &info)

	// any: public destinations only, even without a PAA token
	usePolicy(t, hosts.SelectionAny)
	if ok, err := CheckHost(ctx, "203.0.113.5:3389"); !ok {
		t.Fatalf("public host should be allowed in any mode (err: %s)", err)
	}
	for _, h := range []string{"127.0.0.1:3389", "10.0.0.1:3389", "203.0.113.5:22"} {
		if ok, _ := CheckHost(ctx, h); ok {
			t.Fatalf("%s must be refused at the gateway in any mode", h)
		}
	}

	usePolicy(t, hosts.SelectionSigned)
	if ok, err := CheckHost(ctx, "localhost:3389"); ok || err == nil {
		t.Fatalf("signed host selection requires a PAA token")
	}

	usePolicy(t, hosts.SelectionRoundRobin)
	if ok, err := CheckHost(ctx, "try.my.server:3389"); ok {
		t.Fatalf("unlisted host should NOT be allowed (err: %s)", err)
	}
	if ok, err := CheckHost(ctx, "my-MYNAME-host:3389"); !ok {
		t.Fatalf("templated host should be allowed (err: %s)", err)
	}
	if ok, _ := CheckHost(ctx, "finance:3389"); ok {
		t.Fatalf("group restricted host allowed for a non-member")
	}
	info.User.SetGroups([]string{"finance"})
	if ok, err := CheckHost(ctx, "finance:3389"); !ok {
		t.Fatalf("group restricted host refused for a member (err: %s)", err)
	}
}

func TestCheckPinnedHost(t *testing.T) {
	ctx := context.Background()

	usePolicy(t, hosts.SelectionSigned)
	if ok, err := CheckPinnedHost(ctx, "localhost:3389"); !ok {
		t.Fatalf("pinned host refused in signed mode: %s", err)
	}

	usePolicy(t, hosts.SelectionAny)
	if ok, _ := CheckPinnedHost(ctx, "127.0.0.1:3389"); ok {
		t.Fatalf("pinned host skipped the any-mode destination policy")
	}
}
