package identity

import (
	"log"
	"testing"
)

func TestMarshalling(t *testing.T) {
	u := NewUser()
	u.SetUserName("ANAME")
	u.SetAuthenticated(true)
	u.SetDomain("DOMAIN")

	c := NewUser()
	data, err := u.Marshal()
	if err != nil {
		log.Fatalf("Cannot marshal %s", err)
	}

	err = c.Unmarshal(data)
	if err != nil {
		t.Fatalf("Error while unmarshalling: %s", err)
	}

	if u.UserName() != c.UserName() || u.Authenticated() != c.Authenticated() || u.Domain() != c.Domain() {
		t.Fatalf("identities not equal: %+v != %+v", u, c)
	}
}

func TestGroupsSurviveMarshalling(t *testing.T) {
	u := NewUser()
	u.SetGroups([]string{"finance", "admins", ""})

	data, err := u.Marshal()
	if err != nil {
		t.Fatalf("Cannot marshal %s", err)
	}
	c := NewUser()
	if err := c.Unmarshal(data); err != nil {
		t.Fatalf("Error while unmarshalling: %s", err)
	}

	got := c.Groups()
	if len(got) != 2 || got[0] != "admins" || got[1] != "finance" {
		t.Fatalf("Groups() = %v, want [admins finance]", got)
	}
}
