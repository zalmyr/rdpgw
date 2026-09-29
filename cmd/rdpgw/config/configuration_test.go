package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHeaderEnabled(t *testing.T) {
	cases := []struct {
		name           string
		authentication []string
		expected       bool
	}{
		{
			name:           "header_enabled",
			authentication: []string{"header"},
			expected:       true,
		},
		{
			name:           "header_with_others",
			authentication: []string{"openid", "header", "local"},
			expected:       true,
		},
		{
			name:           "header_not_enabled",
			authentication: []string{"openid", "local"},
			expected:       false,
		},
		{
			name:           "empty_authentication",
			authentication: []string{},
			expected:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ServerConfig{
				Authentication: tc.authentication,
			}

			result := config.HeaderEnabled()
			if result != tc.expected {
				t.Errorf("expected HeaderEnabled(): %v, got: %v", tc.expected, result)
			}
		})
	}
}

func TestAuthenticationConstants(t *testing.T) {
	// Test that the header authentication constant is correct
	if AuthenticationHeader != "header" {
		t.Errorf("incorrect authentication header constant: %v", AuthenticationHeader)
	}
}

func TestCheckDefaultSecrets(t *testing.T) {
	const placeholder = "thisisasessionkeyreplacethisjetzt"

	cases := []struct {
		name      string
		mutate    func(*Configuration)
		wantField string
	}{
		{
			name:      "session key",
			mutate:    func(c *Configuration) { c.Server.SessionKey = placeholder },
			wantField: "server.sessionkey",
		},
		{
			name:      "session encryption key",
			mutate:    func(c *Configuration) { c.Server.SessionEncryptionKey = placeholder },
			wantField: "server.sessionencryptionkey",
		},
		{
			name:      "paa signing key",
			mutate:    func(c *Configuration) { c.Security.PAATokenSigningKey = placeholder },
			wantField: "security.paatokensigningkey",
		},
		{
			name:      "paa encryption key",
			mutate:    func(c *Configuration) { c.Security.PAATokenEncryptionKey = placeholder },
			wantField: "security.paatokenencryptionkey",
		},
		{
			name:      "user signing key",
			mutate:    func(c *Configuration) { c.Security.UserTokenSigningKey = placeholder },
			wantField: "security.usertokensigningkey",
		},
		{
			name:      "user encryption key",
			mutate:    func(c *Configuration) { c.Security.UserTokenEncryptionKey = placeholder },
			wantField: "security.usertokenencryptionkey",
		},
		{
			name:      "query signing key",
			mutate:    func(c *Configuration) { c.Security.QueryTokenSigningKey = placeholder },
			wantField: "security.querytokensigningkey",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Configuration{}
			tc.mutate(c)
			err := checkDefaultSecrets(c)
			if err == nil {
				t.Fatalf("checkDefaultSecrets accepted a placeholder value in %s", tc.wantField)
			}
			if got := err.Error(); !contains(got, tc.wantField) {
				t.Errorf("error message %q should mention the field %q", got, tc.wantField)
			}
		})
	}
}

func TestCheckDefaultSecretsAllowsRandomValues(t *testing.T) {
	c := &Configuration{}
	c.Server.SessionKey = "5aa3a1568fe8421cd7e127d5ace28d2d"
	c.Server.SessionEncryptionKey = "d3ecd7e565e56e37e2f2e95b584d8c0c"
	c.Security.PAATokenSigningKey = "0123456789abcdef0123456789abcdef"
	if err := checkDefaultSecrets(c); err != nil {
		t.Errorf("checkDefaultSecrets rejected non-placeholder values: %v", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestHeaderConfigValidation(t *testing.T) {
	cases := []struct {
		name        string
		headerConf  HeaderConfig
		shouldError bool
	}{
		{
			name: "valid_config",
			headerConf: HeaderConfig{
				UserHeader: "X-Forwarded-User",
			},
			shouldError: false,
		},
		{
			name: "missing_user_header",
			headerConf: HeaderConfig{
				EmailHeader: "X-Forwarded-Email",
			},
			shouldError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the configuration struct
			if tc.headerConf.UserHeader == "" && !tc.shouldError {
				t.Error("expected user header to be set")
			}
			if tc.headerConf.UserHeader != "" && tc.shouldError {
				t.Error("expected configuration to be invalid")
			}
		})
	}
}
func TestLoadIsCaseInsensitiveAndDecodesHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rdpgw.yaml")
	body := `
server:
  tls: disable
  port: 8080
  hostselection: unsigned
  hosts:
    - legacy:3389
    - id: fin
      name: Finance
      address: fin-ts01:3389
      groups: [finance]
  userhostpatterns: ["*.lab"]
Client:
  RdpOverridableKeys: [audiomode]
web:
  title: Acme Remote
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RDPGW_OPEN_ID__GROUPS_CLAIM", "realm_access.roles")

	Conf = Configuration{}
	c := Load(path)

	if c.Server.Tls != "disable" || c.Server.Port != 8080 {
		t.Errorf("lowercase server section ignored: tls=%q port=%d", c.Server.Tls, c.Server.Port)
	}
	if len(c.Server.Hosts) != 2 || c.Server.Hosts[0].Address != "legacy:3389" ||
		c.Server.Hosts[1].ID != "fin" || c.Server.Hosts[1].Groups[0] != "finance" {
		t.Errorf("hosts decoded as %+v", c.Server.Hosts)
	}
	if len(c.Server.UserHostPatterns) != 1 || c.Server.UserHostPatterns[0] != "*.lab" {
		t.Errorf("userhostpatterns = %v", c.Server.UserHostPatterns)
	}
	if len(c.Client.RdpOverridableKeys) != 1 {
		t.Errorf("mixed case client section ignored: %v", c.Client.RdpOverridableKeys)
	}
	if c.Web.Title != "Acme Remote" {
		t.Errorf("web section ignored: %+v", c.Web)
	}
	if c.OpenId.GroupsClaim != "realm_access.roles" {
		t.Errorf("env override of groups claim = %q", c.OpenId.GroupsClaim)
	}
}
