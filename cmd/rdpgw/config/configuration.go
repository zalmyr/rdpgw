package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// knownDefaultSecrets is the list of placeholder session/token-key values
// that appear in README.md and the dev compose files. Operators that
// copy-paste the examples into a real deployment would be running with
// widely-published keys, so the gateway refuses to start when one of these
// is set for any of the session-/token-binding fields.
var knownDefaultSecrets = []string{
	"thisisasessionkeyreplacethisjetzt",
	"thisisasessionkeyreplacethisjetz",
	"thisisasessionkeyreplacethisnunu!",
	"thisisasessionkeyreplacethisnunu",
	"thisisasessionencryptionkey12345",
}

func checkDefaultSecrets(c *Configuration) error {
	fields := []struct {
		name  string
		value string
	}{
		{"server.sessionkey", c.Server.SessionKey},
		{"server.sessionencryptionkey", c.Server.SessionEncryptionKey},
		{"security.paatokensigningkey", c.Security.PAATokenSigningKey},
		{"security.paatokenencryptionkey", c.Security.PAATokenEncryptionKey},
		{"security.usertokensigningkey", c.Security.UserTokenSigningKey},
		{"security.usertokenencryptionkey", c.Security.UserTokenEncryptionKey},
		{"security.querytokensigningkey", c.Security.QueryTokenSigningKey},
	}
	for _, f := range fields {
		if f.value == "" {
			continue
		}
		for _, def := range knownDefaultSecrets {
			if f.value == def {
				return fmt.Errorf("%s is set to a known placeholder value (%q); replace it with a unique secret before starting", f.name, def)
			}
		}
	}
	return nil
}

const (
	TlsDisable = "disable"
	TlsAuto    = "auto"

	HostSelectionSigned     = "signed"
	HostSelectionRoundRobin = "roundrobin"

	SessionStoreCookie = "cookie"
	SessionStoreFile   = "file"

	AuthenticationOpenId   = "openid"
	AuthenticationBasic    = "local"
	AuthenticationKerberos = "kerberos"
	AuthenticationHeader   = "header"
)

type Configuration struct {
	Server   ServerConfig   `koanf:"server"`
	OpenId   OpenIDConfig   `koanf:"openid"`
	Kerberos KerberosConfig `koanf:"kerberos"`
	Header   HeaderConfig   `koanf:"header"`
	Caps     RDGCapsConfig  `koanf:"caps"`
	Security SecurityConfig `koanf:"security"`
	Client   ClientConfig   `koanf:"client"`
	Web      WebConfig      `koanf:"web"`
}

type ServerConfig struct {
	GatewayAddress string `koanf:"gatewayaddress"`
	Port           int    `koanf:"port"`
	BindAddress    string `koanf:"bindaddress"`
	CertFile       string `koanf:"certfile"`
	KeyFile        string `koanf:"keyfile"`
	// Hosts lists the destinations users may connect to, either as
	// "host:port" strings or as mappings with id/name/address/groups/users;
	// see hosts.Entry.
	Hosts []hosts.Entry `koanf:"hosts"`
	// HostsFile is an optional YAML file with more entries under a
	// top-level `hosts:` key. It is re-read on SIGHUP and when it changes.
	HostsFile            string   `koanf:"hostsfile"`
	HostSelection        string   `koanf:"hostselection"`
	SessionKey           string   `koanf:"sessionkey"`
	SessionEncryptionKey string   `koanf:"sessionencryptionkey"`
	SessionStore         string   `koanf:"sessionstore"`
	MaxSessionLength     int      `koanf:"maxsessionlength"`
	SendBuf              int      `koanf:"sendbuf"`
	ReceiveBuf           int      `koanf:"receivebuf"`
	Tls                  string   `koanf:"tls"`
	Authentication       []string `koanf:"authentication"`
	AuthSocket           string   `koanf:"authsocket"`
	BasicAuthTimeout     int      `koanf:"basicauthtimeout"`
	// AllowedDestinationPorts gates the TCP ports `hostselection: any` may
	// forward to. Empty defaults to {3389}. Ignored for the curated host
	// modes (roundrobin, signed, unsigned).
	AllowedDestinationPorts []int `koanf:"alloweddestinationports"`
	// AllowPrivateDestinations, when true, lets `hostselection: any`
	// forward to loopback, RFC1918, link-local, and IPv6 ULA targets.
	// Default false.
	AllowPrivateDestinations bool `koanf:"allowprivatedestinations"`
	// TrustedProxies is the CIDR allow-list of upstream proxies whose
	// X-Forwarded-For header is honored when deriving the client IP.
	// Empty (the default) makes the gateway ignore X-Forwarded-For
	// entirely and use r.RemoteAddr.
	TrustedProxies []string `koanf:"trustedproxies"`
	// UserHostPatterns lets users type in their own destination when
	// HostSelection is unsigned, as long as it matches one of these
	// patterns (e.g. "*.corp.local:3389", "10.20.0.0/16"). Empty disables
	// user supplied hosts.
	UserHostPatterns []string `koanf:"userhostpatterns"`
}

type KerberosConfig struct {
	Keytab   string `koanf:"keytab"`
	Krb5Conf string `koanf:"krb5conf"`
}

type OpenIDConfig struct {
	ProviderUrl  string `koanf:"providerurl"`
	ClientId     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
	// GroupsClaim is the ID token claim with the user's groups, used by
	// group restricted hosts. Nested claims use dots: realm_access.roles.
	GroupsClaim string `koanf:"groupsclaim"`
}

type HeaderConfig struct {
	UserHeader        string `koanf:"userheader"`
	UserIdHeader      string `koanf:"useridheader"`
	EmailHeader       string `koanf:"emailheader"`
	DisplayNameHeader string `koanf:"displaynameheader"`
	// GroupsHeader carries a comma separated list of the user's groups.
	GroupsHeader string `koanf:"groupsheader"`
	// TrustedProxies is the CIDR allow-list of upstream proxies allowed to
	// stamp UserHeader (and friends). Empty disables header auth at runtime.
	TrustedProxies []string `koanf:"trustedproxies"`
}

type RDGCapsConfig struct {
	SmartCardAuth   bool `koanf:"smartcardauth"`
	TokenAuth       bool `koanf:"tokenauth"`
	IdleTimeout     int  `koanf:"idletimeout"`
	RedirectAll     bool `koanf:"redirectall"`
	DisableRedirect bool `koanf:"disableredirect"`
	EnableClipboard bool `koanf:"enableclipboard"`
	EnablePrinter   bool `koanf:"enableprinter"`
	EnablePort      bool `koanf:"enableport"`
	EnablePnp       bool `koanf:"enablepnp"`
	EnableDrive     bool `koanf:"enabledrive"`
}

type SecurityConfig struct {
	PAATokenEncryptionKey  string `koanf:"paatokenencryptionkey"`
	PAATokenSigningKey     string `koanf:"paatokensigningkey"`
	UserTokenEncryptionKey string `koanf:"usertokenencryptionkey"`
	UserTokenSigningKey    string `koanf:"usertokensigningkey"`
	QueryTokenSigningKey   string `koanf:"querytokensigningkey"`
	QueryTokenIssuer       string `koanf:"querytokenissuer"`
	VerifyClientIp         bool   `koanf:"verifyclientip"`
	EnableUserToken        bool   `koanf:"enableusertoken"`
}

type ClientConfig struct {
	Defaults string `koanf:"defaults"`
	// kept for backwards compatibility
	UsernameTemplate string `koanf:"usernametemplate"`
	SplitUserDomain  bool   `koanf:"splituserdomain"`
	NoUsername       bool   `koanf:"nousername"`
	SigningCert      string `koanf:"signingcert"`
	SigningKey       string `koanf:"signingkey"`
	// RdpOverridableKeys is the operator allow-list of RDP setting keys that
	// the /connect endpoint may override from URL query parameters. Empty
	// disables URL-based overrides. Entries are normalized (lowercase, no
	// whitespace), so "use multimon" and "usemultimon" are equivalent.
	RdpOverridableKeys []string `koanf:"rdpoverridablekeys"`
}

// WebConfig customizes the browser interface.
type WebConfig struct {
	// TemplatesPath is a directory whose files (index.html, style.css,
	// app.js, images) override the built-in web interface.
	TemplatesPath       string `koanf:"templatespath"`
	Title               string `koanf:"title"`
	Logo                string `koanf:"logo"`
	PageTitle           string `koanf:"pagetitle"`
	SelectServerMessage string `koanf:"selectservermessage"`
	PreparingMessage    string `koanf:"preparingmessage"`
	PrimaryColor        string `koanf:"primarycolor"`
}

func ToCamel(s string) string {
	s = strings.TrimSpace(s)
	n := strings.Builder{}
	n.Grow(len(s))
	var capNext bool = true
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_' || v == ' ' || v == '-' || v == '.'
			if v == '.' {
				n.WriteByte(v)
			}
		}
	}
	return n.String()
}

var Conf Configuration

// mergeLower loads a provider and merges its keys, lowercased, into dst.
// Struct tags are lowercase and mapstructure only matches case-insensitively
// within a section, so without this a `server:` section in YAML and the
// `Server.*` defaults would live side by side and `server:` be ignored.
func mergeLower(dst *koanf.Koanf, p koanf.Provider, pa koanf.Parser) error {
	tmp := koanf.New(".")
	if err := tmp.Load(p, pa); err != nil {
		return err
	}
	for key, val := range tmp.All() {
		if err := dst.Set(strings.ToLower(key), val); err != nil {
			return err
		}
	}
	return nil
}

func Load(configFile string) Configuration {

	var k = koanf.New(".")

	mergeLower(k, confmap.Provider(map[string]interface{}{
		"Server.Tls":                 "auto",
		"Server.Port":                443,
		"Server.BindAddress":         "",
		"Server.SessionStore":        "cookie",
		"Server.HostSelection":       "roundrobin",
		"Server.Authentication":      "openid",
		"Server.AuthSocket":          "/tmp/rdpgw-auth.sock",
		"Server.BasicAuthTimeout":    5,
		"Client.NetworkAutoDetect":   1,
		"Client.BandwidthAutoDetect": 1,
		"Security.VerifyClientIp":    true,
		"Caps.TokenAuth":             true,
		"OpenId.GroupsClaim":         "groups",
	}, "."), nil)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Config file %s not found, using defaults and environment", configFile)
	} else {
		if err := mergeLower(k, file.Provider(configFile), yaml.Parser()); err != nil {
			log.Fatalf("Error loading config from file: %v", err)
		}
	}

	if err := mergeLower(k, env.ProviderWithValue("RDPGW_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "RDPGW_")), "__", ".", -1)
		key = ToCamel(key)

		v = strings.Trim(v, " ")

		// handle lists
		if strings.Contains(v, " ") {
			return key, strings.Split(v, " ")
		}
		return key, v

	}), nil); err != nil {
		log.Fatalf("Error loading config from environment: %v", err)
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	for section, dst := range map[string]interface{}{
		"server":   &Conf.Server,
		"openid":   &Conf.OpenId,
		"header":   &Conf.Header,
		"caps":     &Conf.Caps,
		"security": &Conf.Security,
		"client":   &Conf.Client,
		"kerberos": &Conf.Kerberos,
		"web":      &Conf.Web,
	} {
		if err := k.UnmarshalWithConf(section, dst, koanfTag); err != nil {
			log.Fatalf("Invalid configuration in section %s: %s", section, err)
		}
	}

	if err := checkDefaultSecrets(&Conf); err != nil {
		log.Fatalf("refusing to start: %s", err)
	}

	if len(Conf.Security.PAATokenEncryptionKey) != 32 {
		Conf.Security.PAATokenEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokenencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Security.PAATokenSigningKey) != 32 {
		Conf.Security.PAATokenSigningKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokensigningkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Security.EnableUserToken {
		if len(Conf.Security.UserTokenEncryptionKey) != 32 {
			Conf.Security.UserTokenEncryptionKey, _ = security.GenerateRandomString(32)
			log.Printf("No valid `security.usertokenencryptionkey` specified (empty or not 32 characters). Setting to random")
		}
	}

	if len(Conf.Server.SessionKey) != 32 {
		Conf.Server.SessionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Server.SessionEncryptionKey) != 32 {
		Conf.Server.SessionEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Server.HostSelection == "signed" && len(Conf.Security.QueryTokenSigningKey) == 0 {
		log.Fatalf("host selection is set to `signed` but `querytokensigningkey` is not set")
	}

	if Conf.Server.HostSelection == "signed" && !Conf.Caps.TokenAuth {
		log.Fatalf("host selection `signed` requires caps.tokenauth: the gateway can only verify signed hosts through the PAA token")
	}

	if Conf.Server.BasicAuthEnabled() && Conf.Server.Tls == "disable" {
		log.Fatalf("basicauth=local and tls=disable are mutually exclusive")
	}

	if Conf.Server.NtlmEnabled() && Conf.Server.KerberosEnabled() {
		log.Fatalf("ntlm and kerberos authentication are not stackable")
	}

	if !Conf.Caps.TokenAuth && Conf.Server.OpenIDEnabled() {
		log.Fatalf("openid is configured but tokenauth disabled")
	}

	if Conf.Server.KerberosEnabled() && Conf.Kerberos.Keytab == "" {
		log.Fatalf("kerberos is configured but no keytab was specified")
	}

	if Conf.Server.HeaderEnabled() && Conf.Header.UserHeader == "" {
		log.Fatalf("header authentication is configured but no user header was specified")
	}

	// prepend '//' if required for URL parsing
	if !strings.Contains(Conf.Server.GatewayAddress, "//") {
		Conf.Server.GatewayAddress = "//" + Conf.Server.GatewayAddress
	}

	return Conf
}

func (s *ServerConfig) OpenIDEnabled() bool {
	return s.matchAuth("openid")
}

func (s *ServerConfig) KerberosEnabled() bool {
	return s.matchAuth("kerberos")
}

func (s *ServerConfig) BasicAuthEnabled() bool {
	return s.matchAuth("local") || s.matchAuth("basic")
}

func (s *ServerConfig) NtlmEnabled() bool {
	return s.matchAuth("ntlm")
}

func (s *ServerConfig) HeaderEnabled() bool {
	return s.matchAuth("header")
}

func (s *ServerConfig) matchAuth(needle string) bool {
	for _, q := range s.Authentication {
		if q == needle {
			return true
		}
	}
	return false
}
