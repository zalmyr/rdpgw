package main

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bolkedebruin/gokrb5/v8/keytab"
	"github.com/bolkedebruin/gokrb5/v8/service"
	"github.com/bolkedebruin/gokrb5/v8/spnego"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/kdcproxy"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/web"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thought-machine/go-flags"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
)

const (
	gatewayEndPoint  = "/remoteDesktopGateway/"
	kdcProxyEndPoint = "/KdcProxy"
)

var opts struct {
	ConfigFile string `short:"c" long:"conf" default:"rdpgw.yaml" description:"config file (yaml)"`
}

var conf config.Configuration

// templates holds the built-in web interface (index.html, css, js, images).
//
//go:embed templates
var templates embed.FS

// hostsFilePollInterval is how often a configured hosts file is checked for
// changes, in addition to reloading it on SIGHUP.
const hostsFilePollInterval = 30 * time.Second

func listenAddress(bindAddress string, port int) string {
	return net.JoinHostPort(bindAddress, strconv.Itoa(port))
}

func initHostPolicy() *hosts.Policy {
	policy, err := hosts.NewPolicy(hosts.Config{
		Selection:                conf.Server.HostSelection,
		Entries:                  conf.Server.Hosts,
		HostsFile:                conf.Server.HostsFile,
		AllowedDestinationPorts:  conf.Server.AllowedDestinationPorts,
		AllowPrivateDestinations: conf.Server.AllowPrivateDestinations,
		UserHostPatterns:         conf.Server.UserHostPatterns,
	})
	if err != nil {
		log.Fatalf("Invalid host configuration: %s", err)
	}
	log.Printf("Host selection %s with %d configured hosts", policy.Selection(), policy.Catalog().Len())

	if conf.Server.HostsFile != "" {
		go policy.Watch(hostsFilePollInterval, nil)
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				if err := policy.Reload(); err != nil {
					log.Printf("hosts: keeping previous host list, reload of %s failed: %s", conf.Server.HostsFile, err)
				} else {
					log.Printf("hosts: reloaded %d entries on SIGHUP", policy.Catalog().Len())
				}
			}
		}()
	}
	return policy
}

func initOIDC(callbackUrl *url.URL, keepGroup web.GroupFilter) *web.OIDC {
	// set oidc config
	provider, err := oidc.NewProvider(context.Background(), conf.OpenId.ProviderUrl)
	if err != nil {
		log.Fatalf("Cannot get oidc provider: %s", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.OpenId.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID:     conf.OpenId.ClientId,
		ClientSecret: conf.OpenId.ClientSecret,
		RedirectURL:  callbackUrl.String(),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	security.OIDCProvider = provider
	security.Oauth2Config = oauthConfig

	o := web.OIDCConfig{
		OAuth2Config:      &oauthConfig,
		OIDCTokenVerifier: verifier,
		GroupsClaim:       conf.OpenId.GroupsClaim,
		KeepGroup:         keepGroup,
	}

	return o.New()
}

// builtinTemplates returns the embedded web interface files.
func builtinTemplates() fs.FS {
	sub, err := fs.Sub(templates, "templates")
	if err != nil {
		log.Fatalf("Cannot load built-in web interface: %s", err)
	}
	return sub
}

func main() {
	// load config
	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}
	conf = config.Load(opts.ConfigFile)

	// set callback url and external advertised gateway address
	url, err := url.Parse(conf.Server.GatewayAddress)
	if err != nil {
		log.Fatalf("Cannot parse server gateway address %s due to %s", conf.Server.GatewayAddress, err)
	}
	if url.Scheme == "" {
		url.Scheme = "https"
	}
	url.Path = "callback"

	// set security options
	security.VerifyClientIP = conf.Security.VerifyClientIp
	security.SigningKey = []byte(conf.Security.PAATokenSigningKey)
	security.EncryptionKey = []byte(conf.Security.PAATokenEncryptionKey)
	security.UserEncryptionKey = []byte(conf.Security.UserTokenEncryptionKey)
	security.UserSigningKey = []byte(conf.Security.UserTokenSigningKey)
	security.QuerySigningKey = []byte(conf.Security.QueryTokenSigningKey)
	policy := initHostPolicy()
	security.HostPolicy = policy
	// only keep groups in the session that some host entry refers to
	keepGroup := func(g string) bool { return policy.Catalog().ReferencesGroup(g) }

	// init session store
	web.InitStore([]byte(conf.Server.SessionKey),
		[]byte(conf.Server.SessionEncryptionKey),
		conf.Server.SessionStore,
		conf.Server.MaxSessionLength,
	)

	web.InitTrustedProxies(conf.Server.TrustedProxies)

	// configure web backend
	w := &web.Config{
		QueryInfo:        security.QueryInfo,
		QueryTokenIssuer: conf.Security.QueryTokenIssuer,
		EnableUserToken:  conf.Security.EnableUserToken,
		HostPolicy:       policy,
		RdpOpts: web.RdpOpts{
			UsernameTemplate:   conf.Client.UsernameTemplate,
			SplitUserDomain:    conf.Client.SplitUserDomain,
			NoUsername:         conf.Client.NoUsername,
			OverridableRdpKeys: conf.Client.RdpOverridableKeys,
		},
		GatewayAddress: url,
		TemplateFile:   conf.Client.Defaults,
		RdpSigningCert: conf.Client.SigningCert,
		RdpSigningKey:  conf.Client.SigningKey,
		TemplatesPath:  conf.Web.TemplatesPath,
		Templates:      builtinTemplates(),
		Web: web.WebConfig{
			Title:               conf.Web.Title,
			Logo:                conf.Web.Logo,
			PageTitle:           conf.Web.PageTitle,
			SelectServerMessage: conf.Web.SelectServerMessage,
			PreparingMessage:    conf.Web.PreparingMessage,
			PrimaryColor:        conf.Web.PrimaryColor,
		},
	}

	if conf.Caps.TokenAuth {
		w.PAATokenGenerator = security.GeneratePAAToken
	}
	if conf.Security.EnableUserToken {
		w.UserTokenGenerator = security.GenerateUserToken
	}
	h := w.NewHandler()

	log.Printf("Starting remote desktop gateway server")
	cfg := &tls.Config{}

	// configure tls security
	if conf.Server.Tls == config.TlsDisable {
		log.Printf("TLS disabled - rdp gw connections require tls, make sure to have a terminator")
	} else {
		// auto config
		tlsConfigured := false

		tlsDebug := os.Getenv("SSLKEYLOGFILE")
		if tlsDebug != "" {
			w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
			}
			log.Printf("Key log file set to: %s", tlsDebug)
			cfg.KeyLogWriter = w
		}

		if conf.Server.KeyFile != "" && conf.Server.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
			if err != nil {
				log.Fatalf("Cannot load certfile %s or keyfile %s: %s", conf.Server.CertFile, conf.Server.KeyFile, err)
			}
			cfg.Certificates = append(cfg.Certificates, cert)
			tlsConfigured = true
		}

		if !tlsConfigured {
			log.Printf("Using acme / letsencrypt for tls configuration. Enabling http (port 80) for verification")
			// setup a simple handler which sends a HTHS header for six months (!)
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Strict-Transport-Security", "max-age=15768000 ; includeSubDomains")
				fmt.Fprintf(w, "Hello from RDPGW")
			})

			certMgr := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(url.Host),
				Cache:      autocert.DirCache("/tmp/rdpgw"),
			}
			cfg.GetCertificate = certMgr.GetCertificate

			go func() {
				http.ListenAndServe(listenAddress(conf.Server.BindAddress, 80), certMgr.HTTPHandler(nil))
			}()
		}
	}

	// gateway confg
	gw := protocol.Gateway{
		RedirectFlags: protocol.RedirectFlags{
			Clipboard:  conf.Caps.EnableClipboard,
			Drive:      conf.Caps.EnableDrive,
			Printer:    conf.Caps.EnablePrinter,
			Port:       conf.Caps.EnablePort,
			Pnp:        conf.Caps.EnablePnp,
			DisableAll: conf.Caps.DisableRedirect,
			EnableAll:  conf.Caps.RedirectAll,
		},
		IdleTimeout:   conf.Caps.IdleTimeout,
		SmartCardAuth: conf.Caps.SmartCardAuth,
		TokenAuth:     conf.Caps.TokenAuth,
		ReceiveBuf:    conf.Server.ReceiveBuf,
		SendBuf:       conf.Server.SendBuf,
	}

	if conf.Caps.TokenAuth {
		gw.CheckPAACookie = security.CheckPAACookie
		gw.CheckHost = security.CheckSession(security.CheckPinnedHost)
	} else {
		gw.CheckHost = security.CheckHost
	}

	r := mux.NewRouter()

	// ensure identity is set in context and get some extra info
	r.Use(web.EnrichContext)

	// prometheus metrics
	r.Handle("/metrics", promhttp.Handler())

	// for sso callbacks
	r.HandleFunc("/tokeninfo", web.TokenInfo)

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()

	// gateway endpoint
	rdp := r.PathPrefix(gatewayEndPoint).Subrouter()

	// browser facing authentication: openid or header (proxy) auth
	var webAuth func(http.Handler) http.Handler
	if conf.Server.OpenIDEnabled() {
		log.Printf("enabling openid extended authentication")
		o := initOIDC(url, keepGroup)
		r.HandleFunc("/callback", o.HandleCallback)
		webAuth = o.Authenticated
		if conf.Server.HeaderEnabled() {
			log.Printf("Warning: both openid and header authentication are enabled; the web interface uses openid")
		}
	} else if conf.Server.HeaderEnabled() {
		if len(conf.Header.TrustedProxies) == 0 {
			log.Fatalf("header authentication is enabled but `header.trustedproxies` is empty; refusing to start in an exploitable configuration")
		}
		log.Printf("enabling header authentication with user header: %s (trusted proxies: %v)", conf.Header.UserHeader, conf.Header.TrustedProxies)
		headerConfig := &web.HeaderConfig{
			UserHeader:        conf.Header.UserHeader,
			UserIdHeader:      conf.Header.UserIdHeader,
			EmailHeader:       conf.Header.EmailHeader,
			DisplayNameHeader: conf.Header.DisplayNameHeader,
			GroupsHeader:      conf.Header.GroupsHeader,
			KeepGroup:         keepGroup,
			TrustedProxies:    conf.Header.TrustedProxies,
		}
		webAuth = headerConfig.New().Authenticated
	}

	if webAuth != nil {
		authed := func(f http.HandlerFunc) http.Handler { return webAuth(f) }
		r.Handle("/connect", authed(h.HandleDownload))

		// Web interface and API routes (authenticated)
		r.Handle("/", authed(h.HandleWebInterface))
		api.Handle("/hosts", authed(h.HandleHostList))
		api.Handle("/user", authed(h.HandleUserInfo))
		api.Handle("/settings", authed(h.HandleSettings))

		// Static files (no authentication required)
		r.PathPrefix("/static/").Handler(h.StaticHandler("/static/"))
		r.PathPrefix("/assets/").Handler(h.StaticHandler("/assets/"))

		// the token authenticated gateway endpoint is only unauthenticated
		// at the HTTP level when no HTTP level gateway auth is stacked
		if !conf.Server.KerberosEnabled() && !conf.Server.BasicAuthEnabled() && !conf.Server.NtlmEnabled() {
			rdp.Name("gw").HandlerFunc(gw.HandleGatewayProtocol)
		}
	}

	// for stacking of authentication
	auth := web.NewAuthMux()
	rdp.MatcherFunc(web.NoAuthz).HandlerFunc(auth.SetAuthenticate)

	// ntlm
	if conf.Server.NtlmEnabled() {
		log.Printf("enabling NTLM authentication")
		ntlm := web.NTLMAuthHandler{SocketAddress: conf.Server.AuthSocket, Timeout: conf.Server.BasicAuthTimeout}
		rdp.NewRoute().HeadersRegexp("Authorization", "NTLM").HandlerFunc(ntlm.NTLMAuth(gw.HandleGatewayProtocol))
		rdp.NewRoute().HeadersRegexp("Authorization", "Negotiate").HandlerFunc(ntlm.NTLMAuth(gw.HandleGatewayProtocol))
		auth.Register([]string{`NTLM`, `Negotiate`}, func(r *http.Request) bool {
			return r.Header.Get("Sec-WebSocket-Protocol") != "binary" // rdp client for ios is incompatible with this NTLM method.
		})
	}

	// basic auth
	if conf.Server.BasicAuthEnabled() {
		log.Printf("enabling basic authentication")
		q := web.BasicAuthHandler{SocketAddress: conf.Server.AuthSocket, Timeout: conf.Server.BasicAuthTimeout}
		rdp.NewRoute().HeadersRegexp("Authorization", "Basic").HandlerFunc(q.BasicAuth(gw.HandleGatewayProtocol))
		auth.Register([]string{`Basic realm="restricted", charset="UTF-8"`}, nil)
	}

	// spnego / kerberos
	if conf.Server.KerberosEnabled() {
		log.Printf("enabling kerberos authentication")
		keytab, err := keytab.Load(conf.Kerberos.Keytab)
		if err != nil {
			log.Fatalf("Cannot load keytab: %s", err)
		}
		rdp.NewRoute().HeadersRegexp("Authorization", "Negotiate").Handler(
			spnego.SPNEGOKRB5Authenticate(web.TransposeSPNEGOContext(http.HandlerFunc(gw.HandleGatewayProtocol)),
				keytab,
				service.Logger(log.Default())))

		// kdcproxy
		k := kdcproxy.InitKdcProxy(conf.Kerberos.Krb5Conf)
		r.HandleFunc(kdcProxyEndPoint, k.Handler).Methods("POST")
		auth.Register([]string{"Negotiate"}, nil)
	}

	// setup server
	server := http.Server{
		Addr:         listenAddress(conf.Server.BindAddress, conf.Server.Port),
		Handler:      r,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	if conf.Server.Tls == config.TlsDisable {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
