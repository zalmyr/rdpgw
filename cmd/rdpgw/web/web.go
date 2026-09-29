package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andrewheberle/rdpsign"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
)

type TokenGeneratorFunc func(context.Context, string, string) (string, error)
type UserTokenGeneratorFunc func(context.Context, string) (string, error)
type QueryInfoFunc func(context.Context, string, string) (string, error)

type Config struct {
	PAATokenGenerator  TokenGeneratorFunc
	UserTokenGenerator UserTokenGeneratorFunc
	QueryInfo          QueryInfoFunc
	QueryTokenIssuer   string
	EnableUserToken    bool
	// HostPolicy decides which destinations a user may connect to. When nil
	// one is built from Hosts / HostSelection / AllowedDestinationPorts /
	// AllowPrivateDestinations.
	HostPolicy               *hosts.Policy
	Hosts                    []string
	HostSelection            string
	AllowedDestinationPorts  []int
	AllowPrivateDestinations bool
	GatewayAddress           *url.URL
	RdpOpts                  RdpOpts
	TemplateFile             string
	RdpSigningCert           string
	RdpSigningKey            string
	// TemplatesPath is a directory whose files override the built-in web
	// interface files (index.html, style.css, app.js, images).
	TemplatesPath string
	// Templates holds the built-in web interface files.
	Templates fs.FS
	// Web customizes the browser interface. Zero values fall back to the
	// built-in defaults.
	Web WebConfig
}

type RdpOpts struct {
	UsernameTemplate string
	SplitUserDomain  bool
	NoUsername       bool
	// OverridableRdpKeys is the operator-supplied allow-list of RDP setting
	// keys that the /connect endpoint may override from URL query parameters.
	// Empty (the default) disables URL-based RDP overrides entirely. Each
	// entry is matched against the rdp struct tag of an RdpSettings field
	// after normalization (lowercase, no whitespace), so "use multimon",
	// "Use Multimon" and "usemultimon" are equivalent.
	OverridableRdpKeys []string
}

type Handler struct {
	paaTokenGenerator  TokenGeneratorFunc
	enableUserToken    bool
	userTokenGenerator UserTokenGeneratorFunc
	queryInfo          QueryInfoFunc
	queryTokenIssuer   string
	gatewayAddress     *url.URL
	policy             *hosts.Policy
	rdpOpts            RdpOpts
	rdpDefaults        string
	rdpSigner          *rdpsign.Signer
	templatesPath      string
	embedded           fs.FS
	files              fs.FS
	webConfig          WebConfig
	htmlTemplate       *template.Template
}

func (c *Config) NewHandler() *Handler {
	policy := c.HostPolicy
	if policy == nil {
		entries := make([]hosts.Entry, 0, len(c.Hosts))
		for _, h := range c.Hosts {
			entries = append(entries, hosts.Entry{Address: h})
		}
		var err error
		policy, err = hosts.NewPolicy(hosts.Config{
			Selection:                c.HostSelection,
			Entries:                  entries,
			AllowedDestinationPorts:  c.AllowedDestinationPorts,
			AllowPrivateDestinations: c.AllowPrivateDestinations,
		})
		if err != nil {
			log.Fatalf("Invalid host configuration: %s", err)
		}
	}

	handler := &Handler{
		paaTokenGenerator:  c.PAATokenGenerator,
		enableUserToken:    c.EnableUserToken,
		userTokenGenerator: c.UserTokenGenerator,
		queryInfo:          c.QueryInfo,
		queryTokenIssuer:   c.QueryTokenIssuer,
		gatewayAddress:     c.GatewayAddress,
		policy:             policy,
		rdpOpts:            c.RdpOpts,
		rdpDefaults:        c.TemplateFile,
		templatesPath:      c.TemplatesPath,
	}

	// set up RDP signer if config values are set
	if c.RdpSigningCert != "" && c.RdpSigningKey != "" {
		signer, err := rdpsign.New(c.RdpSigningCert, c.RdpSigningKey)
		if err != nil {
			log.Fatal("Could not set up RDP signer", err)
		}

		handler.rdpSigner = signer
	}

	handler.embedded = c.Templates
	handler.webConfig = c.Web.withDefaults()

	// Load HTML template
	handler.loadHTMLTemplate()

	return handler
}

// getHost resolves the destination for a /connect request under the host
// policy, for the user in ctx.
func (h *Handler) getHost(ctx context.Context, u *url.URL) (string, error) {
	var verify func(string) (string, error)
	if h.queryInfo != nil {
		verify = func(token string) (string, error) {
			return h.queryInfo(ctx, token, h.queryTokenIssuer)
		}
	}
	subject := hosts.SubjectFrom(identity.FromCtx(ctx))
	return h.policy.Select(subject, u.Query().Get("host"), verify)
}

func (h *Handler) HandleDownload(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)
	ctx := r.Context()

	opts := h.rdpOpts

	if !id.Authenticated() {
		log.Printf("unauthenticated user %s", id.UserName())
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}

	// determine host to connect to
	host, err := h.getHost(ctx, r.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// split the username into user and domain
	var user = id.UserName()
	var domain = ""
	if opts.SplitUserDomain {
		creds := strings.SplitN(id.UserName(), "@", 2)
		user = creds[0]
		if len(creds) > 1 {
			domain = creds[1]
		}
	}

	render := user
	if opts.UsernameTemplate != "" {
		render = fmt.Sprint(h.rdpOpts.UsernameTemplate)
		render = strings.Replace(render, "{{ username }}", user, 1)
		if h.rdpOpts.UsernameTemplate == render {
			log.Printf("Invalid username template. %s == %s", h.rdpOpts.UsernameTemplate, user)
			http.Error(w, errors.New("invalid server configuration").Error(), http.StatusInternalServerError)
			return
		}
	}

	if h.paaTokenGenerator == nil {
		log.Printf("Cannot create an RDP file for %s: caps.tokenauth is disabled", user)
		http.Error(w, "gateway token authentication is disabled", http.StatusInternalServerError)
		return
	}
	token, err := h.paaTokenGenerator(ctx, user, host)
	if err != nil {
		log.Printf("Cannot generate PAA token for user %s due to %s", user, err)
		http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
		return
	}

	if h.enableUserToken {
		userToken, err := h.userTokenGenerator(ctx, user)
		if err != nil {
			log.Printf("Cannot generate token for user %s due to %s", user, err)
			http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
			return
		}
		render = strings.Replace(render, "{{ token }}", userToken, 1)
	}

	// authenticated
	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		log.Printf("Cannot generate random seed due to %s", err)
		http.Error(w, errors.New("unable to generate random sequence").Error(), http.StatusInternalServerError)
		return
	}
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")

	var d *rdp.Builder
	if h.rdpDefaults == "" {
		d = rdp.NewBuilder()
	} else {
		d, err = rdp.NewBuilderFromFile(h.rdpDefaults)
		if err != nil {
			log.Printf("Cannot load RDP template file %s due to %s", h.rdpDefaults, err)
			http.Error(w, errors.New("unable to load RDP template").Error(), http.StatusInternalServerError)
			return
		}
	}

	// Apply URL-driven RDP option overrides (e.g. ?usemultimon=1) before
	// the server-controlled fields below, so authoritative gateway/auth
	// settings always win regardless of what an operator put on the
	// allow-list.
	if err := d.ApplyOverrides(r.URL.Query(), h.rdpOpts.OverridableRdpKeys); err != nil {
		log.Printf("rejected rdp override for user %s: %s", id.UserName(), err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !h.rdpOpts.NoUsername {
		d.Settings.Username = render
		if domain != "" {
			d.Settings.Domain = domain
		}
	}
	d.Settings.FullAddress = host
	d.Settings.GatewayHostname = h.gatewayAddress.Host
	d.Settings.GatewayCredentialsSource = rdp.SourceCookie
	d.Settings.GatewayAccessToken = token
	d.Settings.GatewayCredentialMethod = 1
	d.Settings.GatewayUsageMethod = 1

	// no rdp siging so return as-is
	if h.rdpSigner == nil {
		http.ServeContent(w, r, fn, time.Now(), strings.NewReader(d.String()))
		return
	}

	// get rdp content
	rdpContent := d.String()

	// sign rdp content
	signedContent, err := h.rdpSigner.Sign(rdpContent)
	if err != nil {
		log.Printf("Could not sign RDP file due to %s", err)
		http.Error(w, errors.New("could not sign RDP file").Error(), http.StatusInternalServerError)
		return
	}

	// return signd rdp file
	http.ServeContent(w, r, fn, time.Now(), bytes.NewReader(signedContent))
}
