package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/hosts"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// WebConfig customizes the browser interface.
type WebConfig struct {
	// Title is the browser tab title.
	Title string
	// Logo is the text next to the logo in the header.
	Logo string
	// PageTitle is the main heading.
	PageTitle           string
	SelectServerMessage string
	PreparingMessage    string
	// PrimaryColor overrides the --primary CSS variable, e.g. "#1f6feb".
	PrimaryColor string
}

var safeCSSColor = regexp.MustCompile(`^(#[0-9A-Fa-f]{3,8}|[A-Za-z]{3,20}|(rgb|rgba|hsl|hsla|oklch)\([0-9.,%/ ]+\))$`)

func (c WebConfig) withDefaults() WebConfig {
	def := func(v *string, d string) {
		if strings.TrimSpace(*v) == "" {
			*v = d
		}
	}
	def(&c.Title, "RDP Gateway")
	def(&c.Logo, "RDP Gateway")
	def(&c.PageTitle, "Select a Server to Connect")
	def(&c.SelectServerMessage, "Select a server to connect")
	def(&c.PreparingMessage, "Preparing your connection...")
	if c.PrimaryColor != "" && !safeCSSColor.MatchString(c.PrimaryColor) {
		log.Printf("Ignoring invalid web primary color %q", c.PrimaryColor)
		c.PrimaryColor = ""
	}
	return c
}

// overlayFS serves files from dir when present there, else from base.
type overlayFS struct {
	dir  fs.FS
	base fs.FS
}

func (o overlayFS) Open(name string) (fs.File, error) {
	if o.dir != nil {
		if f, err := o.dir.Open(name); err == nil {
			return f, nil
		}
	}
	if o.base != nil {
		return o.base.Open(name)
	}
	return nil, fs.ErrNotExist
}

// uiFiles returns the web interface files: the operator's TemplatesPath
// (or ./templates when it exists, for existing deployments) layered over
// the files built into the binary.
func (h *Handler) uiFiles() fs.FS {
	if h.files != nil {
		return h.files
	}
	dir := h.templatesPath
	if dir == "" {
		dir = "./templates"
	}
	o := overlayFS{base: h.embedded}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		o.dir = os.DirFS(dir)
		log.Printf("Web interface files in %s override the built-in ones", dir)
	} else if h.templatesPath != "" {
		log.Printf("Warning: templates path %s not found, using built-in web interface", h.templatesPath)
	}
	h.files = o
	return o
}

// loadHTMLTemplate parses index.html, falling back to a minimal built-in
// page when no template is available.
func (h *Handler) loadHTMLTemplate() {
	data, err := fs.ReadFile(h.uiFiles(), "index.html")
	if err == nil {
		h.htmlTemplate, err = template.New("index").Parse(string(data))
	}
	if err != nil {
		log.Printf("Warning: cannot load web interface template: %v; using minimal fallback", err)
		h.htmlTemplate = template.Must(template.New("index").Parse(fallbackHTMLTemplate))
	}
}

var staticTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "application/javascript; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".ico":   "image/x-icon",
	".woff2": "font/woff2",
}

// StaticHandler serves the web interface's static files (css, js, images)
// below prefix. Only files with a known static extension are served.
func (h *Handler) StaticHandler(prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, prefix)), "/")
		ctype, ok := staticTypes[strings.ToLower(path.Ext(name))]
		if !ok || name == "" || !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(h.uiFiles(), name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}

// Host represents a host available for connection
type Host struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Description string `json:"description"`
	IsDefault   bool   `json:"isDefault"`
	// ConnectURL downloads the RDP file for this host.
	ConnectURL string `json:"connectUrl"`
}

// UserInfo represents the current authenticated user
type UserInfo struct {
	Username      string    `json:"username"`
	Authenticated bool      `json:"authenticated"`
	AuthTime      time.Time `json:"authTime"`
	Groups        []string  `json:"groups,omitempty"`
}

// Settings tells the browser interface what the user may do.
type Settings struct {
	HostSelection string `json:"hostSelection"`
	// AllowCustomHost is true when the user may type a destination.
	AllowCustomHost bool `json:"allowCustomHost"`
	// CustomHostPatterns lists the allowed destinations, for display.
	CustomHostPatterns []string `json:"customHostPatterns,omitempty"`
	// Message explains the host list, e.g. in signed mode.
	Message string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Cannot encode response: %s", err)
	}
}

func connectURL(host string) string {
	if host == "" {
		return "/connect"
	}
	return "/connect?host=" + url.QueryEscape(host)
}

// HandleHostList returns the list of available hosts for the authenticated user
func (h *Handler) HandleHostList(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)
	if id == nil || !id.Authenticated() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	visible := h.policy.Visible(hosts.SubjectFrom(id))
	list := []Host{}

	switch h.policy.Selection() {
	case hosts.SelectionRoundRobin:
		if len(visible) > 0 {
			desc := "Connect to an available server automatically"
			if len(visible) > 1 {
				desc = fmt.Sprintf("Connect to one of %d available servers automatically", len(visible))
			}
			list = append(list, Host{
				ID:          "roundrobin",
				Name:        "Available Servers",
				Description: desc,
				IsDefault:   true,
				ConnectURL:  connectURL(""),
			})
		}
	case hosts.SelectionSigned:
		// destinations come as signed links from an external portal
	default:
		for _, v := range visible {
			desc := v.Description
			if desc == "" {
				desc = "Connect to " + v.Address
			}
			list = append(list, Host{
				ID:          v.ID,
				Name:        v.Name,
				Address:     v.Address,
				Description: desc,
				IsDefault:   v.Default,
				ConnectURL:  connectURL(v.ID),
			})
		}
	}

	writeJSON(w, list)
}

// HandleSettings describes the host selection behaviour to the browser.
func (h *Handler) HandleSettings(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)
	if id == nil || !id.Authenticated() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s := Settings{HostSelection: h.policy.Selection()}
	switch s.HostSelection {
	case hosts.SelectionAny:
		s.AllowCustomHost = true
	case hosts.SelectionUnsigned:
		if uh := h.policy.UserHosts(); uh != nil {
			s.AllowCustomHost = true
			s.CustomHostPatterns = uh.Patterns()
		}
	case hosts.SelectionSigned:
		s.Message = "Use the connection link provided by your administrator."
	}
	writeJSON(w, s)
}

// HandleUserInfo returns information about the current authenticated user
func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)
	if id == nil || !id.Authenticated() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	writeJSON(w, UserInfo{
		Username:      id.UserName(),
		Authenticated: id.Authenticated(),
		AuthTime:      id.AuthTime(),
		Groups:        id.Groups(),
	})
}

// HandleWebInterface serves the main web interface
func (h *Handler) HandleWebInterface(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)
	if id == nil || !id.Authenticated() {
		// Redirect to authentication
		http.Redirect(w, r, "/connect", http.StatusFound)
		return
	}
	if h.htmlTemplate == nil {
		h.loadHTMLTemplate()
	}
	cfg := h.webConfig.withDefaults()

	templateData := struct {
		Title               string
		Logo                string
		PageTitle           string
		SelectServerMessage string
		PreparingMessage    string
		PrimaryColor        template.CSS
	}{
		Title:               cfg.Title,
		Logo:                cfg.Logo,
		PageTitle:           cfg.PageTitle,
		SelectServerMessage: cfg.SelectServerMessage,
		PreparingMessage:    cfg.PreparingMessage,
		// validated against safeCSSColor in withDefaults
		PrimaryColor: template.CSS(cfg.PrimaryColor),
	}

	var buf bytes.Buffer
	if err := h.htmlTemplate.Execute(&buf, templateData); err != nil {
		log.Printf("Failed to execute template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

// fallbackHTMLTemplate is used when no index.html is available
const fallbackHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 800px; margin: 2rem auto; padding: 2rem; background: white; border-radius: 12px; }
        .server-card { border: 2px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; cursor: pointer; }
        .server-card.selected { border-color: #333; }
        .connect-button { width: 100%; background: #333; color: white; border: none; border-radius: 8px;
                         padding: 1rem 2rem; font-size: 1.1rem; cursor: pointer; }
        .connect-button:disabled { background: #a0aec0; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.PageTitle}}</h1>
        <div id="serversGrid"></div>
        <button class="connect-button" id="connectButton" disabled>{{.SelectServerMessage}}</button>
        <div id="loading" style="display:none;">{{.PreparingMessage}}</div>
    </div>
    <script>
        let selectedServer = null;
        async function loadServers() {
            const response = await fetch('/api/v1/hosts');
            if (!response.ok) return;
            const servers = await response.json();
            const grid = document.getElementById('serversGrid');
            servers.forEach(server => {
                const card = document.createElement('div');
                card.className = 'server-card';
                const name = document.createElement('strong');
                name.textContent = server.name;
                const desc = document.createElement('div');
                desc.textContent = server.description;
                card.append(name, desc);
                card.onclick = () => {
                    document.querySelectorAll('.server-card').forEach(c => c.classList.remove('selected'));
                    card.classList.add('selected');
                    selectedServer = server;
                    document.getElementById('connectButton').disabled = false;
                };
                grid.appendChild(card);
            });
        }
        function connectToServer() {
            if (!selectedServer) return;
            document.getElementById('loading').style.display = 'block';
            window.location.href = selectedServer.connectUrl;
        }
        document.addEventListener('DOMContentLoaded', loadServers);
        document.getElementById('connectButton').onclick = connectToServer;
    </script>
</body>
</html>`
