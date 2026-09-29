# RDP Gateway Web Interface

These files make up the browser interface served at `/`. They are built into
the `rdpgw` binary, so you don't need to install them anywhere.

## Branding without editing files

```yaml
Web:
  Title: Acme Remote Access      # browser tab title
  Logo: Acme                     # header text
  PageTitle: Select a desktop    # main heading
  SelectServerMessage: Select a server to connect
  PreparingMessage: Preparing your connection...
  PrimaryColor: "#1f6feb"        # overrides the --primary CSS variable
```

## Replacing files

Set `Web.TemplatesPath` to a directory (or keep a `./templates` directory next
to the working directory, as older versions required). Any file found there
replaces the built-in file with the same name, and files you don't provide fall
back to the built-in ones. Only change what you need, for example a custom
`style.css` and `icon.svg`.

| File | Purpose |
|------|---------|
| `index.html` | Go `html/template`. Variables: `{{.Title}}`, `{{.Logo}}`, `{{.PageTitle}}`, `{{.SelectServerMessage}}`, `{{.PreparingMessage}}`, `{{.PrimaryColor}}` |
| `style.css` | Styles. Colors come from CSS variables in `:root`. |
| `app.js` | Loads the user, settings and hosts, renders them and downloads the RDP file. |
| `icon.svg`, `connect.svg` | Logo and host icon. |

Files are served from `/static/<name>` (and `/assets/<name>` for older
templates) without authentication. Only `.css`, `.js`, `.svg`, `.png`, `.jpg`,
`.jpeg`, `.ico` and `.woff2` files are served, so a `README.md` or `index.html`
in the directory is never exposed.

## API used by the interface

All endpoints need an authenticated session.

| Endpoint | Returns |
|----------|---------|
| `GET /api/v1/user` | `{username, authenticated, authTime, groups}` |
| `GET /api/v1/settings` | `{hostSelection, allowCustomHost, customHostPatterns, message}` |
| `GET /api/v1/hosts` | `[{id, name, address, description, isDefault, connectUrl}]`, only the hosts this user may use. In `roundrobin` mode this is one "Available Servers" entry, and in `signed` mode it is empty. |
| `GET /connect[?host=<id or host>]` | The RDP file. Errors are returned as plain text with status 400. |

When you write your own `app.js`, insert values with `textContent` rather than
`innerHTML`: host names and descriptions come from configuration and from user
names.
