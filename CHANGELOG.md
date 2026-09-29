# Changelog

All user-visible changes to rdpgw will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `hostselection: any` destination rules (public addresses, allowed ports)
  are now enforced by the gateway itself, not only on `/connect`.
  Previously a basic, NTLM or Kerberos client could open a tunnel to any
  host:port, including internal ones.
- `hostselection: signed` works: the gateway used to refuse every signed
  host. It now accepts the host pinned in the PAA token.
- Lowercase or mixed case section names in the YAML config (`server:`,
  `client:` ...) were silently ignored; section and key names are now
  case-insensitive.
- The web interface works in `signed` mode (shows a notice instead of a
  list that couldn't connect) and shows the gateway's error message when
  a download fails.
- OpenID Connect no longer continues with an empty user name when the
  ID token has no username claim.
- A missing or unreadable TLS cert/key and an unparsable
  `GatewayAddress` now stop startup with a clear error instead of
  starting with an empty certificate or crashing later.
- The container image is built from the checked-out source instead of a
  fresh clone of upstream `master`, with Go 1.25 to match `go.mod`.
- `go.sum` is committed; CI checks that it is tidy.

### Changed

- The dev container image no longer ships a baked-in TLS key/cert.
  The runtime image carries `openssl` and the entrypoint generates an
  ephemeral self-signed cert at first start if none is mounted at the
  configured path; each container instance gets its own key. The
  entrypoint also runs entirely as UID 1001 (no more `USER 0`).
- rdpgw refuses to start when any of `Server.SessionKey`,
  `Server.SessionEncryptionKey`, `Security.PAATokenSigningKey`,
  `Security.PAATokenEncryptionKey`, `Security.UserTokenSigningKey`,
  `Security.UserTokenEncryptionKey`, or `Security.QueryTokenSigningKey`
  matches a published placeholder value from `README.md` / the dev
  compose files. See [UPGRADING.md](UPGRADING.md) for the full list.
- `rdpgw-auth` now creates its socket with mode `0660` and accepts only
  connections whose peer UID is on an allow-list (default: the daemon's
  own UID). Operators running rdpgw and rdpgw-auth as different users
  must list the gateway's UID via `--allow-uid` or share a group via
  `--allow-gid`. See [UPGRADING.md](UPGRADING.md).
- `X-Forwarded-For` is now honored only when the request arrives from
  a `Server.TrustedProxies` CIDR. The default `Server.TrustedProxies`
  is empty, so by default the request's `RemoteAddr` (host portion) is
  the source of `AttrClientIp`. See [UPGRADING.md](UPGRADING.md) if
  your deployment relies on a fronting proxy stamping XFF.
- `server.hostselection: any` now refuses destinations that resolve to
  loopback, RFC1918, link-local, IPv6 ULA, unspecified, or multicast
  addresses, and only forwards to ports in `Server.AllowedDestinationPorts`
  (default `[3389]`). Operators that need the old behavior can opt back in
  with `Server.AllowPrivateDestinations: true` and an extended port list.
  See [UPGRADING.md](UPGRADING.md) for migration notes. The other
  host-selection modes (`roundrobin`, `signed`, `unsigned`) already used
  the operator-curated `Server.Hosts` list and are unaffected.

### Added

- Structured host entries in `Server.Hosts` with `id`, `name`,
  `description`, `default` and per-user / per-group access rules
  (`users`, `groups`). Plain `host:port` strings keep working. See
  [docs/hosts.md](docs/hosts.md).
- Host placeholders `{{ username }}`, `{{ user }}` and `{{ domain }}`
  next to `{{ preferred_username }}`. They are applied to names and
  descriptions too, and values that could change the address are refused.
- `Server.HostsFile`: extra hosts in a separate YAML file, reloaded on
  `SIGHUP` and when the file changes. An invalid file keeps the previous
  list.
- `Server.UserHostPatterns`: in `unsigned` mode users can type in hosts
  that match operator patterns (hostname globs, CIDRs, ports).
- Group membership from OpenID Connect (`OpenId.GroupsClaim`, default
  `groups`, nested claims supported) and header auth
  (`Header.GroupsHeader`).
- `Web` config section for branding (`Title`, `Logo`, `PageTitle`,
  messages, `PrimaryColor`) and `Web.TemplatesPath` to override
  individual web interface files.
- The web interface is built into the binary; `/api/v1/settings`
  endpoint; host search, a custom host field and recently used hosts.
- `rdpgw-auth --allow-uid` and `--allow-gid` flags (repeatable).
- `Server.TrustedProxies` (`[]string`, CIDR, default empty).
- `Server.AllowedDestinationPorts` (`[]int`, default `[3389]`).
- `Server.AllowPrivateDestinations` (`bool`, default `false`).
