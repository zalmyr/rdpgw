# Hosts and host selection

The hosts are the RDP servers the gateway will forward users to. You define them
in the configuration file, and optionally in a separate hosts file that can be
changed without restarting the gateway. Users never pick a raw address that you
haven't allowed.

## Defining hosts

`Server.Hosts` takes a list. Each item is either a plain `host:port` string, as
in earlier versions, or a mapping:

```yaml
Server:
  HostSelection: unsigned
  Hosts:
    - xrdp:3389                          # plain string: everyone, id derived from the address
    - id: finance
      name: Finance terminal server      # shown in the web interface
      address: fin-ts01.corp.local:3389
      description: Shared finance desktop
      groups: [finance]                  # only members of these groups...
      users: [alice@corp.local]          # ...or these users may use it
      default: true                      # preselected in the web interface
    - id: my-vm
      name: "{{ user }}'s workstation"
      address: "vm-{{ user }}.corp.local:3389"
```

| Field | Meaning |
|-------|---------|
| `id` | Used in `/connect?host=<id>`. Letters, digits, `.`, `_`, `-`. Derived from the address when omitted. |
| `name` | Display name. Defaults to the address. |
| `address` | `host:port` (the port defaults to 3389). May contain placeholders. |
| `description` | Shown under the name. |
| `groups`, `users` | Access rules. If both are empty, every authenticated user may use the host. Otherwise the user must be listed in `users` or belong to one of the `groups`. |
| `default` | Preselected entry. The first visible entry is used when none is marked. |

### Placeholders

`address`, `name` and `description` may contain:

| Placeholder | Value for `alice@corp.local` |
|-------------|------------------------------|
| `{{ username }}`, `{{ preferred_username }}` | `alice@corp.local` |
| `{{ user }}` | `alice` |
| `{{ domain }}` | `corp.local` |

A placeholder in `address` is only filled in when its value consists of
letters, digits, `.`, `_` and `-`. If the value has any other character (for
example the `@` in `{{ username }}`, or an empty `{{ domain }}`), the entry is
hidden from that user. This stops a crafted user name from changing the host or
port. For hostnames, use `{{ user }}` and `{{ domain }}`.

### Hosts file

Set `Server.HostsFile` to keep hosts out of the main configuration:

```yaml
Server:
  HostsFile: /etc/rdpgw/hosts.yaml
```

```yaml
# /etc/rdpgw/hosts.yaml
hosts:
  - id: lab-1
    address: lab-1.corp.local:3389
    groups: [lab]
```

The entries in this file are added after `Server.Hosts`. The gateway reloads the
file on `SIGHUP` and also checks every 30 seconds whether the file changed, so an
updated Kubernetes ConfigMap takes effect on its own. If the new file is invalid
(for example duplicate ids or a malformed address), the gateway logs the error and
keeps the previous list.

## Groups

Group rules need to know which groups the user belongs to:

* **OpenID Connect:** read from the ID token claim in `OpenId.GroupsClaim`
  (default `groups`). Use dots for nested claims, for example
  `realm_access.roles` for Keycloak realm roles.
* **Header authentication:** read from the comma separated header in
  `Header.GroupsHeader`.
* **Basic, NTLM and Kerberos:** these methods provide no groups. Use `users`
  rules for these users.

Only groups used by at least one host entry are stored in the session, which
keeps the session cookie small. Groups are read when the user logs in, so after
you add a new group to the hosts file, its members see the new host the next
time they log in.

## Host selection modes

`Server.HostSelection` decides how the destination is chosen:

| Mode | Behaviour |
|------|-----------|
| `roundrobin` (default) | The gateway picks a random host from those the user may use. |
| `unsigned` | The user picks a host from the list, by id (the web interface does this) or by address. `UserHostPatterns` can also let users type in a host (see below). |
| `signed` | An external portal creates signed links (`/connect?host=<token>`). The signed value must name a host the user may use, by id or by address. Requires `Caps.TokenAuth: true` and `Security.QueryTokenSigningKey`. The web interface shows no list in this mode. |
| `any` | The user may connect to any public address on a port in `AllowedDestinationPorts` (default `[3389]`). Loopback, private, link-local and multicast addresses are refused unless `AllowPrivateDestinations: true`. The configured hosts appear as suggestions. |

### Letting users type in a host

In `unsigned` mode you can allow users to enter hosts that aren't in the list,
as long as they match a pattern:

```yaml
Server:
  HostSelection: unsigned
  UserHostPatterns:
    - "*.lab.corp.local:3389"   # hostname glob, fixed port
    - "*.dev.corp.local"        # port must be in AllowedDestinationPorts
    - "10.20.0.0/16:3389"       # CIDR; hostnames must resolve entirely inside it
    - "[fd00::/8]:3389"         # IPv6 needs brackets when a port is given
    - "rdp-*.corp.local:*"      # any port
```

Patterns state exactly what you allow, so they may cover private ranges. The web
interface shows a "Connect to another host" field and remembers recently used
hosts in the browser.

## Where the rules are enforced

The same rules are checked in two places:

1. **`/connect`** (and the web interface's `/api/v1/hosts`): the host is resolved
   for the logged-in user, and when `Caps.TokenAuth` is on it is fixed in the
   signed PAA token.
2. **The gateway protocol:**
   * With a PAA token, the client must connect to exactly the host in the
     token. In `any` mode the destination rules are also checked again.
   * Without a PAA token (basic, NTLM and Kerberos authentication), the host
     the client asks for is checked against the host list, the user's access
     rules, and `UserHostPatterns` or the `any` destination rules.
