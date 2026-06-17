# VTY Access and Authentication

zebra-rs exposes its command-line interface over a small gRPC channel
that three programs use:

- `vty` — interactive shell (a patched bash 5.3 that calls `vtyhelper`
  per keystroke for completion, execution, and show output)
- `vtyhelper` — short-lived gRPC client invoked by `vty` per command
- `vtyctl` — scriptable one-shot client (`apply`, `show`, `clear`,
  `mcp` subcommands)

All three talk to the `zebra-rs` daemon over the same gRPC service.
The default transport is a **Linux abstract Unix socket** scoped by the
process network namespace; TCP is available as an opt-in for
programmatic or remote access.

## Transports

| Transport | URI form | When to use |
|---|---|---|
| Abstract Unix socket (default) | `unix:NAME` | Local management; per-netns isolation |
| TCP | `tcp:HOST:PORT` | Remote/programmatic access (opt-in) |

### Abstract Unix sockets

The abstract namespace lives in the kernel rather than the filesystem
and is scoped by the process network namespace. Two practical
consequences:

- No `*.sock` file to chown, chmod, or clean up after a crash.
- A daemon in `netns:vrf-red` and another in `netns:vrf-blue` can both
  bind `@zebra-rs/vty` simultaneously — they cannot see each other's
  socket.

`ss -xal` lists abstract sockets with an `@` prefix:

```
$ ss -xal | grep zebra-rs
u_str LISTEN 0 4096   @zebra-rs/vty   ...
```

Two zebra-rs instances in the same netns trying to bind the same
abstract name produces `EADDRINUSE` — this is a configuration error
and the second daemon fails to start.

### TCP

TCP has no transport-level authentication: anyone who can reach the
port can issue commands. Use it only on a trusted management network
or behind a firewall.

## Server: `zebra-rs --vty-socket`

```
--vty-socket <URI>
    VTY gRPC listen address.
    Forms:
      unix:NAME           Linux abstract Unix socket (default)
      tcp:HOST:PORT       TCP listener
    Default: unix:zebra-rs/vty
```

Examples:

```bash
# Default — abstract UDS @zebra-rs/vty in the current netns
zebra-rs

# One daemon per VRF
ip netns exec vrf-red  zebra-rs &
ip netns exec vrf-blue zebra-rs &

# Legacy TCP behavior
zebra-rs --vty-socket tcp:0.0.0.0:2666
```

## Clients

### `vty` (interactive shell)

`vty` invokes `vtyhelper` with no explicit endpoint, so it inherits
the default `unix:zebra-rs/vty`. To talk to a TCP-mode daemon, export
`CLI_SERVER_URL` before launching the shell:

```bash
CLI_SERVER_URL=tcp://router.example.com:2666 vty
```

### `vtyhelper`

| Option / env | Default | Notes |
|---|---|---|
| `--base <URI>` | `unix:zebra-rs/vty` | Server endpoint URI |
| `--port <PORT>` | `2666` | Used only with bare-host `--base` for back-compat |
| `CLI_SERVER_URL` | (unset) | Environment override for `--base` |

`--base` accepts `unix:NAME`, `tcp://host:port`, `http://host:port`,
or a bare `http://host` prefix that is combined with `--port` (the
historical form).

### `vtyctl`

| Option | Default | Notes |
|---|---|---|
| `--host <URI>` | `unix:zebra-rs/vty` | Server endpoint URI |

`--host` accepts:

- `unix:NAME` — abstract Unix socket
- `tcp://host:port`, `http://host:port` — TCP
- bare hostname (e.g. `127.0.0.1`) — combined with `:2666` as TCP

Examples:

```bash
# Default — local abstract UDS
vtyctl show 'show ip route'

# Inside a netns
ip netns exec vrf-red vtyctl show 'show ip route'

# Remote TCP
vtyctl show --host tcp://router.example.com:2666 'show bgp'

# Legacy bare hostname (back-compat)
vtyctl show --host 127.0.0.1 'show ip route'
```

## Per-netns deployment

Because abstract UDS is netns-scoped, running one daemon per VRF needs
no extra configuration:

```bash
# Set up namespaces and start daemons
ip netns add vrf-red
ip netns add vrf-blue
ip netns exec vrf-red  /usr/bin/zebra-rs &
ip netns exec vrf-blue /usr/bin/zebra-rs &

# Connect into a namespace to drive it
ip netns exec vrf-red  vty                              # interactive
ip netns exec vrf-red  vtyctl show 'show ip route'      # scripted
```

Each daemon binds the same `@zebra-rs/vty` name in its own namespace;
clients reach the right daemon by virtue of which netns they are
running in. No per-instance socket-name configuration is needed.

Cross-netns access is intentionally not supported by abstract UDS — a
client in `netns:A` cannot reach a daemon in `netns:B`. Use TCP if you
need cross-netns access.

## Peer identity and the allow-list

Every gRPC request over a Unix socket carries the peer's credentials
via `SO_PEERCRED`, which the kernel guarantees (the client cannot
forge them). The server logs the peer for each call at INFO:

```
INFO vty rpc uid=1000 gid=1000 pid=109579
```

### Parent-shell check and `sudo`

In addition to the peer's own uid, the daemon walks `/proc` to find
the client's parent process and — for non-root peers — verifies the
parent's real uid matches the peer uid. This binds a session to the
shell that spawned the client and rejects mismatched-uid ancestry
(PID-reuse races, unexpected setuid chains).

There is one exception: **when the peer uid is 0, the parent-uid
match is skipped.** Without this short-circuit, `sudo <cmd>` from a
non-root login fails with `parent uid mismatch` because the outer
`sudo` process retains the invoking user's real uid even though the
client itself is running as root. With the short-circuit, the
following all work:

```bash
sudo vtyctl apply -f cfg.yaml
sudo ip netns exec vrf-red vtyctl show 'show ip route'
```

The remaining guards still apply to root peers: cross-PID-namespace
clients and orphaned clients (parent reparented to init, or the
parent process disappeared between the credential snapshot and the
`/proc` lookup) are rejected regardless of uid.

Non-root peers must connect from a same-uid shell — a setuid
escalation to a non-root effective uid is still refused.

### `ZEBRA_VTY_ALLOW_UIDS` — peer UID allow-list

Set this environment variable on the `zebra-rs` process to restrict
VTY access to a comma-separated list of UIDs:

```bash
# Only uid 1001 and 1002 may use the VTY
ZEBRA_VTY_ALLOW_UIDS=1001,1002 zebra-rs
```

Requests from peers outside the list are rejected with a gRPC
`PermissionDenied`:

```
Error: code: 'The caller does not have permission to execute the specified operation',
       message: "uid 1000 is not permitted to use the VTY"
```

and the server logs:

```
WARN vty rpc denied: uid not in allow-list uid=1000 gid=1000 pid=109604
```

When the variable is unset, every peer in the netns is allowed and
each call is just logged. The allow-list applies only to Unix-socket
connections; TCP connections carry no peer-cred and are not subject
to the check.

### Admin-required RPCs

The following RPCs require the caller's session to hold the Admin
role and will fail with `PermissionDenied` otherwise:

| Action | Path |
|---|---|
| `vtyctl apply` (push config) | Apply RPC |
| `vtyctl clear` (operational reset) | Clear RPC |
| Entering `configure` mode | DoExec RPC (mode=exec, line=`configure`) |
| Any command inside configure mode | DoExec RPC (mode=configure) |

Three ways to acquire Admin:

- **Root (uid 0)**: implicit Admin from session creation — no
  `enable` needed.
- **Interactive**: run `enable` in the vty shell, type your
  password (PAM auth via `vtypam`). The Admin role is held for 15
  minutes idle (sliding — refreshed on each authorized RPC) with a
  4-hour absolute cap.
- **Service account**: list your uid in
  `ZEBRA_VTY_SERVICE_ACCOUNTS` (see below) — permanent Admin from
  session creation.

Read-only commands (`vtyctl show`, `vty` show) and Tab/`?`
completion are not gated — a non-admin user can still see what
commands exist.

#### `configure` auto-elevate

When a non-admin user types `configure` in the vty shell, the
shell automatically prompts for a password and authenticates
against the **caller's own account** (sudo-style — same as
`enable`):

```text
host> configure
Password: ********
host(configure)#
```

Admin sessions (root, service-accounts, users within a current
`enable` TTL) bypass the prompt entirely — the optimistic first
attempt succeeds and configure mode is entered immediately. The
prompt only appears for users who would otherwise be denied.

The same password that authenticates `enable` works here.
`configure` is the convenience flow that combines `enable` + mode
entry in one step for one-shot configuration sessions; `enable`
is the standalone command for operators who want to hold the
Admin role across multiple commands without re-authenticating.

Configure-mode locking (single-writer mutex) is intentionally not
yet implemented; multiple admins can simultaneously enter
configure mode and pile up candidate edits. This will land with
the deferred Phase 5 work.

### `ZEBRA_VTY_SERVICE_ACCOUNTS` — permanent-admin uids

Sessions for uids listed here start with the `Admin` role from
session creation and do not require an interactive `enable`. Use
this for automation accounts (Ansible, cron jobs, monitoring) that
cannot meaningfully type a password.

```bash
# uid 999 and 1001 are permanent admins; no PAM auth required for them.
ZEBRA_VTY_SERVICE_ACCOUNTS=999,1001 zebra-rs
```

The typical deployment sets this in a systemd drop-in:

```ini
# /etc/systemd/system/zebra-rs.service.d/service-accounts.conf
[Service]
Environment=ZEBRA_VTY_SERVICE_ACCOUNTS=999,1001
```

Notes:

- The value is read once at daemon startup; runtime changes require
  a `systemctl restart zebra-rs`.
- Root (uid 0) is always implicit admin and does not need to be
  listed.
- If a service-account uid happens to type `enable`, the daemon
  returns success without invoking PAM (no password prompt).
- A service-account session can still call `disable` to drop to
  View for that session only; reconnecting yields a fresh Admin
  session.

### YANG configuration (runtime-mutable)

Service-accounts can also be defined via YANG, in which case they
are mutable at runtime and persist across daemon restarts (via the
config file):

```
host# configure
host(configure)# set vty service-account 999 description "Ansible automation"
host(configure)# set vty service-account 1001
host(configure)# commit
```

YANG-defined accounts are the **union** with the env-var set;
either source grants Admin. `delete vty service-account 999`
removes the uid from the YANG set immediately on commit (existing
sessions for that uid keep their Admin role until reconnect — the
gate is applied at session creation, not on each RPC).

In practice, pick **one** mechanism per deployment:
- env var (via systemd Environment=) when admin lifecycle is
  managed by the host (provisioning tools, package configs)
- YANG when admin lifecycle should be managed via the CLI itself
  (live operator changes, no daemon restart)

## Migration from earlier versions

The default transport changed from `tcp:0.0.0.0:2666` to
`unix:zebra-rs/vty`. Existing tooling that pointed at TCP needs
explicit opt-in on both sides:

```bash
zebra-rs --vty-socket tcp:0.0.0.0:2666 &
vtyctl show --host tcp://127.0.0.1:2666 'show ip route'
```

The bare-hostname form `vtyctl --host 127.0.0.1` is still combined
with `:2666` and treated as TCP, so the most common legacy
invocations keep working unchanged.

The `vtyctl mcp` subcommand's `--port` is TCP-only; it has no effect
when `--host` is a `unix:` URI.
