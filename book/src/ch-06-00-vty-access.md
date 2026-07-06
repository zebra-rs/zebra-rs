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
- **`zebra-rs` group member**: run `enable` or `configure` — no
  password prompt; Admin is held for 15 minutes idle (sliding) with
  a 4-hour absolute cap, same as a successful PAM enable.
- **Everyone else**: run `enable` or `configure` and enter the
  **root password** (PAM via `vtypam`). Admin is held for 15 minutes
  idle (sliding) with a 4-hour absolute cap.

Read-only commands (`vtyctl show`, `vty` show) and Tab/`?`
completion are not gated — a non-admin user can still see what
commands exist.

#### `zebra-rs` configure-authorization group

The Debian/RPM package creates a system group named `zebra-rs`:

```bash
getent group zebra-rs
sudo usermod -aG zebra-rs alice
# alice must log out and back in (or `newgrp zebra-rs`) for membership
# to take effect in an existing shell.
```

Members of this group can run `enable` or `configure` **without a
password**. The daemon checks supplementary group membership via
NSS (`getgrouplist`) when handling the `Enable` RPC; the group
name defaults to `zebra-rs` and can be overridden with
`ZEBRA_VTY_CONFIG_GROUP` on the daemon.

If the group does not exist on the host, the check is skipped and
only root-PAM elevation is available (aside from uid 0).

Package lifecycle (Debian/Ubuntu `.deb`):

- **Install** — `postinst` creates the `zebra-rs` system group if
  missing.
- **`apt remove`** — the group is **kept** so memberships survive a
  reinstall.
- **`apt purge`** — `postrm` removes the group (when `delgroup` is
  available).

#### `configure` auto-elevate

When a non-admin user types `configure`, the shell first tries
configure directly (root succeeds immediately). On failure, group
members run passwordless `enable`; everyone else is prompted for
the **root password** before retry:

```text
host> configure
host(configure)#
```

Group members and users who already ran `enable` within the current
TTL enter configure mode with no prompt. Non-members see:

```text
host> configure
Root password: ********
host(configure)#
```

`configure` combines `enable` + mode entry for one-shot
configuration sessions; `enable` is for operators who want to hold
the Admin role across multiple commands.

Configure-mode locking (single-writer mutex) is intentionally not
yet implemented; multiple admins can simultaneously enter
configure mode and pile up candidate edits. This is deferred to
future work.

#### Scripted admin (`vtyctl apply` / `clear`)

`vtyctl` does not call `enable`. Use `sudo vtyctl …` for
non-interactive pushes, or run from a root session.

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
