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
vtyctl show --host tcp://router.example.com:2666 'show ip bgp'

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
