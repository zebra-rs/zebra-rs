# Command Line Options

The `zebra-rs` daemon is configured at startup by a small set of command
line options. Running `zebra-rs --help` prints the authoritative list;
this chapter explains what each option does and how they interact.

## Quick reference

| Option | Short | Argument | Default | Purpose |
|---|---|---|---|---|
| `--yang-path` | `-y` | `PATH` | search order (below) | Directory the YANG schema is loaded from |
| `--config-file` | `-c` | `FILENAME` | search order (below) | Configuration file loaded at startup |
| `--daemon` | `-d` | — | foreground | Detach and run in the background |
| `--log-output` | | `stdout \| syslog \| file` | `stdout` | Where log records are written |
| `--log-file` | | `PATH` | `./zebra-rs.log` | Log file path when `--log-output=file` |
| `--log-format` | | `terminal \| json \| elasticsearch` | `terminal` | Log record serialization |
| `--no-nhid` | | — | off | Embed nexthops in routes instead of using nexthop IDs (kernels < 5.3) |
| `--pid-file` | | `PATH` | `/var/run/zebra-rs.pid` (daemon mode) | Write the process ID to this file |
| `--vty-socket` | | `unix:NAME \| tcp:HOST:PORT` | `unix:zebra-rs/vty` | Management (VTY gRPC) listen address |

## `-c`, `--config-file FILENAME`

Loads a configuration file at startup and commits it as the running
configuration. When omitted, the daemon looks for `zebra-rs.conf` in the
following locations, in order:

1. `~/.zebra-rs/zebra-rs.conf`, if it exists
2. `/etc/zebra-rs/zebra-rs.conf` (the default load/save target)

This is the load *and* save target, so when neither exists the daemon
still defaults to the system path. Passing `--config-file` overrides both
the *load* and *save* target, so the `load` and `save` commands in the
`configure` mode also operate on the file you named.

The file format is detected automatically from its first meaningful
line, mirroring the `vtyctl apply -f FILENAME` handler. Any of the four
configuration representations is accepted:

- **CLI** — the Cisco-style indented block format (`show running-config`).
- **JSON** — a JSON document of the configuration tree.
- **YAML** — a YAML document of the configuration tree.
- **set/delete** — a flat list of `set …` / `delete …` statements (the
  `formal` format that `load` and `save` consume).

The four formats are interchangeable; see
[Show Config Commands](ch-06-02-show-config-commands.md) for examples of
each. The same configuration expressed in every format:

```
# CLI
system {
  hostname r1;
  router-id 10.0.0.1;
}
```

```yaml
# YAML
system:
  hostname: r1
  router-id: 10.0.0.1
```

```json
{ "system": { "hostname": "r1", "router-id": "10.0.0.1" } }
```

```
# set/delete
set system hostname r1
set system router-id 10.0.0.1
```

```sh
zebra-rs --config-file /etc/zebra-rs/zebra-rs.conf
zebra-rs -c /etc/zebra-rs/startup.yaml
```

An empty (or comment-only) file is loaded as an empty configuration. If
the document references a key the YANG schema does not recognize, the
file is rejected as a whole — no partial configuration is applied — and
the offending key is reported on the error log so a typo cannot silently
leave a half-applied configuration.

## `-y`, `--yang-path PATH`

Sets the directory the YANG schema is loaded from. The schema defines
every available configuration and show command, so the daemon cannot
start without it. When `--yang-path` is not given (or the path does not
exist), the following locations are tried in order:

1. `--yang-path` argument, if the path exists
2. `~/.zebra-rs/yang`
3. `/usr/share/zebra-rs/yang` (`make install` and Debian package layout)

Startup aborts if none resolve. The schemas are program data, so both
`make install` and the `.deb` place them under `/usr/share`, and a bare
`zebra-rs` on a package host resolves them without a flag.

## `-d`, `--daemon`

Detaches from the controlling terminal and runs in the background. The
current working directory is preserved across the fork, so relative
paths passed to `--yang-path`, `--config-file`, or `--pid-file` resolve
the same way they would in the foreground. In daemon mode the process ID
is written to `/var/run/zebra-rs.pid` unless `--pid-file` overrides it.

## `--pid-file PATH`

Writes the process ID to `PATH` on startup. This is useful for service
managers and for the test harness to locate and stop the daemon. In
`--daemon` mode it replaces the default `/var/run/zebra-rs.pid`.

## `--vty-socket ADDRESS`

Sets the address the management interface (the VTY gRPC server that
`vtyctl` connects to) listens on. Two forms are accepted:

- `unix:NAME` — a Linux abstract unix-domain socket (the default,
  `unix:zebra-rs/vty`).
- `tcp:HOST:PORT` — a TCP endpoint.

Running several daemons on one host — for example in test namespaces —
requires giving each a distinct `--vty-socket`.

## `--no-nhid`

Disables the use of kernel nexthop IDs and instead embeds the nexthop
directly in each route. Nexthop ID objects require Linux kernel 5.3 or
newer; set this flag on older kernels.

## Logging options

`--log-output`, `--log-file`, and `--log-format` control where log
records go and how they are serialized. These are covered in detail in
[Logging Configuration](ch-03-00-logging-overview.md); the quick summary
is:

- `--log-output stdout|syslog|file` selects the destination
  (default `stdout`).
- `--log-file PATH` names the file when `--log-output=file`
  (default `./zebra-rs.log`).
- `--log-format terminal|json|elasticsearch` selects the record format
  (default `terminal`).
