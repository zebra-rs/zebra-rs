# Operational Show Commands

The `show` commands report the *live operational state* of the router —
routes, neighbors, link-state databases, sessions, and the contents of
every protocol's tables. They are read-only: a `show` never changes
configuration.

This is distinct from the configuration viewers
(`show running-config` / `show candidate-config`), which render the
*configuration* tree and are covered in
[Show Config Commands](ch-06-02-show-config-commands.md).

This page covers what every show command has in common: how to run
one, how to get JSON, the per-VRF forms, and the
[daemon commands](#daemon-commands). Each protocol documents its
own show commands in its chapter, next to its configuration:

- [BGP Show Commands](ch-02-48-bgp-show.md) — every address family's
  Loc-RIB, neighbor state, Adj-RIB-In/Out, update-groups, EVPN service
  state, and the MUP controller.
- [IS-IS Show Commands](ch-07-13-isis-show.md) — adjacencies, the
  LSDB, topology, routes, DIS election, Fast ReRoute, and Flex-Algo.
- [OSPFv2 Show Commands](ch-08-18-ospf-show.md) and
  [OSPFv3 Show Commands](ch-15-18-ospfv3-show.md) — instances,
  interfaces, neighbors, the LSDB, routes, the SPF tree, Segment Routing,
  Flex-Algo, TI-LFA and Graceful Restart.
- [PIM](ch-17-00-pim.md#show-commands) — PIM, IGMP and MLD state and
  the multicast routing table.
- [Routing Table (RIB)](ch-18-00-rib.md) — the IPv4/IPv6 routing tables,
  nexthop groups, the MPLS label table and the label space.
- [Router ID Selection](ch-00-01-router-id.md) — `show router-id`.
- [Interface Configuration](ch-00-02-interface-configuration.md#show-commands)
  — interfaces, VRFs and IPv6 Neighbor Discovery.
- [Bridge Configuration](ch-00-04-bridge-configuration.md#show-commands)
  — the EVPN MAC table and the kernel bridge FDB.
- [SRv6](ch-04-00-srv6.md#show-segment-routing-srv6-sid) — the SRv6
  SIDs.
- [eBPF Data Plane](ch-16-00-ebpf.md#show-ebpf) — the eBPF forwarding
  tables and counters.
- [BFD](ch-10-00-bfd.md#verifying-sessions) — BFD sessions and their
  counters.
- [STAMP](ch-09-00-twamp-stamp.md#show-commands) — the delay and loss
  measurement sessions.
- [Policy Show Commands](ch-05-05-policy-show.md) — route policies,
  match-sets and key-chains.

## How to run a show command

A `show` command can be issued two ways:

**From the interactive VTY shell** (the `vty` binary), type the command
directly. Tab completion and `?` help are driven by the same YANG
grammar that validates the command:

```
r1> show ip route
r1> show bgp summary
r1> show isis neighbor detail
```

**From the `vtyctl` client**, pass the full command as one quoted
argument to `vtyctl show`:

```
vtyctl show 'show ip route'
vtyctl show 'show bgp summary'
```

Both paths reach the same per-protocol handler inside the daemon, so the
output is identical.

## JSON output

> **Goal:** every `show` command supports JSON. The handler for each
> command branches on a `json` flag and emits a structured document, so
> any `show` can be machine-read without screen-scraping the text view.

There are two independent ways to request JSON.

### The `-j` / `--json` flag (universal)

`vtyctl show -j '<command>'` sets `ShowRequest.json = true`, which is
plumbed through to every handler. The default (no flag) renders the
human-readable text view:

```
vtyctl show -j 'show ip route'      # JSON RIB
vtyctl show    'show ip route'      # text RIB
```

The flag is accepted on *any* `show` command. Each protocol's show
reference notes the top-level shape of the JSON each command returns.

There is no trailing `json` keyword: `show bgp summary json` is
rejected. Use `-j` or `cli format json`.

### `cli format json` (per-session default)

Inside an interactive VTY session you can flip the default output format
for the whole session instead of typing `-j` every time:

```
r1> cli format json
```

`cli format terminal` switches back to the human-readable view.

### Config viewers carry their own keyword

`show running-config` and `show candidate-config` are dispatched by the
configuration manager rather than a protocol handler, so they select
their format with a trailing keyword (`formal` / `json` / `yaml`) rather
than the `-j` flag. See
[Show Config Commands](ch-06-02-show-config-commands.md).

## Per-VRF forms

For OSPFv2, OSPFv3, IS-IS and BGP, a `vrf <name>` selector can be
inserted after the protocol keyword:

```
show ospf vrf blue neighbor
show isis vrf red database
show bgp vrf customer-a summary
```

These are **not** a separate set of handlers. The configuration manager
strips the `vrf <name>` selector and replays the remaining command
against the named VRF's protocol task, so a per-VRF form gives the same
output and JSON as its non-VRF sibling. Only some commands have a
per-VRF form, though: the grammar accepts `vrf <name>` in front of a
fixed set of subcommands per protocol, and each protocol's show page
lists them. The `show ip route vrf` / `show ipv6 route vrf` forms are
different: the RIB answers them itself, from its per-VRF tables. See
[Routing Table (RIB)](ch-18-00-rib.md#show-ip-route-vrf-name).

## Daemon commands

These describe the daemon itself.

### `show version`

The version, the git hash the binary was built from, and the build date:

```
r1> show version
zebra-rs version 26.10.1 (d470a230)
Build Date: 2026-10-18 05:04:38 UTC
```

JSON: `{ "package_name", "package_version", "git_hash", "git_branch",
"git_date", "git_message", "git_dirty", "build_date" }`.

### `show hostname`

The configured `system hostname`, or the system's when none is
configured, or `unknown` when there is neither:

```
r1> show hostname
r1
```

JSON: `{ "hostname": "r1" }`, or `null` when there is neither.

### `show task`

The protocol tasks the daemon runs and the VRF each runs in. It confirms
that a per-VRF protocol instance started:

```
r1> show task
Protocol      VRF
bfd           default
ospf          blue
ospf          default
ospfv3        default
stamp         default
```

JSON: a list of `{ "protocol", "vrf" }`.
