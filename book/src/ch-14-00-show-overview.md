# Operational Show Commands

The `show` commands report the *live operational state* of the router —
routes, neighbors, link-state databases, sessions, and the contents of
every protocol's tables. They are read-only: a `show` never changes
configuration.

This is distinct from the configuration viewers
(`show running-config` / `show candidate-config`), which render the
*configuration* tree and are covered in
[Show Config Commands](ch-06-02-show-config-commands.md). Everything
else under `show` is documented in this section:

- [System, RIB and Forwarding](ch-14-01-show-system-rib.md) — version,
  interfaces, the IPv4/IPv6 routing tables, nexthops, MPLS, L2, VRFs,
  and SRv6 SIDs.
- [BGP](ch-14-02-show-bgp.md) — every address family's Loc-RIB, neighbor
  state, Adj-RIB-In/Out, update-groups, and the MUP controller.
- [OSPFv2 and OSPFv3](ch-14-03-show-ospf.md) — instances, interfaces,
  neighbors, the LSDB, the SPF tree, and Segment Routing / TI-LFA state.
- [IS-IS](ch-14-04-show-isis.md) — adjacencies, the LSDB, topology,
  routes, DIS election, and Fast ReRoute.
- [Neighbor Discovery, BFD and STAMP](ch-14-05-show-bfd-stamp-nd.md) —
  IPv6 ND, BFD sessions, and STAMP delay measurement.
- [Policy Objects](ch-14-06-show-policy.md) — route policies,
  prefix-sets, community-sets, AS-path-sets, and key-chains.

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

The flag is accepted on *any* `show` command. Each command's page below
notes the top-level shape of the JSON it returns.

### `cli format json` (per-session default)

Inside an interactive VTY session you can flip the default output format
for the whole session instead of typing `-j` every time:

```
r1> set cli format json
```

`set cli format terminal` switches back to the human-readable view.

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
against the named VRF's protocol task. Each per-VRF form therefore
mirrors its non-VRF sibling exactly — same output, same JSON, same
arguments. The `show ip route vrf` / `show ipv6 route vrf` RIB forms
work the same way and are documented on the
[System, RIB and Forwarding](ch-14-01-show-system-rib.md) page.
