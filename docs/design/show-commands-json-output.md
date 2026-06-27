# `show` Commands — Catalog and JSON Output Support

This document catalogs every `show` CLI command in zebra-rs and records
whether its handler renders structured **JSON** output in addition to the
default human-readable text.

> Goal: all `show` commands should support JSON output. This catalog is the
> tracking sheet — it lists every command and flags the ones whose handler
> still renders text only, so the remaining gap is explicit.

Source of truth: the `show` grammar in `zebra-rs/yang/exec.yang` and the
`ShowCallback` registrations across `zebra-rs/src/**/show*.rs`.

## How JSON output is requested

There are two independent mechanisms:

1. **The `-j` / `--json` flag (universal).** `zctl show -j '<command>'`
   (or `--json`) sets `ShowRequest.json = true`. The flag is plumbed
   through `DisplayRequest` to **every** `ShowCallback`, whose signature
   is `fn(&Proto, Args, json: bool) -> String`. The flag is therefore
   accepted on *any* show command; whether a distinct JSON document comes
   back depends on the handler:
   - Handlers that **honor** it branch on `json` and emit
     `serde_json::to_string_pretty(...)`.
   - Handlers that **ignore** it take the parameter as `_json` and always
     render text (the flag is silently a no-op).

   ```
   zctl show -j 'show ip route'        # JSON RIB
   zctl show 'show ip route'           # text RIB
   ```

   Plumbing: `vtyctl/src/main.rs` (`-j`) → `vtyctl/src/show.rs`
   (`ShowRequest.json`) → `zebra-rs/src/config/serve.rs:461`
   (`json: request.json`) → each module's `ShowCallback`.

2. **Config-tree sub-keyword (`running-config` / `candidate-config`).**
   These are dispatched by `install_func` in
   `zebra-rs/src/config/commands.rs`, not by the `ShowCallback` builder,
   and carry their **own** output-format keyword rather than reading `-j`:

   ```
   show running-config            # native flat config
   show running-config formal     # set-style flat statements
   show running-config json       # pretty-printed JSON
   show running-config yaml       # YAML
   ```

   (`show candidate-config` mirrors this for the uncommitted edit buffer.)

A separate session knob, `cli format json` (`/cli/format/json`), sets the
default output format for an interactive vty session.

## Per-VRF forms

`show <proto> vrf <name> …` for OSPFv2 / OSPFv3 / IS-IS / BGP is **not** a
separate handler set. The config manager strips the `vrf <name>` selector
(`vrf_redirect_split`) and replays the remaining command against the
per-VRF task's show channel, so each per-VRF form's JSON support **mirrors
its non-VRF sibling** in the tables below.

---

## RIB / interface / forwarding (`zebra-rs/src/rib/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show version` | Daemon version (config-tree handler) | text only |
| `show router-id` | Effective global router ID | ✅ |
| `show hostname` | System hostname | ✅ |
| `show vrf` | VRF table | ✅ |
| `show task` | Spawned protocol tasks and their VRF (manager handler) | text only |
| `show interface [<name>] [detail]` | Interface state | ✅ |
| `show ip route` | IPv4 routing table | ✅ |
| `show ip route detail` | IPv4 RIB, IOS-XR detail blocks | ✅ |
| `show ip route prefix <A.B.C.D/M> [detail]` | One IPv4 prefix | ✅ |
| `show ip route vrf [<name>] [detail]` | IPv4 RIB per VRF | ✅ |
| `show ipv6 route` | IPv6 routing table | ✅ |
| `show ipv6 route detail` | IPv6 RIB, IOS-XR detail blocks | ✅ |
| `show ipv6 route prefix <X::Y/M> [detail]` | One IPv6 prefix | ✅ |
| `show ipv6 route vrf [<name>] [detail]` | IPv6 RIB per VRF | ✅ |
| `show nexthop` | Nexthop groups | ✅ |
| `show mpls ilm` | MPLS incoming-label map | ✅ |
| `show l2 mac table` | Bridge MAC table | ✅ |
| `show l2 neighbor` | Bridge FDB entries | ✅ |
| `show segment-routing srv6 sid` | Allocated SRv6 SIDs | ✅ |
| `show evpn vni all` | EVPN VNI information | text only |
| `show running-config [formal\|json\|yaml]` | Committed config | ✅ (sub-keyword) |
| `show candidate-config [formal\|json\|yaml]` | Uncommitted config | ✅ (sub-keyword) |

## BGP (`zebra-rs/src/bgp/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show bgp [<addr>\|<prefix>]` | IPv4 unicast RIB (default family) | ✅ |
| `show bgp summary` | Neighbor status per AFI/SAFI | ✅ |
| `show bgp ipv4 [<addr>\|<prefix>\|summary]` | IPv4 unicast RIB | ✅ |
| `show bgp ipv4 <prefix> longer-prefix` | IPv4 equal-or-more-specific | text only |
| `show bgp ipv6 [<addr>\|<prefix>\|summary]` | IPv6 unicast RIB | ✅ |
| `show bgp ipv6 <prefix> longer-prefix` | IPv6 equal-or-more-specific | text only |
| `show bgp vpnv4 [<addr>\|<prefix>\|summary]` | VPNv4 RIB (all RDs) | ✅ |
| `show bgp vpnv6 [<addr>\|<prefix>\|summary]` | VPNv6 RIB (all RDs) | ✅ |
| `show bgp evpn [route-type <type>]` | EVPN RIB | ✅ ◐ |
| `show bgp evpn summary` | EVPN-enabled neighbors | ✅ |
| `show bgp evpn ethernet-segment` | Local Ethernet Segments (RFC 7432) | text only |
| `show bgp labeled-unicast` | Labeled-Unicast (SAFI 4) RIB | ✅ ◐ |
| `show bgp flowspec [ipv6]` | Flowspec RIB (SAFI 133) | ✅ ◐ |
| `show bgp sr-policy [ipv6]` | SR Policy RIB (SAFI 73) | ✅ ◐ |
| `show bgp link-state` | Link-State RIB (SAFI 71) | ✅ ◐ |
| `show bgp attributes` | Attribute-store statistics | text only |
| `show bgp neighbor [<addr>\|<name>]` | Neighbor information | ✅ |
| `show bgp neighbor <addr> advertised-routes [ipv6\|vpnv4\|evpn]` | Adj-RIB-Out | ✅ (evpn ◐) |
| `show bgp neighbor <addr> received-routes [ipv6\|vpnv4\|evpn]` | Adj-RIB-In | ✅ (evpn ◐) |
| `show bgp neighbor <addr> rtcv4` | IPv4 Route Target Constraints | text only |
| `show bgp neighbor-group [<name>]` | Neighbor-group inheritance state | ✅ |
| `show bgp update-group [<id>]` | Update-groups (IOS-XR style) | ✅ |
| `show bgp mup [summary]` | Mobile User Plane RIB (SAFI 85) | ✅ ◐ |
| `show bgp mup mup-c [session\|association]` | MUP Controller status | ✅ ◐ |
| `show bgp vrf [<name>] [summary\|neighbor\|ipv4\|ipv6\|mup]` | Per-VRF BGP (redirected) | ✅ |

◐ = honors `-j` but currently emits an empty array/object placeholder
pending a finalized JSON schema.

## OSPFv2 (`zebra-rs/src/ospf/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show ospf` | Instance summary | ✅ |
| `show ospf interface` | Interface status | ✅ |
| `show ospf neighbor [detail]` | Neighbors | ✅ |
| `show ospf database [detail]` | LSDB | ✅ |
| `show ospf route` | OSPF routing table | ✅ |
| `show ospf spf` | SPF tree | ✅ |
| `show ospf graph` | Topology graph | ✅ |
| `show ospf ti-lfa` | TI-LFA per-destination repair paths | ✅ |
| `show ospf repair-list [detail]` | TI-LFA repair-list | ✅ |
| `show ospf flex-algo` | Flexible Algorithm (RFC 9350) state | ✅ |
| `show ospf segment-routing` | SR database | ✅ |
| `show ospf graceful-restart` | GR helper status | ✅ |
| `show ospf checkpoint` | GR on-disk checkpoint | ✅ |
| `show ospf vrf <name> …` | Per-VRF (redirected; mirrors above) | per sibling |

## OSPFv3 (`zebra-rs/src/ospf/show_v3.rs`)

| Command | Description | JSON |
|---|---|---|
| `show ospfv3` | Instance summary | ✅ |
| `show ospfv3 interface` | Interface status | ✅ |
| `show ospfv3 neighbor [detail]` | Neighbors | ✅ |
| `show ospfv3 database [detail]` | LSDB | ✅ |
| `show ospfv3 route` | OSPFv3 routing table | ✅ |
| `show ospfv3 spf` | SPF tree | ✅ |
| `show ospfv3 graph` | Topology graph | ✅ |
| `show ospfv3 ti-lfa` | TI-LFA per-destination repair paths | ✅ |
| `show ospfv3 repair-list [detail]` | TI-LFA repair-list | ✅ |
| `show ospfv3 segment-routing` | SR state | ✅ |
| `show ospfv3 srv6` | SRv6 state (locator, End/End.X SIDs) | ✅ |
| `show ospfv3 flex-algo` | Flexible Algorithm (RFC 9350) state | ✅ |
| `show ospfv3 vrf <name> …` | Per-VRF (redirected; mirrors above) | per sibling |

## IS-IS (`zebra-rs/src/isis/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show isis` | Basic IS-IS information | text only |
| `show isis summary` | Summary | text only |
| `show isis route [detail]` | Route table (TI-LFA/SR-MPLS/SRv6) | ✅ |
| `show isis topology` | SPF tree (per-AFI) | ✅ |
| `show isis database [detail]` | LSDB | ✅ |
| `show isis neighbor [detail]` | Neighbors | ✅ |
| `show isis interface [detail]` | Interfaces | ✅ |
| `show isis dis statistics` | DIS election statistics | ✅ |
| `show isis dis history` | DIS election history | ✅ |
| `show isis hostname` | Dynamic hostnames | ✅ |
| `show isis spf [detail]` | SPF computation results | ✅ |
| `show isis graph` | Topology graph | ✅ |
| `show isis graceful-restart` | GR per-adjacency state (RFC 5306) | ✅ |
| `show isis checkpoint` | GR on-disk checkpoint | ✅ |
| `show isis ti-lfa` | TI-LFA repair paths (graph view) | ✅ |
| `show isis repair-list [detail]` | TI-LFA repair-list | ✅ |
| `show isis egress-protection` | Mirror SID egress-protection entries | text only |
| `show isis fast-reroute summary` | Per-level TI-LFA counters | text only |
| `show isis fast-reroute prefix <A.B.C.D/M> detail` | Per-prefix TI-LFA repair | text only |
| `show isis flex-algo` | Flexible Algorithm (RFC 9350) state | text only |
| `show isis flex-algo route [algorithm <id>]` | Per-algorithm IPv4 routes | text only |
| `show isis vrf <name> …` | Per-VRF (redirected; mirrors above) | per sibling |

## IPv6 ND (`zebra-rs/src/nd/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show ipv6 nd` | ND per-interface summary | ✅ |
| `show ipv6 nd interface [<ifname>]` | ND detail per interface | ✅ |

## BFD (`zebra-rs/src/bfd/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show bfd` | Session summary | ✅ |
| `show bfd peers [<addr>]` | Per-peer detail (FRR-style) | ✅ |
| `show bfd counters` | Per-session control-packet counters | ✅ |

## STAMP (`zebra-rs/src/stamp/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show stamp` | Session summary | ✅ |
| `show stamp session` | Per-session detail | ✅ |
| `show stamp statistics` | Sender/reflector packet counters | ✅ |

## Policy / route-policy objects (`zebra-rs/src/policy/show.rs`)

| Command | Description | JSON |
|---|---|---|
| `show policy` | Route policies | text only |
| `show prefix-set [name <name>]` | Prefix sets | text only |
| `show community-set [name <name>]` | Community sets | text only |
| `show ext-community-set [name <name>]` | Extended-community sets | text only |
| `show large-community-set [name <name>]` | Large-community sets | text only |
| `show as-path-set [name <name>]` | AS-path sets | text only |
| `show key-chains [name <name>]` | Key chains | text only |

---

## Coverage summary

| Module | Commands | JSON (incl. ◐ placeholder) | Text only |
|---|---:|---:|---:|
| RIB / forwarding / config | 22 | 19 | 3 |
| BGP | 25 | 20 | 5 |
| OSPFv2 | 13 | 13 | 0 |
| OSPFv3 | 12 | 12 | 0 |
| IS-IS | 21 | 14 | 7 |
| IPv6 ND | 2 | 2 | 0 |
| BFD | 3 | 3 | 0 |
| STAMP | 3 | 3 | 0 |
| Policy objects | 7 | 0 | 7 |

(Counts exclude the `vrf <name>` redirect forms, which inherit their
sibling's status. Some BGP "JSON" entries are ◐ placeholders that honor
the flag but still emit an empty array/object.)

### Remaining gaps (still text only)

These are the commands to convert to reach "all `show` commands support
JSON":

- **RIB:** `show task`, `show version` (both use the config-tree /
  manager dispatch that does not carry the `-j` flag — needs plumbing),
  and `show evpn vni all` (lives in the BGP/EVPN module)
- **BGP:** `show bgp <afi> <prefix> longer-prefix`,
  `show bgp evpn ethernet-segment`, `show bgp attributes`,
  `show bgp neighbor <addr> rtcv4`
- **IS-IS:** `show isis` (root), `summary`, `egress-protection`,
  `fast-reroute …`, `flex-algo [route …]`
- **Policy objects:** every `show … -set` / `show policy` /
  `show key-chains` command

### Placeholder JSON (BGP ◐ — honors `-j`, emits empty array/object)

`show bgp evpn`, `labeled-unicast`, `flowspec [ipv6]`,
`sr-policy [ipv6]`, `link-state`, `mup [mup-c …]`, and the
`advertised-routes evpn` / `received-routes evpn` neighbor views. The
flag is wired but the per-AFI serialization schema is not yet filled in.
