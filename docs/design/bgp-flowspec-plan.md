# BGP Flowspec (IPv4 + IPv6) — Design & Phasing Plan

Tracks the implementation of BGP Flow Specification (RFC 8955 / 8956,
validation per RFC 9117) for zebra-rs, covering IPv4 and IPv6 unicast
Flowspec (AFI 1/2, SAFI 133). This document is the living plan + status:
it captures the RFC surface, how FRR/Cisco map the hard part, the
architecture decisions, the YANG schema, the phase-by-phase slice, and
**what has landed vs what's left** so a contributor can resume without
the conversation history.

Read this first if you're touching `crates/bgp-packet/src/attrs/nlri_flowspec.rs`,
`flowspec_action.rs`, the `MpReachAttr::Flowspec` / `MpUnreachAttr::Flowspec`
arms, the `LocalRib.flowspec_v4/v6` tables, `bgp::route::route_flowspec_*`,
`bgp::flowspec` (validation), or `zebra-rs/yang/zebra-bgp-flowspec.yang`.

## Status (updated 2026-05-30)

**The control plane is complete** for IPv4 + IPv6 unicast Flowspec
(SAFI 133): negotiate → receive → validate (RFC 9117) → Loc-RIB
best-path → re-advertise to peers, with a per-neighbor validation
toggle. All slices below are merged to `main`. The dataplane (Phase 4)
and a few validation refinements remain — see **Leftover work**.

| Slice            | PR    | What landed                                                                                  |
| ---------------- | ----- | -------------------------------------------------------------------------------------------- |
| 0 — codec        | #1046 | `FlowspecNlri` (v4+v6 components), action ext-comms, §5.1 `Ord`, round-trip tests            |
| 1a — capability  | #1048 | `flowspec-ipv4`/`flowspec-ipv6` family, MP capability negotiation, `show ip bgp summary` label |
| 1b — receive     | #1050 | `AdjRibFlowspecTable`, `route_flowspec_update/withdraw`, `show ip bgp flowspec [ipv6]`        |
| 2 — validation   | #1052 | RFC 9117 `flowspec_validate` (b.1 originator-match + b.2 AS_PATH-local), surfaced in `show`   |
| (rename)         | #1053 | `ipv4-flowspec`→`flowspec-ipv4` (+ v6) for type-first consistency with `label-v4`            |
| 3a — Loc-RIB     | #1056 | `LocalRibFlowspecTable` (cands+selected) + best-path; `show` reads the Loc-RIB                |
| 3b — advertise   | #1057 | `route_advertise/withdraw_flowspec_to_peers`, gated on validity; `AdjRib<Out>` flowspec       |
| 3c — knob        | #1058 | per-neighbor `flowspec { validation <bool> }` (`zebra-bgp-flowspec.yang`)                    |

### Where the pieces live

- **Codec:** `crates/bgp-packet/src/attrs/nlri_flowspec.rs` (NLRI),
  `flowspec_action.rs` (action ext-comms), `MpReachAttr::Flowspec` /
  `MpUnreachAttr::Flowspec` in `mp_reach.rs` / `mp_unreach.rs`.
- **Validation:** `zebra-rs/src/bgp/flowspec.rs`
  (`flowspec_validate`, `flowspec_validate_with_mode`).
- **RIB + receive + advertise:** `zebra-rs/src/bgp/route.rs`
  (`route_flowspec_*`, `LocalRibFlowspecTable`,
  `route_advertise/withdraw_flowspec_to_peers`); `adj_rib.rs`
  (`AdjRibFlowspecTable`).
- **Config / YANG:** `zebra-afi-safi.yang` (family enum),
  `zebra-bgp-flowspec.yang` (validation knob),
  `config/configs.rs::Args::afi_safi`,
  `bgp/config.rs::config_flowspec_validation`.
- **Show:** `zebra-rs/src/bgp/show.rs` (`show_bgp_flowspec`),
  `exec.yang` (`show ip bgp flowspec`).

## Locked decisions (2026-05-30)

| Decision        | Choice                                | Consequence                                                                 |
| --------------- | ------------------------------------- | --------------------------------------------------------------------------- |
| **Scope**       | IPv4 **and** IPv6 unicast (SAFI 133)  | VPN flowspec (SAFI 134), `redirect-to-VRF` dataplane deferred to a later series |
| **Dataplane**   | Control-plane first, `tc` later       | Phases 0–3 ship receive/validate/RIB/advertise/show with **no install**; the `tc`-flower netlink southbound is a dedicated Phase 4 track (mirrors how the VPNv6-leak series shipped control-plane-only) |
| **Origination** | Receive / reflect first               | Router consumes + re-advertises peer flowspec (RR / consumer role). Local-rule config (match+action YANG) and self-origination deferred to a later PR |

Branch per phase, smallest-reviewable-PR-first (per project convention).

## RFC surface

| RFC      | Role                                                                    |
| -------- | ----------------------------------------------------------------------- |
| RFC 8955 | IPv4 Flowspec NLRI + traffic-filtering-action extended communities (obsoletes RFC 5575) |
| RFC 8956 | IPv6 Flowspec — prefix `offset`, Flow Label (type 13), `redirect-ipv6`  |
| RFC 9117 | Revised validation procedure (current normative validation — supersedes RFC 8955 §6) |

**SAFIs:** 133 = Flowspec unicast (in scope), 134 = Flowspec L3VPN (deferred).

### NLRI = ordered list of components

A packet matches a flow spec only if it matches **all** components.
Components are strictly ordered by type number on the wire; RFC 8955 §5.1
ordering rules define **rule precedence**, which maps directly to dataplane
filter priority (lowest type/most-specific = highest precedence = applied first).

| Type | IPv4 (8955)        | IPv6 (8956) difference                          |
| ---- | ------------------ | ----------------------------------------------- |
| 1    | Destination Prefix | + `offset` field                                |
| 2    | Source Prefix      | + `offset` field                                |
| 3    | IP Protocol        | "Upper-Layer Protocol" (first non-ext Next Hdr) |
| 4    | Port               | identical                                       |
| 5    | Destination Port   | identical                                       |
| 6    | Source Port        | identical                                       |
| 7    | ICMP Type          | ICMPv6 Type                                     |
| 8    | ICMP Code          | ICMPv6 Code                                     |
| 9    | TCP Flags (bitmask)| identical                                       |
| 10   | Packet Length      | identical                                       |
| 11   | DSCP               | identical                                       |
| 12   | Fragment (bitmask) | IPv6 fragment-header semantics                  |
| 13   | —                  | **Flow Label** (IPv6 only)                      |

Component values use two operator encodings:
- **numeric_op** `{e, a, len, lt, gt, eq}` — ports, lengths, protocol, DSCP.
- **bitmask_op** `{e, a, len, not, match}` — TCP flags, fragment.

`e` = end-of-list, `a` = AND (else OR), `len` = value width `1<<len` octets.
NLRI length field: 1 octet (`< 240`) or 2 octets (`0xfnnn`, up to 4095).

### Actions = transitive extended communities

| Hex                       | Action                | Payload                                       |
| ------------------------- | --------------------- | --------------------------------------------- |
| `0x8006`                  | traffic-rate-bytes    | AS(2) + IEEE-float rate, bytes/s (`0.0` = drop) |
| `0x800c`                  | traffic-rate-packets  | rate in packets/s                             |
| `0x8007`                  | traffic-action        | bit 47 = terminal, bit 46 = sample            |
| `0x8008 / 0x8108 / 0x8208`| rt-redirect (AS2/IPv4/AS4) | redirect to VRF via Route-Target         |
| `0x800d`                  | redirect-ipv6 (8956)  | IPv6-address-specific RT                       |
| `0x8009`                  | traffic-marking       | DSCP value                                    |

Normalized into a dataplane-independent action set:

```rust
enum FlowspecAction {
    Discard,                     // traffic-rate-bytes 0.0
    RateLimitBytes(f32),
    RateLimitPackets(f32),
    Sample,
    Terminal,
    RedirectVrf(RouteTarget),    // dataplane deferred
    RedirectIp(IpAddr),          // dataplane deferred
    MarkDscp(u8),
}
```

### Validation (RFC 9117)

A received flowspec is *valid* only if it embeds a destination-prefix
component **and** the route's originator matches the best-path unicast
route toward that destination (loosely for eBGP; iBGP / "designated
controller" relax this). Must be **re-validated whenever unicast routes
change** — hook the existing NHT / RIB-change notification path
(`bgp/nht.rs`) so revalidation is event-driven, not polled. Invalid rules
stay in Adj-RIB-In but are not installed and not re-advertised. A
per-neighbor `validation { strict | disable }` knob covers the
controller/iBGP relaxation case.

## How FRR / Cisco do it (the lesson)

- **FRR** (`bgpd` + `zebra`): control plane is ordinary MP-BGP. The
  dataplane historically programs **ipset + iptables + `ip rule` + a
  reserved block of policy routing tables**; the GSoC-2022 "Zebra Traffic
  Control" work added a proper **`tc` (netlink)** southbound
  (qdisc/filter/police). FRR supports a subset of components and an
  "interface-set" notion for where rules apply.
- **Cisco IOS-XR / Juniper**: identical control plane; actions expressed
  through native frameworks (XR MQC `class-map`/`policy-map`; Juniper
  auto-generates a firewall filter). Both do RFC validation, v4+v6,
  redirect-to-VRF and redirect-to-nexthop.

**Lesson:** the receive/advertise/RIB control plane is ~standard MP-BGP
and reuses zebra-rs's EVPN/VPNv4 machinery almost entirely. The divergent,
expensive, platform-specific part is **action → dataplane**, and zebra-rs
has *zero* traffic-control southbound today. The plan therefore separates
the cheap, high-reuse control plane from the new, large dataplane build.

## Fit against current zebra-rs

| Layer                                       | Status                              | Anchor                                          |
| ------------------------------------------- | ----------------------------------- | ----------------------------------------------- |
| `Safi::Flowspec = 133`                      | **exists**                          | `crates/bgp-packet/src/afi.rs:38`               |
| Ext-community framework                     | **exists**, extend                  | `attrs/ext_com.rs`, `ext_com_type.rs`           |
| MP_REACH/UNREACH AFI/SAFI dispatch          | **exists** (VPNv4/EVPN/MUP)         | `attrs/mp_reach.rs:111-361`                     |
| Capability negotiation per family           | **generic** for any SAFI            | `caps/mp.rs`, `bgp/cap.rs:30-48`                |
| Per-peer family enable `config.mp`          | **exists**; parser needs new names  | `bgp/peer.rs:202-209`, `config/configs.rs:125`  |
| **Exact-match RIB** (not prefix-trie)       | **template** = `LocalRibEvpnTable`  | `bgp/route.rs:826-831, 932-943`                 |
| Unicast Loc-RIB + NHT (for validation)      | **exists**                          | `bgp/nht.rs`                                     |
| **tc / policer / ACL southbound**           | **does NOT exist — Phase 4 build**  | nothing in `fib/`, `rib/`                       |
| VRF tables / l3mdev (redirect-to-VRF)       | **exists** (deferred use)           | `fib/netlink/handle.rs:1649-1717`               |

Closest end-to-end template: **EVPN Type-5 series** (exact-match RIB, new
`MpReachAttr` variant, `route_evpn_update()`) crossed with the
**VPNv6-leak series** (control-plane-only landing, dataplane deferred).

## Architecture

```
                        ┌─────────────────────────────────────────┐
   wire  ───────────►   │ crates/bgp-packet                        │  Phase 0
                        │  FlowspecNlri (component TLV codec, v4/v6)│
                        │  FlowspecAction ext-comm sub-types        │
                        │  Ord per RFC 8955 §5.1 (= filter prio)    │
                        └───────────────┬─────────────────────────┘
                          MpReachAttr::Flowspec / MpUnreachAttr::Flowspec
                        ┌───────────────▼─────────────────────────┐
                        │ zebra-rs/src/bgp                          │
   Adj-RIB-In  ─────►   │  AdjRibFlowspecTable<D>                   │  Phase 1
   validation  ─────►   │  validate vs unicast Loc-RIB (RFC 9117)   │  Phase 2
   Loc-RIB     ─────►   │  LocalRib.flowspec_v4 / flowspec_v6       │  Phase 3
   re-advertise─────►   │  update-group flush to flowspec peers     │
                        └───────────────┬─────────────────────────┘
                              rib::Message::Flowspec{Add,Del}  (stubbed P1-3)
                        ┌───────────────▼─────────────────────────┐
                        │ zebra-rs/src/rib + fib  (NEW southbound)  │  Phase 4
                        │  tc qdisc + flower filter +               │
                        │  police / skbedit  via netlink            │
                        └───────────────────────────────────────────┘
```

### Codec (`crates/bgp-packet`) — Phase 0

New `nlri_flowspec.rs` mirroring `nlri_vpnv4.rs` / `nlri_evpn.rs`:
- `FlowspecComponent` enum (the 13 component types) and
  `FlowspecNlri { components: Vec<FlowspecComponent> }`, AFI-parameterized so
  one vec serves v4 (types 1–12) and v6 (types 1–13 with prefix `offset`).
- `MpReachAttr::Flowspec { afi, nlri: Vec<FlowspecNlri> }` and
  `MpUnreachAttr::Flowspec` — **no next-hop** (MP_REACH next-hop length 0).
- Extend `ext_com_type.rs` with the `0x80xx` action sub-types + typed
  accessors (`as_traffic_rate`, `as_traffic_action`, `as_redirect_rt`,
  `as_traffic_marking`).
- **`Ord` on `FlowspecNlri` per RFC 8955 §5.1** (type-ascending,
  more-specific-prefix wins, else `memcmp`) so the `BTreeMap` iterates in
  rule-precedence order → reusable as dataplane filter priority.
- Round-trip parse/emit tests in `crates/bgp-packet/tests`.

### RIB / control plane (`zebra-rs/src/bgp`) — Phases 1–3

Follow the **EVPN exact-match pattern**, *not* `LocalRibTable<P>`
(flowspec is not a longest-prefix lookup — overlapping rules coexist):
- `LocalRib { … flowspec_v4: BTreeMap<FlowspecNlri, BgpRib>, flowspec_v6: … }`
  (`route.rs:932`).
- `AdjRibFlowspecTable<D>` paralleling `AdjRibEvpnTable<D>` (`adj_rib.rs:92`).
- `route_flowspec_update()` / `_withdraw()` paralleling `route_evpn_update()`,
  dispatched from `route_from_peer()` (`route.rs:3239`).
- Best-path: no MED / AS-path install semantics — selection is "valid?" +
  precedence (from `Ord`). Keep simple (first valid wins).
- `cap.rs:30` `CapAfiMap::new()` gains `(Ip,133)` and `(Ip6,133)`;
  `config/configs.rs:125` `Args::afi_safi()` gains `flowspec-ipv4` /
  `flowspec-ipv6`; `show.rs:76` label map gets the strings.

### RIB message channel — Phase 4

`rib::Message` (`rib/inst.rs:32`) gains
`FlowspecAdd { afi, nlri, actions, ifindex: Option<u32> }` /
`FlowspecDel { afi, nlri }`, with new async `FibHandle::flowspec_install /
uninstall`. Stubbed/logged in Phases 1–3; real `tc`-flower (qdisc + flower
classifier + `police`/`skbedit` actions, filter `prio` from the `Ord`) in
Phase 4. `netlink-packet-route` (the route-centric fork) lacks
`RTM_NEW{T,Q}FILTER` / `TCA_*` and must be extended (or raw netlink used).
VPP's classifier/ACL is the natural future high-performance target.

## YANG schema

Three pieces, following `zebra-bgp-evpn.yang` / `zebra-bgp-redistribute.yang`
conventions (kebab-case module, presence containers, augment into
`…/router/bgp/afi-safi`, validated by `yang_load_tests` in
`config/manager.rs:1183`).

**(a) Family activation** — extend `zebra-afi-safi.yang` `afi-safi` grouping
enum with `flowspec-ipv4`, `flowspec-ipv6`; add matching arms to
`Args::afi_safi()` (`config/configs.rs:125`). Neighbor activation then works
unchanged via the existing per-neighbor `afi-safi/<name>/enabled` path:

```
set router bgp 65000 neighbor 10.0.0.1 afi-safi flowspec-ipv4 enabled true
set router bgp 65000 neighbor 2001:db8::1 afi-safi flowspec-ipv6 enabled true
```

**(b) Per-neighbor validation knob** — augment the neighbor afi-safi:

```yang
leaf validation { type enumeration { enum strict; enum disable; } default strict; }
```

**(c) `zebra-bgp-flowspec.yang` (prefix `zbf`) — deferred to the origination
PR.** Local rule definition (match criteria + action choice) lives here when
self-origination lands; the receive/reflect milestones do not need it.
Sketch retained for the later series:

```yang
container flowspec {
  list rule {
    key "name";
    leaf afi { type enumeration { enum ipv4; enum ipv6; } }
    container match {
      leaf destination-prefix { type inet:ip-prefix; }
      leaf source-prefix      { type inet:ip-prefix; }
      leaf-list protocol         { type uint8; }
      leaf-list destination-port { type string; }   // "=80", ">=1024&<=2048"
      leaf-list source-port      { type string; }
      leaf-list packet-length    { type string; }
      leaf dscp       { type uint8 { range "0..63"; } }
      leaf tcp-flags  { type string; }
      leaf fragment   { type string; }
      leaf flow-label { type uint32; }               // ipv6 only
    }
    container action {
      choice kind {
        leaf rate-limit-bytes   { type uint64; }     // 0 = discard
        leaf rate-limit-packets { type uint64; }
        leaf discard            { type empty; }
        leaf redirect-vrf       { type string; }
        leaf redirect-ip        { type inet:ip-address; }
        leaf mark-dscp          { type uint8 { range "0..63"; } }
      }
      leaf sample { type boolean; default false; }
    }
  }
}
```

`config.rs` handlers follow the `config_redistribute_*` / `config_vrf_evpn_*`
pattern (`config.rs:1622`, `vrf_config.rs:358`) — one callback per leaf into a
`BgpFlowspecConfig` map on `Bgp`.

## Phasing (status)

| Phase     | Scope                                                              | Status                                           |
| --------- | ------------------------------------------------------------------ | ------------------------------------------------ |
| 0         | Codec: `FlowspecNlri` (v4+v6) + action ext-comms + `Ord` + tests   | ✅ merged (#1046)                                |
| 1a / 1b   | Capability + receive → Adj-RIB-In + `show ip bgp flowspec`         | ✅ merged (#1048, #1050)                         |
| 2         | RFC 9117 validation vs unicast Loc-RIB                             | ✅ merged (#1052) — computed live, see leftovers |
| 3a/3b/3c  | Loc-RIB best-path + re-advertise + per-neighbor validation knob    | ✅ merged (#1056, #1057, #1058)                  |
| 4         | Dataplane: `tc`-flower netlink southbound                          | ⬜ not started (the large, isolated build)       |

Phases 0–3 deliver a standards-compliant, interoperable,
route-reflector-capable Flowspec **control plane**, mirroring how the v6
BGP stack shipped control-plane-first. Phase 4 carries the real
engineering risk.

## Leftover work

### Control-plane refinements (Phase 3 leftovers)

1. **Event-driven re-validation.** RFC 9117 validity is currently
   computed at receive/withdraw and at `show` time (see
   `route_flowspec_propagate` and `show_bgp_flowspec`). A flow spec that
   arrives *before* its covering unicast route — or whose covering route
   later changes originator or disappears — is not automatically
   re-evaluated, so its advertised state can go stale. Needs a
   **perf-safe trigger**: a naive hook in the unicast update path would
   re-validate every flow spec on every unicast UPDATE (O(N) per route
   during full-table convergence). Options: a prefix-indexed reverse map
   (flow specs keyed by covering prefix), debounced re-validation at
   convergence / unicast EoR, or piggybacking the NHT notification
   machinery. `flowspec_validate_with_mode` is built to be reused by the
   trigger.
2. **RFC 8955 rule-c.** The "no more-specific unicast route received
   from a different neighboring AS than the best-match route" check is
   not implemented. Self-contained addition to `flowspec_validate` (scan
   the unicast RIB under the destination prefix); low value in common
   deployments, no YANG/config impact.

### Phase 4 — dataplane (`tc`-flower southbound)

The big, isolated build. zebra-rs has **no** traffic-control southbound
today, and the `netlink-packet-route` fork lacks `RTM_NEW{T,Q}FILTER` /
`TCA_*`.

- Add `rib::Message::FlowspecAdd { afi, nlri, actions, ifindex }` /
  `FlowspecDel` (`rib/inst.rs`) and async `FibHandle::flowspec_install /
  uninstall` (`fib/netlink/`). Stub/log until the southbound lands; the
  hook point is `route_flowspec_propagate` (alongside the advertise).
- Map the normalized `FlowspecAction` set → a `tc` **flower** classifier
  (matching the flow spec components) plus actions: `police` (rate-limit
  / drop), `skbedit`/`pedit` (DSCP marking), `mirred` / route (redirect).
  Filter `prio` comes from the §5.1 `Ord` so rules apply in precedence
  order.
- Extend the `netlink-packet-route` fork (or use raw netlink) for the tc
  message types and attributes.
- `redirect-to-VRF` reuses the existing VRF / l3mdev table infra
  (`fib/netlink/handle.rs`).
- VPP's classifier/ACL is the natural future high-performance target.

### Deferred (later series)

- **VPN flowspec** (SAFI 134) + `redirect-to-VRF` propagation (`Safi`
  enum needs a `FlowspecVpn = 134` variant).
- **`redirect-to-IP`** / RFC 8956 `redirect-ipv6` (a 20-octet
  IPv6-address-specific community, not yet decoded — see
  `flowspec_action.rs`).
- **Local flow-spec rule origination** (operator-configured match +
  action) — planned extension to `zebra-bgp-flowspec.yang`.
- **Add-path / update-group batching** for flowspec advertise (current
  send is one NLRI per UPDATE, direct via `send_flowspec_one`).
- **JSON** output for `show ip bgp flowspec` (returns `[]` today).
- VPP classifier/ACL southbound.
