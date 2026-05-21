# BGP ↔ IS-IS Flex-Algorithm — deferred follow-ups

Status as of 2026-05-21. The integration spine landed in
[`bgp-flex-algo-integration.md`](bgp-flex-algo-integration.md) over
12 PRs (#670, #675, #679, #681, #683, #684, #686, #687, #690, #692,
#697, #701). This file lists the work consciously deferred so the
spine could ship — none of these block production use of the
end-to-end path for the common case (default-VRF IPv4 unicast,
single Color, single nexthop, strict fallback).

Each entry: **what / why deferred / where in code / suggested PR
size**. Pick any one independently.

## Resolver semantics

### 1. RFC 9256 §2.5 fallback ordering

**What:** When a route carries multiple Color extended communities,
walk them in attribute order and try each binding. v1 already does
this for "unbound color → try next", but the spec also defines
preference-based fallback where higher-preference SR Policies are
tried first and per-color preference values shape the ordering.

**Why deferred:** Single-color is the common case; the resolver
landed as "first hit wins" with a stub for the multi-color path.
Real fallback needs the Tunnel-Encap attribute Preference sub-TLV
(type 6) decoded — currently parse-and-store opaque.

**Where:** `resolve_flex_algo_label_inner` in
`zebra-rs/src/bgp/route.rs`. The Preference decoder belongs in
`crates/bgp-packet/src/attrs/tunnel_encap.rs` (extend the existing
opaque `TunnelSubTlv` enum with typed variants).

**Size:** small (~150 lines: Preference decode + resolver re-order
+ tests).

### 2. CO-bits semantics (draft-ietf-idr-bgp-ct §3.2.1)

**What:** The Color extended community has 2 CO bits in its Flags
field that select transport-class matching mode (00 default, 01 any
transport supporting color, 10 SR-aware transport, 11 reserved). v1
parses CO bits via `Color::co_bits()` but the resolver ignores them
and treats every entry as CO=00.

**Why deferred:** CO ≠ 00 is rare in deployments today; the BGP-CT
spec is still in IDR working-group.

**Where:** `resolve_flex_algo_label_inner` in
`zebra-rs/src/bgp/route.rs`. Add a CO-bits filter on the per-color
loop. May need a per-binding flag on `ColorPolicy::bindings` to
record which CO modes a binding satisfies.

**Size:** small (~100 lines).

### 3. ECMP-aware shadow

**What:** `Bgp::flex_algo_routes` keeps only the **first**
`FlexAlgoNexthop` per `(algo, prefix)` (see `process_rib_msg`).
IS-IS's `FlexAlgoRoute` already carries the full ECMP set; the BGP
shadow flattens it.

**Why deferred:** Forwarding works through any one of the ECMP
nexthops — the kernel FIB will load-balance independently if BGP
installs multiple Uni members per route. v1 was easier with a
1:1 shadow.

**Where:** Change `Bgp::flex_algo_routes` value type to
`Vec<FlexAlgoNexthop>`. Extend `fib_install_v4` to build a
`Nexthop::Multi` when more than one nexthop is present. Update
`color_aware_nht_tests` fixtures.

**Size:** medium (~250 lines: shadow surgery + multi-nexthop
install + tests).

## Coverage gaps

### 4. Per-VRF Color → Flex-Algo binding

**What:** Today `Bgp::color_policy` and `Bgp::flex_algo_routes` only
exist on the global `Bgp`; per-VRF runtimes pass `None` for both
fields on `BgpTop` (see `zebra-rs/src/bgp/vrf/inst.rs::process_msg`
and the comment "Color → Flex-Algo binding is a default-VRF concept
today; per-VRF support is a follow-up").

**Why deferred:** The IS-IS per-algo RIB is a single-instance global
concept; per-VRF IS-IS isn't a thing in zebra-rs today either.
Operators run BGP-VPN over a global IS-IS underlay and the colour-
to-algo binding is a property of that underlay.

**Where:** Decide whether to move `color_policy` onto `BgpVrf` (per-
VRF binding tables) or just thread the global instance's reference
into the per-VRF `BgpTop`. Likely the latter for the common case
plus an optional per-VRF override.

**Size:** medium (~300 lines, mostly plumbing).

### 5. IPv6 colour-aware NHT

**What:** `fib_install_v4` handles the IPv4 install path; the IPv6
equivalent (`fib_install_v6` if/when it exists, or whatever sends
the v6 Loc-RIB winner to the FIB) doesn't push a colour-based
label.

**Why deferred:** IPv6 BGP Loc-RIB is shallower in zebra-rs today
(most v6 traffic in deployments today is direct, not service-
routed). The fix is symmetric to v4 once the v6 install path
exists; `Bgp::flex_algo_routes` would need a sibling for v6
prefixes (`Isis::rib_flex_algo` is IPv4-only today too —
see follow-up #6).

**Where:** `zebra-rs/src/bgp/route.rs`, `zebra-rs/src/isis/rib.rs`.

**Size:** medium (~400 lines: per-algo IPv6 RIB + IPv6 publish +
v6 resolver + tests).

### 6. IS-IS per-algo IPv6 RIB

**What:** `Isis::rib_flex_algo` is `Levels<BTreeMap<u8,
PrefixMap<Ipv4Net, SpfRoute>>>`. Per-algo IPv6 (TLV 236 / 237) is
not built. This blocks both per-algo IPv6 forwarding inside IS-IS
and the v6 colour-aware NHT above.

**Why deferred:** Bigger lift than v4 (requires per-algo MT 2 SPF
or per-algo single-topology v6 — design decision pending).

**Where:** `zebra-rs/src/isis/rib.rs`. Mirror
`build_rib_from_flex_algo` for IPv6.

**Size:** large (~500 lines).

### 7. ENHE + colour label push

**What:** RFC 8950 (IPv4-over-IPv6 NEXT_HOP) routes install via
`Nexthop::Link(ifindex)` rather than `Nexthop::Uni`. The colour-
aware label push in `fib_install_v4` only patches the `Uni` case;
ENHE routes silently skip the label.

**Why deferred:** ENHE + Color is an unusual combination; the
production paths we care about are either ENHE without Color or
Color without ENHE. Fix is straightforward but needs the
`Nexthop::Link` variant to grow an MPLS stack (today it doesn't).

**Where:** `crates/zebra-rs/src/rib/nexthop/inst.rs` (extend
`Nexthop::Link` or wrap in a new variant), then `fib_install_v4` in
`zebra-rs/src/bgp/route.rs`.

**Size:** small-medium (~200 lines).

## IS-IS-side follow-ups

### 8. SRLG-exclude enforcement in per-algo SPF

**What:** `flex_algo.config[algo].srlg_exclude` is stored but not
consulted by `graph_flex_algo`. The constraint is in the FAD on the
wire but the SPF graph builder skips it.

**Why deferred:** Needs a `peer_link_srlg` cache (we don't currently
parse peer SRLG advertisements off TLV 138/139). Adding the cache
mirrors the `peer_link_affinity` pattern (PR #616).

**Where:**
1. New `peer_link_srlg` cache in `zebra-rs/src/isis/inst.rs` +
   parse in `lsdb::rebuild_sys_state`.
2. Extend `link_passes_fad` in `zebra-rs/src/isis/flex_algo.rs`
   with the SRLG-exclude check.

**Size:** medium (~350 lines: cache + parse + predicate + tests).

### 9. Per-algo TI-LFA

**What:** `build_rib_from_flex_algo` explicitly skips TI-LFA backup
stamping (see the doc-comment). Per-algo routes have no fast-
reroute today.

**Why deferred:** The FAD topology may not admit the algo-0 TI-LFA
repair; per-algo repair needs per-algo TI-LFA computation which is
a sizeable extension to the existing `tilfa_repair_path`.

**Where:** `zebra-rs/src/isis/tilfa.rs` (parameterize by algo +
FAD), `zebra-rs/src/isis/rib.rs` (call from per-algo build).

**Size:** large (~600 lines).

### 10. FAD non-IGP metric types

**What:** FAD `metric_type` byte is parsed (1 = MinUnidirLinkDelay,
2 = TeDefault) but `graph_flex_algo` always uses the IGP metric.

**Why deferred:** Needs per-link delay metric parsing (RFC 8570
sub-TLV 33) and per-link TE metric (RFC 5305 sub-TLV 18) caches —
see notes in `flex-algo-roadmap.md` §7.

**Where:** New `peer_link_delay` / `peer_link_te_metric` caches in
`zebra-rs/src/isis/inst.rs`, parse in `lsdb::rebuild_sys_state`,
metric selection in `graph_flex_algo`.

**Size:** medium-large (~400 lines).

## Testing

### 11. BDD integration tests for the Flex-Algo path

**What:** Multi-instance topology test exercising the full chain:
two IS-IS speakers + one BGP speaker, set FAD 128, configure
`color-policy color 100 flex-algorithm 128`, originate a BGP route
with `color:0:100`, verify kernel FIB on the egress shows the
algo-128 outer label.

**Why deferred:** BDD harness setup is a separate body of work; per
[`zebra-rs-ci-and-merge-rules.md`](../../zebra-rs-ci-and-merge-rules.md)
memory BDD is excluded from CI gates. Defer until the harness for
similar multi-protocol scenarios exists (or piggyback on the
existing IS-IS Flex-Algo BDD work flagged in
`flex-algo-roadmap.md` §8).

**Where:** `bdd/` directory.

**Size:** medium.

### 12. Live-topology / interop validation

**What:** Run zebra-rs as both ingress and egress against FRR /
IOS-XR / Junos in a real lab; verify Color → Flex-Algo steering
interops on the wire.

**Why deferred:** No infrastructure in zebra-rs CI for live-vendor
interop. Useful before declaring production-ready.

**Where:** External lab / CI harness; results documented in this
file (or a new lab-notes doc) when run.

## Wire-format completeness

### 13. SRv6 service TLVs full decode (RFC 9252)

**What:** PR #683 added structured decode for Prefix-SID
Label-Index + Originator-SRGB but kept the SRv6 L3/L2 Service
TLVs (types 5 / 6) as opaque bytes. A full SRv6 services
implementation needs the nested SRv6 SID Information / SRv6 SID
Structure sub-sub-TLVs.

**Why deferred:** SRv6 services is its own substantial track. The
opaque parse-and-store keeps round-trip exact so this fills in
without touching senders.

**Where:** `crates/bgp-packet/src/attrs/prefix_sid.rs` (extend
`PrefixSidTlv::Srv6L3Service` / `Srv6L2Service` from `Vec<u8>` to
structured variants).

**Size:** medium (~400 lines: nested sub-TLV codec + tests).

### 14. Tunnel Encap sub-TLV typed decoders

**What:** PR #684 landed the Tunnel Encap attribute as opaque
sub-TLVs. Phase 2.1's `set color` / `match color` route-map work
landed without needing typed sub-TLVs because Color rides on a
different attribute (extcomm) — but the Tunnel-Encap Color sub-TLV
(type 4) and Preference sub-TLV (type 6) are still opaque.

**Why deferred:** No consumer needs them yet. Once the resolver
grows preference-based fallback (#1 above) the Preference sub-TLV
becomes load-bearing.

**Where:** `crates/bgp-packet/src/attrs/tunnel_encap.rs`. Promote
opaque variants to typed.

**Size:** small (~200 lines per sub-TLV type, do as needed).

### 15. SR Policy SAFI (SAFI 73) + draft-ietf-idr-segment-routing-te-policy

**What:** No support for receiving SR Policy NLRI from a
controller. zebra-rs today is a client of `color_policy` binding
configured locally; a controller-driven deployment would use
SAFI 73 to advertise SR Policies.

**Why deferred:** Out of scope per the design doc — "no PCEP". SR
Policy receive overlaps in spirit with controller-driven model
which we explicitly skipped.

**Where:** New `crates/bgp-packet/src/sr_policy.rs` + NLRI codec
+ SAFI 73 registration; consumer integration on the BGP side.

**Size:** large (~800 lines).

## Operations

### 16. `show bgp flex-algo` command

**What:** Operators can see per-route Color + Label-Index via
`show ip bgp <prefix>` (PR #692). There's no aggregate view:
"what colors does this router currently bind, and how many routes
match each?"

**Why deferred:** Single-route view covers most debugging needs;
aggregate is nice-to-have.

**Where:** `zebra-rs/src/bgp/show.rs` — new `show_bgp_flex_algo`
callback registered in `show_build`. YANG addition under
`/show/bgp/flex-algo`.

**Size:** small (~200 lines).

### 17. `show isis flex-algo route` JSON output

**What:** PR #681 added `show isis flex-algo` and `show isis
flex-algo route` with text output; existing IS-IS show commands
also have JSON output (`show isis route` for instance). The
flex-algo equivalents don't.

**Why deferred:** Text was sufficient for operators on landing.

**Where:** `zebra-rs/src/isis/show.rs`. Mirror the JSON path in
`show_isis_route`.

**Size:** small (~150 lines).

### 18. BGP-LS Flex-Algo advertisement (Phase 6 from the original plan)

**What:** zebra-rs could advertise its IS-IS Flex-Algo state to a
controller via BGP-LS (SAFI 71/72) per RFC 9551 / RFC 9552. Not
needed for the Color-into-Flex-Algo forwarding case (that's local-
config-driven); only relevant when a controller wants visibility.

**Why deferred:** Per the original integration plan: "Not required
for the BGP-steers-into-Flex-Algo use case... recommend deferring
until a concrete consumer exists."

**Where:** New `crates/bgp-packet/src/bgp_ls/` codec; consumer on
the BGP side.

**Size:** large (~1500 lines, multi-PR).

## Quick-pick recommendations

If picking up one item next, the ranking by value-per-line:

1. **#16 (`show bgp flex-algo`)** — cheap, immediately useful to
   operators, low risk.
2. **#8 (SRLG-exclude enforcement)** — closes a known FAD-
   constraint gap; pattern matches existing `peer_link_affinity`
   work.
3. **#1 (RFC 9256 §2.5 fallback)** — first thing a multi-Color
   deployment will need; pure-function unit-testable.
4. **#3 (ECMP-aware shadow)** — easy win once anyone runs
   topologies with parallel paths to the egress.

Larger investments (#6 IPv6 RIB, #9 per-algo TI-LFA, #15 SR
Policy SAFI, #18 BGP-LS) should each gate on having a concrete
consumer.
