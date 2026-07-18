# IPv6 PIM-SM/SSM and MLD — Architecture and Phasing Plan

Status: **proposed — revised after adversarial review against the implemented IPv4 code**
(see the appendix for the review deltas). The intended delivery order is IPv6 SSM first,
then ASM/static-RP, LAN and VRF parity, BSR, and finally Embedded-RP. IPv4 behavior and
its existing management surface remain compatible throughout the work.

The implementation shares one compile-time-generic PIM protocol core between address
families: a single `Pim<A: PimAf>` actor monomorphized per `(VRF, AF)` instance. It must
not duplicate the IPv4 module, and it must not degrade the TIB into an unvalidated
`IpAddr` table in which IPv4 and IPv6 state can mix.

---

## 1. Goal and scope

Deliver IPv6 PIM Sparse Mode and Source-Specific Multicast as a first-class zebra-rs
address family, including:

- PIMv6 Hello, neighbor and DR election over link-local transport.
- Join/Prune, Assert, Register/Register-Stop, SPT switchover and `(S,G,rpt)` state.
- MLDv1 compatibility and an MLDv2 querier with group/source membership.
- IPv6 SSM using `FF3x::/32` by default.
- Static IPv6 RP mappings, IPv6 BSR, and Embedded-RP.
- Linux MRT6 MIF/MFC programming and kernel upcalls.
- IPv6 RPF through the existing dual-stack, VRF-aware RIB NHT API (landed in the VRF
  phase of the IPv4 arc).
- Default-table and per-VRF operation.
- Text and JSON show commands, YANG configuration and live BDD coverage.

The first supported release boundary is the SSM vertical slice: MLDv2 `(S,G)` report →
PIMv6 Join → Linux MRT6 forwarding → delivery of real UDPv6 traffic. ASM and dynamic RP
discovery follow as independent increments.

### Non-goals

This arc does not add MSDP/Anycast-RP, AutoRP, PIM-DM, State Refresh, BFD for PIM,
mtrace, an MLD proxy, MLAG/VXLAN multicast coupling, or multicast ECMP rebalancing.

---

## 2. Standards surface

| RFC | Role |
|---|---|
| [RFC 7761](https://www.rfc-editor.org/rfc/rfc7761) | PIM-SM for IPv4 and IPv6, including PIMv6 checksum and transport rules |
| [RFC 4607](https://www.rfc-editor.org/rfc/rfc4607.html) | IPv6 SSM and the `FF3x::/32` allocation |
| [RFC 3810](https://www.rfc-editor.org/rfc/rfc3810) | MLDv2 source-filtering and querier behavior |
| [RFC 2710](https://www.rfc-editor.org/rfc/rfc2710) | MLDv1 compatibility |
| [RFC 5059](https://www.rfc-editor.org/rfc/rfc5059) | IPv6 Bootstrap Router behavior and scoped zones |
| [RFC 3956](https://www.rfc-editor.org/rfc/rfc3956) | Embedded-RP encoding and RP mapping precedence |
| [RFC 3542](https://www.rfc-editor.org/rfc/rfc3542.html) | IPv6 packet-info, hop-limit and extension-header socket APIs |

---

## 3. Current code status

IPv6 PIM is not available at runtime or in configuration.

### Reusable foundations

- `crates/pim-packet/src/addr.rs` already parses and emits Encoded-Unicast,
  Encoded-Group and Encoded-Source for address families 1 and 2, into `IpAddr`.
- The Hello codec already parses the Secondary Address List option
  (`HelloTlv::AddressList`) — needed for real IPv6 RPF′ matching (§5.3), currently
  dropped on receive.
- `ProtoContext::raw_socket` accepts an IPv6 domain and applies `SO_BINDTODEVICE` for a
  VRF before returning the socket; `for_vrf_no_rib` supports VRF socket probes.
- OSPFv3 provides the working raw-IPv6 template: `ospf_socket_ipv6`
  (`zebra-rs/src/ospf/socket.rs:133`) and `zebra-rs/src/ospf/network_v6.rs`
  (`IPV6_RECVPKTINFO`, `in6_pktinfo` recv/send, interface-scoped joins). IPv6 raw
  sockets deliver **no IP header** — unlike the IPv4 read task, there is no IHL strip.
- `crates/nd-packet` exports `compute_icmp6_checksum` (RFC 8200 pseudo-header form) —
  the exact function MLD and PIMv6 checksums need. Lift it into `packet-utils` rather
  than writing a third copy.
- RIB links carry both `addr4` and `addr6` (including link-locals).
- RIB NHT is dual-stack and VRF-aware since PR #1988: `NexthopRegister { vrf_id }`
  resolves IPv6 targets against the right global/VRF `table_v6`, and
  `ResolvedNexthop` already carries the ifindex — a link-local nexthop is therefore
  structurally scoped.
- The protocol/dataplane seam is sound: `pim/mroute.rs` owns kernel calls and reports
  typed upcalls to a single-threaded actor. All FSM timers are deadline-driven off one
  sleep arm — nothing about timing is AF-specific.
- `../frr/pimd/pim6d` is built locally and available as an interoperability peer.

### IPv4-only implementation points (verified against the tree)

- `SgKey`, `TibEntry`, `PimLink`, `Neighbor`, RPF cache, `RpSet`, BSR state, Register
  and Assert state use `Ipv4Addr`/`Ipv4Net` directly.
- `pim/mroute.rs` declares only the IPv4 `MRT_*`, `Vifctl`, `Mfcctl`, `igmpmsg` ABI.
- `pim/socket.rs` + `pim/network.rs` implement only IPv4 protocol-103 and IGMP
  transports; the read task strips a variable-length IPv4 header (IHL), which has no
  IPv6 counterpart.
- `pim/igmp` is welded to `Pim` and to `Ipv4Addr` groups/sources.
- `pim-packet` checksums are IPv4-implicit (`PimPacket::emit` computes internally, no
  pseudo-header context); the IPv6 form changes this API for all emit call sites.
- YANG exposes only IPv4 RP addresses/prefixes and IGMP; show dispatch has no AF
  selector and no `mld` token in `is_pim`.
- BDD traffic scripts are IPv4-only.

### Known IPv4 behavior gaps this plan interacts with (be honest about them)

1. **No DR gating of membership-driven forwarding.** IGMP `INCLUDE`/`EXCLUDE` state
   feeds the TIB on *every* router on the LAN; duplicate forwarding is resolved by the
   assert election instead. This was a deliberate Phase-6 decision **and the
   `pim_assert` BDD feature depends on it** to trigger its election deterministically.
   Any plan that "fixes DR gating" without reworking that feature breaks the suite
   (§6.2 resolves this).
2. **Neighbor secondary addresses are parsed but not stored.** `Neighbor` keeps no
   `secondary` list, and upstream-neighbor matching compares the RIB nexthop against
   hello *source* addresses only. IPv4 tolerates this; IPv6 does not (§5.3).
3. **GenID bounce is logged but not acted on.** RFC 7761 wants the joined state
   re-sent toward a restarted neighbor.
4. **No MFC counter polling.** Traffic-created `(S,G)` keepalive relies on
   NOCACHE/WHOLEPKT punts, so receiverless entries churn every 210 s (documented).
5. **QQIC/Max-Resp exponent encodings are clamped** (values ≥128 unsupported) in the
   IGMP codec.

Baseline at the time of writing is green: `pim-packet` 15 tests, `zebra-rs` pim unit
tests 6, seven live `pim_*.feature` files.

---

## 4. Target architecture — one generic core, monomorphized per (VRF, AF)

### 4.1 Supervisor and instances

Extract the supervision duties that currently live inside the default IPv4 instance
(config split/replay, VRF child registry, show registration) into a small, non-generic
`PimSupervisor` actor, and make every protocol engine a typed `Pim<A>` instance:

```text
config manager ── spawn_pim ──► PimSupervisor            (non-generic, no sockets)
                                ├── Pim<Ipv4>            default table
                                ├── Pim<Ipv6>            default table (when configured)
                                └── per VRF <name>
                                    ├── Pim<Ipv4>
                                    └── Pim<Ipv6>
```

- The supervisor owns the `cm`/`show` channels registered with the manager, performs
  `vrf_config_split` (unchanged) and a new AF split (`/router/pim/ipv6/…` →
  the `Ipv6` instance; everything else → `Ipv4`), buffers replay logs per
  `(vrf, af)`, and spawns/despawns instances on the same intent+kernel-event gating
  the VRF pattern uses today.
- Show routing: the manager keeps resolving `show pim …` to the one registered "pim"
  channel — the supervisor's. The supervisor forwards each `DisplayRequest` to the
  right instance by inspecting the `vrf`/`ipv6` path segments and passing the request's
  `resp` sender through (the VRF redirect in the manager continues to work unchanged;
  keys like `"pim:vrf:<name>"` are registered by the supervisor for its VRF nodes).
- Each `Pim<A>` owns its sockets, timers, TIB, membership state and kernel table, so an
  IPv6 socket or MRT6 failure cannot disable IPv4. Instance spawn keeps the
  sockets-before-RIB-subscribe failure contract.

This is a refactor of working code and is therefore its own phase with zero IPv6
runtime (§12 Phase 2). Its acceptance bar is byte-identical IPv4 behavior.

### 4.2 The `PimAf` trait — the full surface, stated up front

`ipnet` has no trait unifying `Ipv4Net`/`Ipv6Net`, so prefix behavior must come from
the AF trait, not from bounds on the prefix type. The trait is wider than a first
sketch suggests; hiding that width is how genericization stalls halfway. Target
surface (guidance, not gospel):

```rust
pub trait PimAf: Copy + Eq + Send + Sync + 'static {
    type Addr:  Copy + Ord + Eq + Hash + Display + Debug + Send + Sync + Serialize;
    type Prefix: Copy + Ord + Eq + Display + Debug + Send + Sync + Serialize;
    type Fp: PimForwardingPlane<Self>;                    // MRT vs MRT6 (§7)

    // Constants.
    const NAME: &'static str;                             // "ipv4" / "ipv6"
    const ALL_PIM_ROUTERS: Self::Addr;                    // 224.0.0.13 / ff02::d
    const GENERAL_QUERY_DST: Self::Addr;                  // 224.0.0.1 / ff02::1
    const MEMBERSHIP_REPORT_DST: Self::Addr;              // 224.0.0.22 / ff02::16
    const DEFAULT_SSM_RANGE: Self::Prefix;                // 232/8 / ff3x::/32 (§8.2)
    const DEFAULT_RP_RANGE: Self::Prefix;                 // 224/4 / ff00::/8

    // Address classification.
    fn is_multicast(a: Self::Addr) -> bool;
    fn is_link_local(a: Self::Addr) -> bool;              // fe80::/10; false for v4
    fn is_reserved_group(a: Self::Addr) -> bool;          // 224.0.0.0/24 / link-scope
    fn multicast_scope(a: Self::Addr) -> u8;              // v6 scope nibble; v4 fixed

    // Prefix operations (ipnet lacks a common trait).
    fn prefix_new(addr: Self::Addr, len: u8) -> Option<Self::Prefix>;
    fn prefix_contains(p: &Self::Prefix, a: &Self::Addr) -> bool;
    fn prefix_len(p: &Self::Prefix) -> u8;
    fn host_prefix(a: Self::Addr) -> Self::Prefix;        // /32 / /128

    // Wire boundary: pim-packet stays `IpAddr`; convert exactly once
    // at ingress (reject the other family) and once at egress.
    fn from_ip(ip: IpAddr) -> Option<Self::Addr>;
    fn to_ip(a: Self::Addr) -> IpAddr;

    // Link policy: the hello/DR identity. v4 = first configured
    // address; v6 = the interface's link-local (RFC 7761 §4.3.1
    // requires link-local sources for multicast PIMv6).
    fn primary_addr(link: &crate::rib::Link) -> Option<Self::Addr>;
    fn link_prefixes(link: &crate::rib::Link) -> Vec<Self::Prefix>;

    // Checksums (§5.1): v4 = plain; v6 = pseudo-header over (src, dst).
    fn checksum_ctx(src: Self::Addr, dst: Self::Addr) -> PimChecksumContext;

    // Transports (§5.2, §6.1): spawn read/write tasks feeding the
    // instance channel. Concrete per AF — the v4 task strips an IHL,
    // the v6 task does not and must carry (src, dst) for checksums.
    fn spawn_pim_transport(...) -> io::Result<PimTransport>;
    fn spawn_membership_transport(...) -> io::Result<GmTransport>;

    // Membership codec adapter (§6): parse/build IGMP vs MLD wire
    // forms into the shared Gm<A> event model.
    type GmCodec: GmCodec<Self>;

    // Register support (§8.3): a minimal inner header naming (S,G)
    // for Null-Registers, and inner-packet (S,G) extraction.
    fn null_register_payload(src: Self::Addr, grp: Self::Addr) -> Vec<u8>;
    fn register_inner_sg(data: &[u8]) -> Option<(Self::Addr, Self::Addr)>;
}
```

### 4.3 What becomes generic (the point of the exercise)

Every module that contains protocol meaning is parameterized — not just the TIB:

| Module | Becomes | Notes |
|---|---|---|
| `tib.rs` | `SgKey<A>`, `TibEntry<A>`, all `impl Pim<A>` | mechanical |
| `macros.rs` | pure fns over `BTreeMap<SgKey<A>, TibEntry<A>>` | tests instantiate `Ipv4` |
| `link.rs`, `neighbor.rs` | `PimLink<A>`, `Neighbor<A>` (+ `secondary: Vec<A::Addr>`) | §5.3 |
| `rpf.rs` | cache keyed `A::Addr`; NHT register passes `A::to_ip` | NHT is already dual-stack |
| `jp.rs`, `register.rs`, `assert_fsm.rs`, `bsr.rs`, `rp.rs` | `impl Pim<A>` throughout | RP LPM via `PimAf` prefix fns |
| `igmp/` | `Gm<A>` shared engine + `GmCodec` adapters (§6) | rename to `gm/` |
| `inst.rs` | `Pim<A: PimAf>` actor, `Message<A>`, `PimSend<A>` | monomorphized |
| `mroute.rs` | `PimForwardingPlane<A>` trait + `Mrt4`/`Mrt6` impls | §7 |

What stays concrete, and why:

- **`pim-packet`** parses to `IpAddr` (wire truth: encoded addresses carry a family
  byte). The actor converts via `A::from_ip` at ingress and **rejects** cross-family
  addresses — including every encoded address inside a BSM/C-RP and a Register's inner
  packet family.
- **`PimSupervisor`**, spawn glue, YANG callback registration: two thin per-AF callback
  tables (`fn(&mut Pim<A>, Args, ConfigOp)` monomorphizes cleanly; no `dyn` needed).
- **Transports and forwarding planes**: concrete per AF behind the trait; this is where
  `libc`/UAPI details live and where tests pin C ABI layouts.

### 4.4 Link-local scoping — use the structure that already exists

A bare link-local `Ipv6Addr` is not a unique endpoint, but the IPv4 code already keys
everything that matters by interface: neighbors live in per-link maps
(`PimLink::nbrs`), `RpfState::Gateway` carries `{ ifindex, nexthop }`, and J/P
aggregation is keyed `(ifindex, nbr)`. **No pervasive `ScopedAddr` type is needed** —
introducing one would churn every signature for structure we already have. The real
rules are narrower:

- Never use a link-local address as a router-wide key (RPF targets, RP addresses, BSR
  addresses, `SgKey` members must be global-scope; assert this at ingress).
- Wherever a link-local is stored, the ifindex is already adjacent — keep it that way,
  and add a debug assertion when inserting into any global-keyed map.

---

## 5. PIMv6 packet and socket rules

### 5.1 Checksum context

Replace the implicit-IPv4 checksum in `PimPacket::emit` with an explicit context:

```rust
pub enum PimChecksumContext {
    Ipv4,
    Ipv6 { src: Ipv6Addr, dst: Ipv6Addr },
}
```

This is an API change for **every existing emit call site** (mechanical; the v4 arm
behaves identically) and for the receive-side verifier, which needs the outer
(src, dst) — both already available from `recvmsg` packet-info. IPv6 PIM checksums
include the pseudo-header (reuse the lifted `compute_icmp6_checksum` accumulator with
next-header 103). Register messages keep the eight-octet coverage, with the
pseudo-header upper-layer length set accordingly; the receive path also accepts the
RFC 7761 compatibility form (checksum over the whole message). Tests cover both.

### 5.2 Multicast control socket

IPv6 raw socket for protocol 103, mirroring `ospf_socket_ipv6`/`network_v6.rs`:

- Join `ff02::d` per enabled interface; hop limit 1; multicast loopback off.
- `IPV6_RECVPKTINFO`; recover dst + ingress ifindex; **no IP header to strip**.
- Pin link-local source and egress interface via `in6_pktinfo` on every multicast
  send; compute the checksum only after (src, dst) are fixed.
- Drop multicast PIM packets whose source is not link-local.

Unicast PIM (Register, Register-Stop, C-RP-Adv) needs a domain-wide reachable source:
deterministic selection (highest global address, or the RP/BSR-configured address when
it is local) plus an explicit config override, recomputed into the checksum context.

### 5.3 Secondary address list — required for IPv6, backported to IPv4

IPv6 hellos are sourced from link-locals, but the RIB's resolved nexthop toward a
source or RP may be a **global** address (or vice versa, an IGP link-local). Matching
"is this nexthop a live PIM neighbor" against hello sources alone therefore fails on
IPv6 in completely ordinary topologies — joins would never be sent. Fix as part of the
generic core, for both families:

- Store `hello.address_list()` on `Neighbor` (parsed today, dropped today).
- Advertise our own secondary addresses (v6: global addresses; the LL is the source).
- Upstream-neighbor matching (`tib_update`, `jp_recv` targeting, RPF′) consults the
  primary **and** secondary addresses.

---

## 6. Membership engine: one `Gm<A>`, two codecs

Rename/regeneralize `pim/igmp` into a `Gm<A>` engine holding everything that is
protocol-identical: querier election (lowest address wins in both), group/source
tables, INCLUDE/EXCLUDE modes, GMI/OQPI/LMQT deadlines, older-version-host
compatibility, and the `synced`/`asm_synced` TIB-bridge diffs. The `GmCodec` adapter
per AF owns wire parsing/building and transport validation only.

Concrete reuse: MLDv2 record types are numerically identical to IGMPv3's — share the
`IgmpRecordType` enum (rename `GmRecordType`). Implement the exponent-coded Max-Resp /
QQIC forms once, for both families (removing the current v4 clamp).

### 6.1 MLD transport requirements

ICMPv6 raw socket with an `ICMP6_FILTER` passing types 130/131/132/143 only. Validate
before touching state: link-local source (or unspecified for some host reports per
RFC 3810 §5.2.13), hop limit 1 (recovered via ancillary data), Router Alert
hop-by-hop option present. Outbound queries: LL source pinned per interface, hop
limit 1, Router Alert, `ff02::1` general / group-specific to the group. Checksums via
the shared ICMPv6 pseudo-header helper. MLD needs interface joins of `ff02::16` (v2
reports) and `ff02::1` semantics analogous to the IGMP socket's fixed-group joins.

### 6.2 DR coupling — resolve the contradiction with `pim_assert`

RFC-correct behavior gates membership-driven upstream/OIF state on being the LAN's
elected DR. The IPv4 code deliberately does not gate — and the `pim_assert` feature
**depends** on both routers forwarding to trigger its election. The plan is to adopt
DR gating, but honestly:

- Implement DR gating in the shared `Gm<A>`→TIB bridge (Phase 0), for both families,
  with re-evaluation of all local membership on every DR transition.
- **Rework `pim_assert` in the same PR**: give the non-DR router downstream state via
  an explicit PIM join from a third router (or a divergent static route), so duplicate
  forwarding — and the election — still occurs. The assert machinery remains the
  safety net for genuinely divergent topologies; the feature must test that, not the
  absence of DR gating.
- Keep non-DR membership tracking warm so DR failover is immediate (state exists,
  only the TIB bridge is gated).

---

## 7. Linux MRT6 forwarding plane

Define the trait both planes implement:

```rust
pub trait PimForwardingPlane<A: PimAf> {
    fn new(ctx: &ProtoContext, table_id: u32) -> io::Result<Self>;
    fn vif_add(&mut self, ifindex: u32);
    fn vif_del(&mut self, ifindex: u32);
    fn vif(&self, ifindex: u32) -> Option<u16>;
    fn ifindex_of(&self, vif: u16) -> Option<u32>;
    fn mfc_add(&self, src: A::Addr, grp: A::Addr, iif: u16, oifs: &[u16]);
    fn mfc_del(&self, src: A::Addr, grp: A::Addr);
    // Upcall parsing stays in the concrete impl's read task; both
    // produce the same typed Upcall<A>.
}
```

`Mrt6` specifics, from the installed `linux/mroute6.h` UAPI:

- `AF_INET6 / SOCK_RAW / IPPROTO_ICMPV6` socket; `MRT6_TABLE` **before** `MRT6_INIT`
  for VRF instances (fail spawn loudly if unsupported — never fall back to the default
  table); `MRT6_PIM` for register/assert upcalls; `MIFF_REGISTER` MIF in slot 0.
- `MRT6_ADD_MIF/DEL_MIF` with `mif6ctl` — its ifindex field (`mif6c_pifi`) is 16-bit;
  reject unrepresentable ifindexes explicitly instead of truncating.
- `MRT6_ADD_MFC/DEL_MFC` with `mf6cctl` and the `if_set` bitmap (`IF_SETSIZE` bits).
- Upcalls: `mrt6msg` (`im6_mbz == 0` in the **first byte** distinguishes upcalls from
  genuine ICMPv6, whose first byte is a nonzero type — the discriminator differs from
  IPv4's protocol-field-at-offset-9 because there is no outer header). NOCACHE,
  WRONGMIF, WHOLEPKT, WRMIFWHOLE map onto the existing typed `Upcall` events.
- Size/offset assertions (or `static_assert`-style tests) for every hand-declared
  struct, both AFs — the IPv4 declarations get them retroactively.

Counter polling (`SIOCGETSGCNT[_IN6]`) for keepalive refresh is an explicit **parity
decision**: either land it for both families as one small FP-trait extension, or keep
the documented 210 s receiverless-entry churn for both. Do not ship it v6-only.

---

## 8. RPF, SSM, RP and Register behavior

### 8.1 RPF

RIB NHT already resolves IPv6 targets against the correct (VRF) `table_v6` and returns
`{ addr, ifindex }` — a link-local nexthop is usable as-is because `RpfState::Gateway`
keeps the ifindex. The generic RPF cache keys by `A::Addr`, registers via
`A::to_ip`, and the connected-source check walks `A::link_prefixes`. The
upstream-neighbor liveness check uses §5.3 secondary matching.

### 8.2 SSM

Default range `FF3x::/32` — matching any scope nibble, i.e. membership in
`ff30::/12` with the reserved-plen bits honored; encode this as the `Ipv6` impl of
`is_ssm` rather than one literal prefix. Never forward interface-local (`ff01`) or
link-local (`ff02`) scope; reject them at membership ingress, TIB creation and NOCACHE
(the v4 `224.0.0.0/24` guard generalizes to `A::is_reserved_group`).

### 8.3 Static RP and Register

RP LPM generalizes through the `PimAf` prefix functions. The RP-side register path and
DR-side suppression FSM are already AF-neutral logic; the concrete bits are
`A::register_inner_sg` (inner-packet family must equal the outer family — reject
otherwise) and `A::null_register_payload` (a minimal IPv6 header: version 6, payload
length 0, next header NONE(59), hop limit, src=S, dst=G). Keep the IPv4 arc's policy —
no reliance on kernel register decapsulation at the RP; switch-to-SPT-immediately —
unless FRR interop testing (§11.4) shows a peer that requires the decap window.
Register unicast source selection per §5.2.

---

## 9. BSR and Embedded-RP

Generalize BSR after static-RP ASM works. Every encoded address in one Bootstrap or
C-RP message must match the outer family (parser-enforced). IPv6 BSR additionally
takes: scoped-zone awareness (at minimum: refuse to elect/flood across `ff02`-scope
boundaries), the RFC 5059 group-to-RP **hash** (currently simplified on IPv4 — make
the hash an acceptance criterion for the BSR phase *of both families*, since the
selection must agree across the domain), and semantic fragmentation for RP-sets that
exceed one MTU.

Embedded-RP is the final phase: recognize `ff70::/12`-style R-bit encodings, validate
RIID/plen, derive the RP address, and install it at RFC 3956 precedence (above BSR,
below explicit static config), keyed per group rather than per range.

---

## 10. Configuration and operational surface

Every existing IPv4 command and its JSON shape is preserved; unqualified `router pim`,
`show pim`, `show igmp`, `show mroute` continue to mean IPv4.

```text
router pim ipv6 interface <if-name> [dr-priority|hello|passive]
router pim ipv6 interface <if-name> mld enabled <bool> | version <1|2> | ...
router pim ipv6 rp static <ipv6-address> group <ipv6-prefix>
router pim ipv6 bsr candidate-bsr|candidate-rp ...
router pim vrf <name> ipv6 ...

show pim ipv6 [interface|neighbor|upstream|rp-info|assert|bsr]
show pim vrf <name> ipv6 ...
show mld [vrf <name>] [interface|groups]
show mroute [vrf <name>] ipv6
```

Mechanics, stated concretely because they are where plans die:

- The `ipv6` subtree sits under the PIM container **and** under each PIM `vrf` entry,
  so the existing `vrf_config_split` keeps working and the supervisor's AF split runs
  on the post-VRF-strip path.
- `is_pim` in the manager gains the `mld` token (it already has `pim`, `igmp`,
  `mroute`).
- The supervisor forwards `DisplayRequest`s to the right `(vrf, af)` instance
  (§4.1); JSON output carries an `"af"` field and never pads IPv6 addresses to
  IPv4 column widths.
- IPv6 PIM/MLD activate only on explicit config; an IPv6 address on an interface must
  not start multicast routing.

---

## 11. Testing strategy

Every phase keeps all IPv4 unit and BDD tests green. Genericization is not complete if
it changes IPv4 wire output, timers, configuration or show results — with the single
declared exception of the DR-gating behavior change and its reworked `pim_assert`
feature (§6.2), which land together, visibly, in Phase 0.

### 11.1 Packet tests

- IPv6 encoded unicast/group/source round trips; mixed outer/encoded family rejection
  (incl. BSM internals and Register inner packets).
- PIMv6 Hello (with Address List), J/P, Assert, Register, Register-Stop, Bootstrap,
  C-RP fixtures with pseudo-header checksums — success and corruption cases; Register
  eight-octet coverage plus whole-message compatibility acceptance.
- MLDv1 Query/Report/Done, all MLDv2 record types, exponent-coded Max-Resp/QQIC (both
  families once shared), truncated/invalid-scope negatives.
- Where the FRR interop runs (§11.4) produce captures, retain them as fixtures.

### 11.2 Pure protocol tests (macros/FSM instantiate `A = Ipv6`)

- Secondary-address upstream matching (global nexthop ↔ LL hello source).
- DR transitions enabling/disabling the membership TIB bridge (both AFs).
- GenID restart re-sync toward the bounced neighbor.
- IPv6 RP LPM, BSR hash agreement, Embedded-RP precedence.
- SSM classification across scopes; reserved-scope rejection.
- Assert metrics fed by IPv6 RPF results.

### 11.3 Linux adapter tests

- Layout assertions for `mif6ctl`, `mf6cctl`, `if_set`, `mrt6msg` (and, retroactively,
  the IPv4 `Vifctl`/`Mfcctl`/`igmpmsg`).
- MIF 16-bit ifindex representability; `mrt6msg` first-byte discrimination without an
  outer header; `MRT6_TABLE`-before-`MRT6_INIT` ordering; EADDRINUSE behavior when
  another owner holds MRT6.

### 11.4 Live BDD

New IPv6 traffic helpers (do not overload the IPv4 scripts): the SSM receiver must use
`MCAST_JOIN_SOURCE_GROUP` (46) with a hand-packed `group_source_req`
(ifindex + two `sockaddr_storage`) — Python does not expose a convenience API for it;
budget for that in the script, mirroring `ssm_recv.py`'s file-logging contract.

Vertical progression, each with explicit teardown scenarios:

1. Two-router PIMv6 adjacency, DR election, LL-source enforcement.
2. MLDv1/v2 querier election and group/source state.
3. Two-router SSM: real UDPv6 delivery + `ip -6 mroute` assertions.
4. Three-router static-RP ASM: Register cycle settling in suppression, SPT state.
5. Multi-access IPv6 assert election (reworked-trigger topology per §6.2).
6. IPv6 SSM inside a named VRF with default-table isolation asserts.
7. IPv6 BSR election and learned mappings, zero static RP.
8. Embedded-RP ASM with neither static RP nor BSR.

Interop gate: at least PIMv6 adjacency, MLDv2-driven SSM and BSR against the locally
built `../frr/pimd/pim6d`, using the same netns harness.

---

## 12. Phasing and acceptance gates

Each phase is one reviewable PR leaving the tree tested and useful.

| Phase | Deliverable | Required proof |
|---|---|---|
| 0 | **DONE** — IPv4 correctness floor: DR gating **with `pim_assert` rework**, GenID re-sync, neighbor secondary-address storage/matching, ABI layout tests for existing structs | all seven IPv4 features green (assert feature redesigned, not deleted) |
| 1 | **DONE** — Codec groundwork: checksum context API (all emit sites), MLD wire types, exponent encodings, mixed-family rejection, ICMPv6 checksum helper lifted to `packet-utils` | fixture + negative tests; IPv4 fixtures byte-identical |
| 2 | `Pim<A>`/`Gm<A>`/FP-trait genericization; **IPv4 runtime only**. Landed in compiling slices (see note). | all IPv4 unit + live BDD unchanged |
| 3.0 | Extract the shared `Gm<A>` engine + `GmCodec` (rename `igmp/`→`gm/`); the membership transport moves off `Pim<A>` into the engine so `Pim<Ipv6>` needs no IGMP fields. IPv4-only runtime | IPv4 membership BDD unchanged (`pim_igmp`) |
| 3.1 | `Ipv6` marker + `Mrt6` stub + PIMv6 socket, Hello/neighbor/DR over LL, AF-split spawn of a default-table `Pim<Ipv6>` | two-router adjacency BDD; invalid-transport negatives |
| 4 | MLDv1/v2 codec via `Gm<Ipv6>` + TIB bridge (the second `GmCodec`, now plugging into the engine from 3.0) | querier/compat/source-filter BDD |
| 5 | `Mrt6` plane + generic RPF + SSM end-to-end | UDPv6 delivery + kernel MIF/MFC asserts (MVP gate) |
| 6 | Static-RP ASM, IPv6 Register path, SPT | three-router ASM traffic proof |
| 7 | IPv6 assert + per-VRF `Pim<Ipv6>` | LAN election + VRF isolation BDD |
| 8 | IPv6 BSR (hash + fragmentation as acceptance criteria) | election/discovery BDD + FRR interop |
| 9 | Embedded-RP | precedence tests + ASM datapath proof |

### Phase 2 slicing note

Genericizing `Pim` to `Pim<A>` is a big-bang at the module level (every method hangs off
the god-object), so Phase 2 lands as compiler-verified slices, each keeping IPv4 green,
consistent with the arc's smallest-safe-slice rule:

- **Slice 2a — data model (DONE).** Introduce `PimAf` (associated `Addr`/`Prefix` only,
  no methods yet, so nothing is dead) + the `Ipv4` marker impl, and parameterize every
  state type over `A` with `A = Ipv4` defaults: `SgKey<A>`, `TibEntry<A>`, `RpfState<A>`,
  `Neighbor<A>`, `AssertMetric/State<A>`, `RpSet<A>`, `BsrConfig/Run<A>`, `IgmpIf/Group<A>`,
  `PimLink<A>`. All logic stays concrete-IPv4 (methods on `impl Pim` / `impl PimLink<Ipv4>`),
  byte-identical. Verified: unit tests, `@pim_ssm`/`@pim_asm` live, identical binary md5.
- **Slice 2b — logic + trait methods.** Measured, this is a ~5,600-LOC change (~15
  `impl Pim` blocks flipping to `impl<A: PimAf> Pim<A>`, ~130 concrete `Ipv4Addr`/`Ipv4Net`
  touchpoints) that cannot compile mid-way, so it lands as three compiler-verified,
  byte-identical sub-slices, each its own PR:
  - **2b.1 — pure semantics on `PimAf`.** Classification (`is_multicast`/`is_ssm`/
    `is_reserved_group`), prefix ops (`prefix_new`/`prefix_contains`/`prefix_len`/
    `prefix_addr`) and the `DEFAULT_SSM_RANGE`/`DEFAULT_RP_RANGE` consts, with every
    existing concrete call site (`rp.rs`, `register.rs`, `igmp`, `tib.rs`, `bsr.rs`,
    `config.rs`) routed through `Ipv4::…`. `Pim` stays concrete; unit-tested; byte-identical.
    (`NAME`, `host_prefix`, wire conversion, etc. are deferred to the slice that first
    needs them, so no trait method is ever dead under `-D warnings`.)
  - **2b.2 — the forwarding-plane seam.** `PimForwardingPlane<A>` (rename
    `ForwardingPlane`→`Mrt4`, `Upcall`→`Upcall<A>`), with `Mrt4: PimForwardingPlane<Ipv4>`.
    This is the one seam the flip *requires* — the `Pim.fp` field type must be trait-bound
    before `Pim` can be generic. `Pim` stays concrete, holding `Mrt4`.
  - **2b.3 — the actor flip (DONE).** `Pim` → `Pim<A>`, `Message<A>`, `PimSend<A>`,
    `IgmpSend<A>`, `Upcall<A>`, `ShowCallback<A>`, `Callback<A>`, and every `impl Pim` →
    `impl<A: PimAf> Pim<A>` (the membership FSM in `igmp/` flipped generically *in place* —
    `A`-generic, not extracted; IGMP wire fields convert at the boundary via `from_ip`).
    Only the leaf constructors stay concrete: `Pim<Ipv4>::new` (wires the IPv4 sockets +
    `Mrt4`), `callback_build`/`show_build` (parse/render IPv4 CLI). The `PimAf` surface grew
    to match §4.2: `type Fp`, `ALL_PIM_ROUTERS`/`GENERAL_QUERY_DST` consts, `from_ip`/`to_ip`,
    `prefix_from_ipnet`/`link_prefixes`, `is_unspecified`, `null_register_payload`/
    `register_inner_sg` — each landed with its caller. Only `Pim::<Ipv4>` is spawned; still
    IPv4-runtime-only. Verified: unit + workspace tests, forced-clean clippy, full pim BDD
    suite live with identical binary md5.

  **`Gm<A>` engine extraction deferred to Phase 4.** §6's standalone `Gm<A>` engine +
  `GmCodec` adapter (rename `igmp/`→`gm/`) is *not* done in Phase 2. Extracting the shared
  membership engine with only the IGMP codec present designs the engine/codec seam blind;
  MLD is the second implementor that validates it, so the extraction lands in Phase 4
  alongside `Gm<Ipv6>`/MLD. Through Phase 2/3 the membership FSM stays as `impl<A> Pim<A>`
  methods (already `A`-generic after 2b.3), which is all the flip needs.

**Supervisor deferral.** The standalone `PimSupervisor` (§4.1) is deferred to **Phase 7**,
where per-VRF × AF becomes the flat matrix that actually needs a non-generic parent.
Through Phases 3–6 the default `Pim<Ipv4>` instance keeps acting as the parent (it already
owns the manager's `cm`/`show` channels and spawns/routes per-VRF children): Phase 3 adds an
**AF-split** mirroring `vrf_config_split`, so `/router/pim/ipv6/…` spawns and routes a
default-table `Pim<Ipv6>` child exactly like a VRF child. This reuses proven machinery and
reaches live PIMv6 adjacency with the least churn; the supervisor refactor lands once the
`(vrf, af)` product makes the parent-instance tree awkward (Phase 7).

### MVP gate — after Phase 5

- MLDv2 INCLUDE report creates IPv6 `(S,G)` state on the DR only.
- PIMv6 J/P converges across two routers with LL transport and secondary matching.
- RPF resolves from the correct (VRF) IPv6 table.
- MRT6 shows the expected MIF/OIF split; real UDPv6 reaches the receiver.
- All IPv4 behavior unchanged (post-Phase-0 baseline).

### Full-parity gate — after Phase 8

- Static and BSR-learned IPv6 mappings selected correctly, hash-consistent.
- Register/Register-Stop and immediate SPT with IPv6 encapsulation.
- Assert and multi-access behavior covered; VRFs isolated in separate MRT6 tables.
- Operational output sufficient to diagnose convergence (scoped addresses, RPF, TIB,
  MFC).

---

## 13. Principal risks and mitigations

| Risk | Mitigation |
|---|---|
| RPF′ never matches because hellos are LL and RIB nexthops are global | Secondary Address List stored + consulted (§5.3), landed in Phase 0 for both AFs |
| DR-gating change breaks the assert suite | The gating and the `pim_assert` rework are one PR (§6.2) |
| Genericization stalls on `ipnet`'s missing common trait | Prefix ops live on `PimAf` from the start (§4.2) |
| IPv4 regressions during the refactor | Phase 2 ships zero IPv6 runtime; acceptance is unchanged IPv4 BDD + fixtures |
| PIMv6 checksum wrong when kernel picks the source | Pin source/interface via `in6_pktinfo` before computing (§5.2) |
| MLD accepted without Router Alert / hop-limit validation | Ancillary-data validation precedes any state change (§6.1) |
| Mixed-family state at runtime | One `A::from_ip` conversion point per ingress; reject and count mismatches |
| Linux ABI drift / layout mistakes | Isolated declarations + layout assertions, both AFs (§11.3) |
| MRT6 VRF state lands in the default table | `MRT6_TABLE` before `MRT6_INIT`; spawn fails loudly when unsupported |
| 16-bit MIF ifindex truncation | Validate before every `MRT6_ADD_MIF` |
| Scope leakage (`ff01`/`ff02` forwarded) | `A::is_reserved_group`/scope checks at membership, TIB and NOCACHE boundaries |
| v6-only counter polling diverges the AFs | Counter/KAT refresh is an explicit both-or-neither decision (§7) |
| Simplified BSR selection disagrees across the domain | RFC 5059 hash is an acceptance criterion for the BSR phase, both AFs |

---

## 14. Completion definition

IPv6 support is complete when PIMv6 SSM and ASM operate in the default table and a
named VRF; MLDv1/v2 membership drives the TIB via the shared `Gm<A>` engine; static,
BSR and Embedded-RP mappings are selected at the correct precedence with a
domain-consistent hash; MRT6 forwarding and upcalls drive the same typed FSM events as
IPv4 through the `PimForwardingPlane<A>` trait; family, scope and checksum rules are
enforced at both edges; show/JSON output is AF-explicit; and the IPv6 unit, adapter,
BDD and FRR interop gates pass with every IPv4 test still green.

---

## Appendix — adversarial review deltas (what changed and why)

Findings from reviewing the previous revision against the implemented IPv4 code:

1. **DR-gating contradiction (blocking).** The old §6.2 demanded IPv4 DR gating as a
   prerequisite without noting that `pim_assert.feature` deterministically depends on
   ungated dual forwarding. Resolved: gating + feature rework are one Phase-0 PR.
2. **Secondary Address List missing (blocking for v6).** Upstream-neighbor matching
   compares RIB nexthops against hello sources only; with LL hello sources and global
   RIB nexthops, IPv6 joins would never transmit. Added §5.3, Phase 0, and a top risk.
3. **Generics stopped halfway.** The old trait sketch omitted prefix operations
   (`ipnet` has no unifying trait), wire-boundary conversion, primary-address policy
   (v6 = link-local), transports, membership codec and register helpers — the places
   genericization actually gets stuck. §4.2 states the full surface; §4.3 fixes the
   module-by-module scope; the supervisor is extracted so no typed instance plays
   parent (§4.1).
4. **`ScopedAddr` overreach removed.** Neighbors, RPF gateways and J/P buckets are
   already interface-scoped structurally; a pervasive scoped type would churn every
   signature for no new information. Replaced with narrow rules + assertions (§4.4).
5. **Counter-polling asymmetry.** `SIOCGETSGCNT_IN6` appeared v6-only while IPv4 has
   no polling (documented 210 s churn). Now an explicit both-or-neither decision.
6. **Upcall discrimination corrected/clarified.** v6 upcalls are distinguished by a
   zero first byte (`im6_mbz`) against nonzero ICMPv6 types — not by reusing the v4
   offset trick; stated with the no-outer-header consequence for both PIM and mroute
   read paths.
7. **Reuse pointers added.** `nd-packet::compute_icmp6_checksum` (lift to
   `packet-utils`), shared IGMPv3/MLDv2 record-type enum, `ospf/network_v6.rs` as the
   transport template, locally built `../frr/pimd/pim6d` for interop, and the
   `group_source_req` packing cost in the BDD receiver script.
8. **Supervisor/show routing mechanics specified** (§4.1, §10) — the old plan asserted
   AF selection without saying how a `DisplayRequest` reaches a typed instance; the
   forwarding path and the YANG placement that keeps `vrf_config_split` working are
   now explicit. `is_pim` gaining the `mld` token is called out.
9. **Phase-0 scope made testable.** "Correctness floor" now names its items (DR
   gating + assert rework, GenID re-sync, secondary addresses, ABI layout tests)
   instead of gesturing at them; the vague "keepalive-counter tests" item became the
   §7 parity decision.
