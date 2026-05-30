# BGP SR Policy (RFC 9256 / 9830 / 9831) — Implementation Plan

Status: proposed (2026-05-30). Scope locked with Kunihiro: headend
**consumer** first, **SRv6** segment dataplane first, **control-plane**
first (receive → typed TLVs → policy DB + selection + show). Originator,
dataplane install, and automated color steering are later phases.

Branch: `bgp-sr-policy` (already created off `main`).

Status note: numbers below (PR counts, file lists, byte offsets) are
estimates to guide the work, not commitments.

## Table of contents

1. What we are building
2. Standards basis — the load-bearing numbers
3. Reference implementations (FRR / Cisco) and what they tell us
4. Architecture overview
5. Packet codec design (`crates/bgp-packet`)
6. Control-plane design (`zebra-rs/src/bgp`)
7. YANG schema proposal
8. Show / operational model
9. Dataplane realization (deferred — design sketch)
10. Automated steering (deferred — design sketch)
11. Phasing / PR plan
12. Validation strategy
13. Risks and open questions

---

## 1. What we are building

BGP SR Policy distributes Segment Routing Traffic Engineering policies
through BGP (SAFI 73). A *controller / PCE / route-reflector* originates
policies; a *headend router* consumes them, selects the active candidate
path per `<color, endpoint>`, programs a Binding SID, and steers
color-tagged service traffic onto the policy.

zebra-rs is a router, so the primary role is **headend consumer**. The
feature must work for both **IPv4 and IPv6** — the address family of the
SR Policy NLRI (AFI 1 vs AFI 2 = endpoint family) is independent of the
segment dataplane (SR-MPLS vs SRv6) carried inside.

This plan delivers, in order:

- **Phase 1–3 (this body of work):** negotiate SAFI 73, parse the NLRI
  and the SR Policy Tunnel Encapsulation sub-TLVs into typed structures,
  store candidate paths in an SR Policy database, run RFC 9256 active
  candidate-path selection, and expose it through `show`. No FIB install,
  no traffic steering yet.
- **Phase 4+ (later):** realize the active path in the dataplane (SRv6
  first via seg6 lwtunnel + Binding SID local SID), then automated
  steering of color-tagged unicast/VPN routes onto policies, then the
  originator side.

This mirrors the rhythm of the VPNv6-leak series and the Flowspec plan:
land a correct, observable control plane first; attach the dataplane
behind it.

## 2. Standards basis — the load-bearing numbers

| Item | Value | Source |
|------|-------|--------|
| SR Policy SAFI | **73** (AFI 1 = IPv4, AFI 2 = IPv6) | RFC 9830 §2.1 |
| NLRI layout | `Length(1) ‖ Distinguisher(4) ‖ Color(4) ‖ Endpoint(4 or 16)` | RFC 9830 §2.1 |
| NLRI Length (bits) | **96** (v4) / **192** (v6) | RFC 9830 §2.1 |
| Next-hop | 4 or 16 octets, AFI inferred from length, *independent of policy AFI* | RFC 9830 §2.1 |
| Carrier attribute | Tunnel Encapsulation, **path attr 23**, optional-transitive | RFC 9012 §2 |
| Tunnel-Type | **15** (SR Policy) | RFC 9830 / IANA |
| Sub-TLV length width | 1 octet for type ≤127, 2 octets for type ≥128 | RFC 9012 §2 |

**SR Policy sub-TLVs** (inside the Tunnel-Type-15 TLV):

| Type | Sub-TLV | Notes |
|-----:|---------|-------|
| 12 | Preference | Flags(1)+Resv(1)+Preference(4); default 100 |
| 13 | Binding SID | Flags(1)+Resv(1)+BSID(0/4/16); S=bit0, I=bit1 |
| 14 | ENLP | values 1=v4,2=v6,3=both,4=none |
| 15 | Priority | Priority(1)+Resv(1); 0–255, lower=higher, default 128 |
| 20 | SRv6 Binding SID | Flags(1)+Resv(1)+SID(16)+opt Behavior/Structure(8); S,I,B flags |
| 128 | Segment List | Resv(1)+opt Weight+segments |
| 129 | Candidate-Path Name | UTF-8 |
| 130 | Policy Name | UTF-8 |

**Segment List inner registry** (the codepoints ≠ the A–K letters — this
will bite if assumed):

| Code | Segment | RFC | Carries |
|-----:|---------|-----|---------|
| 1 | Type A | 9830 | SR-MPLS label (4 oct: 20-bit label/TC/S/TTL) |
| 13 | Type B | 9830 | SRv6 SID (16) + opt Endpoint Behavior & SID Structure |
| 3/4/5/6/7/8 | C/D/E/F/G/H | 9831 | IPv4/IPv6 node/interface addrs + opt SR-MPLS SID |
| 14/15/16 | I/J/K | 9831 | IPv6 addrs + SR-Algo + opt SRv6 SID |
| 9 | Weight | 9830 | Flags(1)+Resv(1)+Weight(4); 0 invalid, default 1 |
| 2, 10, 11, 12 | **deprecated** | — | must be ignored if seen |

**Segment flags** (Type C–K): V=bit0 (verification), A=bit1 (SR-Algo
present), S=bit2 (SID present), B=bit3 (SRv6 behavior/structure present).
**SRv6 Endpoint Behavior & SID Structure** (8 oct): Behavior(2)+Resv(2)+
LB-len(1)+LN-len(1)+Fun-len(1)+Arg-len(1), four lengths sum ≤ 128.

**Architecture (RFC 9256):**
- Policy identity = `<headend, color, endpoint>`; color is non-zero u32;
  endpoint may be null (`0.0.0.0` / `::`) for color-only policies.
- Candidate-path identity = `<protocol-origin, originator, discriminator>`.
  Protocol-Origin: PCEP=10, **BGP SR Policy=20**, Config=30.
  Originator = `<ASN(4), node-address(128)>`. Discriminator = the NLRI
  Distinguisher for BGP-sourced CPs.
- **Active candidate-path selection** (§2.9), highest wins:
  1. valid only → 2. highest Preference → 3. higher Protocol-Origin →
  4. prefer existing/installed → 5. lower Originator → 6. higher
  Discriminator.
- Weighted ECMP across a policy's segment lists by `w / Σw`.

**Distribution rules (RFC 9830 §4.2):**
- An SR Policy update **MUST** carry NO_ADVERTISE, or ≥1 Route Target in
  IPv4-address format, or both — else the NLRI is malformed and not given
  to the SR Policy module.
- If RTs are present, **≥1 RT must equal the receiver's BGP Identifier**
  (router-id, RFC 6286) for the policy to be *usable* locally. Non-matching
  RT updates are still valid (a route reflector forwards them) but not
  consumed.

## 3. Reference implementations

**FRR — does NOT implement SAFI 73.** `lib/iana_afi.h` has no SR Policy
SAFI; `grep SAFI_SRTE` across FRR returns nothing. FRR builds SR policies
in **pathd** (local `segment-list` / `policy` config + PCEP as a PCC) and
pushes them to zebra via `ZEBRA_SR_POLICY_SET`. bgpd's only SR-TE
touchpoint is the ingress route-map `set sr-te color`, which steers
locally-learned routes onto an already-present pathd policy. **Consequence:
zebra-rs implementing SAFI-73 receive is net-new relative to FRR, and FRR
cannot be used as a wire interop peer.** FRR's pathd CLI model
(`segment-list NAME { index N mpls label L }`, `policy color C endpoint E
{ binding-sid L; candidate-path preference P { explicit segment-list NAME |
dynamic } }`) is, however, the de-facto config shape we mirror for the
*originator* / local-policy phase.

**Cisco IOS-XR** — full headend model: SR On-Demand Nexthop (ODN)
auto-instantiates a policy to a BGP next-hop carrying a matching Color
Extended Community; Automated Steering resolves a service route onto the
policy whose `endpoint == route-nexthop` and `color == route-color`; with
multiple colors the highest numeric color with a valid policy wins;
Color-Only (CO) bits in the Color Extended Community flags control
fallback (00 strict endpoint match, 01/10 progressively broader). This is
our reference for the later steering phase and for wire validation.

## 4. Architecture overview

```
        ┌──────────────────────────── crates/bgp-packet ────────────────────────────┐
 wire → │ Safi::SrTePolicy(73) → MpReachAttr::SrPolicy{nexthop, Vec<SrPolicyNlri>}   │
        │ TunnelEncap(attr 23, type 15) → srpolicy::SrPolicyTlvs (typed view)        │
        └───────────────────────────────────────────────────────────────────────────┘
                                   │ parsed UpdatePacket
                                   ▼
        ┌──────────────────────── zebra-rs/src/bgp ─────────────────────────────────┐
        │ route_from_peer → route_srpolicy_update()                                  │
        │   ├─ usability filter (NO_ADVERTISE | RT==router-id, RFC 9830 §4.2)        │
        │   ├─ Adj-RIB-In (srpolicy table, keyed by NLRI)                            │
        │   └─ SrPolicyDb: key <color,endpoint> → CandidatePaths                     │
        │        └─ active-CP selection (RFC 9256 §2.9)                              │
        │ show bgp ipv4|srv6 sr-policy  ← reads SrPolicyDb                           │
        └───────────────────────────────────────────────────────────────────────────┘
                                   │ active CP (segment lists, BSID)   ← PHASE 4+
                                   ▼
        ┌──────────────── zebra-rs/src/rib + fib (deferred) ────────────────────────┐
        │ BSID local SID (SRv6 End.B6.Encaps via seg6local) + seg6 encap nexthop     │
        │ color-extcomm steering resolver onto SrPolicyDb (reconcile w/ color_policy)│
        └───────────────────────────────────────────────────────────────────────────┘
```

Module ownership:

- **`crates/bgp-packet`** — `Safi::SrTePolicy`; `nlri_srpolicy.rs` NLRI
  codec; `srpolicy.rs` typed view over the Tunnel-Type-15 sub-TLVs;
  `MpReachAttr::SrPolicy` variant. (Generic `TunnelEncap` stays as the
  forward-compatible/pass-through carrier; the typed layer is built on
  top, exactly as its doc-comment anticipates.)
- **`zebra-rs/src/bgp`** — new `sr_policy.rs` (DB + selection + config);
  `adj_rib.rs` gains an srpolicy table; `route.rs` gains the receive
  handler; `show.rs` gains the show commands; `cap.rs`/config gain AF
  activation.
- **`zebra-rs/src/rib` + `fib`** — Phase 4+ only.

## 5. Packet codec design (`crates/bgp-packet`)

### 5.1 SAFI

`afi.rs`: add `SrTePolicy = 73` to `Safi`, plus the two `From` arms
(`SrTePolicy => 73`, `73 => SrTePolicy`) and the round-trip test list.
Display string `"SR Policy"`.

### 5.2 NLRI codec — `attrs/nlri_srpolicy.rs`

```rust
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SrPolicyNlri {
    pub distinguisher: u32,
    pub color: u32,
    pub endpoint: IpAddr,   // v4 or v6 per MP header AFI
}
```

`ParseNlri<SrPolicyNlri>` (matching the established trait pattern used by
`nlri_vpnv4.rs` etc.):

- read length byte; validate `== 96` (AFI 1) or `== 192` (AFI 2),
  reject otherwise;
- `distinguisher = be_u32`, `color = be_u32`;
- endpoint = 4 or 16 octets driven by the AFI passed down from the
  `MpReachHeader` (same way `MupRoute::parse` takes `afi`);
- emit mirrors parse, length byte derived from the endpoint family.

`MpReachAttr` gains `SrPolicy { nexthop: IpAddr, updates: Vec<SrPolicyNlri> }`
and the matching `MpUnreachAttr` arm; dispatch added in
`mp_reach.rs` / `mp_unreach.rs` for `(Ip|Ip6, SrTePolicy)`.

### 5.3 Typed Tunnel sub-TLVs — `attrs/srpolicy.rs`

A typed view that decodes/encodes the sub-TLVs of a Tunnel-Type-15 TLV.
The generic `TunnelEncap` keeps storing opaque `TunnelSubTlv`s (so unknown
sub-TLVs round-trip for reflectors); the typed layer converts to/from it.

```rust
pub struct SrPolicyTlvs {
    pub preference: Option<u32>,
    pub binding_sid: Option<BindingSid>,
    pub srv6_binding_sid: Option<Srv6BindingSid>,
    pub enlp: Option<Enlp>,
    pub priority: Option<u8>,
    pub segment_lists: Vec<SegmentList>,
    pub policy_name: Option<String>,
    pub cp_name: Option<String>,
}

pub enum BindingSid { None, MplsLabel(u32), }          // sub-TLV 13
pub struct Srv6BindingSid {                            // sub-TLV 20
    pub sid: Ipv6Addr,
    pub behavior: Option<Srv6BehaviorStructure>,
    pub flags: u8,                                     // S,I,B
}
pub struct SegmentList {                               // sub-TLV 128
    pub weight: Option<u32>,                           // inner code 9
    pub segments: Vec<Segment>,
}
pub enum Segment {
    TypeA { flags: u8, label: u32 },                   // inner code 1  (SR-MPLS)
    TypeB { flags: u8, sid: Ipv6Addr,                  // inner code 13 (SRv6)
            behavior: Option<Srv6BehaviorStructure> },
    Unknown { code: u8, value: Vec<u8> },              // C–K + deprecated, preserved
}
```

**v1 implements Type A (1) and Type B (13)**; all other segment codes
decode into `Segment::Unknown` (bytes preserved), and the deprecated codes
2/10/11/12 are accepted-and-ignored. SRv6-first means Type B is the
priority; Type A is cheap to add alongside. C–K are a follow-up.

Validation in the codec: a Segment List mixing SR-MPLS and SRv6 is
rejected; SRv6 behavior/structure without a SID is rejected; reserved
fields ignored on read, zeroed on write. Round-trip tests per sub-TLV,
following the existing `tunnel_encap.rs` test style.

### 5.4 Color Extended Community accessor (for the later steering phase)

`ext_com.rs` already parses extended communities. Add a typed
accessor for type `0x030b` returning `{ color: u32, co: u8 }` (CO bits =
top two bits of the flags octets). Not consumed until the steering phase,
but landing it with the codec keeps the wire layer complete.

## 6. Control-plane design (`zebra-rs/src/bgp/sr_policy.rs`)

### 6.1 Data model

```rust
pub struct SrPolicyKey { pub color: u32, pub endpoint: IpAddr }

pub struct CandidatePathKey {                 // RFC 9256 §2.2
    pub protocol_origin: u8,                   // 20 for BGP
    pub originator: (u32, IpAddr),             // <ASN, node-address>
    pub discriminator: u32,                    // = NLRI distinguisher
}

pub struct CandidatePath {
    pub key: CandidatePathKey,
    pub preference: u32,                        // default 100
    pub priority: u8,                           // default 128
    pub binding_sid: Option<BindingSid>,
    pub srv6_binding_sid: Option<Srv6BindingSid>,
    pub enlp: Option<Enlp>,
    pub segment_lists: Vec<SegmentList>,
    pub name: Option<String>,
    pub valid: bool,                            // validation result
    pub attr: Arc<BgpAttr>,                     // for re-advertise / origin info
}

pub struct SrPolicy {
    pub key: SrPolicyKey,
    pub candidates: BTreeMap<CandidatePathKey, CandidatePath>,
    pub active: Option<CandidatePathKey>,       // selection result
}

pub struct SrPolicyDb {
    pub policies: BTreeMap<SrPolicyKey, SrPolicy>,
}
```

`SrPolicyDb` lives on `Bgp` next to `local_rib` / `color_policy`.

### 6.2 Receive path

`route.rs::route_from_peer` gains an arm for `MpReachAttr::SrPolicy` →
`route_srpolicy_update()`:

1. **Usability filter (RFC 9830 §4.2):** require NO_ADVERTISE community or
   ≥1 RT (IPv4-address format) in the attribute; if RTs present, mark
   *usable* only when one equals `bgp.router_id`. Non-usable-but-valid
   routes are still stored in Adj-RIB-In for reflection but excluded from
   the `SrPolicyDb`.
2. **Adj-RIB-In:** add `srpolicy` table to `adj_rib.rs`, keyed by
   `SrPolicyNlri` (distinguisher, color, endpoint). Stores raw attr for
   soft-reconfig / reflection.
3. **Decode** the Tunnel-Type-15 TLV via `SrPolicyTlvs`, build a
   `CandidatePath` (one NLRI = one CP; distinguisher = discriminator;
   originator from ORIGINATOR_ID or the peer; protocol-origin = 20).
4. **Validate** the CP (minimal in v1: at least one non-empty segment
   list, no mixed SR-MPLS/SRv6, BSID well-formed). Mark `valid`.
5. **Insert/update/withdraw** in `SrPolicyDb[<color,endpoint>]`,
   re-run selection.

### 6.3 Active candidate-path selection

Pure function over `SrPolicy.candidates`, RFC 9256 §2.9 order: valid only
→ max preference → max protocol-origin → incumbent (the previous `active`)
→ min originator → max discriminator. Sets `SrPolicy.active`. Unit-tested
against the RFC tie-break ladder.

### 6.4 Capability + AF activation

`Safi::SrTePolicy` flows through the existing `CapMultiProtocol` /
`AfiSafis` machinery unchanged once the enum value and the
`Args::afi_safi()` parser mapping exist. Per-neighbor activation reuses
`config_afi_safi` (`/router/bgp/neighbor/afi-safi/enabled`).

## 7. YANG schema proposal

### 7.1 AF activation — extend `zebra-afi-safi.yang`

Add two enum values to the config-facing `afi-safi` grouping so a neighbor
can activate the family and so the capability is negotiated:

```yang
grouping afi-safi {
  leaf name {
    type enumeration {
      enum ipv4; enum ipv6; enum vpnv4; enum vpnv6; enum evpn;
      enum sr-policy-v4;   // AFI 1 / SAFI 73
      enum sr-policy-v6;   // AFI 2 / SAFI 73
    }
  }
}
```

`Args::afi_safi()` maps `sr-policy-v4 → AfiSafi(Ip, SrTePolicy)` and
`sr-policy-v6 → AfiSafi(Ip6, SrTePolicy)`. Config to peer with a
controller / RR:

```
router bgp 65000 {
  neighbor 10.0.0.1 {
    remote-as 65000;
    afi-safi sr-policy-v4 { enabled; }
    afi-safi sr-policy-v6 { enabled; }
  }
}
```

### 7.2 New module `zebra-bgp-sr-policy.yang`

Follows the `zebra-bgp-color-policy.yang` pattern: a grouping augmented
into both `/configure:set/.../bgp` and `/configure:delete/.../bgp`. For
the consumer-first scope the config surface is intentionally small; the
local-policy / originator config (the FRR-pathd-shaped `segment-list` +
`policy` tree) is a documented future grouping.

```yang
grouping bgp-sr-policy-extension {
  container sr-policy {
    ext:help "BGP SR Policy (SAFI 73) consumer settings";
    presence "Enable BGP SR Policy processing";

    leaf headend {
      ext:help "Headend address used as the policy headend / RT match
                (defaults to the BGP router-id)";
      type inet:ip-address;
    }

    container binding-sid {
      ext:help "How a received policy's Binding SID is realized locally";
      leaf allocation {
        type enumeration { enum explicit; enum dynamic; }
        default explicit;   // honour the advertised BSID; dynamic = carve locally
      }
    }

    // FUTURE (originator / local policies, deferred): mirrors FRR pathd —
    //   list segment-list { key name; list segment { key index;
    //       choice type { case mpls { leaf label; }
    //                     case srv6 { leaf sid; } } } }
    //   list policy { key "color endpoint"; leaf binding-sid;
    //       list candidate-path { key preference;
    //           choice { case explicit { leaf-list segment-list; }
    //                    case dynamic  { ... } } } }
  }
}

augment "/configure:set/config:router/bgp:bgp"    { uses bgp-sr-policy-extension; }
augment "/configure:delete/config:router/bgp:bgp" { uses bgp-sr-policy-extension; }
```

Rust side mirrors `color_policy.rs`: a `config_sr_policy_*` callback set
registered in `config.rs`, staging onto `Bgp::sr_policy_config`. Remember
`cargo`/`clippy` do not validate YANG — the `yang_load_tests` CI guard
does, so the module must load cleanly there.

## 8. Show / operational model

zebra-rs `show` is hand-rolled Rust→(text|JSON), not an NMDA datastore, so
the operational model is Rust structs serialized with serde, registered in
`show.rs` (e.g. `show_add("/show/ip/bgp/sr-policy", ...)`). Commands:

- `show bgp ipv4 sr-policy` / `show bgp ipv6 sr-policy` — one block per
  `<color, endpoint>`: each candidate path with preference, origin,
  discriminator, validity, the `*` active marker, BSID, and segment lists
  (label stack or SRv6 SID list) with weights.
- `show bgp ipv4 sr-policy detail` — adds attribute provenance (peer,
  originator, RT/NO_ADVERTISE usability verdict).
- `show bgp ipv4 sr-policy adj-rib-in` — raw received NLRI incl.
  not-usable entries.

Text shape (sketch):

```
SR Policy color 100 endpoint 10.0.0.9 (IPv4)
  Candidate-path pref 200 origin BGP(20) disc 1  [active] valid
    binding-sid: SRv6 fc00:0:9::100 (End.B6.Encaps)
    segment-list weight 1:
      fc00:0:2:: (Type B)
      fc00:0:9:: (Type B)
  Candidate-path pref 100 origin BGP(20) disc 2  valid
    ...
```

## 9. Dataplane realization (deferred — design sketch)

SRv6 first, reusing the existing SID/locator + seg6 lwtunnel machinery:

- **Binding SID** for an SRv6 policy = a local SID with **End.B6.Encaps**
  behavior (IANA SRv6 Endpoint Behavior — *confirm exact codepoint before
  coding*). Allocate from the configured locator (when `allocation
  dynamic`) or honour the advertised SRv6 BSID (`explicit`). Install via
  the existing `route_sid_install` / `build_seg6local_lwtunnel` path, with
  the encap = the active path's segment list.
- **Segment list → forwarding**: H.Encap (default per repo's SRv6 encap
  policy) or H.Encap.Red; `NexthopUni.segs` + `encap_type`, resolved to a
  first-hop via NHT against the first segment / endpoint.
- **Weighted ECMP** across segment lists → `NexthopMulti` with per-member
  weights.
- SR-MPLS variant (later): BSID = an ILM (incoming label) that pushes the
  label stack; `NexthopUni.mpls_label` + `label_manager` for dynamic BSID.

The active path feeds the dataplane only when the policy is *valid* and
its first segment resolves (NHT) — same gate philosophy as the NHT series.

## 10. Automated steering (deferred — design sketch)

Steers color-tagged service routes (IPv4/IPv6/VPNv4/VPNv6) onto a policy:

- On a received unicast/VPN route carrying a Color Extended Community,
  resolve onto `SrPolicyDb[<color, nexthop>]`; apply CO-bit fallback
  (00 strict, 01/10 broaden to null-endpoint / any-AF). Highest numeric
  matching color wins.
- The resolved policy's BSID/segment list becomes the route's forwarding
  nexthop (hooks into `VpnNexthop` resolution + NHT, where v6/VPN nexthop
  resolution already lives).
- **Reconcile with the existing `color_policy` (color → flex-algo) map:**
  both are color-keyed steering. Proposed precedence — an explicit SR
  Policy match wins over a flex-algo binding; flex-algo is the fallback
  when no policy exists for the color. Likely unify both under a single
  `steering`/`color-policy` config umbrella at that time.

## 11. Phasing / PR plan

Small PRs, branch already `bgp-sr-policy`. `cargo fmt` + workspace clippy
before each; CI is source of truth (don't run bdd locally).

**Control-plane (this body of work):**

- **PR1 — SAFI + NLRI codec.** `Safi::SrTePolicy=73`, `nlri_srpolicy.rs`,
  `MpReachAttr/MpUnreachAttr::SrPolicy`, capability negotiation,
  `Args::afi_safi` + `zebra-afi-safi.yang` enums. Decode-only into
  Adj-RIB-In, no DB. Round-trip + negotiation tests.
- **PR2 — typed sub-TLVs.** `srpolicy.rs` typed view (Preference, BSID,
  SRv6 BSID, ENLP, Priority, Segment List with Type A + Type B, names) +
  Color Extended Community accessor. Per-sub-TLV round-trip tests.
- **PR3 — SR Policy DB + selection + show.** `sr_policy.rs`, usability
  filter, validation, RFC 9256 §2.9 selection, `show bgp … sr-policy`,
  minimal `sr-policy` config container. Selection unit tests.

**Later (separate bodies of work, re-confirm direction first):**

- **PR4 — SRv6 dataplane** (BSID End.B6.Encaps + seg6 encap, weighted ECMP).
- **PR5 — SR-MPLS dataplane** (BSID ILM + label-stack push).
- **PR6 — automated steering** (color extcomm resolver, CO bits,
  color_policy reconciliation).
- **PR7 — originator** (config-defined local policies advertised as SAFI
  73, NO_ADVERTISE / RT=peer-router-id attachment) + RR pass-through.

## 12. Validation strategy

- **Unit / round-trip tests** in `bgp-packet` for the NLRI and every
  sub-TLV (the codec is the highest-risk surface and FRR can't peer with
  it).
- **Selection tests** exercising each RFC 9256 §2.9 tie-break rung.
- **Wire interop:** FRR is *not* usable (no SAFI 73). Validate against a
  **Cisco IOS-XR** speaker or **a captured SAFI-73 UPDATE pcap** replayed
  into the parser. Capture our own emitted bytes once the originator
  lands and diff against the reference.
- **BDD** for the receive→DB→show pipeline in CI (not run locally).

## 13. Risks and open questions

- **No FRR interop peer** — the single biggest risk. Mitigate with pcap
  fixtures + IOS-XR. Get at least one real SAFI-73 capture early.
- **Segment-List inner registry codepoints ≠ A–K letters** and several are
  deprecated — table-drive the decode, test the deprecated codes.
- **Endpoint/segment AFI independence** — the policy AFI (NLRI) and the
  segment dataplane (MPLS vs SRv6) vary independently; keep them decoupled
  in the type system (don't infer SRv6 from AFI 2).
- **End.B6.Encaps codepoint** — confirm the exact IANA SRv6 Endpoint
  Behavior value before the dataplane phase.
- **Steering vs flex-algo precedence** — decide when PR6 is designed; both
  are color-keyed and must not double-resolve.
- **Originator scope** — confirm whether a real controller/PCE is in the
  test topology, or whether the originator phase is purely for self-interop.
```
