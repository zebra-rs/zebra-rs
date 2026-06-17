# BGP Labeled Unicast (SAFI 4) — Status, Architecture, Follow-ups

Tracks BGP Labeled Unicast (BGP-LU, RFC 3107 / RFC 8277), including
6PE (RFC 4798), for `label-v4` (AFI 1, SAFI 4) and `label-v6` (AFI 2,
SAFI 4). The control plane and the MPLS dataplane have both landed;
this document captures **what landed**, **why each slice landed in the
shape it did**, and **what's intentionally deferred** so a future
contributor can resume without reading the conversation history.

Same standing guidance as elsewhere in `docs/design/`: recommend the
smallest meaningful slice with the main tradeoff, ship one branch / one
PR at a time, don't queue follow-up files before review.

Read this first if you're touching the `v4lu` / `v6lu` Loc-RIB tables,
`Labelv4Nlri` / `Labelv6Nlri`, `MpReachAttr::Labelv4/Labelv6`,
`route_labelv4/v6_*`, `route_advertise_to_peers_labelv4/v6`,
`fib_install_labelv4/v6`, `reconcile_swap_ilm`, `BgpRib.local_label`,
`BgpTop.lu_labels` / `LuLabels`, `NhtDep::V4lu/V6lu`, or
`IlmType::Swap`.

Config surface:

```
router {
  bgp {
    neighbor 10.0.0.1 {
      afi-safi label-v4 { enable true; }
      afi-safi label-v6 { enable true; }
    }
    afi-safi label-v4 {
      network 10.0.0.0/24;
      redistribute connected;
    }
    afi-safi label-v6 {
      network 2001:db8::/48;
      redistribute static;
    }
  }
}
```

## What landed

Built control-plane-first, one branch / one PR per phase. Final landed
set, in merge order:

| Phase | PR    | Subject                                                          |
| ----- | ----- | --------------------------------------------------------------- |
| 1     | #1042 | NLRI codec in `bgp-packet` (`Labelv4/v6Nlri`, MP_REACH/UNREACH, 6PE next-hop) |
| 2–4   | #1047 | negotiate + Loc-RIB ingest + `show` + advertise + `network` label-v4 |
| 4b    | #1054 | `network` label-v6 + redistribute into label-v4 / label-v6      |
| 5a+5b | #1060 | MPLS dataplane: ingress label-push + transit swap-ILM / local label |

Phases 2–4 were authored as separate stacked PRs (#1043/#1044/#1047)
but **consolidated into #1047** at merge time: the Flow Spec and RTC
series were landing in parallel and re-conflicted the stack (always
additively — both sides add enum variants / a module / YANG enums in
the same regions), so the remaining three phases were squashed into one
PR to land in a single CI cycle rather than chase a fast-moving `main`.
Lesson for the next multi-PR series here: with a busy `main`, prefer
fewer / consolidated PRs over a tall stack.

## Architecture

### Wire codec (`bgp-packet`)

`Safi::MplsLabel = 4` and its `u8`↔`Safi` conversions already existed.
Phase 1 added the NLRI types that ride it, in
`crates/bgp-packet/src/attrs/nlri_labeled_unicast.rs`:

- `Labelv4Nlri` / `Labelv6Nlri` — a 3-octet MPLS label plus an
  IPv4/IPv6 prefix. The layout is a VPNv4/VPNv6 NLRI **minus the 8-octet
  Route Distinguisher**: the length field counts the label (24 bits)
  plus the prefix, so parse subtracts 24, not 88. Identity
  (`PartialEq`/`Eq`/`Hash`) **excludes the label** — same reasoning as
  `Vpnv4Nlri` — so a prefix-keyed advertise-cache removal still matches
  an entry cached under its real label.
- `MpReachAttr::Labelv4 / Labelv6` and `MpUnreachAttr::Labelv4(Eor) /
  Labelv6(Eor)`, decoded in `parse_nlri_opt` for `(Ip, MplsLabel)` and
  `(Ip6, MplsLabel)`, with matching emit helpers.
- Next-hop: IPv4 LU accepts a v4 (4 octets) or v6 (16/32, RFC 8950)
  next-hop; IPv6 LU is 16 octets, and an IPv4 next-hop is emitted as its
  IPv4-mapped IPv6 form for **6PE** (RFC 4798).

### Capability negotiation (control-plane only)

Negotiation is automatic: `zebra-afi-safi.yang` names `label-v4` /
`label-v6`, `configs.rs::afi_safi()` maps them to `(Ip/Ip6,
MplsLabel)`, `config_afi_safi` stores the enabled family in
`peer.config.mp`, and `build_open_packet` already emits a
`CapMultiProtocol` per enabled family. No SAFI-4-specific OPEN code.

### Loc-RIB and the best-path engine

`LocalRib` grew `v4lu: LocalRibTable<Ipv4Net>` and `v6lu:
LocalRibTable<Ipv6Net>` (plus `AdjRib.v4lu/v6lu`). The best-path engine
is the existing NLRI-agnostic `LocalRibTable` — it compares only
`BgpRib` fields — so labeled routes select exactly like unicast. The
per-prefix **received** label rides each `BgpRib.label`.

`route_labelv4/v6_update` / `_withdraw` ingest received routes (mirror
the v6-unicast path), `route_clean` sweeps the LU tables on peer-down
(no LLGR yet), and `show bgp labeled-unicast` lists both Loc-RIBs
with a Label column.

### Advertise and origination

`route_update_labelv4/v6` build the `(NLRI, attr, next-hop, label)` for
each peer, mirroring `route_update_ipv6`'s attribute handling
(split-horizon, iBGP-RR gating, AS_PATH prepend, next-hop-self,
LOCAL_PREF, ORIGINATOR_ID/CLUSTER_LIST). `attrs.nexthop` is **cleared**
so the MP_REACH is the sole next-hop — `BgpAttr::attr_emit` only emits a
legacy (type-3) NEXT_HOP for `BgpNexthop::Ipv4`, which would
double-encode otherwise.

`route_advertise_to_peers_labelv4/v6` send immediately per peer (no
update-group batching yet — LU volumes are small, e.g. PE loopbacks).
Origination sources:

- **propagate-received** — a received LU best-path winner re-advertises
  (RR / inter-AS Option-C transit);
- **6PE** — `route_update_labelv6` encodes a next-hop-self over an IPv4
  transport session as the IPv4-mapped IPv6 next-hop;
- **`network`** — `route_add/del_label_v4/v6` originate into `v4lu/v6lu`
  with implicit-null (the YANG `network` key is a `union` of
  ipv4-prefix / ipv6-prefix; `config_network` parses per afi-safi);
- **redistribute** — `redist_afi_valid` accepts the label families, and
  `route_redist_add` fans one per-AFI RIB subscription into **every**
  configured `(afi-safi, source)` table, so the same connected/static/
  IGP route can land in `ipv4` *and* `label-v4`. This also fixed a
  latent bug: the v4-unicast inject is now gated on `(ipv4, source)`
  being configured.

### MPLS dataplane

Two halves, both reusing the FRR-validated VPNv4/VPNv6 + NHT machinery.

**5a — ingress LSR (forward into the LSP).** A received labeled route
installs an IP FIB entry that pushes the received label toward its
recursively-resolved BGP next-hop, via `fib_install_labelv4/v6` →
`build_vpn_fib_entry(received_label, transport)`, where the transport
comes from the **global** NHT cache (not a per-VRF map).
`NhtDep::V4lu/V6lu` track the next-hop (register-then-gate);
`nht_reeval_dep` / `nht_reinstall_transport` re-install on resolve /
reroute. Self-originated FECs install nothing (we are the egress).
`fib_install_labelv4/v6` take `(rib_client, cache)` directly — not a
`BgpTop` — so the `inst.rs` NHT re-eval can call them too.

**5b — transit/egress LSR (swap).** When we re-advertise with
next-hop-self we become the forwarding hop, so we allocate a per-prefix
**local label** (`BgpRib.local_label`, distinct from the received
`label`), advertise *that* in the NLRI, and program an ILM that swaps it
to the received label toward the resolved transport:

- `IlmType::Swap` — a generic label-swap ILM; the netlink builder
  already emits the `NewDestination` swap for any non-`DecapVrf` entry,
  so this variant only labels the owner for show output / ILM selection.
- the swap stack rides `NexthopUni.mpls_label` (the ILM swap field),
  **not** `NexthopUni.mpls` (which IP-route installs use) — a real,
  easy-to-miss distinction.
- labels reuse the shared `VrfLabelAllocator` (the same dynamic pool as
  per-VRF labels). Per-prefix maps `lu_label_v4/v6` live on `Bgp`,
  threaded as `BgpTop.lu_labels` (`LuLabels`) into the **single** receive
  `BgpTop` (the one with `nexthop_cache: Some(...)`); `None` at every
  other ~25 `BgpTop` construction site — self-originated FECs advertise
  implicit-null and need no local label.
- `reconcile_swap_ilm` (called from `fib_install_labelv4/v6`, so
  receive + NHT-reeval + originate all hit it) installs the swap ILM
  when the next-hop resolves, removes it when unresolved.
- `request_label_block()` is called eagerly when a label family is
  enabled, so a dynamic block is usually granted before routes arrive;
  with no block yet a route advertises the received label as a fallback.

Forwarding behaviour by role: an egress PE for a self-originated FEC
advertises implicit-null (peer does PHP, IP lookup lands locally); a
transit/Option-C ASBR re-advertising with next-hop-self advertises its
local label and swaps `local → [transport…, received]`; an iBGP speaker
advertising next-hop-unchanged passes the received label through and
installs no local label / ILM.

## Status: control-plane green, forwarding not real-run-validated

Every phase is `cargo fmt` + workspace-`clippy -D warnings` clean with
its unit tests green (codec round-trips in `bgp-packet`; the zebra-rs
suite + `yang_load_tests`). The **MPLS forwarding itself — the kernel
LFIB label push (5a) and swap (5b) — is not exercised by the unit
suite.** It mirrors the VPNv4/VPNv6 install + NHT paths that *are*
FRR-validated, but the BGP-LU push/swap should be confirmed on a live
FRR + kernel-MPLS run / BDD before being relied on. This is the one
thing software couldn't settle here.

## Deferred / known gaps

- **Real-run forwarding validation** (above) — the top follow-up.
- **IPv6 *unicast* redistribute** delivery is still storage-only
  (`route_redist_add`'s V6 batch feeds `label-v6` but not `ipv6`); this
  is a pre-existing gap independent of LU, left untouched.
- **Received + self-originated same prefix**: when the originated path
  wins best-path, the swap ILM allocated for the received path isn't
  torn down (the local label stays mapped). Harmless — the label is no
  longer advertised, so no traffic arrives on it — but it leaks a label
  until the prefix is fully withdrawn.
- **No update-group batching** for LU advertise (immediate per-peer
  send). Fine at loopback scale; revisit if full-table LU appears.
- **No LLGR** for the LU families in `route_clean` (matches v6 unicast).
- **No async relabel**: if a label block hasn't arrived when a route is
  first received, that prefix keeps advertising the received label even
  after the block lands (it isn't re-evaluated). The eager
  `request_label_block()` on family-enable makes this rare.
- **Per-afi-safi redistribute metric/policy** beyond the static
  `metric` override is not threaded for the label families (matches the
  unicast redistribute, which only carries `metric`).
