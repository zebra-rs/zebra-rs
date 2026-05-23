# OSPFv3 follow-ups

Snapshot of remaining v3 work as of `main` ≈ commit `dcb9b20c` (PR #818
merged). Captures both the "obvious next slice" candidates and the
larger features still missing, so a future session can pick from a
known list instead of re-deriving the state of the world.

Before picking the next item, follow the project's standing guidance:
recommend the smallest meaningful slice with the main tradeoff, let
the user redirect, and ship one branch / one PR at a time. Multiple
file batches before review have backfired in this codebase.

## Recently landed (context)

This session landed v3 PRs in this order. Each is a self-contained
slice; reading their diffs is the fastest way to learn the file
layout if you're new to the v3 path.

- **#806** — `Ospf<Ospfv3>` IPv6 RIB diff/apply + `top.rib6` shadow.
  `show ipv6 ospf route` walks the shadow.
- **#807** — Drop `IPV6_V6ONLY` on the v3 raw socket (Linux returns
  `EINVAL` on raw sockets with non-TCP/UDP protocols).
- **#808** — Retransmit-list bookkeeping for area-scope flooding +
  `ospfv3_ls_ack_recv` + `Message::Retransmit` dispatch +
  `Ospf<Ospfv3>::process_retransmit`.
- **#811** — Link-LSA MaxAge flush on `Message::Disable` via
  `link_lsa_flush`.
- **#813** — Initialize `OspfLink::interface_id` from `link.index`
  (was permanently 0).
- **#814** — Retransmit-list bookkeeping for link-scope flooding
  (`flood_link_scope_lsa`).
- **#816** — Network-LSA MaxAge flush on `Message::Disable` via
  `network_lsa_flush`.
- **#818** — Populate `nbr.db_sum` for v3 via
  `ospfv3_populate_initial_db_summary` (initial DBD was carrying zero
  headers, forcing peers to learn LSDB via flooding alone).

## Small / one-PR each

### Self-originated LSA flush on `despawn_ospfv3` / instance shutdown
Today `despawn_ospfv3` (in `zebra-rs/src/config/ospf.rs`) just drops
channels and sends `rib::Message::ProtoCleanup`. Self-originated
Router-LSA / Network-LSA / Link-LSA / Intra-Area-Prefix-LSA stay in
peers' LSDBs until each peer's own copy ages out. A polite shutdown
would set every self-originated LSA to MaxAge and re-flood before
tearing down. Nuance: the task is being killed, so the flushed LSU
needs a brief drain window before the socket closes — easiest with a
short `tokio::time::sleep` after the floods but before the channel
drop.

### Drop lingering `#[allow(dead_code)]` on `socket.rs` v6 helpers
`set_ipv6_pktinfo`, `ospf_join_if_v6`, `ospf_join_alldrouters_v6`,
`ospf_leave_alldrouters_v6` (in `zebra-rs/src/ospf/socket.rs`) still
carry `#[allow(dead_code)]` from when the v6 socket family wasn't
wired. They're all called now — drop the attributes.

### Stale `Ospfv3Lsa::update` TODO claim
`zebra-rs/src/ospf/version.rs:151` still says the v3 `update_lsa`
"implementation hasn't landed yet — the impl is a TODO no-op". The
actual impl at `crates/ospf-packet/src/v3.rs:1474` computes the
Fletcher checksum and length correctly. Refresh the comment.

### Hello-packet `interface_id` consistency check
RFC 5340 §4.2.2.1: if a neighbor's Hello arrives with a different
`interface_id` than we previously recorded, drop the packet. Today
`ospfv3_hello_recv` overwrites `nbr.interface_id` on every Hello
without checking — minor robustness gap.

## Medium

### AS-External-LSA / redistribution for v3
v2's `inst.rs:702` note ("Summary/AS-External origination not yet
implemented; flush with MaxAge") applies equally to v3. Needs:
build, install, flood through the AS-scope LSDB (`lsdb_as`), and
include in SPF as external-route candidates. Largest remaining
single-area protocol gap; would let zebra-rs v3 redistribute
connected/static/BGP routes.

### Loopback interfaces
`ifsm.rs:17` notes loopback handling is elided. Loopbacks are
common router interfaces and currently can't be advertised as stub
networks. Needs an IFSM path that treats `IFF_LOOPBACK` as
Point-to-Point with no neighbors, advertising the prefix into the
Router-LSA / Intra-Area-Prefix-LSA.

### Forwarding-address resolution §16.4 step 3
`inst.rs:3196` deferred this — needed for correct multi-router
external-route forwarding. Has to inspect the AS-External-LSA's
forwarding address and resolve it against the local LSDB.

### DBD-MTU mismatch sequence-number tracking
`ospfv3_db_desc_recv` drops mismatched-MTU DBDs but doesn't reset
the seqnum on either side. After a mismatch, ExStart can loop
without ever clearing. Minor.

## Large

### Inter-Area-Prefix-LSA / Inter-Area-Router-LSA / ABR
Multi-area v3. Needs:
1. ABR classification (router attached to >=2 active areas).
2. Type-3 (Inter-Area-Prefix-LSA, 0x2003) origination per ABR from
   intra-area SPF results.
3. Type-4 (Inter-Area-Router-LSA, 0x2004) for ASBR reachability
   across areas.
4. Inter-area SPF stage that consumes #2 / #3 into the IPv6 RIB.

Chunky. Split into "ABR detection + Type-3 originate", "Type-3
ingestion in SPF + inter-area routes", "Type-4 + ASBR".

### Stub area / NSSA for v3
YANG schema already has the identities (see
`yang/ietf-ospf@2022-10-19.yang:374`) but no backend wiring. Needs
`AreaType::Stub` / `Nssa` handling in flooding scope filters, ABR
origination of default-route Inter-Area-Prefix-LSA, etc.

### NBMA networks
`nfsm.rs:22` — currently neither v2 nor v3 implement NBMA. Needs
configured static neighbor list, unicast Hello to each, no DR
multicast.

### Segment-routing for v3
v2 has SR-MPLS; v3 needs RFC 8666 LSA TLVs (Prefix-SID,
Adjacency-SID, SR-Algorithm). Label-map bookkeeping is already
generic over V on the v2 side, so a lot of plumbing is shareable.

## Validation (no new protocol code)

### Two-router FRR-peer test harness
Highest payoff per line: we've shipped eight v3 PRs without ever
booting against a real peer. A netns + FRR ospf6d test that walks
adjacency to Full and diffs LSDB / IPv6 RIB against a known-good
fixture would surface latent interop bugs in everything since #806.
Reuse the existing v2 BDD scaffolding if possible (see
`zebra-rs/bdd/` — currently excluded from CI but locally runnable).

### Single-router golden-traffic captures
Lock the wire format we just shipped by capturing one `pcap` per
packet type (Hello / DBD / LSReq / LSU / LSAck) and adding a
fixture-decode test. Cheap regression guard once the FRR harness is
in.

## Known smell — not blocking but worth a sweep

- `Message<V>` `Retransmit(u32, Ipv4Addr)` / `LsReqRetransmit` /
  `DdRetransmit` carry `Ipv4Addr` even on v3, where it's the
  router-id (not the wire address). Works because `link.nbrs` is
  keyed by `Ipv4Addr` on both versions, but the type is misleading —
  consider renaming the field or wrapping in a `NbrKey` newtype.
- `ospfv3_db_desc_proc` does `nbr.dd.recv = dd.clone()` at both the
  start and end of the function. Dead write at the start — pick one
  position.
- `network_lsa_originate`'s flush branch (`!is_dr || full_nbr_count
  == 0`) duplicates `network_lsa_flush` from #816. Could fold by
  having `network_lsa_originate` call `network_lsa_flush` when the
  preconditions don't hold.
