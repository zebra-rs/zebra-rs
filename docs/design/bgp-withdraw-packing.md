# BGP withdraw packing: per-peer pending withdrawals

Status: implemented (branch `bgp-withdraw-pack`, 2026-09-06).

## Problem

Every BGP withdraw left the router as its own one-NLRI UPDATE. The
announce side has batched for a long time — the per-peer VPNv4 / VPNv6 /
EVPN caches and the per-update-group IPv4 / IPv6 caches group NLRIs by
attribute and paginate to the negotiated message size — but the withdraw
side went straight from best-path to `Peer::send_update`. A peer going
down, a route-reflector sweep, a soft-out that now denies a table: each
produced thousands of 27-octet UPDATEs where a handful of 4096-octet ones
would do (`docs/design/bgp-code-review-findings.md`, "~100× the packet
count on a full-table withdraw sweep").

## Model

rustybgp's `PendingTx` (`daemon/src/peer_tx.rs`): per peer, a `reach` map
and an `unreach` map keyed on route identity. `reach()` removes the key
from `unreach` and vice versa, so a key is in at most one of the two; the
drain sends the withdrawals first as one logical Unreach message that the
codec splits to the wire size, then the reaches grouped by attribute.

zebra-rs already had the reach half. This change adds the unreach half
and, because zebra-rs's announce caches are not all per-peer, an explicit
rule for keeping the wire in step with the Adj-RIB-Out.

## Implementation

### Codec (`crates/bgp-packet`)

- `UpdatePacket::pop_ipv4_withdraw` — one withdraw-only UPDATE per call
  from the legacy Withdrawn Routes field, as many NLRIs as fit
  `max_packet_size`, the rest left queued.
- `UpdatePacket::pop_mp_withdraw` — the MP_UNREACH_NLRI form, backed by
  `MpUnreachAttr::attr_emit_mut`: one generic paginator for every list
  family that measures each NLRI by encoding it (EVPN / Flowspec vary by
  route type) and budgets the whole packet (header + withdrawn-length +
  attribute-length + 4-octet attribute header + AFI/SAFI), the rule PR
  #2370 established for MP_REACH.
- End-of-RIB variants are refused by the pop (an empty MP_UNREACH *is* an
  EoR on the wire) and keep going through `try_emit`.

### Queue and drain (`zebra-rs/src/bgp/pending_withdraw.rs`)

`Peer::pending_withdraw` holds one set per family — IPv4 / IPv6 unicast,
VPNv4 / VPNv6, EVPN, IPv4 / IPv6 labeled-unicast — keyed on route
identity, so a route withdrawn twice before the flush is sent once. Every
withdraw site (`route_withdraw_ipv4/6/vpnv6/evpn`, the labeled-unicast
branches of `route_advertise_labeled`) now queues instead of sending.

Queueing arms one `Message::FlushWithdraw(ident)` per peer, a ~1 ms
next-tick marker (`Timer::once_ms(1)`, the `adv-interval 0` shape). The
marker lands on the instance channel *behind* the ingest already queued,
so under a burst the drain runs after the whole backlog has been processed
and packs everything it produced; when the router is idle a withdraw costs
one extra tick. The drain builds one `UpdatePacket` per family and loops
`pop_*` until dry.

### Keeping the wire in step with the Adj-RIB-Out

Queueing opens a window in which a route can be re-advertised before its
withdraw goes out. Two rules close it:

1. **The Adj-RIB-Out is the authority at drain time.** Every advertise
   site records the route in `peer.adj_out` as it queues or sends, and
   every withdraw site removes it before queueing. At drain, a queued NLRI
   whose `(prefix, path-id)` is back in the Adj-RIB-Out has been superseded
   by a newer announcement — pending in a cache or already sent — and is
   dropped. `id == 0` (non-AddPath) matches any row for the prefix; a real
   path-id must match exactly. The per-peer caches also cancel directly:
   `send_vpnv4/6` and `send_evpn` remove the queued withdraw of the route
   they queue (rustybgp's `reach()`), and the announce-side eviction on
   withdraw (`cache_remove_*`) was already there. The Adj-RIB-Out check is
   what makes the invariant hold for IPv4 / IPv6 unicast, whose
   announcements ride a cache shared by the whole update-group.
2. **An in-flight update-group flush gates the drain.** The IPv4 / IPv6
   unicast flush job encodes and enqueues its announcements on a
   blocking-pool thread. A withdraw enqueued from the main task while that
   job runs could reach the writer *before* the job's announcement of the
   same prefix and leave the peer holding a route the Adj-RIB-Out has
   dropped. So those two families stay queued while any job carrying the
   peer's announcements is out: `flush_ipv4/6` counts the job up on each
   member (`Peer::flush_jobs_v4/v6`), the `FlushDone` message carries the
   member list, and `flush_done_ipv4/6` counts it off and drains the
   released members after every job byte is on the writer — replacing the
   per-group `deferred_withdraw_*` parking that served the same race
   (sharding plan A.2). The count lives on the peer, not the group, and
   `flush_done` settles it whether or not the group still exists:
   configuration can detach a group's last member (deleting the group) or
   move a peer to another group while the job is out, and neither may
   strand a parked withdrawal or release it early.

`route_clean` (session leaves Established) drops the queue and the marker
with the advertise caches; the flush is gated on Established so a marker
that outlives its session cannot push anything onto a new one.

Rule 1 makes the Adj-RIB-Out load-bearing in a way it was not before: a
withdraw site that forgets to remove its row now silently cancels its own
withdraw instead of merely leaving a phantom row for soft-out. The first
full-suite run caught exactly one such site — the VPNv6 AddPath withdraw
(`route_withdraw_vpnv6_addpath`) never removed the row, and its advertise
twin never recorded one, so only dump-recorded rows existed and
`bgp_shard_addpath_vpnv6` kept a withdrawn path. Both now mirror the VPNv4
AddPath path. Any new withdraw site must remove its Adj-RIB-Out row
before queueing.

### What still sends immediately

MUP, Flowspec, SR Policy, RTC and BGP-LS withdrawals keep their
one-per-UPDATE sends; the codec paginates them already, so moving them
onto the queue is a per-site change when it matters. IPv4 withdrawals
under an RFC 8950 (extended next-hop) session still use the legacy field;
rustybgp switches to MP_UNREACH there.

## Verification

- `crates/bgp-packet` unit tests: pagination fills each packet to the
  budget for IPv4 (legacy and Add-Path), VPNv4, VPNv6, IPv6 and mixed-type
  EVPN; extended-message budget; EoR refusal; no path attributes on a
  withdraw-only UPDATE.
- `pending_withdraw` unit tests: one marker per burst; 3000 IPv4
  withdrawals in four UPDATEs; Adj-RIB-Out reconciliation for non-AddPath
  and AddPath ids and per-RD for VPN / EVPN; re-advertise cancels a queued
  VPN withdraw; a down peer discards. `update_group` test: the in-flight
  gate holds a unicast withdraw (a VPN one on the same peer still goes) and
  `flush_done_ipv4` releases it.
- BDD `@bgp_withdraw_packing` (`bdd/tests/scripts/bgp_withdraw_packing.py`):
  two scripted iBGP clients of a zebra-rs RR; the observer parses the raw
  TCP stream. Per family (IPv4, IPv6, VPNv4, VPNv6, EVPN) and per message
  size (4096 / 65535): 1000 withdrawals arrive within a computed UPDATE
  bound with no stale announcement overtaking one; announce+withdraw and
  withdraw+announce sent back to back settle absent / present.
