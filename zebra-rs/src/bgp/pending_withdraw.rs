//! Per-peer pending withdrawals: the withdraw half of the outbound
//! batching that the advertise caches (`cache_vpnv4`, the update-group
//! `cache_ipv4`, …) provide for announcements.
//!
//! Modelled on rustybgp's `PendingTx`: instead of putting every withdrawn
//! NLRI on the wire as its own one-route UPDATE the moment best-path
//! removes it, a withdraw is queued on the peer and a next-tick flush
//! ([`Message::FlushWithdraw`], armed once per peer while anything is
//! queued) drains the queue into as few UPDATEs as the negotiated message
//! size allows. Because the flush marker lands on the BGP instance channel
//! *behind* whatever ingest is already queued, a burst — a peer going down,
//! a route-reflector sweep, a soft-out — is drained in one go, so packing
//! scales with the backlog and stays at one extra tick of latency when the
//! router is idle.
//!
//! # Keeping the wire in step with the Adj-RIB-Out
//!
//! Queueing a withdraw opens a window in which the same route can be
//! re-advertised before the withdraw goes out. Two rules close it:
//!
//! 1. **The Adj-RIB-Out is the authority at drain time.** Every advertise
//!    site records the route in `peer.adj_out` as it queues or sends the
//!    announcement, and every withdraw site removes it before queueing the
//!    withdraw. So when the queue drains, a queued NLRI whose `(prefix,
//!    path-id)` is back in the Adj-RIB-Out has been superseded by a newer
//!    announcement — pending in a cache or already sent — and is dropped:
//!    sending it would tear down a route the Adj-RIB-Out says the peer
//!    holds. (The announce-side caches already evict a queued announce on
//!    withdraw, and [`Peer::send_vpnv4`] & co. drop a queued withdraw on
//!    re-advertise, mirroring rustybgp's `reach()` / `unreach()`; the
//!    Adj-RIB-Out check is what makes this hold for the families whose
//!    announcements ride a shared update-group cache.)
//! 2. **An in-flight update-group flush gates the drain.** The IPv4 /
//!    IPv6 unicast flush job encodes and enqueues its announcements on a
//!    blocking-pool thread; a withdraw enqueued from the main task while
//!    that job runs could land on the writer *before* the job's
//!    announcement of the same prefix, leaving the peer with a route the
//!    Adj-RIB-Out has already dropped. So those two families stay queued
//!    while any job carrying this peer's announcements is out
//!    (`Peer::flush_jobs_v4` / `v6`, counted up when the job is spawned),
//!    and [`flush_done`](super::update_group::flush_done_ipv4) counts the
//!    job off and drains them once every job byte is on the writer
//!    channel. The count lives on the peer rather than the group so it
//!    survives the group being deleted or the peer moving to another
//!    group while the job is out. (This replaces the per-group
//!    `deferred_withdraw_*` parking that served the same race.)
//!
//! A session leaving Established clears the queue and cancels the marker
//! (`route_clean`); the flush itself is gated on Established so a marker
//! that outlives its session cannot push anything onto a new one.

use std::collections::{HashMap, HashSet};

use bgp_packet::{Afi, EvpnRoute, Ipv4Nlri, Ipv6Nlri, MpUnreachAttr, Vpnv4Nlri, Vpnv6Nlri};

use crate::context::Timer;

use super::Message;
use super::adj_rib::{AdjRibTable, Out};
use super::peer::{EvpnCacheKey, Peer};
use super::peer_map::PeerMap;

/// The withdrawals queued for one peer, per family. Each family is a set
/// keyed on route identity — for the VPN families that identity is
/// label-blind (`Vpnv4Nlri`'s `Eq`), and an EVPN route is keyed by
/// `(RD, prefix, path-id)` because the withdraw is rebuilt from the RIB key
/// and never sees the queued NLRI's label or gateway — so a route withdrawn
/// twice before the flush is sent once.
#[derive(Debug, Default)]
pub struct PendingWithdraw {
    pub v4: HashSet<Ipv4Nlri>,
    pub v6: HashSet<Ipv6Nlri>,
    pub v4vpn: HashSet<Vpnv4Nlri>,
    pub v6vpn: HashSet<Vpnv6Nlri>,
    pub evpn: HashMap<EvpnCacheKey, EvpnRoute>,
    pub v4lu: HashSet<Ipv4Nlri>,
    pub v6lu: HashSet<Ipv6Nlri>,
}

impl PendingWithdraw {
    pub fn clear(&mut self) {
        self.v4.clear();
        self.v6.clear();
        self.v4vpn.clear();
        self.v6vpn.clear();
        self.evpn.clear();
        self.v4lu.clear();
        self.v6lu.clear();
    }
}

/// Arm the next-tick flush marker: one `Message::FlushWithdraw` on the
/// instance channel after ~1 ms. Mirrors `start_adv_timer!` with
/// adv-interval 0 — the 1 ms is the executor's turnover, not a debounce.
fn start_withdraw_flush_timer(peer: &Peer) -> Timer {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    Timer::once_ms(1, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::FlushWithdraw(ident)).await;
        }
    })
}

impl Peer {
    /// Arm the flush marker unless one is already pending. The marker is
    /// cleared when it is serviced, so a burst of queued withdraws shares
    /// one flush.
    fn arm_withdraw_flush(&mut self) {
        if self.withdraw_timer.is_none() {
            self.withdraw_timer = Some(start_withdraw_flush_timer(self));
        }
    }

    pub fn queue_withdraw_v4(&mut self, nlri: Ipv4Nlri) {
        self.pending_withdraw.v4.insert(nlri);
        self.arm_withdraw_flush();
    }

    pub fn queue_withdraw_v6(&mut self, nlri: Ipv6Nlri) {
        self.pending_withdraw.v6.insert(nlri);
        self.arm_withdraw_flush();
    }

    pub fn queue_withdraw_v4vpn(&mut self, nlri: Vpnv4Nlri) {
        self.pending_withdraw.v4vpn.insert(nlri);
        self.arm_withdraw_flush();
    }

    pub fn queue_withdraw_v6vpn(&mut self, nlri: Vpnv6Nlri) {
        self.pending_withdraw.v6vpn.insert(nlri);
        self.arm_withdraw_flush();
    }

    pub fn queue_withdraw_evpn(&mut self, key: EvpnCacheKey, route: EvpnRoute) {
        self.pending_withdraw.evpn.insert(key, route);
        self.arm_withdraw_flush();
    }

    pub fn queue_withdraw_v4lu(&mut self, nlri: Ipv4Nlri) {
        self.pending_withdraw.v4lu.insert(nlri);
        self.arm_withdraw_flush();
    }

    pub fn queue_withdraw_v6lu(&mut self, nlri: Ipv6Nlri) {
        self.pending_withdraw.v6lu.insert(nlri);
        self.arm_withdraw_flush();
    }

    /// Drop every queued withdrawal and the flush marker — the session is
    /// gone, and a new one re-syncs from scratch.
    pub fn clear_pending_withdraws(&mut self) {
        self.pending_withdraw.clear();
        self.withdraw_timer = None;
    }
}

/// `Message::FlushWithdraw(ident)`: drain the peer's queued withdrawals
/// onto the wire, family by family. Unicast IPv4 / IPv6 stay queued while
/// a flush job carrying the peer's announcements is in flight (see the
/// module doc); `flush_done_*` drains them afterwards.
pub fn flush_pending_withdraws(ident: usize, peers: &mut PeerMap) {
    let Some(peer) = peers.get_mut_by_idx(ident) else {
        return;
    };
    peer.withdraw_timer = None;
    drain_peer(peer);
}

/// After an update-group flush job for `afi` unicast completed — its
/// `members` already counted off their `flush_jobs_*` — drain the unicast
/// withdrawals those members parked behind it. A member another job is
/// still carrying stays parked until that one completes too, and a slot
/// whose `Peer` value changed since the job was spawned (the peer was
/// removed and re-created at the same address) is not the job's member
/// at all and is left alone.
pub fn drain_after_flush(
    afi: Afi,
    members: &[super::update_group::JobMember],
    peers: &mut PeerMap,
) {
    for &(ident, instance) in members {
        let Some(peer) = peers.get_mut_by_idx(ident) else {
            continue;
        };
        if peer.instance != instance {
            continue;
        }
        let (queued, gated) = match afi {
            Afi::Ip => (!peer.pending_withdraw.v4.is_empty(), peer.flush_jobs_v4 > 0),
            _ => (!peer.pending_withdraw.v6.is_empty(), peer.flush_jobs_v6 > 0),
        };
        if !queued || gated {
            continue;
        }
        if !peer.state.is_established() {
            peer.clear_pending_withdraws();
            continue;
        }
        match afi {
            Afi::Ip => drain_v4(peer),
            _ => drain_v6(peer),
        }
    }
}

fn drain_peer(peer: &mut Peer) {
    if !peer.state.is_established() {
        peer.clear_pending_withdraws();
        return;
    }
    if peer.flush_jobs_v4 == 0 {
        drain_v4(peer);
    }
    if peer.flush_jobs_v6 == 0 {
        drain_v6(peer);
    }
    drain_v4vpn(peer);
    drain_v6vpn(peer);
    drain_evpn(peer);
    drain_v4lu(peer);
    drain_v6lu(peer);
}

/// Whether the Adj-RIB-Out still (or again) holds `(prefix, id)`. `id == 0`
/// is the non-AddPath wire id and matches any row for the prefix — a
/// non-AddPath advertisement is stored under the Loc-RIB `local_id`, never
/// 0 — while a real path-id must match exactly. Shared with the gate-on
/// egress engines ([`super::peer_egress`], [`super::group_egress`]), which
/// pack their own IPv4 withdrawals and apply the same reconcile at flush.
pub(super) fn adj_out_has<P: Ord>(table: &AdjRibTable<Out, P>, prefix: &P, id: u32) -> bool {
    table
        .0
        .get(prefix)
        .is_some_and(|rows| id == 0 || rows.iter().any(|r| r.local_id == id))
}

/// Emit `attr`'s withdrawals as as many UPDATEs as the session's message
/// size needs. A queue the codec cannot paginate — a family with no
/// per-NLRI emitter, or an NLRI larger than an empty UPDATE of the session's
/// size — is logged with the number of withdrawals it still held and
/// dropped, rather than lost silently or spun on.
fn send_mp_withdraws(peer: &Peer, attr: MpUnreachAttr) {
    let mut update = peer.update_packet();
    update.mp_withdraw = Some(attr);
    loop {
        match update.pop_mp_withdraw() {
            Ok(Some(bytes)) => peer.send_packet(bytes),
            Ok(None) => break,
            Err(e) => {
                let left = update.mp_withdraw.as_ref().map_or(0, MpUnreachAttr::len);
                tracing::warn!(
                    peer = %peer.address,
                    "dropping {left} queued withdrawals that cannot be sent: {e}"
                );
                break;
            }
        }
    }
}

fn drain_v4(peer: &mut Peer) {
    if peer.pending_withdraw.v4.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.v4);
    let withdraws: Vec<Ipv4Nlri> = queued
        .into_iter()
        .filter(|n| !adj_out_has(&peer.adj_out.v4, &n.prefix, n.id))
        .collect();
    if withdraws.is_empty() {
        return;
    }
    let mut update = peer.update_packet();
    update.ipv4_withdraw = withdraws;
    while let Some(bytes) = update.pop_ipv4_withdraw() {
        peer.send_packet(bytes);
    }
}

fn drain_v6(peer: &mut Peer) {
    if peer.pending_withdraw.v6.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.v6);
    let withdraws: Vec<Ipv6Nlri> = queued
        .into_iter()
        .filter(|n| !adj_out_has(&peer.adj_out.v6, &n.prefix, n.id))
        .collect();
    if !withdraws.is_empty() {
        send_mp_withdraws(peer, MpUnreachAttr::Ipv6Nlri(withdraws));
    }
}

fn drain_v4vpn(peer: &mut Peer) {
    if peer.pending_withdraw.v4vpn.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.v4vpn);
    let withdraws: Vec<Vpnv4Nlri> = queued
        .into_iter()
        .filter(|n| {
            !peer
                .adj_out
                .v4vpn
                .get(&n.rd)
                .is_some_and(|t| adj_out_has(t, &n.nlri.prefix, n.nlri.id))
        })
        .collect();
    if !withdraws.is_empty() {
        send_mp_withdraws(peer, MpUnreachAttr::Vpnv4(withdraws));
    }
}

fn drain_v6vpn(peer: &mut Peer) {
    if peer.pending_withdraw.v6vpn.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.v6vpn);
    let withdraws: Vec<Vpnv6Nlri> = queued
        .into_iter()
        .filter(|n| {
            !peer
                .adj_out
                .v6vpn
                .get(&n.rd)
                .is_some_and(|t| adj_out_has(t, &n.nlri.prefix, n.nlri.id))
        })
        .collect();
    if !withdraws.is_empty() {
        send_mp_withdraws(peer, MpUnreachAttr::Vpnv6(withdraws));
    }
}

fn drain_evpn(peer: &mut Peer) {
    if peer.pending_withdraw.evpn.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.evpn);
    let withdraws: Vec<EvpnRoute> = queued
        .into_iter()
        .filter(|((rd, prefix, id), _)| {
            !peer.adj_out.evpn.get(rd).is_some_and(|t| {
                t.0.get(prefix)
                    .is_some_and(|rows| *id == 0 || rows.iter().any(|r| r.local_id == *id))
            })
        })
        .map(|(_, route)| route)
        .collect();
    if !withdraws.is_empty() {
        send_mp_withdraws(peer, MpUnreachAttr::Evpn(withdraws));
    }
}

fn drain_v4lu(peer: &mut Peer) {
    if peer.pending_withdraw.v4lu.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.v4lu);
    let withdraws: Vec<bgp_packet::Labelv4Nlri> = queued
        .into_iter()
        .filter(|n| !adj_out_has(&peer.adj_out.v4lu, &n.prefix, n.id))
        .map(|nlri| bgp_packet::Labelv4Nlri {
            label: bgp_packet::Label::default(),
            nlri,
        })
        .collect();
    if !withdraws.is_empty() {
        send_mp_withdraws(peer, MpUnreachAttr::Labelv4(withdraws));
    }
}

fn drain_v6lu(peer: &mut Peer) {
    if peer.pending_withdraw.v6lu.is_empty() {
        return;
    }
    let queued = std::mem::take(&mut peer.pending_withdraw.v6lu);
    let withdraws: Vec<bgp_packet::Labelv6Nlri> = queued
        .into_iter()
        .filter(|n| !adj_out_has(&peer.adj_out.v6lu, &n.prefix, n.id))
        .map(|nlri| bgp_packet::Labelv6Nlri {
            label: bgp_packet::Label::default(),
            nlri,
        })
        .collect();
    if !withdraws.is_empty() {
        send_mp_withdraws(peer, MpUnreachAttr::Labelv6(withdraws));
    }
}

#[cfg(test)]
mod tests {
    use super::super::peer::State;
    use super::super::route::{BgpRib, BgpRibType};
    use super::*;
    use bgp_packet::{
        AfiSafi, BgpAttr, EvpnMulticast, EvpnPrefix, Label, RouteDistinguisher, Safi, UpdatePacket,
    };
    use bytes::BytesMut;
    use ipnet::Ipv4Net;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// An Established peer whose writer channel is `rx`.
    fn established_peer() -> (
        Peer,
        mpsc::UnboundedReceiver<BytesMut>,
        mpsc::Receiver<Message>,
    ) {
        let (tx, rx) = mpsc::channel::<Message>(64);
        let mut peer = Peer::new(
            1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            65001,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.state = State::Established;
        let (ptx, prx) = mpsc::unbounded_channel::<BytesMut>();
        peer.packet_tx = Some(ptx);
        (peer, prx, rx)
    }

    fn rib(local_id: u32) -> BgpRib {
        let mut rib = BgpRib::new_arc(
            2,
            "10.0.0.9".parse().unwrap(),
            BgpRibType::IBGP,
            0,
            100,
            Arc::new(BgpAttr::default()),
            None,
            None,
            false,
        );
        rib.local_id = local_id;
        rib
    }

    fn queued(p: &PendingWithdraw) -> usize {
        p.v4.len()
            + p.v6.len()
            + p.v4vpn.len()
            + p.v6vpn.len()
            + p.evpn.len()
            + p.v4lu.len()
            + p.v6lu.len()
    }

    fn v4(i: u32, id: u32) -> Ipv4Nlri {
        Ipv4Nlri {
            id,
            prefix: Ipv4Net::new(Ipv4Addr::from(0x0A00_0000u32 + i), 32).unwrap(),
        }
    }

    /// Drain the writer channel into parsed UPDATEs.
    fn sent(rx: &mut mpsc::UnboundedReceiver<BytesMut>) -> Vec<UpdatePacket> {
        sent_opt(rx, None)
    }

    fn sent_opt(
        rx: &mut mpsc::UnboundedReceiver<BytesMut>,
        opt: Option<bgp_packet::ParseOption>,
    ) -> Vec<UpdatePacket> {
        let mut out = vec![];
        while let Ok(bytes) = rx.try_recv() {
            let (_, p) = UpdatePacket::parse_packet(&bytes, true, opt.clone()).expect("parses");
            out.push(p);
        }
        out
    }

    /// Parse options for a session with Add-Path negotiated on IPv4 unicast.
    fn add_path_v4() -> bgp_packet::ParseOption {
        let mut opt = bgp_packet::ParseOption::default();
        opt.add_path.insert(
            AfiSafi::new(Afi::Ip, Safi::Unicast),
            bgp_packet::Direct {
                recv: true,
                send: true,
            },
        );
        opt
    }

    /// Queueing arms one flush marker per peer; a burst shares it, and it
    /// lands on the instance channel as `FlushWithdraw(ident)`.
    #[tokio::test]
    async fn queue_arms_one_flush_marker() {
        let (mut peer, _prx, mut rx) = established_peer();
        peer.queue_withdraw_v4(v4(1, 0));
        peer.queue_withdraw_v4(v4(2, 0));
        peer.queue_withdraw_v4vpn(Vpnv4Nlri {
            label: Label::default(),
            rd: RouteDistinguisher::default(),
            nlri: v4(3, 0),
        });
        assert_eq!(queued(&peer.pending_withdraw), 3);
        assert!(peer.withdraw_timer.is_some());
        let msg = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("marker within the timeout")
            .expect("channel open");
        assert!(matches!(msg, Message::FlushWithdraw(1)));
        assert!(rx.try_recv().is_err(), "one marker for the burst");
    }

    /// 3000 queued IPv4 withdrawals go out as four 4096-octet UPDATEs.
    #[tokio::test]
    async fn drain_packs_ipv4_withdrawals() {
        let (mut peer, mut prx, _rx) = established_peer();
        for i in 0..3000 {
            peer.queue_withdraw_v4(v4(i, 0));
        }
        flush_pending_withdraws(1, &mut PeerMap::new());
        // No such peer in that map — nothing sent, queue intact.
        assert_eq!(queued(&peer.pending_withdraw), 3000);

        let mut peers = PeerMap::new();
        let address = peer.address;
        peers.insert(address, peer);
        let ident = peers.get(&address).unwrap().ident;
        flush_pending_withdraws(ident, &mut peers);
        let packets = sent(&mut prx);
        assert_eq!(packets.len(), 4);
        let n: usize = packets.iter().map(|p| p.ipv4_withdraw.len()).sum();
        assert_eq!(n, 3000);
        let peer = peers.get_by_idx(ident).unwrap();
        assert_eq!(queued(&peer.pending_withdraw), 0);
        assert!(peer.withdraw_timer.is_none(), "marker consumed");
    }

    /// A queued withdraw whose route is back in the Adj-RIB-Out was
    /// superseded by a re-advertise and must not go out; one whose
    /// path-id differs from the re-advertised path still does.
    #[tokio::test]
    async fn drain_drops_withdrawals_the_adj_rib_out_has_re_acquired() {
        // Non-AddPath session: id 0 on the wire, rows stored under the
        // Loc-RIB local_id. 10.0.0.1 was re-advertised — dropped;
        // 10.0.0.2 was not — goes.
        let (mut peer, mut prx, _rx) = established_peer();
        peer.queue_withdraw_v4(v4(1, 0));
        peer.adj_out.v4.add(v4(1, 0).prefix, rib(7));
        peer.queue_withdraw_v4(v4(2, 0));
        drain_peer(&mut peer);
        let packets = sent(&mut prx);
        assert_eq!(packets.len(), 1);
        let got: Vec<Ipv4Net> = packets[0].ipv4_withdraw.iter().map(|n| n.prefix).collect();
        assert_eq!(got, vec![v4(2, 0).prefix]);

        // AddPath session: path 3 of 10.0.0.3 withdrawn while path 4 was
        // re-advertised — 3 still goes; path 5 of 10.0.0.4 withdrawn then
        // re-advertised — dropped.
        let (mut peer, mut prx, _rx) = established_peer();
        peer.queue_withdraw_v4(v4(3, 3));
        peer.adj_out.v4.add(v4(3, 0).prefix, rib(4));
        peer.queue_withdraw_v4(v4(4, 5));
        peer.adj_out.v4.add(v4(4, 0).prefix, rib(5));
        drain_peer(&mut peer);
        let packets = sent_opt(&mut prx, Some(add_path_v4()));
        assert_eq!(packets.len(), 1);
        let got: Vec<(Ipv4Net, u32)> = packets[0]
            .ipv4_withdraw
            .iter()
            .map(|n| (n.prefix, n.id))
            .collect();
        assert_eq!(got, vec![(v4(3, 0).prefix, 3)]);
    }

    /// VPN and EVPN withdrawals reconcile against their per-RD tables and
    /// paginate through MP_UNREACH.
    #[tokio::test]
    async fn drain_reconciles_vpn_and_evpn_per_rd() {
        let (mut peer, mut prx, _rx) = established_peer();
        let rd = RouteDistinguisher::from_str("65001:1").unwrap();
        let other = RouteDistinguisher::from_str("65001:2").unwrap();
        for i in 0..3 {
            peer.queue_withdraw_v4vpn(Vpnv4Nlri {
                label: Label::default(),
                rd,
                nlri: v4(i, 0),
            });
        }
        // Same prefix re-advertised under `rd` — dropped; under `other` —
        // a different route, the withdraw still goes.
        peer.adj_out
            .v4vpn
            .entry(rd)
            .or_default()
            .add(v4(0, 0).prefix, rib(9));
        peer.adj_out
            .v4vpn
            .entry(other)
            .or_default()
            .add(v4(1, 0).prefix, rib(9));

        let mcast = |i: u32| {
            EvpnRoute::Multicast(EvpnMulticast {
                id: 0,
                rd,
                ether_tag: 0,
                addr: IpAddr::V4(Ipv4Addr::from(0x0A00_0000u32 + i)),
            })
        };
        for i in 0..2 {
            let (rd, prefix) = EvpnPrefix::from_route(&mcast(i));
            peer.queue_withdraw_evpn((rd, prefix, 0), mcast(i));
        }
        let (_, prefix0) = EvpnPrefix::from_route(&mcast(0));
        peer.adj_out.add_evpn(rd, prefix0, rib(2));

        drain_peer(&mut peer);
        let packets = sent(&mut prx);
        assert_eq!(packets.len(), 2, "one VPNv4 UPDATE and one EVPN UPDATE");
        let vpn: Vec<Ipv4Net> = packets
            .iter()
            .filter_map(|p| match &p.mp_withdraw {
                Some(MpUnreachAttr::Vpnv4(w)) => Some(w.iter().map(|n| n.nlri.prefix)),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(vpn.len(), 2);
        assert!(!vpn.contains(&v4(0, 0).prefix));
        let evpn: Vec<EvpnRoute> = packets
            .iter()
            .filter_map(|p| match &p.mp_withdraw {
                Some(MpUnreachAttr::Evpn(w)) => Some(w.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(evpn, vec![mcast(1)]);
    }

    /// A re-advertise through the VPN advertise cache drops the queued
    /// withdraw for the same route (rustybgp's `reach()` cancelling
    /// `unreach`), so the peer sees one implicit replace, never a withdraw
    /// racing the announcement.
    #[tokio::test]
    async fn re_advertise_cancels_queued_vpn_withdraw() {
        let (mut peer, _prx, _rx) = established_peer();
        let rd = RouteDistinguisher::from_str("65001:1").unwrap();
        let nlri = Vpnv4Nlri {
            label: Label::default(),
            rd,
            nlri: v4(1, 0),
        };
        peer.queue_withdraw_v4vpn(nlri.clone());
        let mut labelled = nlri.clone();
        labelled.label = Label::new(300, 0, true);
        peer.send_vpnv4(labelled, Arc::new(BgpAttr::default()), false);
        assert!(peer.pending_withdraw.v4vpn.is_empty());
        assert_eq!(peer.cache_vpnv4_rev.len(), 1);
    }

    /// The VPNv6 AddPath withdraw must drop the path's Adj-RIB-Out row
    /// before queueing, or the drain's reconciliation would read the row
    /// as a re-advertise and cancel the withdraw. Found by
    /// `bgp_shard_addpath_vpnv6`: the session-up dump recorded the rows,
    /// the AddPath withdraw never removed them, and the peer kept the
    /// withdrawn path.
    #[tokio::test]
    async fn vpnv6_addpath_withdraw_drops_adj_rib_out_row_so_it_is_sent() {
        use super::super::route::route_withdraw_vpnv6_addpath;
        use bgp_packet::{AfiSafi, Direct};
        use ipnet::Ipv6Net;

        let (mut peer, mut prx, _rx) = established_peer();
        // VPNv6 negotiated both ways with AddPath-send, so the membership
        // index puts the peer in the AddPath fan-out set.
        let mp = bgp_packet::CapMultiProtocol::new(&Afi::Ip6, &Safi::MplsVpn);
        if let Some(sr) = peer.cap_map.get_mut(&mp) {
            sr.send = true;
            sr.recv = true;
        }
        peer.opt.add_path.insert(
            AfiSafi::new(Afi::Ip6, Safi::MplsVpn),
            Direct {
                recv: true,
                send: true,
            },
        );
        let rd = RouteDistinguisher::from_str("65001:100").unwrap();
        let prefix: Ipv6Net = "2001:db8:9::/64".parse().unwrap();
        // Two paths advertised (as the session-up dump records them).
        peer.adj_out
            .v6vpn
            .entry(rd)
            .or_default()
            .add(prefix, rib(1));
        peer.adj_out
            .v6vpn
            .entry(rd)
            .or_default()
            .add(prefix, rib(2));
        let mut peers = PeerMap::new();
        let address = peer.address;
        peers.insert(address, peer);
        let ident = peers.get(&address).unwrap().ident;
        peers.membership_enroll(ident);

        route_withdraw_vpnv6_addpath(rd, prefix, &rib(1), &mut peers);

        let peer = peers.get_mut_by_idx(ident).unwrap();
        let rows: Vec<u32> = peer.adj_out.v6vpn[&rd].0[&prefix]
            .iter()
            .map(|r| r.local_id)
            .collect();
        assert_eq!(rows, vec![2], "path 1's row is gone, path 2 stays");
        assert_eq!(peer.pending_withdraw.v6vpn.len(), 1);

        drain_peer(peer);
        let packets = sent_opt(
            &mut prx,
            Some({
                let mut opt = bgp_packet::ParseOption::default();
                opt.add_path.insert(
                    AfiSafi::new(Afi::Ip6, Safi::MplsVpn),
                    Direct {
                        recv: true,
                        send: true,
                    },
                );
                opt
            }),
        );
        assert_eq!(packets.len(), 1, "the withdraw of path 1 goes out");
        match &packets[0].mp_withdraw {
            Some(MpUnreachAttr::Vpnv6(w)) => {
                assert_eq!(w.len(), 1);
                assert_eq!(w[0].rd, rd);
                assert_eq!(w[0].nlri.prefix, prefix);
                assert_eq!(w[0].nlri.id, 1);
            }
            other => panic!("expected a VPNv6 MP_UNREACH, got {other:?}"),
        }
    }

    /// A queue the codec refuses to paginate (Route-Target membership has
    /// no per-NLRI emitter) is dropped with a log line: nothing goes on the
    /// wire and the send loop terminates instead of spinning on the error.
    #[tokio::test]
    async fn send_mp_withdraws_drops_an_unpaginatable_queue_and_returns() {
        use bgp_packet::{ExtCommunityValue, Rtcv4};
        let (peer, mut prx, _rx) = established_peer();
        send_mp_withdraws(
            &peer,
            MpUnreachAttr::Rtcv4(vec![Rtcv4::new(65001, ExtCommunityValue::default())]),
        );
        assert!(sent(&mut prx).is_empty(), "nothing is sent");
    }

    /// A flush on a peer that left Established discards the queue instead
    /// of pushing stale withdrawals onto whatever session comes next.
    #[tokio::test]
    async fn drain_on_a_down_peer_discards() {
        let (mut peer, mut prx, _rx) = established_peer();
        peer.queue_withdraw_v4(v4(1, 0));
        peer.state = State::Idle;
        drain_peer(&mut peer);
        assert!(sent(&mut prx).is_empty());
        assert_eq!(queued(&peer.pending_withdraw), 0);
        assert!(peer.withdraw_timer.is_none());
    }
}
