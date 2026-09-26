//! Review finding #23: a next-hop reachability flip must reach AddPath
//! neighbors, and a path whose next-hop is unreachable must not be sent to
//! them (RFC 4271 §9.1.2.1 makes such a path ineligible).
//!
//! Plain neighbors follow the selection, which already leaves unreachable
//! paths out. AddPath neighbors are sent every candidate, and nothing on
//! their paths looked at the next-hop: the NHT re-evaluation ran only the
//! plain fan-out for IPv4 unicast, VPNv4 and VPNv6; the IPv6-unicast and
//! labeled-unicast AddPath loops, the session-up dumps and the IPv6
//! soft-out sent unreachable candidates. An AddPath neighbor kept, or was
//! sent, a path we cannot forward on.
//!
//! The flips go through `Bgp::nht_handle_update`, the entry point a RIB
//! next-hop reply takes.
use super::*;
use crate::bgp::nht::NhtDep;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{
    BgpRib, BgpRibType, VpnNexthop, route_from_peer, route_soft_out_peer, route_sync_ipv4,
    route_sync_ipv6, route_sync_labelv4, route_sync_labelv6, route_sync_vpnv4, route_sync_vpnv6,
};
use crate::rib::nht::NexthopResolution;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, Ipv4Nlri, Label,
    Origin, ParseOption, RouteDistinguisher, Safi, UpdatePacket, Vpnv4Nexthop, Vpnv6Nexthop,
};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4U: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};
const V6U: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::Unicast,
};
const VPNV4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::MplsVpn,
};
const VPNV6: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::MplsVpn,
};
const LU4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::MplsLabel,
};
const LU6: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::MplsLabel,
};

type Rx = mpsc::UnboundedReceiver<bytes::BytesMut>;

fn fresh_bgp() -> Bgp {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    Box::leak(Box::new(inbound_rx));
    let ctx = crate::context::ProtoContext::default_table(client);
    let (rib_tx, rib_out_rx) = mpsc::unbounded_channel();
    let (rib_inbound_tx, sub_inbound_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_out_rx));
    Box::leak(Box::new(sub_inbound_rx));
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(policy_rx));
    let mut bgp = Bgp::new(
        ctx,
        rib_rx,
        subscriber,
        policy_tx,
        None,
        None,
        mpsc::channel(1).0,
    );
    bgp.router_id = ROUTER_ID;
    bgp
}

/// An Established neighbor of AS 65001 with `fams` negotiated both ways
/// and AddPath send on `addpath`, enrolled in the update-groups.
fn add_peer(
    bgp: &mut Bgp,
    addr: &str,
    remote_as: u32,
    fams: &[AfiSafi],
    addpath: &[AfiSafi],
) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
    let mut peer = Peer::new(
        0,
        65001,
        ROUTER_ID,
        remote_as,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = if remote_as == 65001 {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    peer.remote_id = match ip {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!("IPv4 session addresses only"),
    };
    for fam in fams {
        let entry = peer
            .cap_map
            .entries
            .entry(CapMultiProtocol::new(&fam.afi, &fam.safi))
            .or_default();
        entry.send = true;
        entry.recv = true;
    }
    for fam in addpath {
        peer.opt.add_path.entry(*fam).or_default().send = true;
    }
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    (id, prx)
}

/// The route-level view of `bgp`, with the NHT cache, next to its peers.
fn split(bgp: &mut Bgp) -> (BgpTop<'_>, &mut PeerMap) {
    (
        BgpTop {
            router_id: &bgp.router_id,
            srv6_ipv6_export: bgp.srv6_ipv6_export.as_ref(),
            local_rib: &mut bgp.local_rib,
            shard: &mut bgp.shard,
            tx: &bgp.tx,
            rib_client: &bgp.ctx.rib,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
            interface_addrs: &bgp.interface_addrs,
            vrf_export: None,
            color_policy: Some(&bgp.color_policy),
            flex_algo_routes: Some(&bgp.flex_algo_routes),
            flex_algo_srv6_routes: Some(&bgp.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: Some(&mut bgp.nexthop_cache),
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: bgp.as_sets_withdraw,
        },
        &mut bgp.peers,
    )
}

/// A RIB next-hop reply: `nh` resolves, or stops resolving.
fn resolve(bgp: &mut Bgp, nh: &str, reachable: bool) {
    let resolution = NexthopResolution {
        reachable,
        metric: 0,
        nexthops: Vec::new(),
    };
    bgp.nht_handle_update(0, nh.parse().unwrap(), &resolution);
}

/// A received IPv4-unicast UPDATE for `prefix` from `from`.
fn announce_v4(bgp: &mut Bgp, from: usize, prefix: &str, path: &str, nh: &str) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str(path).unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(nh.parse().unwrap())),
        ..Default::default()
    });
    packet.ipv4_update.push(Ipv4Nlri {
        id: 0,
        prefix: prefix.parse().unwrap(),
    });
    let (mut top, peers) = split(bgp);
    route_from_peer(from, packet, &mut top, peers, None);
}

/// The path-ids `ident` holds for `prefix` in its IPv4-unicast Adj-RIB-Out.
fn held_v4(bgp: &Bgp, ident: usize, prefix: &str) -> Vec<u32> {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    let mut ids: Vec<u32> = bgp
        .peers
        .get_by_idx(ident)
        .unwrap()
        .adj_out
        .v4
        .0
        .get(&prefix)
        .map_or(Vec::new(), |rows| rows.iter().map(|r| r.local_id).collect());
    ids.sort();
    ids
}

/// The path-ids of `ident`'s IPv4-unicast withdraws, parsed as AddPath.
fn withdrawn_v4(rx: &mut Rx) -> Vec<u32> {
    let mut opt = ParseOption::default();
    opt.add_path.entry(V4U).or_default().recv = true;
    let mut ids = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, false, Some(opt.clone()))
            .expect("every UPDATE toward an AddPath peer parses as AddPath");
        if let BgpPacket::Update(update) = packet {
            ids.extend(update.ipv4_withdraw.iter().map(|n| n.id));
        }
    }
    ids
}

/// The local ids of `a`'s and `b`'s IPv4-unicast paths for `prefix`.
fn v4_ids(bgp: &Bgp, prefix: &str, a: usize, b: usize) -> (u32, u32) {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    let cands = bgp.shard.v4.candidates(prefix);
    let id_of = |ident: usize| cands.iter().find(|r| r.ident == ident).unwrap().local_id;
    (id_of(a), id_of(b))
}

// -------------------------------------------------------------------------
// IPv4 unicast, end to end through the ingest and the NHT reply
// -------------------------------------------------------------------------

/// A and B each send P; the AddPath neighbor C holds both. A's next-hop
/// stops resolving: C must lose A's path-id — the plain fan-out alone ran,
/// so C kept it. When the next-hop resolves again, C gets it back.
#[tokio::test]
async fn v4_next_hop_loss_withdraws_the_addpath_path_id_and_recovery_restores_it() {
    let mut bgp = fresh_bgp();
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.2", 65002, &[V4U], &[]);
    let (b, _rb) = add_peer(&mut bgp, "10.0.0.3", 65003, &[V4U], &[]);
    let (c, mut rc) = add_peer(&mut bgp, "10.0.0.4", 65001, &[V4U], &[V4U]);
    announce_v4(&mut bgp, a, "10.23.1.0/24", "65002", "10.0.0.2");
    announce_v4(&mut bgp, b, "10.23.1.0/24", "65003 65009", "10.0.0.3");
    resolve(&mut bgp, "10.0.0.2", true);
    resolve(&mut bgp, "10.0.0.3", true);
    let (id_a, id_b) = v4_ids(&bgp, "10.23.1.0/24", a, b);
    let mut both = vec![id_a, id_b];
    both.sort();
    assert_eq!(held_v4(&bgp, c, "10.23.1.0/24"), both, "C holds both paths");
    let _ = withdrawn_v4(&mut rc);

    resolve(&mut bgp, "10.0.0.2", false);
    assert_eq!(
        held_v4(&bgp, c, "10.23.1.0/24"),
        vec![id_b],
        "A's path-id is withdrawn once its next-hop is unreachable"
    );
    assert_eq!(
        withdrawn_v4(&mut rc),
        vec![id_a],
        "withdrawn under its path-id"
    );

    resolve(&mut bgp, "10.0.0.2", true);
    assert_eq!(
        held_v4(&bgp, c, "10.23.1.0/24"),
        both,
        "A's path-id is re-advertised once its next-hop resolves again"
    );
}

/// A's first UPDATE carries a next-hop that has not resolved yet. The
/// plain neighbor D is not sent the path until it resolves; the AddPath
/// neighbor C must not be either — it was sent the path at once.
#[tokio::test]
async fn v4_addpath_neighbor_is_not_sent_a_path_whose_next_hop_is_unresolved() {
    let mut bgp = fresh_bgp();
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.2", 65002, &[V4U], &[]);
    let (c, _rc) = add_peer(&mut bgp, "10.0.0.4", 65001, &[V4U], &[V4U]);
    let (d, _rd) = add_peer(&mut bgp, "10.0.0.5", 65001, &[V4U], &[]);
    announce_v4(&mut bgp, a, "10.23.2.0/24", "65002", "10.0.0.2");
    assert!(
        held_v4(&bgp, d, "10.23.2.0/24").is_empty(),
        "control: the plain neighbor waits for the next-hop"
    );
    assert!(
        held_v4(&bgp, c, "10.23.2.0/24").is_empty(),
        "the AddPath neighbor waits for the next-hop too"
    );

    resolve(&mut bgp, "10.0.0.2", true);
    assert_eq!(held_v4(&bgp, d, "10.23.2.0/24").len(), 1);
    assert_eq!(
        held_v4(&bgp, c, "10.23.2.0/24").len(),
        1,
        "the AddPath neighbor is sent the path once the next-hop resolves"
    );
}

/// The forwarding plane confirms a hold on `prefix` (a `RouteOffload`
/// ack): mark it and release, as the RIB reply handler does.
fn fib_ack(bgp: &mut Bgp, prefix: &str) {
    let prefix: ipnet::IpNet = prefix.parse().unwrap();
    assert!(
        crate::bgp::route::fib_pending_blocks_sync(&bgp.local_rib, prefix),
        "a hold is pending"
    );
    bgp.local_rib
        .fib_pending
        .insert(prefix, crate::bgp::route::FibPending::Confirmed);
    bgp.fib_pending_release(prefix);
}

/// `suppress-fib-pending`: a first-contact path whose next-hop resolves
/// is installed, and its advertisement waits for the forwarding plane —
/// toward the AddPath neighbor too, which the NHT re-run first sent at
/// once (review of #23). The release sends it to both.
#[tokio::test]
async fn v4_resolved_path_waits_for_the_fib_ack_toward_addpath_neighbors_too() {
    let mut bgp = fresh_bgp();
    bgp.local_rib.suppress_fib_pending = true;
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.2", 65002, &[V4U], &[]);
    let (c, _rc) = add_peer(&mut bgp, "10.0.0.4", 65001, &[V4U], &[V4U]);
    let (d, _rd) = add_peer(&mut bgp, "10.0.0.5", 65001, &[V4U], &[]);
    announce_v4(&mut bgp, a, "10.23.8.0/24", "65002", "10.0.0.2");
    assert!(held_v4(&bgp, c, "10.23.8.0/24").is_empty());
    resolve(&mut bgp, "10.0.0.2", true);
    assert!(
        held_v4(&bgp, d, "10.23.8.0/24").is_empty(),
        "control: the plain neighbor waits for the ack"
    );
    assert!(
        held_v4(&bgp, c, "10.23.8.0/24").is_empty(),
        "the AddPath neighbor waits for the ack too"
    );
    fib_ack(&mut bgp, "10.23.8.0/24");
    assert_eq!(held_v4(&bgp, d, "10.23.8.0/24").len(), 1);
    assert_eq!(held_v4(&bgp, c, "10.23.8.0/24").len(), 1);
}

/// `suppress-fib-pending` with a non-best path: B's next-hop goes away —
/// its path-id is withdrawn at once, although the plain re-advertise of A
/// arms a hold (a withdraw is never held). B's next-hop comes back — B
/// waits for the ack, and the release sends it: the release used to send
/// the AddPath neighbors the selection only, never B.
#[tokio::test]
async fn v4_non_best_recovery_waits_for_the_fib_ack_and_its_loss_does_not() {
    let mut bgp = fresh_bgp();
    bgp.local_rib.suppress_fib_pending = true;
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.2", 65002, &[V4U], &[]);
    let (b, _rb) = add_peer(&mut bgp, "10.0.0.3", 65003, &[V4U], &[]);
    let (c, mut rc) = add_peer(&mut bgp, "10.0.0.4", 65001, &[V4U], &[V4U]);
    announce_v4(&mut bgp, a, "10.23.7.0/24", "65002", "10.0.0.2");
    announce_v4(&mut bgp, b, "10.23.7.0/24", "65003 65009", "10.0.0.3");
    resolve(&mut bgp, "10.0.0.2", true);
    resolve(&mut bgp, "10.0.0.3", true);
    fib_ack(&mut bgp, "10.23.7.0/24");
    let (id_a, id_b) = v4_ids(&bgp, "10.23.7.0/24", a, b);
    let mut both = vec![id_a, id_b];
    both.sort();
    assert_eq!(
        held_v4(&bgp, c, "10.23.7.0/24"),
        both,
        "released: C holds both"
    );
    let _ = withdrawn_v4(&mut rc);

    resolve(&mut bgp, "10.0.0.3", false);
    assert_eq!(
        held_v4(&bgp, c, "10.23.7.0/24"),
        vec![id_a],
        "B's path-id is withdrawn without waiting for the ack"
    );
    assert_eq!(withdrawn_v4(&mut rc), vec![id_b]);

    resolve(&mut bgp, "10.0.0.3", true);
    assert_eq!(
        held_v4(&bgp, c, "10.23.7.0/24"),
        vec![id_a],
        "B waits for the forwarding plane"
    );
    fib_ack(&mut bgp, "10.23.7.0/24");
    assert_eq!(
        held_v4(&bgp, c, "10.23.7.0/24"),
        both,
        "the release sends B to the AddPath neighbor"
    );
}

/// Control: the plain neighbor D follows the flip already — it loses A's
/// path when the next-hop goes and gets it back when it returns. (One path
/// only: a plain best-path switch between two paths leaves the old row in
/// D's Adj-RIB-Out, the below-the-cap `AdjRibTable::add` item.)
#[tokio::test]
async fn v4_plain_neighbor_follows_the_next_hop_flip() {
    let mut bgp = fresh_bgp();
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.2", 65002, &[V4U], &[]);
    let (d, _rd) = add_peer(&mut bgp, "10.0.0.5", 65001, &[V4U], &[]);
    announce_v4(&mut bgp, a, "10.23.3.0/24", "65002", "10.0.0.2");
    resolve(&mut bgp, "10.0.0.2", true);
    assert_eq!(held_v4(&bgp, d, "10.23.3.0/24").len(), 1);
    resolve(&mut bgp, "10.0.0.2", false);
    assert!(held_v4(&bgp, d, "10.23.3.0/24").is_empty());
    resolve(&mut bgp, "10.0.0.2", true);
    assert_eq!(held_v4(&bgp, d, "10.23.3.0/24").len(), 1);
}

// -------------------------------------------------------------------------
// Every family: two candidates in the Loc-RIB, dumped to the AddPath
// neighbor C, then A's next-hop flips
// -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Fam {
    V4,
    V6,
    Vpnv4,
    Vpnv6,
    Lu4,
    Lu6,
}

const RD: &str = "65002:1";

impl Fam {
    fn afi_safi(self) -> AfiSafi {
        match self {
            Fam::V4 => V4U,
            Fam::V6 => V6U,
            Fam::Vpnv4 => VPNV4,
            Fam::Vpnv6 => VPNV6,
            Fam::Lu4 => LU4,
            Fam::Lu6 => LU6,
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Fam::V4 | Fam::Vpnv4 | Fam::Lu4 => "10.23.9.0/24",
            Fam::V6 | Fam::Vpnv6 | Fam::Lu6 => "2001:db8:23:9::/64",
        }
    }

    /// The next-hop source `n` (1 = A, 2 = B) advertises.
    fn nexthop(self, n: u8) -> String {
        match self {
            Fam::V4 | Fam::Vpnv4 | Fam::Lu4 => format!("10.0.0.{}", n + 1),
            Fam::V6 | Fam::Vpnv6 | Fam::Lu6 => format!("2001:db8::{}", n + 1),
        }
    }

    fn dep(self) -> NhtDep {
        let rd = RouteDistinguisher::from_str(RD).unwrap();
        match self {
            Fam::V4 => NhtDep::V4(self.prefix().parse().unwrap()),
            Fam::V6 => NhtDep::V6(self.prefix().parse().unwrap()),
            Fam::Vpnv4 => NhtDep::V4vpn(rd, self.prefix().parse().unwrap()),
            Fam::Vpnv6 => NhtDep::V6vpn(rd, self.prefix().parse().unwrap()),
            Fam::Lu4 => NhtDep::V4lu(self.prefix().parse().unwrap()),
            Fam::Lu6 => NhtDep::V6lu(self.prefix().parse().unwrap()),
        }
    }

    /// Source `n`'s path (1 = A, 2 = B) as learned from peer `ident`, with
    /// its next-hop's reachability.
    fn rib(self, n: u8, ident: usize, reachable: bool) -> BgpRib {
        let rd = RouteDistinguisher::from_str(RD).unwrap();
        let nh: IpAddr = self.nexthop(n).parse().unwrap();
        let (nexthop, vpn) = match (self, nh) {
            (Fam::Vpnv4, _) => {
                let v = Vpnv4Nexthop { rd, nhop: nh };
                (BgpNexthop::Vpnv4(v.clone()), Some(VpnNexthop::V4(v)))
            }
            (Fam::Vpnv6, IpAddr::V6(a)) => {
                let v = Vpnv6Nexthop { rd, nhop: a };
                (BgpNexthop::Vpnv6(v.clone()), Some(VpnNexthop::V6(v)))
            }
            (_, IpAddr::V4(a)) => (BgpNexthop::Ipv4(a), None),
            (_, IpAddr::V6(a)) => (BgpNexthop::Ipv6(a), None),
        };
        let label = match self {
            Fam::V4 | Fam::V6 => None,
            _ => Some(Label::new(100 + n as u32, 0, true)),
        };
        let attr = BgpAttr {
            origin: Some(Origin::Igp),
            aspath: Some(As4Path::from_str(&format!("6500{}", n + 1)).unwrap()),
            nexthop: Some(nexthop),
            ..Default::default()
        };
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::new(10, 0, 0, n + 1),
            BgpRibType::EBGP,
            0,
            0,
            &attr,
            label,
            vpn,
            false,
        );
        rib.nexthop_reachable = reachable;
        rib
    }

    /// Put source `n`'s path, learned from peer `ident`, in the Loc-RIB
    /// with its next-hop tracked (resolved or not); returns its local id.
    fn install(self, bgp: &mut Bgp, n: u8, ident: usize, reachable: bool) -> u32 {
        let rd = RouteDistinguisher::from_str(RD).unwrap();
        let rib = self.rib(n, ident, reachable);
        let (_, _, id) = match self {
            Fam::V4 => bgp.shard.v4.update(self.prefix().parse().unwrap(), rib),
            Fam::V6 => bgp.shard.v6.update(self.prefix().parse().unwrap(), rib),
            Fam::Vpnv4 => bgp
                .shard
                .v4vpn
                .entry(rd)
                .or_default()
                .update(self.prefix().parse().unwrap(), rib),
            Fam::Vpnv6 => bgp
                .shard
                .v6vpn
                .entry(rd)
                .or_default()
                .update(self.prefix().parse().unwrap(), rib),
            Fam::Lu4 => bgp.shard.v4lu.update(self.prefix().parse().unwrap(), rib),
            Fam::Lu6 => bgp.shard.v6lu.update(self.prefix().parse().unwrap(), rib),
        };
        let nh: IpAddr = self.nexthop(n).parse().unwrap();
        bgp.nexthop_cache.track(0, nh, self.dep());
        bgp.nexthop_cache
            .entries
            .get_mut(&(0, nh))
            .unwrap()
            .reachable = reachable;
        id
    }

    /// The session-up dump of this family toward `ident`.
    fn dump(self, bgp: &mut Bgp, ident: usize) {
        let (mut top, peers) = split(bgp);
        let peer = peers.get_mut_by_idx(ident).unwrap();
        match self {
            Fam::V4 => route_sync_ipv4(peer, &mut top),
            Fam::V6 => route_sync_ipv6(peer, &mut top),
            Fam::Vpnv4 => route_sync_vpnv4(peer, &mut top),
            Fam::Vpnv6 => route_sync_vpnv6(peer, &mut top),
            Fam::Lu4 => route_sync_labelv4(peer, &mut top),
            Fam::Lu6 => route_sync_labelv6(peer, &mut top),
        }
    }

    /// The path-ids `ident` holds for the prefix in this family's
    /// Adj-RIB-Out.
    fn held(self, bgp: &Bgp, ident: usize) -> Vec<u32> {
        let rd = RouteDistinguisher::from_str(RD).unwrap();
        let adj = &bgp.peers.get_by_idx(ident).unwrap().adj_out;
        let rows = match self {
            Fam::V4 => adj.v4.0.get(&self.prefix().parse::<Ipv4Net>().unwrap()),
            Fam::Lu4 => adj.v4lu.0.get(&self.prefix().parse::<Ipv4Net>().unwrap()),
            Fam::Vpnv4 => adj
                .v4vpn
                .get(&rd)
                .and_then(|t| t.0.get(&self.prefix().parse::<Ipv4Net>().unwrap())),
            Fam::V6 => adj.v6.0.get(&self.prefix().parse::<Ipv6Net>().unwrap()),
            Fam::Lu6 => adj.v6lu.0.get(&self.prefix().parse::<Ipv6Net>().unwrap()),
            Fam::Vpnv6 => adj
                .v6vpn
                .get(&rd)
                .and_then(|t| t.0.get(&self.prefix().parse::<Ipv6Net>().unwrap())),
        };
        let mut ids: Vec<u32> =
            rows.map_or(Vec::new(), |rows| rows.iter().map(|r| r.local_id).collect());
        ids.sort();
        ids
    }

    /// Source peers A and B and the AddPath neighbor C, an iBGP peer so
    /// the next-hop and label go out unchanged. Returns `(bgp, a, b, c)`.
    fn topology(self) -> (Bgp, usize, usize, usize) {
        let mut bgp = fresh_bgp();
        let fam = self.afi_safi();
        let (a, _) = add_peer(&mut bgp, "10.0.0.2", 65002, &[fam], &[]);
        let (b, _) = add_peer(&mut bgp, "10.0.0.3", 65003, &[fam], &[]);
        let (c, _) = add_peer(&mut bgp, "10.0.0.4", 65001, &[fam], &[fam]);
        (bgp, a, b, c)
    }
}

/// Every family but IPv4 unicast (end to end above): C holds A's and B's
/// paths; A's next-hop stops resolving. C must lose A's path-id — on the
/// IPv6-unicast and labeled-unicast paths the AddPath loop re-sent A's
/// path; on the VPN paths only the plain fan-out ran — and get it back
/// when the next-hop resolves again.
#[tokio::test]
async fn next_hop_loss_withdraws_the_addpath_path_id_in_every_family() {
    for fam in [Fam::V6, Fam::Vpnv4, Fam::Vpnv6, Fam::Lu4, Fam::Lu6] {
        let (mut bgp, a, b, c) = fam.topology();
        let id_a = fam.install(&mut bgp, 1, a, true);
        let id_b = fam.install(&mut bgp, 2, b, true);
        fam.dump(&mut bgp, c);
        assert_eq!(fam.held(&bgp, c), vec![id_a, id_b], "{fam:?}: C holds both");

        resolve(&mut bgp, &fam.nexthop(1), false);
        assert_eq!(
            fam.held(&bgp, c),
            vec![id_b],
            "{fam:?}: A's path-id is withdrawn once its next-hop is unreachable"
        );

        resolve(&mut bgp, &fam.nexthop(1), true);
        assert_eq!(
            fam.held(&bgp, c),
            vec![id_a, id_b],
            "{fam:?}: A's path-id is re-advertised once its next-hop resolves"
        );
    }
}

/// A late AddPath neighbor's session-up dump: A's path has a next-hop
/// that does not resolve, B's does. C must be sent B's path only — every
/// family's dump sent every candidate.
#[tokio::test]
async fn addpath_session_up_dumps_skip_a_path_whose_next_hop_is_unreachable() {
    for fam in [Fam::V4, Fam::V6, Fam::Vpnv4, Fam::Vpnv6, Fam::Lu4, Fam::Lu6] {
        let (mut bgp, a, b, c) = fam.topology();
        let _id_a = fam.install(&mut bgp, 1, a, false);
        let id_b = fam.install(&mut bgp, 2, b, true);
        fam.dump(&mut bgp, c);
        assert_eq!(
            fam.held(&bgp, c),
            vec![id_b],
            "{fam:?}: the dump leaves out the unreachable path"
        );
    }
}

/// N>1: the flip runs in a pool shard and its result goes through main's
/// reduce (`route_apply_bestpath_v4_batch`), read replica included. B,
/// the non-best path, loses its next-hop: the AddPath neighbor C loses
/// B's path-id, and a late AddPath neighbor's dump — which reads the
/// replica — leaves B out. A repeated flip sends nothing; B's next-hop
/// returns and both neighbors get B. The shard reported no AddPath change,
/// so C kept B (review of #23).
#[tokio::test]
async fn v4_sharded_non_best_flip_reaches_addpath_neighbors_and_the_late_dump() {
    use crate::bgp::route::route_apply_bestpath_v4_batch;
    use crate::bgp::shard::{BgpShard, ShardMsg};
    let fam = Fam::V4;
    let (mut bgp, a, b, c) = fam.topology();
    let (tx, mut rx) = mpsc::unbounded_channel();
    bgp.peers.get_mut_by_idx(c).unwrap().packet_tx = Some(tx);
    let id_a = fam.install(&mut bgp, 1, a, true);
    let id_b = fam.install(&mut bgp, 2, b, true);
    let prefix: Ipv4Net = fam.prefix().parse().unwrap();
    let mut worker = BgpShard::default();
    for rib in bgp.shard.v4.candidates(prefix) {
        worker.v4.update(prefix, rib.clone());
    }
    assert_eq!(worker.v4.1.get(&prefix).unwrap().ident, a);
    fam.dump(&mut bgp, c);
    assert_eq!(fam.held(&bgp, c), vec![id_a, id_b]);
    let _ = withdrawn_v4(&mut rx);
    let flip = |worker: &mut BgpShard, bgp: &mut Bgp, reachable| {
        let outs = worker.handle(
            ShardMsg::NexthopReachableBatchV4 {
                nlris: vec![Ipv4Nlri { id: 0, prefix }],
                nh: fam.nexthop(2).parse().unwrap(),
                reachable,
            },
            None,
        );
        let (mut top, peers) = split(bgp);
        route_apply_bestpath_v4_batch(&mut top, peers, outs);
    };
    flip(&mut worker, &mut bgp, false);
    assert_eq!(fam.held(&bgp, c), vec![id_a]);
    assert_eq!(withdrawn_v4(&mut rx), vec![id_b]);
    assert_eq!(bgp.shard.v4.1.get(&prefix).unwrap().ident, a);
    assert!(
        !bgp.shard
            .v4
            .candidates(prefix)
            .iter()
            .find(|r| r.ident == b)
            .unwrap()
            .nexthop_reachable
    );
    let (late, _rx_late) = add_peer(&mut bgp, "10.0.0.5", 65001, &[V4U], &[V4U]);
    fam.dump(&mut bgp, late);
    assert_eq!(fam.held(&bgp, late), vec![id_a]);
    flip(&mut worker, &mut bgp, false);
    assert!(
        withdrawn_v4(&mut rx).is_empty(),
        "no duplicate withdrawal on an unchanged gate"
    );
    flip(&mut worker, &mut bgp, true);
    for peer in [c, late] {
        assert_eq!(fam.held(&bgp, peer), vec![id_a, id_b]);
    }
    assert!(
        bgp.shard
            .v4
            .candidates(prefix)
            .iter()
            .find(|r| r.ident == b)
            .unwrap()
            .nexthop_reachable
    );
}

/// N>1 under `suppress-fib-pending`: the reduce holds the job, but B's
/// withdraw still leaves C at once; B's recovery waits for the ack and the
/// release sends it.
#[tokio::test]
async fn v4_sharded_flip_under_suppress_fib_pending_withdraws_now_and_releases_later() {
    use crate::bgp::route::route_apply_bestpath_v4_batch;
    use crate::bgp::shard::{BgpShard, ShardMsg};
    let fam = Fam::V4;
    let (mut bgp, a, b, c) = fam.topology();
    bgp.local_rib.suppress_fib_pending = true;
    let id_a = fam.install(&mut bgp, 1, a, true);
    let id_b = fam.install(&mut bgp, 2, b, true);
    let prefix: Ipv4Net = fam.prefix().parse().unwrap();
    let mut worker = BgpShard::default();
    for rib in bgp.shard.v4.candidates(prefix) {
        worker.v4.update(prefix, rib.clone());
    }
    fam.dump(&mut bgp, c);
    assert_eq!(fam.held(&bgp, c), vec![id_a, id_b]);
    let flip = |worker: &mut BgpShard, bgp: &mut Bgp, reachable| {
        let outs = worker.handle(
            ShardMsg::NexthopReachableBatchV4 {
                nlris: vec![Ipv4Nlri { id: 0, prefix }],
                nh: fam.nexthop(2).parse().unwrap(),
                reachable,
            },
            None,
        );
        let (mut top, peers) = split(bgp);
        route_apply_bestpath_v4_batch(&mut top, peers, outs);
    };
    flip(&mut worker, &mut bgp, false);
    assert_eq!(fam.held(&bgp, c), vec![id_a], "B withdrawn at once");
    fib_ack(&mut bgp, fam.prefix());
    flip(&mut worker, &mut bgp, true);
    assert_eq!(fam.held(&bgp, c), vec![id_a], "B waits for the ack");
    fib_ack(&mut bgp, fam.prefix());
    assert_eq!(fam.held(&bgp, c), vec![id_a, id_b], "released");
}

/// Several paths can share one tracked next-hop. A single NHT reply must
/// withdraw and restore all their path-ids — including when the loss
/// empties the selection — and a late AddPath neighbor that joins while
/// every candidate is unreachable is sent none (review of #23).
#[tokio::test]
async fn shared_next_hop_flip_withdraws_and_restores_every_path_id_in_every_family() {
    for fam in [Fam::V4, Fam::V6, Fam::Vpnv4, Fam::Vpnv6, Fam::Lu4, Fam::Lu6] {
        let (mut bgp, a, b, c) = fam.topology();
        let id_a = fam.install(&mut bgp, 1, a, true);
        // Same next-hop and attributes, distinct source peer and local ID.
        let id_b = fam.install(&mut bgp, 1, b, true);
        assert_ne!(id_a, id_b);
        fam.dump(&mut bgp, c);
        assert_eq!(fam.held(&bgp, c), vec![id_a, id_b], "{fam:?}");
        resolve(&mut bgp, &fam.nexthop(1), false);
        assert!(fam.held(&bgp, c).is_empty(), "{fam:?}: both IDs must go");
        // A peer joining while every candidate is unreachable sees none.
        let af = fam.afi_safi();
        let (late, _rx) = add_peer(&mut bgp, "10.0.0.5", 65001, &[af], &[af]);
        fam.dump(&mut bgp, late);
        assert!(fam.held(&bgp, late).is_empty(), "{fam:?}: late dump");
        resolve(&mut bgp, &fam.nexthop(1), true);
        for peer in [c, late] {
            assert_eq!(fam.held(&bgp, peer), vec![id_a, id_b], "{fam:?}: recovery");
        }
    }
}

/// IPv6 under `suppress-fib-pending`: B, the non-best path, loses its
/// next-hop. The plain re-advertise of A arms a hold, and the held fan-out
/// returned before the AddPath diff, so C kept B's path-id until the ack
/// or the timeout (review of #23). It must go at once, as on IPv4. B's
/// recovery waits for the ack; the release sends it.
#[tokio::test]
async fn v6_next_hop_loss_withdraws_without_waiting_for_the_fib_ack() {
    let fam = Fam::V6;
    let (mut bgp, a, b, c) = fam.topology();
    let (tx, mut rx) = mpsc::unbounded_channel();
    bgp.peers.get_mut_by_idx(c).unwrap().packet_tx = Some(tx);
    bgp.local_rib.suppress_fib_pending = true;
    let id_a = fam.install(&mut bgp, 1, a, true);
    let id_b = fam.install(&mut bgp, 2, b, true);
    fam.dump(&mut bgp, c);
    assert_eq!(fam.held(&bgp, c), vec![id_a, id_b]);

    while rx.try_recv().is_ok() {}

    resolve(&mut bgp, &fam.nexthop(2), false);
    assert!(
        crate::bgp::route::fib_pending_blocks_sync(&bgp.local_rib, fam.prefix().parse().unwrap()),
        "the surviving path awaits the FIB ack"
    );
    assert_eq!(
        fam.held(&bgp, c),
        vec![id_a],
        "B's path-id is withdrawn before the ack"
    );
    let bytes = rx
        .try_recv()
        .expect("withdrawal must reach the writer before the ack");
    let mut opt = ParseOption::default();
    opt.add_path.entry(V6U).or_default().recv = true;
    let (_, packet) = BgpPacket::parse_packet(&bytes, false, Some(opt)).unwrap();
    let BgpPacket::Update(update) = packet else {
        panic!("expected UPDATE")
    };
    let Some(bgp_packet::MpUnreachAttr::Ipv6Nlri(rows)) = update.mp_withdraw else {
        panic!("expected IPv6 withdrawal")
    };
    assert_eq!(
        rows,
        vec![bgp_packet::Ipv6Nlri {
            id: id_b,
            prefix: fam.prefix().parse().unwrap()
        }]
    );
    assert!(rx.try_recv().is_err(), "no advertisement escapes the hold");
    fib_ack(&mut bgp, fam.prefix());

    resolve(&mut bgp, &fam.nexthop(2), true);
    assert_eq!(fam.held(&bgp, c), vec![id_a], "B waits for the ack");
    let (late, _late_rx) = add_peer(&mut bgp, "10.0.0.5", 65001, &[V6U], &[V6U]);
    fam.dump(&mut bgp, late);
    assert!(
        fam.held(&bgp, late).is_empty(),
        "late dump must respect the hold"
    );
    fib_ack(&mut bgp, fam.prefix());
    assert_eq!(fam.held(&bgp, c), vec![id_a, id_b], "released");
    assert_eq!(
        fam.held(&bgp, late),
        vec![id_a, id_b],
        "release reaches the late peer too"
    );
}

/// IPv6 unicast soft-out toward an AddPath neighbor: A's path turned
/// unreachable (the flag alone, as between a flip and its re-evaluation),
/// then a soft-out. It must withdraw A's path-id, not re-send it — the
/// IPv4 / VPNv4 and VPNv6 soft-outs skip such a path already.
#[tokio::test]
async fn v6_soft_out_withdraws_an_unreachable_addpath_path() {
    let fam = Fam::V6;
    let (mut bgp, a, b, c) = fam.topology();
    let id_a = fam.install(&mut bgp, 1, a, true);
    let id_b = fam.install(&mut bgp, 2, b, true);
    fam.dump(&mut bgp, c);
    assert_eq!(fam.held(&bgp, c), vec![id_a, id_b]);
    bgp.shard.v6.set_nexthop_reachable(
        fam.prefix().parse().unwrap(),
        fam.nexthop(1).parse().unwrap(),
        false,
    );
    let (mut top, peers) = split(&mut bgp);
    route_soft_out_peer(c, &mut top, peers);
    assert_eq!(
        fam.held(&bgp, c),
        vec![id_b],
        "the soft-out withdraws the unreachable path"
    );
}
