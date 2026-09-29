//! Review finding #19: Route Target Constraint (RFC 4684) membership that
//! changes after the session is up must take effect on the VPN routes.
//!
//! Receiving side: the session-up VPNv4 dump waits for the peer's RTC
//! End-of-RIB, so the membership learned before it shapes that dump. A
//! membership the peer added later was only recorded: every advertise path
//! skips a route the membership does not select, so a route skipped while
//! the peer lacked the RT was never sent once it gained it. A withdrawn
//! membership (RTC MP_UNREACH) was ignored outright, so the routes it had
//! selected stayed advertised; a default membership ("send me everything")
//! was ignored too, so a peer that mixed it with an exact RT got only that
//! RT's routes. The VPNv6 dump did not wait for the RTC End-of-RIB at all.
//!
//! Sending side: a zebra-rs PE advertised its membership only at session-up,
//! so a VRF import-RT change mid-session reached no RR.
use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{
    BgpRib, BgpRibType, VpnNexthop, route_from_peer, route_sync, route_sync_vpnv4, route_sync_vpnv6,
};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, ExtCommunityValue,
    Label, MpReachAttr, MpUnreachAttr, Origin, ParseOption, RouteDistinguisher, Rtcv4, Rtcv4Reach,
    Rtcv6, Rtcv6Reach, Safi, UpdatePacket, Vpnv4Nexthop, Vpnv6Nexthop,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const VPNV4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::MplsVpn,
};
const VPNV6: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::MplsVpn,
};
const RTCV4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Rtc,
};
const RTCV6: AfiSafi = AfiSafi {
    afi: Afi::Ip6,
    safi: Safi::Rtc,
};
const RD: &str = "65002:1";
const RT_A: &str = "65000:100";
const RT_B: &str = "65000:200";

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

fn rt(s: &str) -> RouteDistinguisher {
    RouteDistinguisher::from_str(s).unwrap()
}

/// `s` as a Route Target extended community value.
fn rt_value(s: &str) -> ExtCommunityValue {
    let mut v: ExtCommunityValue = rt(s).into();
    v.low_type = 0x02;
    v
}

fn rtc_of(vpn: AfiSafi) -> AfiSafi {
    if vpn.afi == Afi::Ip { RTCV4 } else { RTCV6 }
}

/// An Established iBGP reflector client C with the VPN family `vpn` and its
/// RTC family negotiated, no membership yet.
fn add_peer(bgp: &mut Bgp, vpn: AfiSafi) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = "10.0.0.4".parse().unwrap();
    let mut peer = Peer::new(
        0,
        65000,
        ROUTER_ID,
        65000,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = PeerType::IBGP;
    peer.reflector_client = true;
    peer.remote_id = Ipv4Addr::new(10, 0, 0, 4);
    for fam in [vpn, rtc_of(vpn)] {
        let entry = peer
            .cap_map
            .entries
            .entry(CapMultiProtocol::new(&fam.afi, &fam.safi))
            .or_default();
        entry.send = true;
        entry.recv = true;
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

/// The route-level view of `bgp` next to its peers.
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
            color_policy: None,
            flex_algo_routes: None,
            flex_algo_srv6_routes: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: bgp.as_sets_withdraw,
        },
        &mut bgp.peers,
    )
}

fn vpn_attr(nexthop: BgpNexthop, rts_: &[&str]) -> BgpAttr {
    tag_attr_with_export_rts(
        BgpAttr {
            origin: Some(Origin::Igp),
            aspath: Some(As4Path::from_str("65002").unwrap()),
            nexthop: Some(nexthop),
            ..Default::default()
        },
        &rts_.iter().map(|s| rt(s)).collect(),
    )
}

/// A VPNv4 route for `prefix` under [`RD`] carrying `rts_`, learned from
/// peer slot 1 (not C).
fn put_vpnv4(bgp: &mut Bgp, prefix: &str, rts_: &[&str]) {
    let rd = rt(RD);
    let nh = Vpnv4Nexthop {
        rd,
        nhop: "10.0.0.2".parse().unwrap(),
    };
    let mut rib = BgpRib::new(
        1,
        Ipv4Addr::new(10, 0, 0, 2),
        BgpRibType::IBGP,
        0,
        0,
        &vpn_attr(BgpNexthop::Vpnv4(nh.clone()), rts_),
        Some(Label::new(100, 0, true)),
        Some(VpnNexthop::V4(nh)),
        false,
    );
    rib.nexthop_reachable = true;
    bgp.shard
        .v4vpn
        .entry(rd)
        .or_default()
        .update(prefix.parse().unwrap(), rib);
}

/// The VPNv6 twin of [`put_vpnv4`].
fn put_vpnv6(bgp: &mut Bgp, prefix: &str, rts_: &[&str]) {
    let rd = rt(RD);
    let nh = Vpnv6Nexthop {
        rd,
        nhop: "2001:db8::2".parse().unwrap(),
    };
    let mut rib = BgpRib::new(
        1,
        Ipv4Addr::new(10, 0, 0, 2),
        BgpRibType::IBGP,
        0,
        0,
        &vpn_attr(BgpNexthop::Vpnv6(nh.clone()), rts_),
        Some(Label::new(100, 0, true)),
        Some(VpnNexthop::V6(nh)),
        false,
    );
    rib.nexthop_reachable = true;
    bgp.shard
        .v6vpn
        .entry(rd)
        .or_default()
        .update(prefix.parse().unwrap(), rib);
}

/// Whether C holds `prefix` under [`RD`] in the VPN family of the prefix.
fn held(bgp: &Bgp, ident: usize, prefix: &str) -> bool {
    let adj = &bgp.peers.get_by_idx(ident).unwrap().adj_out;
    match prefix.parse::<ipnet::IpNet>().unwrap() {
        ipnet::IpNet::V4(p) => adj.v4vpn.get(&rt(RD)).is_some_and(|t| t.0.contains_key(&p)),
        ipnet::IpNet::V6(p) => adj.v6vpn.get(&rt(RD)).is_some_and(|t| t.0.contains_key(&p)),
    }
}

/// One RTC membership NLRI: an exact Route Target from origin AS 65000 or
/// from another origin AS, or the default.
#[derive(Clone, Copy)]
enum M {
    Rt(&'static str),
    RtFrom(&'static str, u32),
    Default,
}

fn rtcv4(m: M) -> Rtcv4 {
    match m {
        M::Rt(s) => Rtcv4::new(65000, rt_value(s)),
        M::RtFrom(s, asn) => Rtcv4::new(asn, rt_value(s)),
        M::Default => Rtcv4::default_membership(),
    }
}

fn rtcv6(m: M) -> Rtcv6 {
    match m {
        M::Rt(s) => Rtcv6::new(65000, rt_value(s)),
        M::RtFrom(s, asn) => Rtcv6::new(asn, rt_value(s)),
        M::Default => Rtcv6::default_membership(),
    }
}

fn membership_attr() -> BgpAttr {
    BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str("").unwrap()),
        ..Default::default()
    }
}

/// C announces RTC membership `ms`, through the ingest.
fn announce(bgp: &mut Bgp, c: usize, vpn: AfiSafi, ms: &[M]) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(membership_attr());
    packet.mp_update = Some(if vpn.afi == Afi::Ip {
        MpReachAttr::Rtcv4(Rtcv4Reach {
            snpa: 0,
            nhop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            updates: ms.iter().map(|m| rtcv4(*m)).collect(),
        })
    } else {
        MpReachAttr::Rtcv6(Rtcv6Reach {
            snpa: 0,
            nhop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            updates: ms.iter().map(|m| rtcv6(*m)).collect(),
        })
    });
    let (mut top, peers) = split(bgp);
    route_from_peer(c, packet, &mut top, peers, None);
}

/// C withdraws RTC membership `ms`, through the ingest.
fn withdraw(bgp: &mut Bgp, c: usize, vpn: AfiSafi, ms: &[M]) {
    let mut packet = UpdatePacket::new();
    packet.mp_withdraw = Some(if vpn.afi == Afi::Ip {
        MpUnreachAttr::Rtcv4(ms.iter().map(|m| rtcv4(*m)).collect())
    } else {
        MpUnreachAttr::Rtcv6(ms.iter().map(|m| rtcv6(*m)).collect())
    });
    let (mut top, peers) = split(bgp);
    route_from_peer(c, packet, &mut top, peers, None);
}

/// C's session comes up with membership `ms`: announced while the
/// session-up dump waits for its RTC End-of-RIB, then the dump.
fn session_up(bgp: &mut Bgp, c: usize, vpn: AfiSafi, ms: &[M], rx: &mut Rx) {
    bgp.peers
        .get_mut_by_idx(c)
        .unwrap()
        .eor
        .insert(rtc_of(vpn), true);
    announce(bgp, c, vpn, ms);
    {
        let (mut top, peers) = split(bgp);
        let peer = peers.get_mut_by_idx(c).unwrap();
        if vpn.afi == Afi::Ip {
            route_sync_vpnv4(peer, &mut top);
        } else {
            route_sync_vpnv6(peer, &mut top);
        }
    }
    bgp.peers
        .get_mut_by_idx(c)
        .unwrap()
        .eor
        .remove(&rtc_of(vpn));
    let _ = vpn_updates(bgp, c, rx);
}

/// Every VPN prefix C was advertised and withdrawn (after flushing its VPN
/// queues): `(advertised, withdrawn)`, each sorted.
fn vpn_updates(bgp: &mut Bgp, c: usize, rx: &mut Rx) -> (Vec<String>, Vec<String>) {
    let peer = bgp.peers.get_mut_by_idx(c).unwrap();
    peer.flush_vpnv4();
    peer.flush_vpnv6();
    let (mut adv, mut wd) = (Vec::new(), Vec::new());
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, false, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        match update.mp_update {
            Some(MpReachAttr::Vpnv4(reach)) => {
                adv.extend(reach.updates.iter().map(|r| r.nlri.prefix.to_string()))
            }
            Some(MpReachAttr::Vpnv6(reach)) => {
                adv.extend(reach.updates.iter().map(|r| r.nlri.prefix.to_string()))
            }
            _ => {}
        }
        match update.mp_withdraw {
            Some(MpUnreachAttr::Vpnv4(rows)) => {
                wd.extend(rows.iter().map(|r| r.nlri.prefix.to_string()))
            }
            Some(MpUnreachAttr::Vpnv6(rows)) => {
                wd.extend(rows.iter().map(|r| r.nlri.prefix.to_string()))
            }
            _ => {}
        }
    }
    adv.sort();
    wd.sort();
    (adv, wd)
}

// -------------------------------------------------------------------------
// Receiving side
// -------------------------------------------------------------------------

/// Two exact memberships may name one RT from different origin ASes (an RR
/// reflecting two ASes' interest, say). C holds P under RT A, named by AS
/// 65000 and by AS 65001, then withdraws AS 65000's: AS 65001's still
/// selects P, so nothing is withdrawn — the exact set was keyed by the RT
/// alone, so the first withdraw dropped the RT and withdrew P. Withdrawing
/// the last one does withdraw P.
fn check_withdraw_keeps_an_rt_another_origin_as_names(vpn: AfiSafi, prefix: &str) {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, vpn);
    if vpn == VPNV4 {
        put_vpnv4(&mut bgp, prefix, &[RT_A]);
    } else {
        put_vpnv6(&mut bgp, prefix, &[RT_A]);
    }
    session_up(
        &mut bgp,
        c,
        vpn,
        &[M::Rt(RT_A), M::RtFrom(RT_A, 65001)],
        &mut rc,
    );
    assert!(held(&bgp, c, prefix));

    withdraw(&mut bgp, c, vpn, &[M::Rt(RT_A)]);
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec![]),
        "AS 65001's membership still selects {prefix}"
    );
    assert!(held(&bgp, c, prefix));

    withdraw(&mut bgp, c, vpn, &[M::RtFrom(RT_A, 65001)]);
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec![prefix.to_string()])
    );
    assert!(!held(&bgp, c, prefix));
}

#[tokio::test]
async fn vpnv4_rtc_withdraw_keeps_an_rt_another_origin_as_names() {
    check_withdraw_keeps_an_rt_another_origin_as_names(VPNV4, "10.19.90.0/24");
}

#[tokio::test]
async fn vpnv6_rtc_withdraw_keeps_an_rt_another_origin_as_names() {
    check_withdraw_keeps_an_rt_another_origin_as_names(VPNV6, "2001:db8:19:90::/64");
}

/// C's outbound policy for `vpn` rewrites every route's RTs to RT B. C,
/// member of RT A and RT B, is sent P (RT A) by the live advertise path,
/// carrying RT B; then it withdraws RT B. The reconcile must read the RT C
/// was sent: P leaves C. The VPNv6 live path recorded the row with the
/// attributes before the policy, so the reconcile saw RT A — still a
/// membership — and left P standing.
fn check_withdraw_reads_the_rt_sent(vpn: AfiSafi, prefix: &str) {
    use crate::policy::{
        ExtCommunityMatcher, ExtCommunitySet, PolicyAction, PolicyList, SetExtCommunityConfig,
    };
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, vpn);
    session_up(&mut bgp, c, vpn, &[M::Rt(RT_A), M::Rt(RT_B)], &mut rc);
    let mut policy = PolicyList::default();
    policy.entry(10).action = PolicyAction::Permit;
    let mut setter = SetExtCommunityConfig::new("rewrite-rt".into());
    setter.resolved = Some(ExtCommunitySet {
        vals: [ExtCommunityMatcher::Exact(rt_value(RT_B))]
            .into_iter()
            .collect(),
        ..Default::default()
    });
    policy.entry(10).set_ext_community = Some(setter);
    {
        let output = &mut bgp
            .peers
            .get_mut_by_idx(c)
            .unwrap()
            .policy_list
            .entry(vpn)
            .or_default()
            .output;
        output.name = Some("rewrite-rt".into());
        output.policy_list = Some(policy);
    }

    let rd = rt(RD);
    if vpn == VPNV4 {
        put_vpnv4(&mut bgp, prefix, &[RT_A]);
        let p = prefix.parse().unwrap();
        let selected = vec![bgp.shard.v4vpn[&rd].1.get(&p).unwrap().clone()];
        let (mut top, peers) = split(&mut bgp);
        crate::bgp::route::route_advertise_to_peers(Some(rd), p, &selected, 1, &mut top, peers);
    } else {
        put_vpnv6(&mut bgp, prefix, &[RT_A]);
        let p = prefix.parse().unwrap();
        let selected = vec![bgp.shard.v6vpn[&rd].1.get(&p).unwrap().clone()];
        let (mut top, peers) = split(&mut bgp);
        crate::bgp::route::route_advertise_to_peers_vpnv6(rd, p, &selected, &mut top, peers);
    }
    // The wire UPDATE carried the rewritten RT.
    let peer = bgp.peers.get_mut_by_idx(c).unwrap();
    peer.flush_vpnv4();
    peer.flush_vpnv6();
    let mut sent = Vec::new();
    while let Ok(bytes) = rc.try_recv() {
        let (_, packet) =
            BgpPacket::parse_packet(&bytes, false, Some(ParseOption::default())).unwrap();
        if let BgpPacket::Update(update) = packet
            && matches!(
                update.mp_update,
                Some(MpReachAttr::Vpnv4(_)) | Some(MpReachAttr::Vpnv6(_))
            )
        {
            sent.push(route_rts_from_ecom(&update.bgp_attr.unwrap().ecom));
        }
    }
    assert_eq!(sent, vec![[rt(RT_B)].into_iter().collect()], "setup");

    withdraw(&mut bgp, c, vpn, &[M::Rt(RT_B)]);
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec![prefix.to_string()]),
        "C was sent {prefix} under RT B, no longer a membership"
    );
    assert!(!held(&bgp, c, prefix));
}

#[tokio::test]
async fn vpnv6_rtc_withdraw_reads_the_rt_the_policy_sent() {
    check_withdraw_reads_the_rt_sent(VPNV6, "2001:db8:19:91::/64");
}

/// Control: the VPNv4 live path already recorded the attributes it sent.
#[tokio::test]
async fn vpnv4_rtc_withdraw_reads_the_rt_the_policy_sent() {
    check_withdraw_reads_the_rt_sent(VPNV4, "10.19.91.0/24");
}

/// C's session came up with membership 65000:100: it holds P1 (RT
/// 65000:100) and not P2 (RT 65000:200). C then adds 65000:200: it must be
/// sent P2 — and only P2 — where the membership was only recorded.
#[tokio::test]
async fn vpnv4_rtc_membership_added_mid_session_sends_the_routes_it_selects() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV4);
    put_vpnv4(&mut bgp, "10.19.1.0/24", &[RT_A]);
    put_vpnv4(&mut bgp, "10.19.2.0/24", &[RT_B]);
    session_up(&mut bgp, c, VPNV4, &[M::Rt(RT_A)], &mut rc);
    assert!(held(&bgp, c, "10.19.1.0/24"));
    assert!(!held(&bgp, c, "10.19.2.0/24"), "filtered by membership");

    announce(&mut bgp, c, VPNV4, &[M::Rt(RT_B)]);
    assert!(
        held(&bgp, c, "10.19.2.0/24"),
        "the new membership brings C the route it selects"
    );
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc).0,
        vec!["10.19.2.0/24".to_string()]
    );
}

/// The VPNv6 twin.
#[tokio::test]
async fn vpnv6_rtc_membership_added_mid_session_sends_the_routes_it_selects() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV6);
    put_vpnv6(&mut bgp, "2001:db8:19:1::/64", &[RT_A]);
    put_vpnv6(&mut bgp, "2001:db8:19:2::/64", &[RT_B]);
    session_up(&mut bgp, c, VPNV6, &[M::Rt(RT_A)], &mut rc);
    assert!(held(&bgp, c, "2001:db8:19:1::/64"));
    assert!(
        !held(&bgp, c, "2001:db8:19:2::/64"),
        "filtered by membership"
    );

    announce(&mut bgp, c, VPNV6, &[M::Rt(RT_B)]);
    assert!(
        held(&bgp, c, "2001:db8:19:2::/64"),
        "the new membership brings C the route it selects"
    );
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc).0,
        vec!["2001:db8:19:2::/64".to_string()]
    );
}

/// Control: before C's RTC End-of-RIB the session-up VPNv4 dump is still
/// pending — a membership learned now shapes that dump and sends nothing
/// by itself.
#[tokio::test]
async fn rtc_membership_before_the_rtc_eor_waits_for_the_session_up_dump() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV4);
    bgp.peers.get_mut_by_idx(c).unwrap().eor.insert(RTCV4, true);
    put_vpnv4(&mut bgp, "10.19.3.0/24", &[RT_B]);
    announce(&mut bgp, c, VPNV4, &[M::Rt(RT_B)]);
    assert!(!held(&bgp, c, "10.19.3.0/24"));
    assert_eq!(vpn_updates(&mut bgp, c, &mut rc), (vec![], vec![]));
}

/// C holds P1 and P2 under membership {65000:100, 65000:200}, then
/// withdraws 65000:200 (RTC MP_UNREACH): P2 must be withdrawn from C, P1
/// kept — the withdraw was ignored, so C kept P2.
#[tokio::test]
async fn vpnv4_rtc_membership_withdrawn_withdraws_the_routes_it_selected() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV4);
    put_vpnv4(&mut bgp, "10.19.4.0/24", &[RT_A]);
    put_vpnv4(&mut bgp, "10.19.5.0/24", &[RT_B]);
    session_up(&mut bgp, c, VPNV4, &[M::Rt(RT_A), M::Rt(RT_B)], &mut rc);
    assert!(held(&bgp, c, "10.19.4.0/24") && held(&bgp, c, "10.19.5.0/24"));

    withdraw(&mut bgp, c, VPNV4, &[M::Rt(RT_B)]);
    assert!(!held(&bgp, c, "10.19.5.0/24"), "C loses P2");
    assert!(held(&bgp, c, "10.19.4.0/24"), "C keeps P1");
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec!["10.19.5.0/24".to_string()])
    );
}

/// The VPNv6 twin.
#[tokio::test]
async fn vpnv6_rtc_membership_withdrawn_withdraws_the_routes_it_selected() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV6);
    put_vpnv6(&mut bgp, "2001:db8:19:4::/64", &[RT_A]);
    put_vpnv6(&mut bgp, "2001:db8:19:5::/64", &[RT_B]);
    session_up(&mut bgp, c, VPNV6, &[M::Rt(RT_A), M::Rt(RT_B)], &mut rc);
    assert!(held(&bgp, c, "2001:db8:19:4::/64") && held(&bgp, c, "2001:db8:19:5::/64"));

    withdraw(&mut bgp, c, VPNV6, &[M::Rt(RT_B)]);
    assert!(!held(&bgp, c, "2001:db8:19:5::/64"), "C loses P2");
    assert!(held(&bgp, c, "2001:db8:19:4::/64"), "C keeps P1");
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec!["2001:db8:19:5::/64".to_string()])
    );
}

/// C withdraws its only membership: it wants no VPN route any more, so
/// every route is withdrawn from it. (An empty membership used to mean "no
/// constraint", which would have sent C everything instead.)
#[tokio::test]
async fn vpnv4_last_rtc_membership_withdrawn_withdraws_every_route() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV4);
    put_vpnv4(&mut bgp, "10.19.6.0/24", &[RT_A]);
    put_vpnv4(&mut bgp, "10.19.7.0/24", &[RT_B]);
    session_up(&mut bgp, c, VPNV4, &[M::Rt(RT_A)], &mut rc);
    assert!(held(&bgp, c, "10.19.6.0/24"));

    withdraw(&mut bgp, c, VPNV4, &[M::Rt(RT_A)]);
    assert!(!held(&bgp, c, "10.19.6.0/24"));
    assert!(
        !held(&bgp, c, "10.19.7.0/24"),
        "and nothing is sent instead"
    );
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec!["10.19.6.0/24".to_string()])
    );
}

/// C's membership mixes the default ("send me everything") with an exact
/// RT: C gets every route — the default was ignored, so C got only the
/// exact RT's routes. When C withdraws the default, the routes of other
/// RTs are withdrawn.
#[tokio::test]
async fn rtc_default_membership_sends_every_route_until_it_is_withdrawn() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV4);
    put_vpnv4(&mut bgp, "10.19.8.0/24", &[RT_A]);
    put_vpnv4(&mut bgp, "10.19.9.0/24", &[RT_B]);
    session_up(&mut bgp, c, VPNV4, &[M::Rt(RT_A), M::Default], &mut rc);
    assert!(held(&bgp, c, "10.19.8.0/24"));
    assert!(
        held(&bgp, c, "10.19.9.0/24"),
        "the default membership selects every route"
    );

    withdraw(&mut bgp, c, VPNV4, &[M::Default]);
    assert!(held(&bgp, c, "10.19.8.0/24"));
    assert!(!held(&bgp, c, "10.19.9.0/24"));
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc),
        (vec![], vec!["10.19.9.0/24".to_string()])
    );
}

/// The VPNv6 session-up dump waits for the peer's RTC End-of-RIB, as the
/// VPNv4 one does: C comes up with VPNv6 and IPv6 RTC negotiated; it must
/// be sent no VPNv6 route before its membership and End-of-RIB — the dump
/// ran at once, unfiltered — and then only the routes its membership
/// selects.
#[tokio::test]
async fn vpnv6_session_up_dump_waits_for_the_rtc_eor() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_peer(&mut bgp, VPNV6);
    put_vpnv6(&mut bgp, "2001:db8:19:a::/64", &[RT_A]);
    put_vpnv6(&mut bgp, "2001:db8:19:b::/64", &[RT_B]);
    {
        let (mut top, peers) = split(&mut bgp);
        route_sync(peers.get_mut_by_idx(c).unwrap(), &mut top, false);
    }
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc).0,
        Vec::<String>::new(),
        "no VPNv6 route before the RTC End-of-RIB"
    );
    announce(&mut bgp, c, VPNV6, &[M::Rt(RT_A)]);
    let mut eor = UpdatePacket::new();
    eor.mp_withdraw = Some(MpUnreachAttr::Rtcv6Eor);
    {
        let (mut top, peers) = split(&mut bgp);
        route_from_peer(c, eor, &mut top, peers, None);
    }
    assert_eq!(
        vpn_updates(&mut bgp, c, &mut rc).0,
        vec!["2001:db8:19:a::/64".to_string()],
        "then the routes the membership selects"
    );
}

// -------------------------------------------------------------------------
// Sending side (a zebra-rs PE)
// -------------------------------------------------------------------------

/// Register VRF `name` with IPv4 / IPv6 import RTs, as the RIB reports it.
fn add_vrf(bgp: &mut Bgp, name: &str, import_v4: &[&str], import_v6: &[&str]) {
    bgp.rib_known_vrfs.insert(
        name.to_string(),
        RibKnownVrf {
            import_rts_v4: import_v4.iter().map(|s| rt(s)).collect(),
            import_rts_v6: import_v6.iter().map(|s| rt(s)).collect(),
            ..Default::default()
        },
    );
}

/// A committed import-RT change for VRF `name`.
fn set_imports(bgp: &mut Bgp, name: &str, import_v4: &[&str], import_v6: &[&str]) {
    bgp.process_rib_msg(RibRx::VrfRouteTargets {
        name: name.to_string(),
        ipv4_import_rts: import_v4.iter().map(|s| rt(s)).collect(),
        ipv4_export_rts: BTreeSet::new(),
        ipv6_import_rts: import_v6.iter().map(|s| rt(s)).collect(),
        ipv6_export_rts: BTreeSet::new(),
        mup_import_rts: BTreeSet::new(),
        mup_export_rts: BTreeSet::new(),
    });
}

/// The RTC membership UPDATEs C was sent, in order: `("announce" |
/// "withdraw", RT or "default")`.
fn rtc_sent(rx: &mut Rx) -> Vec<(&'static str, String)> {
    let name = |plen: u8, v: &ExtCommunityValue| {
        if plen == 0 {
            return "default".to_string();
        }
        [RT_A, RT_B]
            .into_iter()
            .find(|s| rt_value(s) == *v)
            .unwrap_or("?")
            .to_string()
    };
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, false, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        match update.mp_update {
            Some(MpReachAttr::Rtcv4(reach)) => out.extend(
                reach
                    .updates
                    .iter()
                    .map(|m| ("announce", name(m.plen, &m.rt))),
            ),
            Some(MpReachAttr::Rtcv6(reach)) => out.extend(
                reach
                    .updates
                    .iter()
                    .map(|m| ("announce", name(m.plen, &m.rt))),
            ),
            _ => {}
        }
        match update.mp_withdraw {
            Some(MpUnreachAttr::Rtcv4(list)) => {
                out.extend(list.iter().map(|m| ("withdraw", name(m.plen, &m.rt))))
            }
            Some(MpUnreachAttr::Rtcv6(list)) => {
                out.extend(list.iter().map(|m| ("withdraw", name(m.plen, &m.rt))))
            }
            _ => {}
        }
    }
    out
}

/// A VRF adds import RT 65000:200 mid-session: every RTC neighbor must be
/// sent the new membership, and withdrawn it when the RT is removed — the
/// membership was sent only at session-up.
#[tokio::test]
async fn vrf_import_rt_change_announces_and_withdraws_rtcv4_membership() {
    let mut bgp = fresh_bgp();
    add_vrf(&mut bgp, "blue", &[RT_A], &[]);
    let (_c, mut rc) = add_peer(&mut bgp, VPNV4);
    set_imports(&mut bgp, "blue", &[RT_A, RT_B], &[]);
    assert_eq!(rtc_sent(&mut rc), vec![("announce", RT_B.to_string())]);
    set_imports(&mut bgp, "blue", &[RT_A], &[]);
    assert_eq!(rtc_sent(&mut rc), vec![("withdraw", RT_B.to_string())]);
}

/// The IPv6 RTC twin.
#[tokio::test]
async fn vrf_import_rt_change_announces_and_withdraws_rtcv6_membership() {
    let mut bgp = fresh_bgp();
    add_vrf(&mut bgp, "blue", &[], &[RT_A]);
    let (_c, mut rc) = add_peer(&mut bgp, VPNV6);
    set_imports(&mut bgp, "blue", &[], &[RT_A, RT_B]);
    assert_eq!(rtc_sent(&mut rc), vec![("announce", RT_B.to_string())]);
    set_imports(&mut bgp, "blue", &[], &[RT_A]);
    assert_eq!(rtc_sent(&mut rc), vec![("withdraw", RT_B.to_string())]);
}

/// With no import RT the membership is the default; the first import RT
/// replaces it, and removing the last brings it back. The new membership
/// is announced before the old one is withdrawn, so the neighbor never
/// sees an empty membership in between (which selects nothing).
#[tokio::test]
async fn rtc_membership_moves_between_the_default_and_exact_rts() {
    let mut bgp = fresh_bgp();
    add_vrf(&mut bgp, "blue", &[], &[]);
    let (_c, mut rc) = add_peer(&mut bgp, VPNV4);
    set_imports(&mut bgp, "blue", &[RT_A], &[]);
    assert_eq!(
        rtc_sent(&mut rc),
        vec![
            ("announce", RT_A.to_string()),
            ("withdraw", "default".to_string())
        ]
    );
    set_imports(&mut bgp, "blue", &[], &[]);
    assert_eq!(
        rtc_sent(&mut rc),
        vec![
            ("announce", "default".to_string()),
            ("withdraw", RT_A.to_string())
        ]
    );
}

/// A VRF deleted from the kernel takes its import RTs out of the
/// membership — unless another VRF still imports them.
#[tokio::test]
async fn vrf_deleted_withdraws_the_rtc_membership_only_it_needed() {
    let mut bgp = fresh_bgp();
    add_vrf(&mut bgp, "blue", &[RT_A], &[]);
    add_vrf(&mut bgp, "gold", &[RT_A, RT_B], &[]);
    let (_c, mut rc) = add_peer(&mut bgp, VPNV4);
    bgp.process_rib_msg(RibRx::VrfDel {
        name: "gold".to_string(),
    });
    assert_eq!(rtc_sent(&mut rc), vec![("withdraw", RT_B.to_string())]);
}
