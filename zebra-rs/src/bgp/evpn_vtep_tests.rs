//! EVPN egress wiring that unit tests of the helpers cannot catch: a
//! received Type-2 Label2 surviving reflection, originated routes with a
//! router-id next hop being re-sent when the router-id gains or loses VTEP
//! status, and the EVPN flag communities.
//!
//! `cargo test -p zebra-rs evpn_vtep_tests`

use super::*;
use crate::bgp::peer::State;
use crate::rib::api::RibRx;
use tokio::sync::mpsc;

const RID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// Our address on the eBGP session: a link address, not the VTEP.
const LINK: Ipv4Addr = Ipv4Addr::new(10, 1, 1, 0);
const ESI: [u8; 10] = [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

fn fresh_bgp() -> Bgp {
    let (rib_tx, _) = mpsc::unbounded_channel();
    let (rib_inbound_tx, _) = mpsc::unbounded_channel();
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let mut bgp = Bgp::new(
        crate::context::ProtoContext::default_table_no_rib(),
        mpsc::unbounded_channel().1,
        subscriber,
        mpsc::unbounded_channel().0,
        None,
        None,
        mpsc::channel(1).0,
    );
    bgp.router_id = RID;
    bgp
}

/// An Established EVPN peer whose writer channel the test drains.
fn peer(
    bgp: &mut Bgp,
    addr: &str,
    ebgp: bool,
) -> (usize, mpsc::UnboundedReceiver<bytes::BytesMut>) {
    use bgp_packet::CapMultiProtocol;
    let (ptx, prx) = mpsc::unbounded_channel();
    let (mtx, mrx) = mpsc::channel(8);
    Box::leak(Box::new(mrx));
    let peer_as = if ebgp { 65001 } else { 65000 };
    let mut peer = Peer::new(
        0,
        65000,
        RID,
        peer_as,
        addr.parse::<IpAddr>().unwrap(),
        None,
        mtx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = if ebgp { PeerType::EBGP } else { PeerType::IBGP };
    peer.reflector_client = !ebgp;
    peer.remote_id = addr.parse().unwrap();
    peer.param.local_addr = Some(std::net::SocketAddr::new(IpAddr::V4(LINK), 179));
    let key = CapMultiProtocol::new(&Afi::L2vpn, &Safi::Evpn);
    let entry = peer.cap_map.entries.get_mut(&key).expect("pre-seeded");
    entry.send = true;
    entry.recv = true;
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(addr.parse().unwrap(), peer);
    let ident = bgp
        .peers
        .get(&addr.parse::<IpAddr>().unwrap())
        .unwrap()
        .ident;
    bgp.peers.membership_enroll(ident);
    (ident, prx)
}

/// Every EVPN route the peer was sent, with the next hop it carried.
fn sent(
    bgp: &mut Bgp,
    ident: usize,
    rx: &mut mpsc::UnboundedReceiver<bytes::BytesMut>,
) -> Vec<(EvpnRoute, IpAddr)> {
    bgp.peers.get_mut_by_idx(ident).unwrap().flush_evpn();
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) =
            bgp_packet::BgpPacket::parse_packet(&bytes, false, Some(Default::default()))
                .expect("a well-formed UPDATE");
        if let bgp_packet::BgpPacket::Update(update) = packet
            && let Some(MpReachAttr::Evpn { nhop, updates, .. }) = update.mp_update
        {
            out.extend(updates.into_iter().map(|route| (route, nhop)));
        }
    }
    out
}

/// An originated Ethernet Segment route whose next hop is the router-id
/// fallback, as `evpn_local_source` fills it with no VTEP configured.
fn originate_es_route(bgp: &mut Bgp) -> (RouteDistinguisher, EvpnPrefix) {
    let rd = rd_from_router_id_vni(RID, 0).unwrap();
    let prefix = EvpnPrefix::EthernetSeg {
        esi: ESI,
        orig: IpAddr::V4(RID),
    };
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn(IpAddr::V4(RID)));
    let rib = BgpRib::new(
        ORIGINATED_PEER,
        Ipv4Addr::UNSPECIFIED,
        BgpRibType::Originated,
        0,
        32768,
        &attr,
        None,
        None,
        false,
    );
    let _ = bgp.local_rib.update_evpn(rd, prefix.clone(), rib);
    (rd, prefix)
}

fn nexthops_for(sent: &[(EvpnRoute, IpAddr)], prefix: &EvpnPrefix) -> Vec<IpAddr> {
    sent.iter()
        .filter(|(route, _)| EvpnPrefix::from_route(route).1 == *prefix)
        .map(|(_, nhop)| *nhop)
        .collect()
}

/// Loopback = router-id = VTEP. A route advertised before the router-id was
/// known to be a VTEP went out with the session address; once a VXLAN
/// device names the router-id as its `local`, that route must be re-sent
/// with the VTEP. Deleting the device reverses it.
#[tokio::test]
async fn router_id_becoming_a_vtep_resends_originated_routes() {
    let mut bgp = fresh_bgp();
    let (ident, mut rx) = peer(&mut bgp, "10.1.1.1", true);
    let (_, prefix) = originate_es_route(&mut bgp);

    bgp.process_rib_msg(RibRx::VxlanAdd {
        vni: 200,
        vtep_local: IpAddr::V4(RID),
    });
    assert!(bgp.local_rib.evpn_vteps.contains(&IpAddr::V4(RID)));
    assert_eq!(
        nexthops_for(&sent(&mut bgp, ident, &mut rx), &prefix),
        vec![IpAddr::V4(RID)],
        "re-sent with the router-id VTEP"
    );

    bgp.process_rib_msg(RibRx::VxlanDel { vni: 200 });
    assert!(bgp.local_rib.evpn_vteps.is_empty());
    assert_eq!(
        nexthops_for(&sent(&mut bgp, ident, &mut rx), &prefix),
        vec![IpAddr::V4(LINK)],
        "the router-id is a placeholder again: rewritten to the session address"
    );
}

/// A VTEP other than the router-id never changes how a router-id next hop
/// is treated, so it must not cause a re-send.
#[tokio::test]
async fn unrelated_vtep_change_sends_nothing() {
    let mut bgp = fresh_bgp();
    let (ident, mut rx) = peer(&mut bgp, "10.1.1.1", true);
    let (_, prefix) = originate_es_route(&mut bgp);

    bgp.process_rib_msg(RibRx::VxlanAdd {
        vni: 200,
        vtep_local: "192.0.2.99".parse().unwrap(),
    });
    assert!(nexthops_for(&sent(&mut bgp, ident, &mut rx), &prefix).is_empty());
}

/// RFC 7432 §7.2 / RFC 9135: a symmetric-IRB Type-2 carries the L3VNI as
/// Label2. Reflected to another client it must still carry it.
#[tokio::test]
async fn reflected_macip_keeps_label2() {
    let mut bgp = fresh_bgp();
    let (from, _from_rx) = peer(&mut bgp, "10.0.0.11", false);
    let (to, mut to_rx) = peer(&mut bgp, "10.0.0.12", false);

    let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
        id: 0,
        rd: rd_from_router_id_vni("10.0.0.11".parse().unwrap(), 1000).unwrap(),
        esi: [0; 10],
        ether_tag: 0,
        mac: [2, 0, 0, 0, 1, 1],
        ip: Some("10.10.0.101".parse().unwrap()),
        vni: 1000,
        label2: Some(2000),
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn("10.0.0.11".parse().unwrap()));
    attr.local_pref = Some(LocalPref::default());
    attr.ecom = Some(ExtCommunity::from([evpn_route_target(65000, 1000)]));

    let mut top = BgpTop {
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
        nexthop_cache: None,
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        central_label_alloc: None,
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    route_evpn_update(
        from,
        &route,
        "10.0.0.11".parse().unwrap(),
        &attr,
        &mut top,
        &mut bgp.peers,
        false,
    );

    let reflected: Vec<_> = sent(&mut bgp, to, &mut to_rx)
        .into_iter()
        .filter_map(|(route, _)| match route {
            EvpnRoute::Mac(m) => Some(m),
            _ => None,
        })
        .collect();
    assert_eq!(reflected.len(), 1, "the client route is reflected");
    assert_eq!(reflected[0].label2, Some(2000));
    assert_eq!(reflected[0].vni, 1000);
}

/// RFC 7432 §7.7/§7.8 and RFC 9161 encodings: sticky is the "S" bit of
/// the MAC Mobility community, default gateway an opaque 0x03/0x0d
/// community, router the "R" bit of the EVPN ND community. The mobility
/// sequence number does not depend on the flags.
#[test]
fn evpn_flag_communities_follow_the_rfc_encodings() {
    let ec = |high_type, low_type, flags: u8| {
        let mut val = [0u8; 6];
        val[0] = flags;
        ExtCommunityValue {
            high_type,
            low_type,
            val,
        }
    };
    let flags = |values: Vec<ExtCommunityValue>| {
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity(values.into_iter().collect()));
        extract_flags_from_attr(&attr)
    };
    let mut sticky = evpn_mac_mobility(7);
    sticky.val[0] = 0x01;
    assert_eq!(flags(vec![sticky.clone()]), 0x01);
    let mut attr = BgpAttr::new();
    attr.ecom = Some(ExtCommunity(vec![sticky].into_iter().collect()));
    assert_eq!(extract_mac_mobility_seq(&attr), 7);
    assert_eq!(flags(vec![evpn_mac_mobility(7)]), 0);
    assert_eq!(flags(vec![ec(0x03, 0x0d, 0)]), 0x02);
    assert_eq!(flags(vec![ec(0x06, 0x08, 0x01)]), 0x04);
    assert_eq!(flags(vec![ec(0x06, 0x08, 0x02)]), 0, "override, not router");
    // The types this used to read are not EVPN flags.
    assert_eq!(
        flags(vec![
            ec(0x09, 0x00, 0),
            ec(0x09, 0x01, 0),
            ec(0x09, 0x03, 0)
        ]),
        0
    );
}
