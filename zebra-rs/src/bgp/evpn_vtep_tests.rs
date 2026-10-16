//! EVPN wiring that unit tests of the helpers cannot catch: a received
//! Type-2 Label2 surviving reflection, originated routes with a router-id
//! next hop being re-sent when the router-id gains or loses VTEP status,
//! and a remote MAC/IP route competing with our own for a local MAC.
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

/// A BGP instance whose messages to the RIB the test reads back.
fn bgp_with_rib() -> (Bgp, mpsc::UnboundedReceiver<crate::rib::client::RibInbound>) {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    let (rib_tx, _) = mpsc::unbounded_channel();
    let (rib_inbound_tx, _) = mpsc::unbounded_channel();
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let mut bgp = Bgp::new(
        crate::context::ProtoContext::default_table(client),
        mpsc::unbounded_channel().1,
        subscriber,
        mpsc::unbounded_channel().0,
        None,
        None,
        mpsc::channel(1).0,
    );
    bgp.router_id = RID;
    (bgp, inbound_rx)
}

/// The Type-2 installs (`true`) and removals (`false`) BGP sent the RIB.
fn mac_messages(
    rx: &mut mpsc::UnboundedReceiver<crate::rib::client::RibInbound>,
) -> Vec<(bool, crate::rib::evpn::MacRouteKey)> {
    let mut out = Vec::new();
    while let Ok(inbound) = rx.try_recv() {
        match inbound.msg {
            crate::rib::Message::EvpnMacAdd(route) => out.push((true, route.key)),
            crate::rib::Message::EvpnMacDel(key) => out.push((false, key)),
            _ => {}
        }
    }
    out
}

/// A MAC/IP path with the given mobility state, for the decision rules.
fn macip_path(seq: u32, sticky: bool, esi: [u8; 10], vtep: &str, originated: bool) -> BgpRib {
    let mut ecom = ExtCommunity::from([evpn_route_target(65000, 100)]);
    if seq > 0 || sticky {
        let mut mobility = evpn_mac_mobility(seq);
        if sticky {
            // RFC 7432 §7.7: the flags octet's "S" bit.
            mobility.val[0] |= 0x01;
        }
        ecom.0.insert(mobility);
    }
    let mut attr = BgpAttr::new();
    attr.ecom = Some(ecom);
    attr.nexthop = Some(BgpNexthop::Evpn(vtep.parse().unwrap()));
    let typ = if originated {
        BgpRibType::Originated
    } else {
        BgpRibType::IBGP
    };
    let mut rib = BgpRib::new(
        0,
        Ipv4Addr::UNSPECIFIED,
        typ,
        0,
        0,
        &attr,
        None,
        None,
        false,
    );
    rib.esi = Some(esi);
    rib
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

/// FRR's order for a local against a remote EVPN path
/// (`bgp_path_info_cmp`): sticky, shared local Ethernet Segment, mobility
/// sequence number, then the lower VTEP address.
#[test]
fn local_path_wins_follows_frr_order() {
    let zero = [0; 10];
    let es = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let local = |seq| macip_path(seq, false, zero, "192.0.2.1", true);
    let remote = |seq, vtep| macip_path(seq, false, zero, vtep, false);
    // Sequence number decides.
    assert!(evpn_local_path_wins(&local(5), &remote(3, "192.0.2.9")));
    assert!(!evpn_local_path_wins(&local(5), &remote(6, "192.0.2.0")));
    // Equal sequence numbers: the lower VTEP wins.
    assert!(evpn_local_path_wins(&local(5), &remote(5, "192.0.2.9")));
    assert!(!evpn_local_path_wins(&local(5), &remote(5, "192.0.1.1")));
    // A sticky MAC beats a non-sticky one, whatever the sequence numbers.
    let sticky_remote = macip_path(1, true, zero, "192.0.2.9", false);
    assert!(!evpn_local_path_wins(&local(5), &sticky_remote));
    let sticky_local = macip_path(1, true, zero, "192.0.2.1", true);
    assert!(evpn_local_path_wins(&sticky_local, &remote(9, "192.0.2.0")));
    // On a shared Ethernet Segment the local path wins.
    let es_local = macip_path(1, false, es, "192.0.2.1", true);
    let es_remote = macip_path(9, false, es, "192.0.2.0", false);
    assert!(evpn_local_path_wins(&es_local, &es_remote));
    let other_es = macip_path(9, false, [9; 10], "192.0.2.0", false);
    assert!(!evpn_local_path_wins(&es_local, &other_es));
}

/// RFC 7432 §7.7: a remote route for a MAC learned here is installed only
/// if it beats our own route. A stale one (lower sequence number) must not
/// overwrite the local FDB row; once the local route goes, it is
/// installed; a newer remote route (the host moved) is installed at once.
#[tokio::test]
async fn stale_remote_route_does_not_override_a_local_mac() {
    let (mut bgp, mut rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let mac = MacAddr::from([2, 0, 0, 0, 1, 1]);
    // A move was seen before: our route carries sequence number 5.
    bgp.local_rib.evpn_remote_mac_seq.insert((100, mac), 4);
    let local = crate::rib::api::FdbEntry {
        vni: 100,
        mac,
        ip: None,
        ifindex: 7,
        bridge_ifindex: 5,
        flags: 0,
        vxlan_local: Some(IpAddr::V4(RID)),
    };
    bgp.evpn_originate_macip(&local);
    mac_messages(&mut rib);

    let remote_rd = rd_from_router_id_vni("10.0.0.11".parse().unwrap(), 100).unwrap();
    let key = crate::rib::evpn::MacRouteKey::new(remote_rd, 100, mac, None);
    let advertise = |bgp: &mut Bgp, seq| {
        let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
            id: 0,
            rd: remote_rd,
            esi: [0; 10],
            ether_tag: 0,
            mac: mac.octets(),
            ip: None,
            vni: 100,
            label2: None,
        });
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Evpn("10.0.0.11".parse().unwrap()));
        attr.local_pref = Some(LocalPref::default());
        attr.ecom = Some(ExtCommunity::from([
            evpn_route_target(65000, 100),
            evpn_mac_mobility(seq),
        ]));
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
    };

    // Stale: not installed (any earlier install removed).
    advertise(&mut bgp, 3);
    assert_eq!(mac_messages(&mut rib), vec![(false, key)]);
    // The local route goes: the remote one is installed.
    bgp.evpn_withdraw_macip(&local);
    assert_eq!(mac_messages(&mut rib), vec![(true, key)]);
    // The host is learned here again: our route (still above 3) wins.
    bgp.evpn_originate_macip(&local);
    assert_eq!(mac_messages(&mut rib), vec![(false, key)]);
    // The host moved away: a higher sequence number is installed at once.
    advertise(&mut bgp, 9);
    assert_eq!(mac_messages(&mut rib), vec![(true, key)]);
}

/// Feed a received MAC/IP route from `from` through ingest.
fn receive_macip(
    bgp: &mut Bgp,
    from: usize,
    rd: RouteDistinguisher,
    mac: MacAddr,
    ip: Option<IpAddr>,
    seq: u32,
) {
    receive_macip_on(bgp, from, rd, mac, ip, seq, [0; 10]);
}

/// [`receive_macip`] for a host on Ethernet Segment `esi`.
fn receive_macip_on(
    bgp: &mut Bgp,
    from: usize,
    rd: RouteDistinguisher,
    mac: MacAddr,
    ip: Option<IpAddr>,
    seq: u32,
    esi: [u8; 10],
) {
    feed_macip(bgp, from, rd, mac, ip, Some(seq), esi);
}

/// Feed the withdrawal of a MAC/IP route from `from` through ingest.
fn withdraw_macip(
    bgp: &mut Bgp,
    from: usize,
    rd: RouteDistinguisher,
    mac: MacAddr,
    ip: Option<IpAddr>,
) {
    feed_macip(bgp, from, rd, mac, ip, None, [0; 10]);
}

/// A MAC/IP route announced with sequence number `seq`, or withdrawn.
fn feed_macip(
    bgp: &mut Bgp,
    from: usize,
    rd: RouteDistinguisher,
    mac: MacAddr,
    ip: Option<IpAddr>,
    seq: Option<u32>,
    esi: [u8; 10],
) {
    let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
        id: 0,
        rd,
        esi,
        ether_tag: 0,
        mac: mac.octets(),
        ip,
        vni: 100,
        label2: None,
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn("10.0.0.11".parse().unwrap()));
    attr.local_pref = Some(LocalPref::default());
    attr.ecom = Some(ExtCommunity::from([
        evpn_route_target(65000, 100),
        evpn_mac_mobility(seq.unwrap_or(0)),
    ]));
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
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    if seq.is_none() {
        route_evpn_withdraw(from, &route, &mut top, &mut bgp.peers);
        return;
    }
    route_evpn_update(
        from,
        &route,
        "10.0.0.11".parse().unwrap(),
        &attr,
        &mut top,
        &mut bgp.peers,
        false,
    );
}

/// The mobility sequence number on our own selected MAC/IP route.
fn local_macip_seq(bgp: &Bgp, mac: MacAddr, ip: IpAddr) -> Option<u32> {
    let rd = rd_from_router_id_vni(RID, 100)?;
    let prefix = EvpnPrefix::MacIp {
        eth_tag: 0,
        mac: mac.octets(),
        ip: Some(ip),
    };
    let rib = bgp.local_rib.evpn.get(&rd)?.selected.get(&prefix)?;
    Some(extract_mac_mobility_seq(&rib.attr))
}

/// An IP that moves to a different MAC (FRR's neighbor sequence numbers):
/// learned here on a new MAC, our route outranks the remote binding of the
/// IP to the old MAC, though the new MAC never moved; a stale remote binding
/// of a local IP is not installed; a newer one (the IP moved away) is.
#[tokio::test]
async fn ip_moving_to_another_mac_outranks_the_old_binding() {
    let (mut bgp, mut rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let ip: IpAddr = "10.10.0.101".parse().unwrap();
    let (old_mac, new_mac) = (
        MacAddr::from([2, 0, 0, 0, 1, 1]),
        MacAddr::from([2, 0, 0, 0, 2, 2]),
    );
    let remote_rd = rd_from_router_id_vni("10.0.0.11".parse().unwrap(), 100).unwrap();
    let old_binding = crate::rib::evpn::MacRouteKey::new(remote_rd, 100, old_mac, Some(ip));

    // The IP lives behind the peer on the old MAC.
    receive_macip(&mut bgp, from, remote_rd, old_mac, Some(ip), 3);
    assert_eq!(mac_messages(&mut rib), vec![(true, old_binding)]);

    // It appears here on a new MAC: our route carries 4, and the old
    // binding leaves the RIB.
    let local = crate::rib::api::FdbEntry {
        vni: 100,
        mac: new_mac,
        ip: Some(ip),
        ifindex: 7,
        bridge_ifindex: 5,
        flags: 0,
        vxlan_local: Some(IpAddr::V4(RID)),
    };
    bgp.evpn_originate_macip(&local);
    assert_eq!(local_macip_seq(&bgp, new_mac, ip), Some(4));
    assert_eq!(mac_messages(&mut rib), vec![(false, old_binding)]);
    // The MAC-only route of the new MAC keeps its own number.
    let mac_only = crate::rib::api::FdbEntry {
        ip: None,
        ..local.clone()
    };
    bgp.evpn_originate_macip(&mac_only);
    let rd = rd_from_router_id_vni(RID, 100).unwrap();
    let mac_only_seq = bgp.local_rib.evpn[&rd].selected[&EvpnPrefix::MacIp {
        eth_tag: 0,
        mac: new_mac.octets(),
        ip: None,
    }]
        .attr
        .clone();
    assert_eq!(extract_mac_mobility_seq(&mac_only_seq), 0);
    mac_messages(&mut rib);

    // A refresh of the stale binding is not installed.
    receive_macip(&mut bgp, from, remote_rd, old_mac, Some(ip), 3);
    assert_eq!(mac_messages(&mut rib), vec![(false, old_binding)]);
    // The IP moved back behind the peer: installed at once.
    receive_macip(&mut bgp, from, remote_rd, old_mac, Some(ip), 7);
    assert_eq!(mac_messages(&mut rib), vec![(true, old_binding)]);
    // Learned here again later, our route carries 8 and wins.
    bgp.evpn_withdraw_macip(&local);
    mac_messages(&mut rib);
    bgp.evpn_originate_macip(&local);
    assert_eq!(local_macip_seq(&bgp, new_mac, ip), Some(8));
    assert_eq!(mac_messages(&mut rib), vec![(false, old_binding)]);
}

/// RFC 7432 §15.1 duplicate address detection, driven through ingest and
/// origination. A host flapping between this node and the peer at
/// 10.0.0.11: each takeover by the peer outranks our route, and the
/// kernel then replaces our local FDB row (simulated by withdrawing the
/// local route); each local learn outranks the peer's route.
struct Flap {
    bgp: Bgp,
    rib: mpsc::UnboundedReceiver<crate::rib::client::RibInbound>,
    from: usize,
    local: crate::rib::api::FdbEntry,
    key: crate::rib::evpn::MacRouteKey,
    remote_rd: RouteDistinguisher,
    seq: u32,
}

impl Flap {
    fn new(
        config: crate::bgp::evpn_dad::DadConfig,
    ) -> (Self, mpsc::UnboundedReceiver<bytes::BytesMut>) {
        let (mut bgp, rib) = bgp_with_rib();
        bgp.advertise_all_vni = true;
        bgp.evpn_dad_configure(config);
        let (from, rx) = peer(&mut bgp, "10.0.0.11", false);
        let mac = MacAddr::from([2, 0, 0, 0, 1, 1]);
        let remote_rd = rd_from_router_id_vni("10.0.0.11".parse().unwrap(), 100).unwrap();
        let local = crate::rib::api::FdbEntry {
            vni: 100,
            mac,
            ip: None,
            ifindex: 7,
            bridge_ifindex: 5,
            flags: 0,
            vxlan_local: Some(IpAddr::V4(RID)),
        };
        bgp.local_fdb.insert((100, mac, None), local.clone());
        let flap = Self {
            bgp,
            rib,
            from,
            local,
            key: crate::rib::evpn::MacRouteKey::new(remote_rd, 100, mac, None),
            remote_rd,
            seq: 0,
        };
        (flap, rx)
    }

    /// The peer advertises the host with a sequence number above ours.
    fn remote(&mut self) {
        self.seq += 1;
        receive_macip(
            &mut self.bgp,
            self.from,
            self.remote_rd,
            self.local.mac,
            None,
            self.seq,
        );
        self.bgp.event_upkeep();
    }

    /// The kernel replaced our local row with the remote one.
    fn kernel_replaced(&mut self) {
        self.bgp.evpn_withdraw_macip(&self.local);
        self.bgp.event_upkeep();
    }

    /// The host is learned here: our route carries the next number.
    fn local(&mut self) {
        self.seq += 1;
        self.bgp.evpn_originate_macip(&self.local);
        self.bgp.event_upkeep();
    }

    fn messages(&mut self) -> Vec<(bool, crate::rib::evpn::MacRouteKey)> {
        mac_messages(&mut self.rib)
    }

    fn advertised(&self) -> bool {
        self.bgp.evpn_macip_originated(&self.local)
    }

    fn dad_key(&self) -> crate::bgp::evpn_dad::DadKey {
        crate::bgp::evpn_dad::DadKey::Mac(100, self.local.mac)
    }
}

fn dad_config(
    max_moves: u32,
    freeze: crate::bgp::evpn_dad::Freeze,
) -> crate::bgp::evpn_dad::DadConfig {
    crate::bgp::evpn_dad::DadConfig {
        enabled: true,
        max_moves,
        time: 180,
        freeze,
    }
}

/// Warn-only (the default action): the duplicate is detected and marked,
/// and routes keep flowing.
#[tokio::test]
async fn flapping_mac_is_detected_and_still_advertised_without_freeze() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Off));
    f.remote(); // the host starts behind the peer: not a move
    f.local(); // 1
    f.remote(); // 2
    f.kernel_replaced();
    assert!(!f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac));
    f.messages();
    f.local(); // 3: detected
    assert!(f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac));
    assert!(f.advertised());
    assert_eq!(f.messages(), vec![(false, f.key)]);
    let view = f.bgp.local_rib.evpn_dad.view(std::time::Instant::now());
    assert_eq!(view.addresses.len(), 1);
    assert!(view.addresses[0].duplicate);
    assert_eq!(view.addresses[0].location, "local");
}

/// Detected on a local learn under a permanent freeze: our route is not
/// advertised, the peer's stays where the kernel has it, later routes
/// from the peer are not installed; `clear` installs the peer's route,
/// the last one received.
#[tokio::test]
async fn freeze_on_a_local_learn_holds_both_sides_until_cleared() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    f.remote();
    f.local(); // 1
    f.remote(); // 2
    f.kernel_replaced();
    f.messages();
    f.local(); // 3: detected and frozen
    assert!(!f.advertised());
    assert_eq!(f.messages(), vec![]);
    assert_eq!(f.bgp.local_rib.evpn_dad.until(f.dad_key()), None);
    // A newer route from the peer is held too.
    f.remote();
    assert_eq!(f.messages(), vec![]);
    assert_eq!(f.bgp.evpn_dad_clear(Some(200), None, None), 0);
    assert_eq!(f.bgp.evpn_dad_clear(Some(100), None, None), 1);
    assert_eq!(f.messages(), vec![(true, f.key)]);
    assert!(!f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac));
}

/// Detected on the peer's takeover under a timed freeze: the peer's route
/// is not installed and ours is withdrawn (FRR removes the local MAC from
/// BGP on a takeover); the freeze elapsing installs the peer's route.
#[tokio::test]
async fn freeze_on_a_takeover_withdraws_ours_and_recovers_on_the_timer() {
    let (mut f, _rx) = Flap::new(dad_config(2, crate::bgp::evpn_dad::Freeze::For(60)));
    f.remote();
    f.local(); // 1
    assert!(f.advertised());
    f.messages();
    f.remote(); // 2: detected and frozen
    assert!(!f.advertised());
    assert_eq!(f.messages(), vec![]);
    let until = f
        .bgp
        .local_rib
        .evpn_dad
        .until(f.dad_key())
        .expect("a timed freeze arms recovery");
    // A wake-up for another freeze is ignored.
    f.bgp
        .evpn_dad_recover(f.dad_key(), until + std::time::Duration::from_secs(1));
    assert_eq!(f.messages(), vec![]);
    f.bgp.evpn_dad_recover(f.dad_key(), until);
    assert_eq!(f.messages(), vec![(true, f.key)]);
    assert!(!f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac));
}

/// Turning detection off releases a frozen address: a local one is
/// advertised again, and its route outranks the peer's.
#[tokio::test]
async fn disabling_detection_readvertises_a_frozen_local_mac() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    f.remote();
    f.local();
    f.remote();
    f.kernel_replaced();
    f.local(); // frozen while local
    assert!(!f.advertised());
    f.messages();
    f.bgp.evpn_dad_configure(crate::bgp::evpn_dad::DadConfig {
        enabled: false,
        ..dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent)
    });
    assert!(f.advertised());
    assert_eq!(f.messages(), vec![(false, f.key)]);
}

fn frozen_mac_with_ip(freeze: crate::bgp::evpn_dad::Freeze) -> (Flap, IpAddr) {
    let (mut f, _rx) = Flap::new(dad_config(2, freeze));
    let ip = "10.10.0.5".parse().unwrap();
    f.remote();
    f.bgp
        .process_rib_msg(RibRx::FdbAdd(crate::rib::api::FdbEntry {
            ip: Some(ip),
            ..f.local.clone()
        })); // first local move
    f.local(); // MAC-only route for the same local MAC
    f.remote(); // second move: MAC frozen, IP inherits the freeze
    assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, Some(ip)));
    assert!(!f.advertised());
    f.messages();
    (f, ip)
}

/// As in FRR (`zebra_evpn_ip_inherit_dad_from_mac`), an IP holds with its
/// duplicate MAC only while bound to it: rebound to a MAC that is not a
/// duplicate, remotely or locally, it is released and its own detection
/// starts over. The duplicate MAC itself stays frozen.
#[tokio::test]
async fn an_ip_rebound_to_a_clean_mac_leaves_the_inherited_hold() {
    use crate::bgp::evpn_dad::Freeze;
    let (mut f, ip) = frozen_mac_with_ip(Freeze::Permanent);
    let other_mac = MacAddr::from([2, 0, 0, 0, 1, 2]);
    receive_macip(&mut f.bgp, f.from, f.remote_rd, other_mac, Some(ip), 10);
    let new_key = crate::rib::evpn::MacRouteKey::new(f.remote_rd, 100, other_mac, Some(ip));
    assert!(f.messages().contains(&(true, new_key)));
    assert!(!f.bgp.local_rib.evpn_dad.frozen(100, other_mac, Some(ip)));
    assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, None));

    let (mut f, ip) = frozen_mac_with_ip(Freeze::Permanent);
    let local = crate::rib::api::FdbEntry {
        mac: other_mac,
        ip: Some(ip),
        ..f.local.clone()
    };
    f.bgp.process_rib_msg(RibRx::FdbAdd(local.clone()));
    assert!(f.bgp.evpn_macip_originated(&local));
    assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, None));
}

/// An IP that moved once, then had its MAC detected: it holds with the
/// MAC (inherited), with a move of its own still counted.
fn ip_moved_then_its_mac_detected() -> (Flap, IpAddr, MacAddr) {
    use crate::bgp::evpn_dad::Freeze;
    let (mut f, _rx) = Flap::new(dad_config(2, Freeze::Permanent));
    let ip = "10.10.0.5".parse().unwrap();
    let other = MacAddr::from([2, 0, 0, 0, 1, 2]);
    // On the peer's other MAC, then learned here on ours: a move.
    receive_macip(&mut f.bgp, f.from, f.remote_rd, other, Some(ip), 1);
    f.bgp
        .process_rib_msg(RibRx::FdbAdd(crate::rib::api::FdbEntry {
            ip: Some(ip),
            ..f.local.clone()
        }));
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].probe.count, 1);
    // Our MAC flaps until detected.
    f.seq = 3;
    f.remote();
    f.local();
    f.remote();
    let dad = &f.bgp.local_rib.evpn_dad;
    assert!(dad.mac_duplicate(100, f.local.mac));
    assert!(dad.frozen(100, f.local.mac, Some(ip)), "inherited");
    assert!(dad.ips[&(100, ip)].probe.duplicate.is_none());
    f.messages();
    (f, ip, other)
}

/// Rebound to a clean MAC, such an IP leaves the hold and its own detection
/// starts over (FRR's `zebra_evpn_ip_inherit_dad_from_mac`): its earlier
/// move is forgotten, not counted with the rebinding. It was: with
/// `max-moves 2` the rebinding completed its own detection, and the
/// rebound route was not installed (remote) nor advertised (local).
#[tokio::test]
async fn an_ip_leaving_a_duplicate_mac_starts_its_detection_over() {
    let (mut f, ip, other) = ip_moved_then_its_mac_detected();
    receive_macip(&mut f.bgp, f.from, f.remote_rd, other, Some(ip), 20);
    let key = crate::rib::evpn::MacRouteKey::new(f.remote_rd, 100, other, Some(ip));
    assert!(f.messages().contains(&(true, key)), "remote: installed");
    let probe = &f.bgp.local_rib.evpn_dad.ips[&(100, ip)].probe;
    assert_eq!((probe.count, probe.duplicate), (0, None));

    let (mut f, ip, other) = ip_moved_then_its_mac_detected();
    receive_macip(&mut f.bgp, f.from, f.remote_rd, f.local.mac, Some(ip), 20);
    let local = crate::rib::api::FdbEntry {
        mac: other,
        ip: Some(ip),
        ..f.local.clone()
    };
    f.bgp.process_rib_msg(RibRx::FdbAdd(local.clone()));
    assert!(f.bgp.evpn_macip_originated(&local), "local: advertised");
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].probe.count, 1);
}

/// Detection forgets a local MAC and IP once the FDB entry is deleted, with
/// detection on or off. It kept an entry for every one that ever came and
/// went.
#[tokio::test]
async fn a_local_address_that_goes_leaves_no_detection_state() {
    use crate::bgp::evpn_dad::{DadConfig, Freeze};
    for enabled in [true, false] {
        let (mut f, _rx) = Flap::new(DadConfig {
            enabled,
            ..dad_config(3, Freeze::Off)
        });
        for i in 0..50u8 {
            let mac = MacAddr::from([2, 0, 0, 1, 0, i]);
            let ip = Some(IpAddr::from([10, 10, 1, i]));
            for ip in [None, ip] {
                f.bgp
                    .process_rib_msg(RibRx::FdbAdd(crate::rib::api::FdbEntry {
                        mac,
                        ip,
                        ..f.local.clone()
                    }));
            }
            for ip in [ip, None] {
                f.bgp
                    .process_rib_msg(RibRx::FdbDel(crate::rib::api::FdbEntry {
                        mac,
                        ip,
                        ..f.local.clone()
                    }));
            }
        }
        let dad = &f.bgp.local_rib.evpn_dad;
        assert!(
            dad.macs.is_empty(),
            "enabled {enabled}: {:?}",
            dad.macs.len()
        );
        assert!(dad.ips.is_empty(), "enabled {enabled}: {:?}", dad.ips.len());
    }
}

/// Changing warn-only to a timed freeze withdraws existing advertisements
/// immediately and arms a real timer that re-advertises on recovery.
#[tokio::test(start_paused = true)]
async fn timed_freeze_after_warn_only_withdraws_and_arms_recovery() {
    use crate::bgp::evpn_dad::Freeze;
    let (mut f, _rx) = Flap::new(dad_config(3, Freeze::Off));
    f.remote();
    f.local();
    f.remote();
    f.kernel_replaced();
    f.local(); // warn-only duplicate, still advertised
    assert!(f.advertised());
    f.messages();
    f.bgp.evpn_dad_configure(dad_config(3, Freeze::For(30)));
    assert!(!f.advertised());
    assert!(
        f.messages().is_empty(),
        "changing the hold does not program the RIB"
    );
    let expected_until = f
        .bgp
        .local_rib
        .evpn_dad
        .until(f.dad_key())
        .expect("timed freeze deadline");
    let message = tokio::time::timeout(std::time::Duration::from_secs(31), f.bgp.rx.recv())
        .await
        .expect("a recovery timer is armed")
        .expect("BGP channel is open");
    let super::super::inst::Message::EvpnDadRecover { key, until } = message else {
        panic!("expected duplicate-address recovery");
    };
    assert_eq!(key, f.dad_key());
    assert_eq!(until, expected_until);
    f.bgp.evpn_dad_recover(key, until);
    assert!(f.advertised());
    assert!(!f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac));
}

#[tokio::test(start_paused = true)]
async fn permanent_freeze_changed_to_timed_freeze_arms_recovery() {
    use crate::bgp::evpn_dad::Freeze;
    let (mut f, _rx) = Flap::new(dad_config(2, Freeze::For(30)));
    f.remote();
    f.local();
    f.remote();
    let stale_until = f.bgp.local_rib.evpn_dad.until(f.dad_key()).unwrap();
    f.messages();
    f.bgp.evpn_dad_configure(dad_config(2, Freeze::Permanent));
    f.bgp.evpn_dad_recover(f.dad_key(), stale_until);
    assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, None));
    assert!(f.messages().is_empty(), "the old timed recovery is ignored");

    f.bgp.evpn_dad_configure(dad_config(2, Freeze::For(60)));
    let expected_until = f.bgp.local_rib.evpn_dad.until(f.dad_key()).unwrap();
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(61), f.bgp.rx.recv())
            .await
            .expect("a recovery timer is armed")
            .expect("BGP channel is open");
        let super::super::inst::Message::EvpnDadRecover { key, until } = message else {
            panic!("expected duplicate-address recovery");
        };
        f.bgp.evpn_dad_recover(key, until);
        if until == expected_until {
            break;
        }
        assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, None));
        assert!(f.messages().is_empty());
    }
    assert_eq!(f.messages(), vec![(true, f.key)]);
    assert!(!f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac));
}

/// One recovery timer per address: re-arming it replaces, and so cancels,
/// the timer before, and releasing the address drops it. Each freeze
/// change spawned another sleeping task and none was cancelled, so
/// toggling the freeze with many duplicates left thousands pending for up
/// to an hour, each waking only to be discarded.
#[tokio::test(start_paused = true)]
async fn recovery_timers_are_replaced_not_stacked() {
    use crate::bgp::evpn_dad::Freeze;
    let (mut f, _rx) = Flap::new(dad_config(2, Freeze::For(30)));
    f.remote();
    f.local();
    f.remote(); // detected, recovering in 30 s
    for secs in [40, 50, 60] {
        f.bgp.evpn_dad_configure(dad_config(2, Freeze::For(secs)));
    }
    assert_eq!(f.bgp.local_rib.evpn_dad.recovery.len(), 1);
    let expected_until = f.bgp.local_rib.evpn_dad.until(f.dad_key()).unwrap();
    // The only wake-up is the last deadline's.
    let message = tokio::time::timeout(std::time::Duration::from_secs(61), f.bgp.rx.recv())
        .await
        .expect("a recovery timer is armed")
        .expect("BGP channel is open");
    let super::super::inst::Message::EvpnDadRecover { key, until } = message else {
        panic!("expected duplicate-address recovery");
    };
    assert_eq!((key, until), (f.dad_key(), expected_until));
    f.bgp.evpn_dad_recover(key, until);
    assert!(f.bgp.local_rib.evpn_dad.recovery.is_empty());
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3600), f.bgp.rx.recv())
            .await
            .is_err(),
        "no timer is left behind"
    );

    // Detected again, then cleared: the timer goes with the freeze.
    f.local();
    f.remote();
    assert_eq!(f.bgp.local_rib.evpn_dad.recovery.len(), 1);
    assert_eq!(f.bgp.evpn_dad_clear(Some(100), None, None), 1);
    assert!(f.bgp.local_rib.evpn_dad.recovery.is_empty());
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3600), f.bgp.rx.recv())
            .await
            .is_err(),
        "the cleared freeze's timer is gone"
    );

    // Detected again, then the freeze turned off, or detection: nothing
    // recovers.
    for config in [
        dad_config(2, Freeze::Off),
        crate::bgp::evpn_dad::DadConfig {
            enabled: false,
            ..dad_config(2, Freeze::For(30))
        },
    ] {
        f.bgp.evpn_dad_configure(dad_config(2, Freeze::For(30)));
        f.local();
        f.remote();
        assert_eq!(f.bgp.local_rib.evpn_dad.recovery.len(), 1);
        f.bgp.evpn_dad_configure(config);
        assert!(f.bgp.local_rib.evpn_dad.recovery.is_empty());
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3600), f.bgp.rx.recv())
                .await
                .is_err(),
            "{config:?}: no timer"
        );
    }
}

/// A frozen IP's local binding on a MAC other than the one the takeover
/// held is withdrawn as well: the IP is frozen, on whichever MAC.
#[tokio::test]
async fn a_frozen_ips_binding_on_another_mac_is_withdrawn() {
    let (mut f, _rx) = Flap::new(dad_config(2, crate::bgp::evpn_dad::Freeze::Permanent));
    let ip: IpAddr = "10.10.0.5".parse().unwrap();
    let remote_mac = MacAddr::from([2, 0, 0, 0, 1, 9]);
    let binding = crate::rib::api::FdbEntry {
        ip: Some(ip),
        ..f.local.clone()
    };
    receive_macip(&mut f.bgp, f.from, f.remote_rd, remote_mac, Some(ip), 1);
    f.bgp.process_rib_msg(RibRx::FdbAdd(binding.clone())); // the IP moved here: 1
    f.bgp.event_upkeep();
    assert!(f.bgp.evpn_macip_originated(&binding));
    receive_macip(&mut f.bgp, f.from, f.remote_rd, remote_mac, Some(ip), 3); // 2
    f.bgp.event_upkeep();
    assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, Some(ip)));
    assert!(!f.bgp.evpn_macip_originated(&binding));
}

/// Clearing an IP detected on a local learn advertises its local binding
/// again.
#[tokio::test]
async fn clearing_an_ip_detected_here_readvertises_its_binding() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let ip: IpAddr = "10.10.0.5".parse().unwrap();
    let remote_mac = MacAddr::from([2, 0, 0, 0, 1, 9]);
    let binding = crate::rib::api::FdbEntry {
        ip: Some(ip),
        ..f.local.clone()
    };
    receive_macip(&mut f.bgp, f.from, f.remote_rd, remote_mac, Some(ip), 1);
    f.bgp.process_rib_msg(RibRx::FdbAdd(binding.clone())); // 1
    receive_macip(&mut f.bgp, f.from, f.remote_rd, remote_mac, Some(ip), 3); // 2
    f.bgp.evpn_withdraw_macip(&binding); // the kernel replaced the binding
    f.bgp.process_rib_msg(RibRx::FdbAdd(binding.clone())); // 3: detected
    f.bgp.event_upkeep();
    assert!(f.bgp.local_rib.evpn_dad.frozen(100, f.local.mac, Some(ip)));
    assert!(!f.bgp.evpn_macip_originated(&binding));

    assert_eq!(f.bgp.evpn_dad_clear(Some(100), None, Some(ip)), 1);
    f.bgp.event_upkeep();
    assert!(f.bgp.evpn_macip_originated(&binding));
}

/// A multihomed host on a segment this node shares with the peer, learned
/// on either PE as its traffic hashes: the peer's route for it on the
/// segment only syncs it (RFC 7432 §8.4, FRR's sync route), and the host is
/// reachable over our own port all along. Each learn here and each re-run
/// of the peer's route after ours went counted a move, two a cycle, so the
/// healthy host was flagged and, with freeze, withdrawn by both PEs. The
/// same host on a segment this node is not on is a duplicate as before.
#[tokio::test]
async fn a_host_moving_within_our_segment_is_no_duplicate() {
    use crate::bgp::ethernet_segment::EthernetSegment;
    use crate::bgp::evpn_dad::Freeze;
    for ours in [true, false] {
        let (mut f, _rx) = Flap::new(dad_config(2, Freeze::Permanent));
        if ours {
            f.bgp.ethernet_segments.insert(
                "es1".to_string(),
                EthernetSegment {
                    esi: Some(ESI),
                    interface: Some("host0".to_string()),
                    ..Default::default()
                },
            );
            f.bgp
                .link_index_by_name
                .insert("host0".to_string(), f.local.ifindex);
            f.bgp.local_rib.own_es.insert(ESI, "host0".to_string());
            assert_eq!(f.bgp.macip_esi(&f.local), Some(ESI));
        }
        for _ in 0..3 {
            f.seq += 1;
            receive_macip_on(
                &mut f.bgp,
                f.from,
                f.remote_rd,
                f.local.mac,
                None,
                f.seq,
                ESI,
            );
            f.bgp.event_upkeep();
            f.local();
            f.kernel_replaced(); // aged out here: the peer's route re-runs
        }
        assert_eq!(
            f.bgp.local_rib.evpn_dad.mac_duplicate(100, f.local.mac),
            !ours,
            "on our segment: {ours}"
        );
    }
}

/// Only the newest binding of an IP moves it. The IP has (mac 1, seq 1)
/// and (mac 2, seq 5) from different RDs; a reconcile re-runs the first,
/// and the host, still on mac 2, is then learned here. That is a move of
/// mac 2, not of the IP, but the re-run had left the IP on mac 1.
#[tokio::test]
async fn an_older_binding_re_run_is_no_ip_move() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let ip: IpAddr = "10.10.0.5".parse().unwrap();
    let old_mac = MacAddr::from([2, 0, 0, 0, 1, 9]);
    let old_rd = rd_from_router_id_vni("10.0.0.12".parse().unwrap(), 100).unwrap();
    receive_macip(&mut f.bgp, f.from, old_rd, old_mac, Some(ip), 1);
    receive_macip(&mut f.bgp, f.from, f.remote_rd, f.local.mac, Some(ip), 5);
    f.bgp
        .evpn_reconcile_remote_mac(100, old_mac.octets(), Some(ip));
    f.bgp.event_upkeep();
    let dad = &f.bgp.local_rib.evpn_dad;
    assert_eq!(dad.ips[&(100, ip)].mac, f.local.mac);

    f.bgp.evpn_originate_macip(&crate::rib::api::FdbEntry {
        ip: Some(ip),
        ..f.local.clone()
    });
    let dad = &f.bgp.local_rib.evpn_dad;
    assert_eq!(dad.macs[&(100, f.local.mac)].count, 1, "the MAC moved");
    assert_eq!(dad.ips[&(100, ip)].probe.count, 0, "the IP kept its MAC");
}

/// Releasing an IP re-advertises its local bindings, but not one on a MAC
/// that has since gone remote: the remote route beat it, and advertising it
/// again was a local learn of that MAC, a move that never happened.
#[tokio::test]
async fn releasing_an_ip_does_not_relearn_its_remote_mac() {
    use crate::bgp::evpn_dad::{Duplicate, IpProbe, Owner, Probe};
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let ip: IpAddr = "10.10.0.5".parse().unwrap();
    let binding = crate::rib::api::FdbEntry {
        ip: Some(ip),
        ..f.local.clone()
    };
    f.bgp
        .local_fdb
        .insert((100, f.local.mac, Some(ip)), binding.clone());
    let now = std::time::Instant::now();
    let dad = &mut f.bgp.local_rib.evpn_dad;
    // The MAC went to the peer within a window; the IP, local, was
    // detected on its own.
    dad.macs.insert(
        (100, f.local.mac),
        Probe {
            owner: Some(Owner::Remote {
                vtep: Some("10.0.0.11".parse().unwrap()),
                sticky: false,
                es: None,
            }),
            count: 1,
            start: Some(now),
            ..Default::default()
        },
    );
    dad.ips.insert(
        (100, ip),
        IpProbe {
            mac: f.local.mac,
            probe: Probe {
                owner: Some(Owner::Local),
                duplicate: Some(Duplicate {
                    since: now,
                    until: None,
                }),
                ..Default::default()
            },
        },
    );
    assert_eq!(f.bgp.evpn_dad_clear(Some(100), None, Some(ip)), 1);
    let dad = &f.bgp.local_rib.evpn_dad;
    assert_eq!(dad.macs[&(100, f.local.mac)].count, 1);
    assert!(dad.detected(None, None, None).is_empty());
    assert!(!f.bgp.evpn_macip_originated(&binding));
}

/// `clear … ip` on an IP its duplicate MAC holds leaves it alone, as FRR
/// refuses it: the IP stays frozen with the MAC whatever its own mark, and
/// clearing the MAC releases both. It reported success and released
/// nothing (or only the IP's own mark, which changed nothing).
#[tokio::test]
async fn clearing_an_ip_its_duplicate_mac_holds_releases_nothing() {
    use crate::bgp::evpn_dad::{Duplicate, IpProbe, Probe};
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let now = std::time::Instant::now();
    let marked = Some(Duplicate {
        since: now,
        until: None,
    });
    let held: IpAddr = "10.10.0.5".parse().unwrap();
    let both: IpAddr = "10.10.0.6".parse().unwrap();
    let dad = &mut f.bgp.local_rib.evpn_dad;
    dad.macs.insert(
        (100, f.local.mac),
        Probe {
            duplicate: marked,
            ..Default::default()
        },
    );
    for (ip, duplicate) in [(held, None), (both, marked)] {
        dad.ips.insert(
            (100, ip),
            IpProbe {
                mac: f.local.mac,
                probe: Probe {
                    duplicate,
                    ..Default::default()
                },
            },
        );
    }
    for ip in [held, both] {
        assert_eq!(f.bgp.evpn_dad_clear(Some(100), None, Some(ip)), 0);
        assert_eq!(f.bgp.evpn_dad_clear(None, None, Some(ip)), 0);
    }
    let dad = &f.bgp.local_rib.evpn_dad;
    assert!(dad.frozen(100, f.local.mac, Some(held)));
    assert_eq!(dad.ips[&(100, both)].probe.duplicate, marked);

    assert_eq!(f.bgp.evpn_dad_clear(Some(100), Some(f.local.mac), None), 1);
    let dad = &f.bgp.local_rib.evpn_dad;
    assert!(!dad.frozen(100, f.local.mac, Some(held)));
    assert!(!dad.frozen(100, f.local.mac, Some(both)));
}

/// An IP is where the newest of its live bindings is: a withdrawn one no
/// longer counts, however high its number was. Detection compared with the
/// highest number ever seen for the IP, which a withdrawal never lowers,
/// so after (mac, seq 100) went, (mac 1, seq 1) then (mac 2, seq 5) left
/// the IP on mac 1, and a learn of mac 2 here counted an IP move.
#[tokio::test]
async fn a_withdrawn_binding_does_not_pin_the_ip() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let ip: IpAddr = "10.10.0.5".parse().unwrap();
    let mac1 = MacAddr::from([2, 0, 0, 0, 1, 8]);
    let mac2 = MacAddr::from([2, 0, 0, 0, 1, 9]);
    receive_macip(&mut f.bgp, f.from, f.remote_rd, f.local.mac, Some(ip), 100);
    withdraw_macip(&mut f.bgp, f.from, f.remote_rd, f.local.mac, Some(ip));
    receive_macip(&mut f.bgp, f.from, f.remote_rd, mac1, Some(ip), 1);
    receive_macip(&mut f.bgp, f.from, f.remote_rd, mac2, Some(ip), 5);
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].mac, mac2);

    let binding = crate::rib::api::FdbEntry {
        mac: mac2,
        ip: Some(ip),
        ..f.local.clone()
    };
    f.bgp.process_rib_msg(RibRx::FdbAdd(binding));
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].probe.count, 0);
}

/// A segment peer's sync route withdrawn while an ordinary remote route
/// for the MAC stays: the MAC is at the ordinary route, and a learn here
/// is a move. The owner kept the sync route's segment, and the move went
/// uncounted.
#[tokio::test]
async fn a_withdrawn_sync_route_leaves_no_exemption() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let sync_rd = rd_from_router_id_vni("10.0.0.12".parse().unwrap(), 100).unwrap();
    f.bgp.local_rib.own_es.insert(ESI, "host0".to_string());
    receive_macip(&mut f.bgp, f.from, f.remote_rd, f.local.mac, None, 1);
    receive_macip_on(&mut f.bgp, f.from, sync_rd, f.local.mac, None, 2, ESI);
    withdraw_macip(&mut f.bgp, f.from, sync_rd, f.local.mac, None);
    f.local();
    assert_eq!(
        f.bgp.local_rib.evpn_dad.macs[&(100, f.local.mac)].count,
        1,
        "learned here from the ordinary route left: a move"
    );
}

/// The IP's winning binding replaced by an UPDATE with a lower sequence
/// number: (mac 1, seq 10) and (mac 2, seq 5) from different RDs, then mac
/// 1's route again with seq 1. The IP is at mac 2 now, and the host
/// learned here on mac 2 kept its MAC. The IP stayed on mac 1, and the
/// learn counted an IP move.
#[tokio::test]
async fn a_binding_replaced_by_an_older_one_moves_the_ip() {
    let (mut f, _rx) = Flap::new(dad_config(3, crate::bgp::evpn_dad::Freeze::Permanent));
    let ip: IpAddr = "10.10.0.5".parse().unwrap();
    let mac1 = MacAddr::from([2, 0, 0, 0, 1, 8]);
    let other_rd = rd_from_router_id_vni("10.0.0.12".parse().unwrap(), 100).unwrap();
    receive_macip(&mut f.bgp, f.from, f.remote_rd, mac1, Some(ip), 10);
    receive_macip(&mut f.bgp, f.from, other_rd, f.local.mac, Some(ip), 5);
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].mac, mac1);
    receive_macip(&mut f.bgp, f.from, f.remote_rd, mac1, Some(ip), 1);
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].mac, f.local.mac);

    f.bgp
        .process_rib_msg(RibRx::FdbAdd(crate::rib::api::FdbEntry {
            ip: Some(ip),
            ..f.local.clone()
        }));
    assert_eq!(f.bgp.local_rib.evpn_dad.ips[&(100, ip)].probe.count, 0);
}

/// EVPN E-Tree (RFC 8317 §4.1): only a Type-2 whose E-Tree community sets
/// the Leaf-Indication flag is a leaf MAC. The community with L clear is
/// invalid on a Type-2 and reads as a root; it is the one that gets logged.
#[test]
fn etree_leaf_flag_needs_the_leaf_indication() {
    let attr = |values: Vec<ExtCommunityValue>| {
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity(values.into_iter().collect()));
        attr
    };
    let leaf = attr(vec![
        evpn_route_target(65000, 100),
        ExtCommunityValue::etree_leaf(),
    ]);
    assert_eq!(
        extract_flags_from_attr(&leaf),
        crate::rib::evpn::MAC_FLAG_ETREE_LEAF
    );
    assert!(!etree_leaf_flag_missing(&leaf));
    // L clear: the ESI-0 A-D form, which is no leaf flag on a Type-2.
    let no_l = attr(vec![ExtCommunityValue::etree_leaf_label(1000)]);
    assert_eq!(extract_flags_from_attr(&no_l), 0);
    assert!(etree_leaf_flag_missing(&no_l));
    let root = attr(vec![evpn_route_target(65000, 100)]);
    assert_eq!(extract_flags_from_attr(&root), 0);
    assert!(!etree_leaf_flag_missing(&root));
}

/// Our own selected MAC-only route for `mac`'s attributes.
fn local_macip_attr(bgp: &Bgp, mac: MacAddr) -> BgpAttr {
    let rd = rd_from_router_id_vni(RID, 100).expect("rd");
    let prefix = EvpnPrefix::MacIp {
        eth_tag: 0,
        mac: mac.octets(),
        ip: None,
    };
    (*bgp.local_rib.evpn[&rd].selected[&prefix].attr).clone()
}

fn has_etree_leaf(attr: &BgpAttr) -> bool {
    attr.ecom
        .as_ref()
        .is_some_and(|ecom| ecom.0.contains(&ExtCommunityValue::etree_leaf()))
}

/// A MAC learned on a leaf AC is advertised with the E-Tree leaf flag, one
/// learned on any other port without it, and a role change re-advertises
/// the MACs already learned with their mobility sequence number unchanged
/// (RFC 8317 §4.1: an attribute change, not a move).
#[tokio::test]
async fn a_mac_learned_on_a_leaf_ac_is_coloured() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.link_index_by_name.insert("ce1".to_string(), 7);
    bgp.link_index_by_name.insert("ce2".to_string(), 8);
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    let learn = |mac: MacAddr, ifindex| crate::rib::api::FdbEntry {
        vni: 100,
        mac,
        ip: None,
        ifindex,
        bridge_ifindex: 5,
        flags: 0,
        vxlan_local: Some(IpAddr::V4(RID)),
    };
    let leaf_mac = MacAddr::from([2, 0, 0, 0, 0xe1, 1]);
    let root_mac = MacAddr::from([2, 0, 0, 0, 0xe1, 2]);
    let portless_mac = MacAddr::from([2, 0, 0, 0, 0xe1, 3]);
    for entry in [
        learn(leaf_mac, 7),
        learn(root_mac, 8),
        learn(portless_mac, 0),
    ] {
        bgp.local_fdb
            .insert((entry.vni, entry.mac, entry.ip), entry.clone());
        bgp.evpn_originate_macip(&entry);
    }
    assert!(has_etree_leaf(&local_macip_attr(&bgp, leaf_mac)));
    assert!(!has_etree_leaf(&local_macip_attr(&bgp, root_mac)));
    assert!(!has_etree_leaf(&local_macip_attr(&bgp, portless_mac)));
    let seq = extract_mac_mobility_seq(&local_macip_attr(&bgp, leaf_mac));

    // ce1 becomes a root and ce2 a leaf: both MACs are re-advertised.
    bgp.etree_leaf_ifs.clear();
    bgp.etree_leaf_ifs.insert("ce2".to_string());
    bgp.evpn_resync_macip_esi();
    let leaf_now_root = local_macip_attr(&bgp, leaf_mac);
    assert!(!has_etree_leaf(&leaf_now_root));
    assert_eq!(extract_mac_mobility_seq(&leaf_now_root), seq);
    assert!(has_etree_leaf(&local_macip_attr(&bgp, root_mac)));
}

/// A received Type-2 hands its leaf flag to the RIB on the installed
/// route (`MacRoute.flags`), where the cradle tee reads it.
#[tokio::test]
async fn a_received_leaf_mac_reaches_the_rib_flagged() {
    let (mut bgp, mut rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let remote_rd = rd_from_router_id_vni("10.0.0.11".parse().unwrap(), 100).unwrap();
    let mut flags_of = |bgp: &mut Bgp, mac: MacAddr, extra: Option<ExtCommunityValue>| {
        let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
            id: 0,
            rd: remote_rd,
            esi: [0; 10],
            ether_tag: 0,
            mac: mac.octets(),
            ip: None,
            vni: 100,
            label2: None,
        });
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Evpn("10.0.0.11".parse().unwrap()));
        attr.local_pref = Some(LocalPref::default());
        let mut ecom = ExtCommunity::from([evpn_route_target(65000, 100)]);
        ecom.0.extend(extra);
        attr.ecom = Some(ecom);
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
        let mut flags = Vec::new();
        while let Ok(inbound) = rib.try_recv() {
            if let crate::rib::Message::EvpnMacAdd(route) = inbound.msg {
                flags.push(route.flags);
            }
        }
        flags
    };
    let leaf = crate::rib::evpn::MAC_FLAG_ETREE_LEAF;
    let mac = MacAddr::from([2, 0, 0, 0, 0xe2, 1]);
    assert_eq!(
        flags_of(&mut bgp, mac, Some(ExtCommunityValue::etree_leaf())),
        vec![leaf]
    );
    // The same route without the community: the MAC is a root again.
    assert_eq!(flags_of(&mut bgp, mac, None), vec![0]);
    // L clear is no leaf.
    let other = MacAddr::from([2, 0, 0, 0, 0xe2, 2]);
    assert_eq!(
        flags_of(
            &mut bgp,
            other,
            Some(ExtCommunityValue::etree_leaf_label(1000))
        ),
        vec![0]
    );
}

/// A MAC learned on a leaf AC before BGP knew the link (cradle's WatchFdb
/// replay can beat the link dump) went out as a root. The link's arrival
/// re-originates it with the leaf flag.
#[tokio::test]
async fn a_leaf_ac_link_arriving_late_colours_its_macs() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    let mac = MacAddr::from([2, 0, 0, 0, 0xe1, 9]);
    let entry = crate::rib::api::FdbEntry {
        vni: 100,
        mac,
        ip: None,
        ifindex: 7,
        bridge_ifindex: 5,
        flags: 0,
        vxlan_local: Some(IpAddr::V4(RID)),
    };
    bgp.local_fdb
        .insert((entry.vni, entry.mac, entry.ip), entry.clone());
    bgp.evpn_originate_macip(&entry);
    assert!(!has_etree_leaf(&local_macip_attr(&bgp, mac)), "no name yet");

    let link = crate::rib::Link {
        index: 7,
        name: "ce1".to_string(),
        mtu: 1500,
        original_mtu: 1500,
        metric: 1,
        flags: Default::default(),
        link_type: crate::rib::LinkType::Ethernet,
        label: false,
        mac: None,
        addr4: Vec::new(),
        addr6: Vec::new(),
        master: None,
        vni: None,
        vrf_table: None,
        bridge: false,
        vxlan_local: None,
        vxlan_metadata: None,
        parent: None,
        vlan_id: None,
        mtu_error: None,
    };
    bgp.process_rib_msg(RibRx::LinkAdd(link));
    assert!(has_etree_leaf(&local_macip_attr(&bgp, mac)));
}

/// A PE with EVPN over MPLS, a service-label space, and one E-Tree leaf AC
/// (`ce1`, ifindex 7) in EVI 100.
fn etree_mpls_bgp() -> (Bgp, mpsc::UnboundedReceiver<crate::rib::client::RibInbound>) {
    let (mut bgp, rib) = bgp_with_rib();
    bgp.evpn_encap = super::super::inst::EvpnEncap::Mpls;
    bgp.service_labels = super::super::label_chunks::LabelChunks::new(
        crate::rib::label_space::SharedLabelSpace::default(),
        "bgp",
        crate::rib::client::ProtoId::from_raw(0),
    );
    bgp.link_index_by_name.insert("ce1".to_string(), 7);
    bgp.link_name_by_index.insert(7, "ce1".to_string());
    bgp.l2_port_evis.insert(7, BTreeSet::from([100]));
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    (bgp, rib)
}

/// The E-Tree messages BGP sent the RIB, as strings for comparison.
fn etree_messages(rx: &mut mpsc::UnboundedReceiver<crate::rib::client::RibInbound>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(inbound) = rx.try_recv() {
        match inbound.msg {
            crate::rib::Message::EtreeLeafLabel { label } => out.push(format!("label {label}")),
            crate::rib::Message::CradleReplAddMplsLeaf {
                bd,
                pe,
                label,
                leaf_label,
            } => out.push(format!("add {bd} {pe} {label} {leaf_label}")),
            crate::rib::Message::CradleReplDelMplsLeaf { bd, pe } => {
                out.push(format!("del {bd} {pe}"))
            }
            _ => {}
        }
    }
    out
}

/// Our own selected leaf-label route (per-ES A-D, ESI 0), if any.
fn local_leaf_ad(bgp: &Bgp) -> Option<BgpAttr> {
    let rd = rd_from_router_id_vni(RID, 0)?;
    let prefix = EvpnPrefix::EthernetAd {
        esi: ZERO_ESI,
        eth_tag: MAX_ET,
    };
    let rib = bgp.local_rib.evpn.get(&rd)?.selected.get(&prefix)?;
    Some((*rib.attr).clone())
}

/// RFC 8317 §4.2.1: under MPLS, a PE with a leaf AC draws one leaf label,
/// tees it to cradle, and advertises it in a per-ES A-D route with ESI 0
/// carrying the E-Tree EC and the leaf AC's EVI RT. With no leaf AC left,
/// the label goes back and the route is withdrawn.
#[tokio::test]
async fn a_leaf_ac_under_mpls_draws_and_advertises_a_leaf_label() {
    let (mut bgp, mut rib) = etree_mpls_bgp();
    bgp.etree_label_reconcile();
    let label = bgp.etree_leaf_label.expect("a leaf label");
    assert_eq!(etree_messages(&mut rib), vec![format!("label {label}")]);
    let attr = local_leaf_ad(&bgp).expect("the leaf-label route");
    let ecom = attr.ecom.expect("communities");
    assert!(ecom.0.contains(&ExtCommunityValue::etree_leaf_label(label)));
    assert!(ecom.0.contains(&evpn_route_target(bgp.asn, 100)));
    // Idempotent: nothing more to say.
    bgp.etree_label_reconcile();
    assert_eq!(etree_messages(&mut rib), Vec::<String>::new());

    bgp.etree_leaf_ifs.clear();
    bgp.etree_label_reconcile();
    assert_eq!(bgp.etree_leaf_label, None);
    assert_eq!(etree_messages(&mut rib), vec!["label 0".to_string()]);
    assert!(local_leaf_ad(&bgp).is_none(), "withdrawn");
}

/// The leaf label is an MPLS mechanism: under VXLAN no label is drawn and
/// no leaf-label route goes out.
#[tokio::test]
async fn no_leaf_label_outside_mpls() {
    let (mut bgp, mut rib) = etree_mpls_bgp();
    bgp.evpn_encap = super::super::inst::EvpnEncap::Vxlan;
    bgp.etree_label_reconcile();
    assert_eq!(bgp.etree_leaf_label, None);
    assert!(local_leaf_ad(&bgp).is_none());
    assert_eq!(etree_messages(&mut rib), Vec::<String>::new());
}

/// Feed a received EVPN route (or its withdrawal) from `from`.
fn feed_evpn(bgp: &mut Bgp, from: usize, route: EvpnRoute, attr: Option<BgpAttr>) {
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
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    match attr {
        Some(attr) => route_evpn_update(
            from,
            &route,
            "10.0.0.11".parse().unwrap(),
            &attr,
            &mut top,
            &mut bgp.peers,
            false,
        ),
        None => route_evpn_withdraw(from, &route, &mut top, &mut bgp.peers),
    }
}

/// A remote PE's leaf-label route (RFC 8317 §4.2.1) with `label`.
fn leaf_ad_route(pe: &str, label: u32) -> (EvpnRoute, BgpAttr) {
    let rd = rd_from_router_id_vni(pe.parse().unwrap(), 0).unwrap();
    let route = EvpnRoute::EthernetAd(bgp_packet::EvpnEthernetAd {
        id: 0,
        rd,
        esi: ZERO_ESI,
        ether_tag: MAX_ET,
        label: 0,
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn(pe.parse().unwrap()));
    attr.local_pref = Some(LocalPref::default());
    attr.ecom = Some(ExtCommunity::from([
        evpn_route_target(65000, 100),
        ExtCommunityValue::etree_leaf_label(label),
    ]));
    (route, attr)
}

/// A remote PE's MPLS IMET for VNI 100 with BUM `label`.
fn mpls_imet_route(pe: &str, label: u32) -> (EvpnRoute, BgpAttr) {
    let rd = rd_from_router_id_vni(pe.parse().unwrap(), 100).unwrap();
    let route = EvpnRoute::Multicast(bgp_packet::EvpnMulticast {
        id: 0,
        rd,
        ether_tag: 0,
        addr: pe.parse().unwrap(),
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn(pe.parse().unwrap()));
    attr.local_pref = Some(LocalPref::default());
    attr.ecom = Some(ExtCommunity::from([evpn_route_target(65000, 100)]));
    attr.pmsi_tunnel = Some(bgp_packet::PmsiTunnel {
        flags: 0,
        tunnel_type: bgp_packet::PmsiTunnel::TUNNEL_INGRESS_REPLICATION,
        vni: label,
        endpoint: pe.parse().unwrap(),
        tree_id: None,
    });
    (route, attr)
}

/// A remote PE's leaf label and BUM label make a leaf slot toward it in
/// each EVI with a local leaf AC; the leaf-label route gone takes the slot
/// with it. A reserved leaf label makes none.
#[tokio::test]
async fn a_remote_leaf_label_makes_a_leaf_slot() {
    let (mut bgp, mut rib) = etree_mpls_bgp();
    bgp.etree_label_reconcile();
    etree_messages(&mut rib);
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let pe = "10.0.0.11";

    let (imet, imet_attr) = mpls_imet_route(pe, 2200);
    feed_evpn(&mut bgp, from, imet, Some(imet_attr));
    let (ad, ad_attr) = leaf_ad_route(pe, 2800);
    feed_evpn(&mut bgp, from, ad.clone(), Some(ad_attr));
    bgp.vpws_df_drain();
    assert_eq!(
        etree_messages(&mut rib),
        vec![format!("add 100 {pe} 2200 2800")]
    );
    assert_eq!(
        bgp.etree_peer_leaf_labels(),
        BTreeMap::from([(pe.parse().unwrap(), 2800)])
    );

    feed_evpn(&mut bgp, from, ad, None);
    bgp.vpws_df_drain();
    assert_eq!(etree_messages(&mut rib), vec![format!("del 100 {pe}")]);

    let (ad, ad_attr) = leaf_ad_route(pe, 15);
    feed_evpn(&mut bgp, from, ad, Some(ad_attr));
    bgp.vpws_df_drain();
    assert_eq!(
        etree_messages(&mut rib),
        Vec::<String>::new(),
        "reserved label"
    );
}

/// A leaf label drawn before the cradle tee existed never reached it: when
/// a tee comes up (`RibRx::CradleUp`) the label and the leaf slots are sent
/// again.
#[tokio::test]
async fn a_new_tee_gets_the_leaf_label_again() {
    let (mut bgp, mut rib) = etree_mpls_bgp();
    bgp.etree_label_reconcile();
    let label = bgp.etree_leaf_label.expect("a leaf label");
    assert_eq!(etree_messages(&mut rib), vec![format!("label {label}")]);
    bgp.process_rib_msg(RibRx::CradleUp);
    assert_eq!(etree_messages(&mut rib), vec![format!("label {label}")]);
}

/// An eBGP spine that sends our own Type-2 back is loop-rejected, and the
/// withdraw re-selects our originated path. That path must not be
/// installed (it would point our local MAC at our own VTEP), nor its
/// sequence number taken for a remote one.
#[tokio::test]
async fn looped_own_macip_is_not_installed() {
    let (mut bgp, mut rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, _rx) = peer(&mut bgp, "10.1.1.1", true);
    let mac = MacAddr::from([2, 0, 0, 0, 1, 1]);
    // A move was seen before: our route carries sequence number 5.
    bgp.local_rib.evpn_remote_mac_seq.insert((100, mac), 4);
    let local = crate::rib::api::FdbEntry {
        vni: 100,
        mac,
        ip: None,
        ifindex: 7,
        bridge_ifindex: 5,
        flags: 0,
        vxlan_local: Some(IpAddr::V4(RID)),
    };
    bgp.evpn_originate_macip(&local);
    mac_messages(&mut rib);

    let own_rd = rd_from_router_id_vni(RID, 100).unwrap();
    withdraw_macip(&mut bgp, from, own_rd, mac, None);
    assert_eq!(mac_messages(&mut rib), vec![]);
    assert_eq!(bgp.local_rib.evpn_remote_mac_seq[&(100, mac)], 4);
}

/// The same for our own Type-3: our VTEP must not join our flood list.
#[tokio::test]
async fn looped_own_imet_does_not_flood_to_ourselves() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, _rx) = peer(&mut bgp, "10.1.1.1", true);
    bgp.evpn_originate_imet(100, IpAddr::V4(RID));

    let route = EvpnRoute::Multicast(EvpnMulticast {
        id: 0,
        rd: rd_from_router_id_vni(RID, 100).unwrap(),
        ether_tag: 0,
        addr: IpAddr::V4(RID),
    });
    feed_evpn(&mut bgp, from, route, None);
    assert!(bgp.local_rib.evpn_flood.remote_vteps(100).is_empty());
}

/// A link as the RIB announces it; `vni` makes it a VXLAN device.
fn rib_link(index: u32, name: &str, vni: Option<u32>) -> crate::rib::Link {
    crate::rib::Link {
        index,
        name: name.to_string(),
        mtu: 1500,
        original_mtu: 1500,
        metric: 1,
        flags: Default::default(),
        link_type: crate::rib::LinkType::Ethernet,
        label: false,
        mac: None,
        addr4: Vec::new(),
        addr6: Vec::new(),
        master: Some(5),
        vni,
        vrf_table: None,
        bridge: false,
        vxlan_local: None,
        vxlan_metadata: None,
        parent: None,
        vlan_id: None,
        mtu_error: None,
    }
}

/// A PE with EVPN over VXLAN advertising VNI 100 from VTEP `RID`, whose
/// bridge holds `vxlan100` (ifindex 9), the E-Tree leaf AC `ce1` (7) and
/// the root AC `ce2` (8).
fn etree_vxlan_bgp() -> (Bgp, mpsc::UnboundedReceiver<crate::rib::client::RibInbound>) {
    let (mut bgp, rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    for (index, name, vni) in [
        (9, "vxlan100", Some(100)),
        (7, "ce1", None),
        (8, "ce2", None),
    ] {
        bgp.process_rib_msg(RibRx::LinkAdd(rib_link(index, name, vni)));
        bgp.process_rib_msg(RibRx::L2PortEvis {
            ifindex: index,
            vnis: BTreeSet::from([100]),
        });
    }
    bgp.process_rib_msg(RibRx::VxlanAdd {
        vni: 100,
        vtep_local: IpAddr::V4(RID),
    });
    (bgp, rib)
}

/// Our own selected IMET for VNI 100.
fn local_imet(bgp: &Bgp) -> BgpAttr {
    let rd = rd_from_router_id_vni(RID, 100).unwrap();
    let prefix = EvpnPrefix::InclusiveMulticast {
        eth_tag: 0,
        orig: IpAddr::V4(RID),
    };
    (*bgp.local_rib.evpn[&rd].selected[&prefix].attr).clone()
}

/// The V1+ scheme (plan §8.5): a VNI whose ACs here are all leaves has its
/// IMET coloured with the Leaf flag. A root AC in it, or none of the ACs a
/// leaf, leaves it uncoloured; the VXLAN device is no AC. Not under MPLS.
#[tokio::test]
async fn a_vni_with_leaf_acs_only_colours_its_imet() {
    let (mut bgp, _rib) = etree_vxlan_bgp();
    assert!(!has_etree_leaf(&local_imet(&bgp)), "ce2 is a root");
    assert_eq!(bgp.etree_mixed_pes(), BTreeMap::new(), "one mixed PE");

    // ce2 leaves the bridge: ce1 is the only AC, and the VXLAN device is
    // not one.
    bgp.process_rib_msg(RibRx::L2PortEvis {
        ifindex: 8,
        vnis: BTreeSet::new(),
    });
    assert!(has_etree_leaf(&local_imet(&bgp)));
    assert_eq!(bgp.etree_leaf_only_vnis(), BTreeSet::from([100]));

    // It comes back: a root again.
    bgp.process_rib_msg(RibRx::L2PortEvis {
        ifindex: 8,
        vnis: BTreeSet::from([100]),
    });
    assert!(!has_etree_leaf(&local_imet(&bgp)));

    // ce2 deleted: leaves only.
    bgp.process_rib_msg(RibRx::LinkDel(8));
    assert!(has_etree_leaf(&local_imet(&bgp)));

    // ce1 a root: no leaf AC at all.
    bgp.etree_leaf_ifs.clear();
    bgp.etree_label_reconcile();
    assert!(!has_etree_leaf(&local_imet(&bgp)));

    // The leaf flag is a VXLAN signal: MPLS has the leaf label.
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    bgp.evpn_encap = super::super::inst::EvpnEncap::Mpls;
    bgp.etree_label_reconcile();
    assert_eq!(bgp.etree_leaf_only_vnis(), BTreeSet::new());
}

/// A remote PE's VXLAN IMET for VNI 100, coloured leaf-only or not, or in
/// the rfc8317bis form (a leaf VNI in the field).
fn vxlan_imet_route(pe: &str, etree: Option<ExtCommunityValue>) -> (EvpnRoute, BgpAttr) {
    let rd = rd_from_router_id_vni(pe.parse().unwrap(), 100).unwrap();
    let route = EvpnRoute::Multicast(bgp_packet::EvpnMulticast {
        id: 0,
        rd,
        ether_tag: 0,
        addr: pe.parse().unwrap(),
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn(pe.parse().unwrap()));
    attr.local_pref = Some(LocalPref::default());
    let mut ecom = ExtCommunity::from([evpn_route_target(65000, 100), evpn_encap_vxlan()]);
    ecom.0.extend(etree);
    attr.ecom = Some(ecom);
    attr.pmsi_tunnel = Some(bgp_packet::PmsiTunnel {
        flags: 0,
        tunnel_type: bgp_packet::PmsiTunnel::TUNNEL_INGRESS_REPLICATION,
        vni: 100,
        endpoint: pe.parse().unwrap(),
        tree_id: None,
    });
    (route, attr)
}

/// The `SetEtreeRemote` tees BGP sent the RIB.
fn etree_remote_messages(
    rx: &mut mpsc::UnboundedReceiver<crate::rib::client::RibInbound>,
) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(inbound) = rx.try_recv() {
        if let crate::rib::Message::CradleEtreeRemote {
            bd,
            remote,
            leaf_only,
        } = inbound.msg
        {
            out.push(format!("{bd} {remote} {leaf_only}"));
        }
    }
    out
}

/// A remote PE's leaf-only IMET marks it for cradle (`SetEtreeRemote`);
/// the colour gone, or the IMET withdrawn, clears the mark. The
/// rfc8317bis form is not a mark, and nothing is teed without a local leaf
/// AC. A new tee gets the marks again.
#[tokio::test]
async fn a_leaf_only_imet_marks_its_pe() {
    let (mut bgp, mut rib) = etree_vxlan_bgp();
    etree_remote_messages(&mut rib);
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let pe = "10.0.0.11";

    let (imet, attr) = vxlan_imet_route(pe, Some(ExtCommunityValue::etree_leaf()));
    feed_evpn(&mut bgp, from, imet.clone(), Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(
        etree_remote_messages(&mut rib),
        vec![format!("100 {pe} true")]
    );

    bgp.process_rib_msg(RibRx::CradleUp);
    assert_eq!(
        etree_remote_messages(&mut rib),
        vec![format!("100 {pe} true")]
    );

    let (_, attr) = vxlan_imet_route(pe, None);
    feed_evpn(&mut bgp, from, imet.clone(), Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(
        etree_remote_messages(&mut rib),
        vec![format!("100 {pe} false")]
    );

    let bis = bgp_packet::EtreeEc {
        flags: bgp_packet::EtreeEc::LEAF,
        field: 5100,
    };
    let (_, attr) = vxlan_imet_route(pe, Some(bis.into()));
    feed_evpn(&mut bgp, from, imet.clone(), Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(etree_remote_messages(&mut rib), Vec::<String>::new());

    let (_, attr) = vxlan_imet_route(pe, Some(ExtCommunityValue::etree_leaf()));
    feed_evpn(&mut bgp, from, imet.clone(), Some(attr));
    bgp.vpws_df_drain();
    etree_remote_messages(&mut rib);
    feed_evpn(&mut bgp, from, imet.clone(), None);
    bgp.vpws_df_drain();
    assert_eq!(
        etree_remote_messages(&mut rib),
        vec![format!("100 {pe} false")]
    );

    // No leaf AC here: no marks.
    bgp.etree_leaf_ifs.clear();
    bgp.etree_label_reconcile();
    let (_, attr) = vxlan_imet_route(pe, Some(ExtCommunityValue::etree_leaf()));
    feed_evpn(&mut bgp, from, imet, Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(etree_remote_messages(&mut rib), Vec::<String>::new());
}

/// A remote PE with a leaf MAC and no leaf-only IMET is mixed; with this
/// PE mixed too, VNI 100's leaf BUM is not isolated between them. A
/// leaf-only IMET from that PE takes it off the list.
#[tokio::test]
async fn two_mixed_pes_are_reported() {
    let (mut bgp, _rib) = etree_vxlan_bgp();
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let pe: IpAddr = "10.0.0.11".parse().unwrap();
    let rd = rd_from_router_id_vni(Ipv4Addr::new(10, 0, 0, 11), 100).unwrap();
    let mac = EvpnRoute::Mac(bgp_packet::EvpnMac {
        id: 0,
        rd,
        esi: [0; 10],
        ether_tag: 0,
        mac: [2, 0, 0, 0, 0xe2, 1],
        ip: None,
        vni: 100,
        label2: None,
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn(pe));
    attr.local_pref = Some(LocalPref::default());
    attr.ecom = Some(ExtCommunity::from([
        evpn_route_target(65000, 100),
        evpn_encap_vxlan(),
        ExtCommunityValue::etree_leaf(),
    ]));
    feed_evpn(&mut bgp, from, mac, Some(attr));
    let (imet, attr) = vxlan_imet_route("10.0.0.11", None);
    feed_evpn(&mut bgp, from, imet.clone(), Some(attr));
    assert_eq!(
        bgp.etree_mixed_pes(),
        BTreeMap::from([(100, vec![None, Some(pe)])])
    );
    let show = |bgp: &Bgp, json| {
        super::super::show::show_bgp_evpn_etree(
            bgp,
            crate::config::Args(std::collections::VecDeque::new()),
            json,
        )
        .unwrap()
    };
    assert!(
        show(&bgp, false).contains(
            "Warning: EVI 100: leaf BUM not isolated between mixed PEs: local, 10.0.0.11"
        )
    );

    let (_, attr) = vxlan_imet_route("10.0.0.11", Some(ExtCommunityValue::etree_leaf()));
    feed_evpn(&mut bgp, from, imet, Some(attr));
    assert_eq!(bgp.etree_mixed_pes(), BTreeMap::new());
    let text = show(&bgp, false);
    assert!(!text.contains("Warning"));
    assert!(text.contains("Remote leaf-only PEs:\n    EVI 100        10.0.0.11\n"));
    let json: serde_json::Value = serde_json::from_str(&show(&bgp, true)).unwrap();
    assert_eq!(json["remoteLeafOnly"][0]["pes"][0], "10.0.0.11");
    assert_eq!(json["bumFiltered"], true);
}

/// A host on our access port, MAC `mac` in VNI 100.
fn local_fdb(mac: MacAddr) -> crate::rib::api::FdbEntry {
    crate::rib::api::FdbEntry {
        vni: 100,
        mac,
        ip: None,
        ifindex: 7,
        bridge_ifindex: 5,
        flags: 0,
        vxlan_local: Some(IpAddr::V4(RID)),
    }
}

/// Our own MAC/IP route for `mac` in VNI 100 as a spine sends it back from
/// `from`, with next hop `nexthop`, past the AS_PATH check (`allowas-in`).
fn echo_own_macip(bgp: &mut Bgp, from: usize, mac: MacAddr, nexthop: IpAddr) -> EvpnPrefix {
    let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
        id: 0,
        rd: rd_from_router_id_vni(RID, 100).unwrap(),
        esi: [0; 10],
        ether_tag: 0,
        mac: mac.octets(),
        ip: None,
        vni: 100,
        label2: None,
    });
    let mut attr = BgpAttr::new();
    attr.nexthop = Some(BgpNexthop::Evpn(nexthop));
    attr.local_pref = Some(LocalPref::default());
    attr.ecom = Some(ExtCommunity::from([evpn_route_target(65000, 100)]));
    let (_, prefix) = EvpnPrefix::from_route(&route);
    feed_evpn(bgp, from, route, Some(attr));
    prefix
}

/// How many received (not originated) paths our own VNI-100 RD holds for
/// `prefix`.
fn received_in_own_rd(bgp: &Bgp, prefix: &EvpnPrefix) -> usize {
    let rd = rd_from_router_id_vni(RID, 100).unwrap();
    bgp.local_rib
        .evpn
        .get(&rd)
        .and_then(|table| table.cands.get(prefix))
        .map_or(0, |cands| {
            cands.iter().filter(|rib| !rib.is_originated()).count()
        })
}

/// With `allowas-in`, our own Type-2 sent back by a spine passes the AS_PATH
/// check. Its next hop is our VTEP, so it is dropped on receipt: when our
/// host leaves, nothing installs its MAC toward ourselves.
#[tokio::test]
async fn an_echo_past_the_loop_check_is_never_installed() {
    let (mut bgp, mut rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.process_rib_msg(RibRx::VxlanAdd {
        vni: 100,
        vtep_local: IpAddr::V4(RID),
    });
    let (from, _rx) = peer(&mut bgp, "10.1.1.1", true);
    let mac = MacAddr::from([2, 0, 0, 0, 1, 1]);
    let local = local_fdb(mac);
    bgp.evpn_originate_macip(&local);
    let prefix = echo_own_macip(&mut bgp, from, mac, IpAddr::V4(RID));
    assert_eq!(received_in_own_rd(&bgp, &prefix), 0);

    mac_messages(&mut rib);
    bgp.evpn_withdraw_macip(&local);
    assert_eq!(mac_messages(&mut rib), vec![]);
}

/// The same for an echo naming our end of the session, where egress
/// re-points an originated route with no VTEP. A remote PE's route on that
/// session is still taken.
#[tokio::test]
async fn an_echo_naming_our_session_address_is_dropped() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, _rx) = peer(&mut bgp, "10.1.1.1", true);
    let mac = MacAddr::from([2, 0, 0, 0, 1, 1]);
    bgp.evpn_originate_macip(&local_fdb(mac));
    let prefix = echo_own_macip(&mut bgp, from, mac, IpAddr::V4(LINK));
    assert_eq!(received_in_own_rd(&bgp, &prefix), 0);

    let remote_rd = rd_from_router_id_vni("10.0.0.11".parse().unwrap(), 100).unwrap();
    receive_macip(&mut bgp, from, remote_rd, mac, None, 1);
    assert!(
        bgp.local_rib
            .evpn
            .get(&remote_rd)
            .is_some_and(|table| !table.selected.is_empty())
    );
}

/// A looped UPDATE for our own route removes nothing, so it sends nothing:
/// not to the spine that looped it, nor to any other peer.
#[tokio::test]
async fn a_looped_update_sends_peers_nothing() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    let (from, mut rx) = peer(&mut bgp, "10.1.1.1", true);
    let (other, mut other_rx) = peer(&mut bgp, "10.1.1.2", true);
    let mac = MacAddr::from([2, 0, 0, 0, 1, 1]);
    bgp.evpn_originate_macip(&local_fdb(mac));
    assert_eq!(sent(&mut bgp, from, &mut rx).len(), 1);
    assert_eq!(sent(&mut bgp, other, &mut other_rx).len(), 1);

    let own_rd = rd_from_router_id_vni(RID, 100).unwrap();
    withdraw_macip(&mut bgp, from, own_rd, mac, None);
    assert_eq!(sent(&mut bgp, from, &mut rx), vec![]);
    assert_eq!(sent(&mut bgp, other, &mut other_rx), vec![]);
}

/// Export `rib` as the selection for `prefix` under `rd`.
fn export_selected(bgp: &mut Bgp, rd: &RouteDistinguisher, prefix: &EvpnPrefix, rib: BgpRib) {
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
        as_sets_withdraw: bgp.as_sets_withdraw,
    };
    route_evpn_export_selected(rd, prefix, &[rib], None, &mut top);
}

/// Our own path selected is never a remote binding: a Type-2 sends the RIB
/// nothing, a Type-3 leaves our VTEP out of the flood list. A looped UPDATE
/// no longer gets this far (`a_looped_update_sends_peers_nothing`); a
/// re-selection such as `bestpath_recompute_untracked` does.
#[tokio::test]
async fn our_own_selected_path_is_not_installed() {
    let (mut bgp, mut rib) = bgp_with_rib();
    let rd = rd_from_router_id_vni(RID, 100).unwrap();
    let own = macip_path(0, false, [0; 10], "192.0.2.1", true);

    let mac = EvpnPrefix::MacIp {
        eth_tag: 0,
        mac: [2, 0, 0, 0, 1, 1],
        ip: None,
    };
    export_selected(&mut bgp, &rd, &mac, own.clone());
    assert_eq!(mac_messages(&mut rib), vec![]);

    let imet = EvpnPrefix::InclusiveMulticast {
        eth_tag: 0,
        orig: IpAddr::V4(RID),
    };
    export_selected(&mut bgp, &rd, &imet, own);
    assert!(bgp.local_rib.evpn_flood.remote_vteps(100).is_empty());
}

/// A leaf-only VXLAN IMET's mark reaches the RIB before the flood entry
/// the same IMET creates: cradle then makes the slot toward that PE
/// root-only from the start, and no local leaf's BUM reaches it meanwhile.
#[tokio::test]
async fn a_leaf_only_mark_precedes_its_flood_slot() {
    let (mut bgp, mut rib) = etree_vxlan_bgp();
    while rib.try_recv().is_ok() {}
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let (imet, attr) = vxlan_imet_route("10.0.0.11", Some(ExtCommunityValue::etree_leaf()));
    feed_evpn(&mut bgp, from, imet, Some(attr));
    let mut order = Vec::new();
    while let Ok(inbound) = rib.try_recv() {
        match inbound.msg {
            crate::rib::Message::CradleEtreeRemote { .. } => order.push("mark"),
            crate::rib::Message::MdbAdd { .. } => order.push("flood"),
            _ => {}
        }
    }
    assert_eq!(order, vec!["mark", "flood"]);
}

/// Whether an UPDATE carrying `route` with `attr` fits `max` bytes.
fn evpn_update_fits(route: EvpnRoute, attr: BgpAttr, max: usize) -> bool {
    let mut update = bgp_packet::UpdatePacket::with_max_packet_size(max);
    update.bgp_attr = Some(attr);
    update.mp_update = Some(bgp_packet::MpReachAttr::Evpn {
        snpa: 0,
        nhop: IpAddr::V4(RID),
        updates: vec![route],
    });
    update.pop_evpn().is_some()
}

/// Our selected leaf-label route under RD `<router-id>:i`, if any.
fn local_leaf_ad_at(bgp: &Bgp, i: u32) -> Option<BgpAttr> {
    let rd = rd_from_router_id_vni(RID, i)?;
    let prefix = EvpnPrefix::EthernetAd {
        esi: ZERO_ESI,
        eth_tag: MAX_ET,
    };
    let rib = bgp.local_rib.evpn.get(&rd)?.selected.get(&prefix)?;
    Some((*rib.attr).clone())
}

/// RFC 7432 §8.2.1 / RFC 8317 §4.2.1: with more leaf EVIs than one UPDATE
/// holds, the RTs are split over several leaf-label routes, each under its
/// own RD and each fitting a 4096-byte UPDATE (no Extended Message, RFC
/// 8654). Fewer EVIs withdraw the routes no longer needed.
#[tokio::test]
async fn many_leaf_evis_split_the_leaf_label_route() {
    let (mut bgp, _rib) = etree_mpls_bgp();
    bgp.l2_port_evis.insert(7, (1..=600).collect());
    bgp.etree_label_reconcile();
    let label = bgp.etree_leaf_label.expect("a leaf label");
    let route = |i: u32| {
        EvpnRoute::EthernetAd(bgp_packet::EvpnEthernetAd {
            id: 0,
            rd: rd_from_router_id_vni(RID, i).unwrap(),
            esi: ZERO_ESI,
            ether_tag: MAX_ET,
            label: 0,
        })
    };

    let mut rts = 0;
    for i in 0..3 {
        let attr = local_leaf_ad_at(&bgp, i).expect("a leaf-label route");
        let ecom = attr.ecom.as_ref().unwrap();
        assert!(ecom.0.contains(&ExtCommunityValue::etree_leaf_label(label)));
        // Every community but the E-Tree EC is an EVI's RT.
        rts += ecom.0.len() - 1;
        assert!(
            evpn_update_fits(route(i), attr, 4096),
            "route {i} fits 4096 bytes"
        );
    }
    assert_eq!(rts, 600, "every leaf EVI's RT, once");
    assert!(local_leaf_ad_at(&bgp, 3).is_none());

    // The control: the old single route with all 600 RTs does not fit.
    let mut all = local_leaf_ad_at(&bgp, 0).unwrap();
    let ecom = all.ecom.as_mut().unwrap();
    for evi in 1..=600 {
        ecom.0.insert(evpn_route_target(bgp.asn, evi));
    }
    assert!(!evpn_update_fits(route(0), all, 4096));

    // Down to 100 leaf EVIs: one route left.
    bgp.l2_port_evis.insert(7, (1..=100).collect());
    bgp.etree_label_reconcile();
    assert!(local_leaf_ad_at(&bgp, 0).is_some());
    assert!(local_leaf_ad_at(&bgp, 1).is_none(), "withdrawn");
    assert!(local_leaf_ad_at(&bgp, 2).is_none(), "withdrawn");
}

/// A PE with EVPN over SRv6 (uSID locator `fd00:1::/48`: LBL 32, LNL 16,
/// FL 16), advertising VNI 100 from VTEP `RID`, whose bridge holds
/// `vxlan100` (9) and the E-Tree leaf AC `ce1` (7).
fn etree_srv6_bgp() -> (Bgp, mpsc::UnboundedReceiver<crate::rib::client::RibInbound>) {
    let (mut bgp, rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.evpn_encap = super::super::inst::EvpnEncap::Srv6;
    bgp.srv6_locator = Some(crate::rib::Locator {
        prefix: Some("fd00:1::/48".parse().unwrap()),
        behavior: Some(crate::rib::LocatorBehavior::Usid),
        ..Default::default()
    });
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    for (index, name, vni) in [(9, "vxlan100", Some(100)), (7, "ce1", None)] {
        bgp.process_rib_msg(RibRx::LinkAdd(rib_link(index, name, vni)));
        bgp.process_rib_msg(RibRx::L2PortEvis {
            ifindex: index,
            vnis: BTreeSet::from([100]),
        });
    }
    bgp.process_rib_msg(RibRx::VxlanAdd {
        vni: 100,
        vtep_local: IpAddr::V4(RID),
    });
    (bgp, rib)
}

/// The E-Tree-over-SRv6 messages BGP sent the RIB, as strings.
fn etree_srv6_messages(
    rx: &mut mpsc::UnboundedReceiver<crate::rib::client::RibInbound>,
) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(inbound) = rx.try_recv() {
        match inbound.msg {
            crate::rib::Message::EtreeLeafArg { arg } => out.push(format!("arg {arg}")),
            crate::rib::Message::SidAdd { sid }
                if sid.behavior == crate::rib::SidBehavior::EndDT2M =>
            {
                let al = sid.structure.map_or(0, |s| s.arg_bits);
                out.push(format!("dt2m {} al {al}", sid.addr));
            }
            crate::rib::Message::SidDel { addr } => out.push(format!("sid del {addr}")),
            crate::rib::Message::CradleReplAddSrv6Leaf { bd, sid, leaf_sid } => {
                out.push(format!("add {bd} {sid} {leaf_sid}"))
            }
            crate::rib::Message::CradleReplDelSrv6Leaf { bd, sid } => {
                out.push(format!("del {bd} {sid}"))
            }
            _ => {}
        }
    }
    out
}

/// The End.DT2M SID structure on an attribute, as (SID, AL).
fn dt2m_of(attr: &BgpAttr) -> Option<(std::net::Ipv6Addr, u8)> {
    evpn_srv6_sid_info(attr, bgp_packet::SRV6_BEHAVIOR_END_DT2M)
        .map(|(sid, st)| (sid, st.map_or(0, |st| st.argument_len)))
}

#[test]
fn sid_arguments_are_placed_after_the_function() {
    let sid: std::net::Ipv6Addr = "fd00:2:0:200::".parse().unwrap();
    let leaf = sid_place_arg(sid, 64, 16, 1).unwrap();
    assert_eq!(
        leaf,
        "fd00:2:0:200:1::".parse::<std::net::Ipv6Addr>().unwrap()
    );
    assert_eq!(sid_read_arg(leaf, 64, 16), Some(1));
    assert_eq!(sid_read_arg(leaf, 48, 16), Some(0x200), "the function");
    assert_eq!(sid_place_arg(sid, 120, 16, 1), None, "past the address");
    assert_eq!(sid_place_arg(sid, 64, 8, 0x100), None, "wider than 8 bits");
}

/// Plan §8.6 (D6): under SRv6 a PE with a leaf AC has leaf argument 1. It
/// is teed for decap; the leaf VNI's End.DT2M is installed with a 16-bit
/// argument and its IMET advertises the argument length; the leaf-label
/// route carries the E-Tree EC with no field and an End.DT2M SID with the
/// argument at LBL+LNL+FL. Without a leaf AC all of it goes, and the
/// End.DT2M is installed plain again.
#[tokio::test]
async fn an_srv6_leaf_ac_gets_a_leaf_argument() {
    let (mut bgp, mut rib) = etree_srv6_bgp();
    assert_eq!(bgp.etree_leaf_arg, Some(1));
    let msgs = etree_srv6_messages(&mut rib);
    assert!(msgs.contains(&"arg 1".to_string()), "{msgs:?}");
    let dt2m = bgp.evpn_dt2m_sids[&100].0;
    assert!(msgs.contains(&format!("dt2m {dt2m} al 16")), "{msgs:?}");
    assert_eq!(dt2m_of(&local_imet(&bgp)), Some((dt2m, 16)));

    let ad = local_leaf_ad(&bgp).expect("the leaf-label route");
    let ecom = ad.ecom.as_ref().unwrap();
    assert!(ecom.0.contains(&ExtCommunityValue::etree_leaf_label(0)));
    assert!(ecom.0.contains(&evpn_route_target(bgp.asn, 100)));
    assert_eq!(
        dt2m_of(&ad),
        Some(("::1:0:0:0".parse().unwrap(), 16)),
        "the argument at offset 64"
    );

    bgp.etree_leaf_ifs.clear();
    bgp.etree_label_reconcile();
    assert_eq!(bgp.etree_leaf_arg, None);
    let msgs = etree_srv6_messages(&mut rib);
    assert!(msgs.contains(&"arg 0".to_string()), "{msgs:?}");
    assert!(msgs.contains(&format!("sid del {dt2m}")), "{msgs:?}");
    assert!(msgs.contains(&format!("dt2m {dt2m} al 0")), "{msgs:?}");
    assert_eq!(dt2m_of(&local_imet(&bgp)), Some((dt2m, 0)));
    assert!(local_leaf_ad(&bgp).is_none(), "withdrawn");
}

/// A remote PE's SRv6 IMET for VNI 100 with End.DT2M `sid` and argument
/// length `al`.
fn srv6_imet_route(pe: &str, sid: &str, al: u8) -> (EvpnRoute, BgpAttr) {
    let (route, mut attr) = vxlan_imet_route(pe, None);
    attr.prefix_sid = Some(super::super::inst::srv6_l2_service_prefix_sid(
        sid.parse().unwrap(),
        Some(crate::rib::SidStructure {
            lb_bits: 32,
            ln_bits: 16,
            fun_bits: 16,
            arg_bits: al,
        }),
        bgp_packet::SRV6_BEHAVIOR_END_DT2M,
    ));
    (route, attr)
}

/// A remote PE's SRv6 leaf-label route with leaf argument `arg` (16 bits
/// at offset 64).
fn srv6_leaf_ad_route(pe: &str, arg: u32) -> (EvpnRoute, BgpAttr) {
    let (route, mut attr) = leaf_ad_route(pe, 0);
    attr.ecom = Some(ExtCommunity::from([
        evpn_route_target(65000, 100),
        ExtCommunityValue::etree_leaf_label(0),
    ]));
    attr.prefix_sid = Some(super::super::inst::srv6_l2_service_prefix_sid(
        sid_place_arg(std::net::Ipv6Addr::UNSPECIFIED, 64, 16, arg).unwrap(),
        Some(crate::rib::SidStructure {
            lb_bits: 32,
            ln_bits: 16,
            fun_bits: 16,
            arg_bits: 16,
        }),
        bgp_packet::SRV6_BEHAVIOR_END_DT2M,
    ));
    (route, attr)
}

/// A remote PE's leaf argument and End.DT2M SID make a leaf slot toward it
/// whose SID carries the argument (RFC 9819 §3.3). An IMET without the
/// argument length makes none (§3.2); the leaf-label route gone takes the
/// slot with it.
#[tokio::test]
async fn a_remote_leaf_argument_makes_an_srv6_leaf_slot() {
    let (mut bgp, mut rib) = etree_srv6_bgp();
    etree_srv6_messages(&mut rib);
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let pe = "10.0.0.11";
    let (ad, ad_attr) = srv6_leaf_ad_route(pe, 1);
    feed_evpn(&mut bgp, from, ad.clone(), Some(ad_attr));

    // The IMET says no argument: no leaf slot.
    let (imet, attr) = srv6_imet_route(pe, "fd00:2:0:200::", 0);
    feed_evpn(&mut bgp, from, imet.clone(), Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(etree_srv6_messages(&mut rib), Vec::<String>::new());

    let (_, attr) = srv6_imet_route(pe, "fd00:2:0:200::", 16);
    feed_evpn(&mut bgp, from, imet, Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(
        etree_srv6_messages(&mut rib),
        vec!["add 100 fd00:2:0:200:: fd00:2:0:200:1::".to_string()]
    );

    feed_evpn(&mut bgp, from, ad, None);
    bgp.vpws_df_drain();
    assert_eq!(
        etree_srv6_messages(&mut rib),
        vec!["del 100 fd00:2:0:200::".to_string()]
    );
}

/// `show bgp evpn etree` under SRv6 names this PE's leaf argument and each
/// remote PE's; a new cradle tee gets the argument again.
#[tokio::test]
async fn srv6_leaf_arguments_show_and_replay() {
    let (mut bgp, mut rib) = etree_srv6_bgp();
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let (ad, ad_attr) = srv6_leaf_ad_route("10.0.0.11", 7);
    feed_evpn(&mut bgp, from, ad, Some(ad_attr));
    let text = super::super::show::show_bgp_evpn_etree(
        &bgp,
        crate::config::Args(std::collections::VecDeque::new()),
        false,
    )
    .unwrap();
    assert!(text.contains("Leaf argument:   1\n"), "{text}");
    assert!(text.contains("10.0.0.11        7 (16 bits)"), "{text}");

    etree_srv6_messages(&mut rib);
    bgp.process_rib_msg(RibRx::CradleUp);
    assert!(etree_srv6_messages(&mut rib).contains(&"arg 1".to_string()));
}

/// Decision D4: a leaf AC's bridge with IRB — a routable address, or a VRF
/// master — is warned about in `show bgp evpn etree`, not refused: two
/// leaves reach each other through L3 there (RFC 8317 §4.2.3). A
/// link-local address alone is no gateway.
#[tokio::test]
async fn irb_on_a_leaf_bridge_is_warned_about() {
    let (mut bgp, _rib) = etree_vxlan_bgp();
    let mut bridge = rib_link(5, "br100", None);
    bridge.master = None;
    bridge.bridge = true;
    bgp.process_rib_msg(RibRx::LinkAdd(bridge.clone()));
    let show = |bgp: &Bgp| {
        super::super::show::show_bgp_evpn_etree(
            bgp,
            crate::config::Args(std::collections::VecDeque::new()),
            false,
        )
        .unwrap()
    };
    let addr = |a: &str| crate::rib::link::LinkAddr {
        addr: a.parse().unwrap(),
        ifindex: 5,
        ..Default::default()
    };
    assert!(bgp.etree_irb_evis().is_empty());
    assert!(!show(&bgp).contains("IRB"));

    bgp.process_rib_msg(RibRx::AddrAdd(addr("fe80::1/64")));
    assert!(
        bgp.etree_irb_evis().is_empty(),
        "a link-local is no gateway"
    );

    bgp.process_rib_msg(RibRx::AddrAdd(addr("10.0.0.1/24")));
    assert_eq!(
        bgp.etree_irb_evis(),
        BTreeMap::from([(100, "br100".to_string())])
    );
    assert!(
        show(&bgp).contains(
            "Warning: EVI 100: IRB on bridge br100: leaves can reach each other through L3"
        ),
        "{}",
        show(&bgp)
    );
    let json: serde_json::Value = serde_json::from_str(
        &super::super::show::show_bgp_evpn_etree(
            &bgp,
            crate::config::Args(std::collections::VecDeque::new()),
            true,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(json["irb"][0]["evi"], 100);

    bgp.process_rib_msg(RibRx::AddrDel(addr("10.0.0.1/24")));
    assert!(bgp.etree_irb_evis().is_empty());
    bgp.process_rib_msg(RibRx::AddrAdd(addr("2001:db8::1/64")));
    assert_eq!(bgp.etree_irb_evis().len(), 1, "a global IPv6 address");
    bgp.process_rib_msg(RibRx::AddrDel(addr("2001:db8::1/64")));

    // In a VRF: symmetric IRB's shape.
    bridge.master = Some(50);
    bgp.process_rib_msg(RibRx::LinkAdd(bridge));
    assert_eq!(bgp.etree_irb_evis().len(), 1, "a VRF master");
}

/// RFC 8317 §4.2.3: a peer advertising a MAC on a segment we also attach to
/// with the other role is a role conflict (a leaf's BUM may loop back into
/// the segment). `show bgp evpn etree` names it, and it is logged once at
/// onset and once at clear. A MAC on no segment, or with the same role, is
/// none; our own role change re-checks.
#[tokio::test]
async fn a_role_conflict_on_a_segment_is_reported() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.ethernet_segments.insert(
        "es1".to_string(),
        super::super::ethernet_segment::EthernetSegment {
            esi: Some(ESI),
            interface: Some("ce1".to_string()),
            ..Default::default()
        },
    );
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let pe: IpAddr = "10.0.0.11".parse().unwrap();
    let rd = rd_from_router_id_vni(Ipv4Addr::new(10, 0, 0, 11), 100).unwrap();
    let mac_route = |esi: [u8; 10], leaf: bool| {
        let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
            id: 0,
            rd,
            esi,
            ether_tag: 0,
            mac: [2, 0, 0, 0, 0xe2, 1],
            ip: None,
            vni: 100,
            label2: None,
        });
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Evpn(pe));
        attr.local_pref = Some(LocalPref::default());
        let mut ecom = ExtCommunity::from([evpn_route_target(65000, 100), evpn_encap_vxlan()]);
        if leaf {
            ecom.0.insert(ExtCommunityValue::etree_leaf());
        }
        attr.ecom = Some(ecom);
        (route, attr)
    };

    // On no segment: no conflict whatever the role.
    let (route, attr) = mac_route([0; 10], false);
    feed_evpn(&mut bgp, from, route, Some(attr));
    bgp.vpws_df_drain();
    assert!(bgp.etree_role_conflicts().is_empty());

    // Our AC on ES-1 is a leaf; the peer says root.
    let (route, attr) = mac_route(ESI, false);
    feed_evpn(&mut bgp, from, route.clone(), Some(attr));
    bgp.vpws_df_drain();
    let conflicts = bgp.etree_role_conflicts();
    assert_eq!(conflicts[&ESI].ac, "ce1");
    assert!(conflicts[&ESI].local_leaf);
    assert_eq!(conflicts[&ESI].pes, BTreeSet::from([pe]));
    assert_eq!(
        bgp.etree_role_conflicts_logged,
        BTreeSet::from([ESI]),
        "onset logged"
    );
    let text = super::super::show::show_bgp_evpn_etree(
        &bgp,
        crate::config::Args(std::collections::VecDeque::new()),
        false,
    )
    .unwrap();
    assert!(
        text.contains(&format!(
            "Warning: ESI {}: role conflict: our AC ce1 is a leaf, 10.0.0.11 advertise its MACs as root",
            bgp_packet::esi_display(&ESI)
        )),
        "{text}"
    );

    // The peer agrees: cleared.
    let (_, attr) = mac_route(ESI, true);
    feed_evpn(&mut bgp, from, route, Some(attr));
    bgp.vpws_df_drain();
    assert!(bgp.etree_role_conflicts().is_empty());
    assert!(bgp.etree_role_conflicts_logged.is_empty(), "clear logged");

    // Our AC becomes a root: the peer's leaf MACs now disagree.
    bgp.etree_leaf_ifs.clear();
    bgp.evpn_resync_macip_esi();
    assert_eq!(bgp.etree_role_conflicts_logged, BTreeSet::from([ESI]));

    // The MAC withdrawn: cleared.
    let (route, _) = mac_route(ESI, true);
    feed_evpn(&mut bgp, from, route, None);
    bgp.vpws_df_drain();
    assert!(
        bgp.etree_role_conflicts_logged.is_empty(),
        "cleared by the withdraw"
    );
}

/// Review finding: a conflicting Type-2 replaced by the same MAC/IP with no
/// ESI ends the conflict, so the clear is logged — and a later conflict on
/// the segment is logged again, not swallowed by stale state.
#[tokio::test]
async fn a_conflict_cleared_by_a_replacement_without_an_esi_is_logged() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.ethernet_segments.insert(
        "es1".to_string(),
        super::super::ethernet_segment::EthernetSegment {
            esi: Some(ESI),
            interface: Some("ce1".to_string()),
            ..Default::default()
        },
    );
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let pe: IpAddr = "10.0.0.11".parse().unwrap();
    let rd = rd_from_router_id_vni(Ipv4Addr::new(10, 0, 0, 11), 100).unwrap();
    let mac_route = |esi: [u8; 10]| {
        let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
            id: 0,
            rd,
            esi,
            ether_tag: 0,
            mac: [2, 0, 0, 0, 0xe2, 1],
            ip: None,
            vni: 100,
            label2: None,
        });
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Evpn(pe));
        attr.local_pref = Some(LocalPref::default());
        attr.ecom = Some(ExtCommunity::from([
            evpn_route_target(65000, 100),
            evpn_encap_vxlan(),
        ]));
        (route, attr)
    };
    // The peer says root on our leaf segment: a conflict.
    let (route, attr) = mac_route(ESI);
    feed_evpn(&mut bgp, from, route, Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(bgp.etree_role_conflicts_logged, BTreeSet::from([ESI]));

    // The same MAC/IP again, now on no segment: the conflict is gone.
    let (route, attr) = mac_route([0; 10]);
    feed_evpn(&mut bgp, from, route, Some(attr));
    bgp.vpws_df_drain();
    assert!(bgp.etree_role_conflicts().is_empty());
    assert!(
        bgp.etree_role_conflicts_logged.is_empty(),
        "the clear is logged"
    );

    // Back on the segment: the onset is logged again.
    let (route, mut attr) = mac_route(ESI);
    attr.local_pref = Some(LocalPref::new(200));
    feed_evpn(&mut bgp, from, route.clone(), Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(bgp.etree_role_conflicts_logged, BTreeSet::from([ESI]));

    // A second path for the same MAC, on no segment and less preferred;
    // the segment path withdrawn promotes it, and the conflict clears.
    let (from2, _rx2) = peer(&mut bgp, "10.0.0.12", false);
    let (route2, attr2) = mac_route([0; 10]);
    feed_evpn(&mut bgp, from2, route2, Some(attr2));
    bgp.vpws_df_drain();
    assert_eq!(bgp.etree_role_conflicts_logged, BTreeSet::from([ESI]));
    feed_evpn(&mut bgp, from, route, None);
    bgp.vpws_df_drain();
    assert!(bgp.etree_role_conflicts().is_empty());
    assert!(
        bgp.etree_role_conflicts_logged.is_empty(),
        "the clear is logged when a withdraw promotes a path off the segment"
    );
}

/// Review finding: a best-path recompute (`bgp bestpath med
/// missing-as-worst`) can move a MAC's winner off the segment with no
/// UPDATE behind it, so the reselection itself marks the role check and the
/// event's upkeep runs it. The MED knob is process-wide, so the reorder is
/// made by hand on the candidates here and the recompute does the rest.
#[tokio::test]
async fn a_conflict_cleared_by_a_recompute_is_logged() {
    let (mut bgp, _rib) = bgp_with_rib();
    bgp.advertise_all_vni = true;
    bgp.ethernet_segments.insert(
        "es1".to_string(),
        super::super::ethernet_segment::EthernetSegment {
            esi: Some(ESI),
            interface: Some("ce1".to_string()),
            ..Default::default()
        },
    );
    bgp.etree_leaf_ifs.insert("ce1".to_string());
    let rd = rd_from_router_id_vni(Ipv4Addr::new(10, 0, 0, 11), 100).unwrap();
    let mac = [2, 0, 0, 0, 0xe2, 1];
    let mac_route = |pe: IpAddr, esi: [u8; 10], local_pref: u32| {
        let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
            id: 0,
            rd,
            esi,
            ether_tag: 0,
            mac,
            ip: None,
            vni: 100,
            label2: None,
        });
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Evpn(pe));
        attr.local_pref = Some(LocalPref::new(local_pref));
        attr.ecom = Some(ExtCommunity::from([
            evpn_route_target(65000, 100),
            evpn_encap_vxlan(),
        ]));
        (route, attr)
    };
    // The segment path (root, on our leaf segment) wins: a conflict.
    let (from, _rx) = peer(&mut bgp, "10.0.0.11", false);
    let (route, attr) = mac_route("10.0.0.11".parse().unwrap(), ESI, 200);
    feed_evpn(&mut bgp, from, route, Some(attr));
    let (from2, _rx2) = peer(&mut bgp, "10.0.0.12", false);
    let (route, attr) = mac_route("10.0.0.12".parse().unwrap(), [0; 10], 100);
    feed_evpn(&mut bgp, from2, route, Some(attr));
    bgp.vpws_df_drain();
    assert_eq!(bgp.etree_role_conflicts_logged, BTreeSet::from([ESI]));

    let prefix = EvpnPrefix::MacIp {
        eth_tag: 0,
        mac,
        ip: None,
    };
    let set_segment_pref = |bgp: &mut Bgp, local_pref: u32| {
        let cands = bgp
            .local_rib
            .evpn
            .get_mut(&rd)
            .unwrap()
            .cands
            .get_mut(&prefix)
            .unwrap();
        let rib = cands.iter_mut().find(|r| r.esi == Some(ESI)).unwrap();
        std::sync::Arc::make_mut(&mut rib.attr).local_pref = Some(LocalPref::new(local_pref));
    };

    // The recompute moves the winner off the segment: the clear is logged.
    set_segment_pref(&mut bgp, 50);
    bgp.bestpath_recompute_all();
    bgp.event_upkeep();
    assert_ne!(
        bgp.local_rib.evpn[&rd].selected[&prefix].esi,
        Some(ESI),
        "the path on no segment won"
    );
    assert!(bgp.etree_role_conflicts().is_empty());
    assert!(
        bgp.etree_role_conflicts_logged.is_empty(),
        "the clear is logged after a recompute"
    );

    // And back: the onset is logged again, not swallowed by stale state.
    set_segment_pref(&mut bgp, 200);
    bgp.bestpath_recompute_all();
    bgp.event_upkeep();
    assert_eq!(bgp.etree_role_conflicts_logged, BTreeSet::from([ESI]));
}
