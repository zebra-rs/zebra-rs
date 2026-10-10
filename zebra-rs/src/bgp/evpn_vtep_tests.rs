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
    let route = EvpnRoute::Mac(bgp_packet::EvpnMac {
        id: 0,
        rd,
        esi: [0; 10],
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
        // What the event loop does after an UPDATE batch.
        self.bgp.evpn_dad_drain();
    }

    /// The kernel replaced our local row with the remote one.
    fn kernel_replaced(&mut self) {
        self.bgp.evpn_withdraw_macip(&self.local);
    }

    /// The host is learned here: our route carries the next number.
    fn local(&mut self) {
        self.seq += 1;
        self.bgp.evpn_originate_macip(&self.local);
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
