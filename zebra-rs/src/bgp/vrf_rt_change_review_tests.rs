//! Review finding #24: a route-target change must take effect on the
//! routes already in the VPN tables.
//!
//! - An import-RT change on a VRF re-evaluates nothing: import RTs are
//!   read only when a route arrives, so an added RT imports none of the
//!   matching routes already held, and a removed one leaves the routes it
//!   imported in the VRF.
//! - An export-RT change re-tags the VRF's own VPN rows and re-advertises
//!   them to the peers, but never re-runs the import: a sibling VRF on the
//!   same PE keeps a route it no longer imports, and one that now imports
//!   it does not get it.
//! - A VPN peer that filters by RT Constraint (RFC 4684) is skipped when
//!   a route's RTs leave its membership — skipped without a withdraw, so
//!   it keeps the old advertisement.
use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{
    BgpRib, BgpRibType, ORIGINATED_PEER, VpnNexthop, route_advertise_to_peers,
    route_advertise_to_peers_vpnv6,
};
use crate::bgp::vrf::msg::BgpVrfMsg;
use crate::bgp::vrf_config::BgpVrfConfig;
use crate::context::Task;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, ExtCommunityValue,
    Label, MpUnreachAttr, Origin, ParseOption, RouteDistinguisher, Safi, Vpnv4Nexthop,
    Vpnv6Nexthop,
};
use ipnet::{Ipv4Net, Ipv6Net};
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

fn rts(list: &[&str]) -> BTreeSet<RouteDistinguisher> {
    list.iter().map(|s| rt(s)).collect()
}

type VrfRx = mpsc::UnboundedReceiver<BgpVrfMsg>;

/// The route-targets of one VRF, per family.
#[derive(Default, Clone, Copy)]
struct Rts<'a> {
    import_v4: &'a [&'a str],
    export_v4: &'a [&'a str],
    import_v6: &'a [&'a str],
    export_v6: &'a [&'a str],
}

/// Register VRF `name` (RD `rd`) with the instance — its task handle, its
/// RT sets, its config — and return the receiving end of its inbox.
fn add_vrf(bgp: &mut Bgp, name: &str, rd: &str, rts_: Rts) -> VrfRx {
    let (inbox, rx) = mpsc::unbounded_channel();
    let (show_tx, show_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(show_rx));
    bgp.vrf_registry.insert(
        name.to_string(),
        crate::bgp::vrf::BgpVrfHandle {
            inbox,
            router_id: ROUTER_ID,
            asn: 65000,
            bfd_client_tx: None,
            bfd_client: String::new(),
            show_tx,
            task: Task::spawn(async {}),
            label: 100,
            ilm_decap_ifindex: None,
            srv6_sid: None,
            rd: Some(rt(rd)),
            evpn_advertise_v4: false,
            evpn_advertise_v6: false,
        },
    );
    bgp.rib_known_vrfs.insert(
        name.to_string(),
        RibKnownVrf {
            import_rts_v4: rts(rts_.import_v4),
            export_rts_v4: rts(rts_.export_v4),
            import_rts_v6: rts(rts_.import_v6),
            export_rts_v6: rts(rts_.export_v6),
            ..Default::default()
        },
    );
    let cfg = BgpVrfConfig {
        rd: Some(rt(rd)),
        ..Default::default()
    };
    bgp.vrfs.insert(name.to_string(), cfg);
    rx
}

/// A committed RT change for VRF `name`, as the RIB delivers it.
fn set_rts(bgp: &mut Bgp, name: &str, rts_: Rts) {
    bgp.process_rib_msg(RibRx::VrfRouteTargets {
        name: name.to_string(),
        ipv4_import_rts: rts(rts_.import_v4),
        ipv4_export_rts: rts(rts_.export_v4),
        ipv6_import_rts: rts(rts_.import_v6),
        ipv6_export_rts: rts(rts_.export_v6),
        mup_import_rts: BTreeSet::new(),
        mup_export_rts: BTreeSet::new(),
    });
}

/// What a VRF task was told: `("import" | "withdraw", rd, prefix)`.
fn told(rx: &mut VrfRx) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        match msg {
            BgpVrfMsg::ImportV4 { rd, prefix, .. } => {
                out.push(("import", rd.to_string(), prefix.to_string()))
            }
            BgpVrfMsg::WithdrawImport { rd, prefix } => {
                out.push(("withdraw", rd.to_string(), prefix.to_string()))
            }
            BgpVrfMsg::ImportV6 { rd, prefix, .. } => {
                out.push(("import", rd.to_string(), prefix.to_string()))
            }
            BgpVrfMsg::WithdrawImportV6 { rd, prefix } => {
                out.push(("withdraw", rd.to_string(), prefix.to_string()))
            }
            _ => {}
        }
    }
    out.sort();
    out
}

fn vpn_attr(nexthop: BgpNexthop, rts_: &[&str]) -> BgpAttr {
    tag_attr_with_export_rts(
        BgpAttr {
            origin: Some(Origin::Igp),
            aspath: Some(As4Path::from_str("65002").unwrap()),
            nexthop: Some(nexthop),
            ..Default::default()
        },
        &rts(rts_),
    )
}

/// A received EVPN Type-5 route imports through the VRF's IPv4 / IPv6
/// import RTs like a VPN route, but its selected path lives in
/// `local_rib.evpn`, not in the shard's VPN tables (review of #24). Hold
/// one for `prefix` carrying RT 65000:200 and imported per blue's current
/// RTs, then change blue's import RTs — adding 65000:200 must import the
/// route, removing it must withdraw it.
fn check_type5_import_rt_change(prefix: ipnet::IpNet, remove: bool) {
    let mut bgp = fresh_bgp();
    let matching = match prefix {
        ipnet::IpNet::V4(_) => Rts {
            import_v4: &["65000:200"],
            ..Default::default()
        },
        ipnet::IpNet::V6(_) => Rts {
            import_v6: &["65000:200"],
            ..Default::default()
        },
    };
    let mut blue = add_vrf(
        &mut bgp,
        "blue",
        "65000:2",
        if remove { matching } else { Rts::default() },
    );
    let rd = rt("65000:9");
    let attr = vpn_attr(
        BgpNexthop::Ipv4("10.0.0.2".parse().unwrap()),
        &["65000:200"],
    );
    let rib = BgpRib::new(
        2,
        "10.0.0.2".parse().unwrap(),
        BgpRibType::IBGP,
        0,
        0,
        &attr,
        Some(Label::new(100, 0, true)),
        None,
        false,
    );
    bgp.local_rib.update_evpn(
        rd,
        bgp_packet::EvpnPrefix::IpPrefix { eth_tag: 0, prefix },
        rib,
    );
    // Match the dispatch performed for a received Type-5 best path.
    let dispatcher = super::super::vrf::VrfImportDispatcher {
        rib_known_vrfs: &bgp.rib_known_vrfs,
        vrf_registry: &bgp.vrf_registry,
    };
    match prefix {
        ipnet::IpNet::V4(p) => {
            super::super::vrf::dispatch_import_v4(&dispatcher, rd, p, &attr, 100, &[], None)
        }
        ipnet::IpNet::V6(p) => {
            super::super::vrf::dispatch_import_v6(&dispatcher, rd, p, &attr, 100, &[], None)
        }
    }
    let before = told(&mut blue);
    assert_eq!(
        before.len(),
        usize::from(remove),
        "initial import follows the old RTs"
    );
    set_rts(
        &mut bgp,
        "blue",
        if remove { Rts::default() } else { matching },
    );
    assert_eq!(
        told(&mut blue),
        vec![(
            if remove { "withdraw" } else { "import" },
            rd.to_string(),
            prefix.to_string()
        )],
        "the RT change must also reconcile a held Type-5 route"
    );
}

#[tokio::test]
async fn type5_v4_import_rt_added_imports_the_held_route() {
    check_type5_import_rt_change("10.24.99.0/24".parse().unwrap(), false);
}

/// A VPN route and a received Type-5 route share `(RD, prefix)` — the key
/// the VRF holds one imported path under, whichever table it came from —
/// with different RTs: the VPN route 65000:100, the Type-5 route
/// 65000:200. Blue holds the Type-5 route, imported last. Blue's import RTs
/// become 65000:100 alone — from 65000:200 (a switch), or, with
/// `vpn_already_matched`, from both (a removal: the VPN route's own match
/// does not change). Applying the messages in delivery order, as the VRF
/// does, blue must end up holding the VPN route (reviews of #24): the
/// per-route replay imported it and then sent the Type-5 route's withdraw
/// for the same key, erasing it; after a removal it sent nothing, so blue
/// kept the Type-5 route; on `main` blue kept the Type-5 route either way.
fn check_rt_switch_between_vpn_and_type5(prefix: ipnet::IpNet, vpn_already_matched: bool) {
    let mut bgp = fresh_bgp();
    let policy = |rt_value: &'static str| match prefix {
        ipnet::IpNet::V4(_) => Rts {
            import_v4: if rt_value == "old" && vpn_already_matched {
                &["65000:100", "65000:200"]
            } else if rt_value == "old" {
                &["65000:200"]
            } else {
                &["65000:100"]
            },
            ..Default::default()
        },
        ipnet::IpNet::V6(_) => Rts {
            import_v6: if rt_value == "old" && vpn_already_matched {
                &["65000:100", "65000:200"]
            } else if rt_value == "old" {
                &["65000:200"]
            } else {
                &["65000:100"]
            },
            ..Default::default()
        },
    };
    let mut blue = add_vrf(&mut bgp, "blue", "65000:2", policy("old"));
    let rd = rt("65000:9");
    match prefix {
        ipnet::IpNet::V4(_) => {
            put_vpnv4(&mut bgp, 2, "65000:9", &prefix.to_string(), &["65000:100"])
        }
        ipnet::IpNet::V6(_) => {
            put_vpnv6(&mut bgp, 2, "65000:9", &prefix.to_string(), &["65000:100"])
        }
    }
    let attr = vpn_attr(
        BgpNexthop::Ipv4("10.0.0.2".parse().unwrap()),
        &["65000:200"],
    );
    let rib = BgpRib::new(
        2,
        "10.0.0.2".parse().unwrap(),
        BgpRibType::IBGP,
        0,
        0,
        &attr,
        Some(Label::new(100, 0, true)),
        None,
        false,
    );
    bgp.local_rib.update_evpn(
        rd,
        bgp_packet::EvpnPrefix::IpPrefix { eth_tag: 0, prefix },
        rib,
    );
    set_rts(&mut bgp, "blue", policy("new"));
    // The path blue holds under the key, named by its RT: the Type-5 route,
    // imported under the old RT.
    let mut held: Option<Vec<String>> = Some(vec!["65000:200".to_string()]);
    while let Ok(msg) = blue.try_recv() {
        match msg {
            BgpVrfMsg::ImportV4 { attr, .. } | BgpVrfMsg::ImportV6 { attr, .. } => {
                held = Some(
                    route_rts_from_ecom(&attr.ecom)
                        .iter()
                        .map(|r| r.to_string())
                        .collect(),
                )
            }
            BgpVrfMsg::WithdrawImport { .. } | BgpVrfMsg::WithdrawImportV6 { .. } => held = None,
            _ => {}
        }
    }
    assert_eq!(
        held,
        Some(vec!["65000:100".to_string()]),
        "blue holds the VPN route the new RT matches"
    );
}

#[tokio::test]
async fn v4_rt_switch_from_type5_to_vpn_leaves_the_vpn_route_imported() {
    check_rt_switch_between_vpn_and_type5("10.24.99.0/24".parse().unwrap(), false);
}

#[tokio::test]
async fn v6_rt_switch_from_type5_to_vpn_leaves_the_vpn_route_imported() {
    check_rt_switch_between_vpn_and_type5("2001:db8:99::/64".parse().unwrap(), false);
}

#[tokio::test]
async fn v4_rt_removal_switches_to_the_vpn_route_that_still_matches() {
    check_rt_switch_between_vpn_and_type5("10.24.99.0/24".parse().unwrap(), true);
}

#[tokio::test]
async fn v6_rt_removal_switches_to_the_vpn_route_that_still_matches() {
    check_rt_switch_between_vpn_and_type5("2001:db8:99::/64".parse().unwrap(), true);
}

#[tokio::test]
async fn type5_v4_import_rt_removed_withdraws_the_held_route() {
    check_type5_import_rt_change("10.24.99.0/24".parse().unwrap(), true);
}

#[tokio::test]
async fn type5_v6_import_rt_added_imports_the_held_route() {
    check_type5_import_rt_change("2001:db8:99::/64".parse().unwrap(), false);
}

#[tokio::test]
async fn type5_v6_import_rt_removed_withdraws_the_held_route() {
    check_type5_import_rt_change("2001:db8:99::/64".parse().unwrap(), true);
}

/// Control: our own originated Type-5 route is left to the VRF export's
/// local leak, as on the ingest path — an import-RT change does not
/// import it.
#[tokio::test]
async fn import_rt_change_leaves_our_own_type5_to_the_local_leak() {
    let mut bgp = fresh_bgp();
    let mut blue = add_vrf(&mut bgp, "blue", "65000:2", Rts::default());
    let rd = rt("65000:1");
    let attr = vpn_attr(
        BgpNexthop::Ipv4("10.0.0.9".parse().unwrap()),
        &["65000:200"],
    );
    let rib = BgpRib::new(
        ORIGINATED_PEER,
        ROUTER_ID,
        BgpRibType::Originated,
        0,
        0,
        &attr,
        Some(Label::new(100, 0, true)),
        None,
        false,
    );
    bgp.local_rib.update_evpn(
        rd,
        bgp_packet::EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "10.24.98.0/24".parse().unwrap(),
        },
        rib,
    );
    set_rts(
        &mut bgp,
        "blue",
        Rts {
            import_v4: &["65000:200"],
            ..Default::default()
        },
    );
    assert!(told(&mut blue).is_empty(), "our own Type-5 is not imported");
}

/// A VPNv4 row for `prefix` under `rd` carrying `rts_`, learned from
/// peer `ident` (or originated by a local VRF: `ORIGINATED_PEER`).
fn put_vpnv4(bgp: &mut Bgp, ident: usize, rd: &str, prefix: &str, rts_: &[&str]) {
    let rd = rt(rd);
    let nh = Vpnv4Nexthop {
        rd,
        nhop: "10.0.0.2".parse().unwrap(),
    };
    let attr = vpn_attr(BgpNexthop::Vpnv4(nh.clone()), rts_);
    let mut rib = BgpRib::new(
        ident,
        Ipv4Addr::new(10, 0, 0, 2),
        if ident == ORIGINATED_PEER {
            BgpRibType::Originated
        } else {
            BgpRibType::IBGP
        },
        0,
        0,
        &attr,
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
fn put_vpnv6(bgp: &mut Bgp, ident: usize, rd: &str, prefix: &str, rts_: &[&str]) {
    let rd = rt(rd);
    let nh = Vpnv6Nexthop {
        rd,
        nhop: "2001:db8::2".parse().unwrap(),
    };
    let attr = vpn_attr(BgpNexthop::Vpnv6(nh.clone()), rts_);
    let mut rib = BgpRib::new(
        ident,
        Ipv4Addr::new(10, 0, 0, 2),
        if ident == ORIGINATED_PEER {
            BgpRibType::Originated
        } else {
            BgpRibType::IBGP
        },
        0,
        0,
        &attr,
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

// -------------------------------------------------------------------------
// Import-RT change
// -------------------------------------------------------------------------

/// VRF blue adds import RT 65000:200: the VPNv4 route already held with
/// that RT must be imported into blue; removing the RT again must withdraw
/// it. VRF gold, whose RTs do not change, is told nothing either time.
#[tokio::test]
async fn vpnv4_import_rt_change_imports_and_withdraws_held_routes() {
    let mut bgp = fresh_bgp();
    let mut blue = add_vrf(&mut bgp, "blue", "65000:2", Rts::default());
    let mut gold = add_vrf(
        &mut bgp,
        "gold",
        "65000:3",
        Rts {
            import_v4: &["65000:200"],
            ..Default::default()
        },
    );
    put_vpnv4(&mut bgp, 0, "65002:1", "10.24.1.0/24", &["65000:200"]);

    set_rts(
        &mut bgp,
        "blue",
        Rts {
            import_v4: &["65000:200"],
            ..Default::default()
        },
    );
    assert_eq!(
        told(&mut blue),
        vec![("import", "65002:1".into(), "10.24.1.0/24".into())],
        "the added import RT imports the held route"
    );
    assert!(told(&mut gold).is_empty(), "gold's RTs did not change");

    set_rts(&mut bgp, "blue", Rts::default());
    assert_eq!(
        told(&mut blue),
        vec![("withdraw", "65002:1".into(), "10.24.1.0/24".into())],
        "the removed import RT withdraws what it imported"
    );
    assert!(told(&mut gold).is_empty());
}

/// The VPNv6 twin.
#[tokio::test]
async fn vpnv6_import_rt_change_imports_and_withdraws_held_routes() {
    let mut bgp = fresh_bgp();
    let mut blue = add_vrf(&mut bgp, "blue", "65000:2", Rts::default());
    put_vpnv6(&mut bgp, 0, "65002:1", "2001:db8:24:1::/64", &["65000:200"]);

    set_rts(
        &mut bgp,
        "blue",
        Rts {
            import_v6: &["65000:200"],
            ..Default::default()
        },
    );
    assert_eq!(
        told(&mut blue),
        vec![("import", "65002:1".into(), "2001:db8:24:1::/64".into())]
    );
    set_rts(&mut bgp, "blue", Rts::default());
    assert_eq!(
        told(&mut blue),
        vec![("withdraw", "65002:1".into(), "2001:db8:24:1::/64".into())]
    );
}

/// A route VRF red originated is not re-imported into red itself when
/// red's import set comes to include red's own export RT.
#[tokio::test]
async fn import_rt_change_does_not_import_a_vrfs_own_route() {
    let mut bgp = fresh_bgp();
    let mut red = add_vrf(
        &mut bgp,
        "red",
        "65000:1",
        Rts {
            export_v4: &["65000:100"],
            ..Default::default()
        },
    );
    put_vpnv4(
        &mut bgp,
        ORIGINATED_PEER,
        "65000:1",
        "10.24.2.0/24",
        &["65000:100"],
    );
    set_rts(
        &mut bgp,
        "red",
        Rts {
            import_v4: &["65000:100"],
            export_v4: &["65000:100"],
            ..Default::default()
        },
    );
    assert!(told(&mut red).is_empty(), "no self-import");
}

// -------------------------------------------------------------------------
// Export-RT change
// -------------------------------------------------------------------------

/// VRF red exports 10.24.3.0/24 with RT 65000:100, which sibling VRF blue
/// imports. Red's export changes to 65000:300, which green imports: blue
/// must lose the route and green must get it.
#[tokio::test]
async fn vpnv4_export_rt_change_moves_the_route_between_sibling_vrfs() {
    let mut bgp = fresh_bgp();
    let mut red = add_vrf(
        &mut bgp,
        "red",
        "65000:1",
        Rts {
            export_v4: &["65000:100"],
            ..Default::default()
        },
    );
    let mut blue = add_vrf(
        &mut bgp,
        "blue",
        "65000:2",
        Rts {
            import_v4: &["65000:100"],
            ..Default::default()
        },
    );
    let mut green = add_vrf(
        &mut bgp,
        "green",
        "65000:3",
        Rts {
            import_v4: &["65000:300"],
            ..Default::default()
        },
    );
    put_vpnv4(
        &mut bgp,
        ORIGINATED_PEER,
        "65000:1",
        "10.24.3.0/24",
        &["65000:100"],
    );

    set_rts(
        &mut bgp,
        "red",
        Rts {
            export_v4: &["65000:300"],
            ..Default::default()
        },
    );
    assert_eq!(
        told(&mut blue),
        vec![("withdraw", "65000:1".into(), "10.24.3.0/24".into())],
        "blue no longer imports red's route"
    );
    assert_eq!(
        told(&mut green),
        vec![("import", "65000:1".into(), "10.24.3.0/24".into())],
        "green now imports it"
    );
    assert!(told(&mut red).is_empty(), "no self-import");
}

/// The VPNv6 twin.
#[tokio::test]
async fn vpnv6_export_rt_change_moves_the_route_between_sibling_vrfs() {
    let mut bgp = fresh_bgp();
    let _red = add_vrf(
        &mut bgp,
        "red",
        "65000:1",
        Rts {
            export_v6: &["65000:100"],
            ..Default::default()
        },
    );
    let mut blue = add_vrf(
        &mut bgp,
        "blue",
        "65000:2",
        Rts {
            import_v6: &["65000:100"],
            ..Default::default()
        },
    );
    let mut green = add_vrf(
        &mut bgp,
        "green",
        "65000:3",
        Rts {
            import_v6: &["65000:300"],
            ..Default::default()
        },
    );
    put_vpnv6(
        &mut bgp,
        ORIGINATED_PEER,
        "65000:1",
        "2001:db8:24:3::/64",
        &["65000:100"],
    );

    set_rts(
        &mut bgp,
        "red",
        Rts {
            export_v6: &["65000:300"],
            ..Default::default()
        },
    );
    assert_eq!(
        told(&mut blue),
        vec![("withdraw", "65000:1".into(), "2001:db8:24:3::/64".into())]
    );
    assert_eq!(
        told(&mut green),
        vec![("import", "65000:1".into(), "2001:db8:24:3::/64".into())]
    );
}

// -------------------------------------------------------------------------
// RT Constraint
// -------------------------------------------------------------------------

/// An Established VPN neighbor of AS 65000 (a reflector client) with `fam`
/// negotiated, a member of the RT Constraint group for `membership`.
fn add_rtc_peer(
    bgp: &mut Bgp,
    fam: AfiSafi,
    membership: &[&str],
) -> (usize, mpsc::UnboundedReceiver<bytes::BytesMut>) {
    add_vpn_peer(bgp, fam, false, membership)
}

/// An Established VPN neighbor of AS 65000 (a reflector client) with `fam`
/// negotiated, AddPath send on it when `addpath`, and RT Constraint
/// membership `membership` (none when empty).
fn add_vpn_peer(
    bgp: &mut Bgp,
    fam: AfiSafi,
    addpath: bool,
    membership: &[&str],
) -> (usize, mpsc::UnboundedReceiver<bytes::BytesMut>) {
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
    // A reflector client, so the iBGP-learned route is reflected to it.
    peer.reflector_client = true;
    peer.remote_id = Ipv4Addr::new(10, 0, 0, 4);
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&fam.afi, &fam.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    if addpath {
        peer.opt.add_path.entry(fam).or_default().send = true;
    }
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    let set: BTreeSet<ExtCommunityValue> = membership
        .iter()
        .map(|s| {
            let mut v: ExtCommunityValue = rt(s).into();
            v.low_type = 0x02;
            v
        })
        .collect();
    if fam.afi == Afi::Ip {
        peer.rtcv4 = set;
    } else {
        peer.rtcv6 = set;
    }
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

/// The prefixes of every VPN withdraw on `rx`.
fn vpn_withdrawn(rx: &mut mpsc::UnboundedReceiver<bytes::BytesMut>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, false, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        if let BgpPacket::Update(update) = packet {
            match update.mp_withdraw {
                Some(MpUnreachAttr::Vpnv4(rows)) => {
                    out.extend(rows.iter().map(|r| r.nlri.prefix.to_string()))
                }
                Some(MpUnreachAttr::Vpnv6(rows)) => {
                    out.extend(rows.iter().map(|r| r.nlri.prefix.to_string()))
                }
                _ => {}
            }
        }
    }
    out
}

/// A VPNv4 neighbor whose RT Constraint membership is 65000:100 holds P,
/// tagged 65000:100. P is re-tagged 65000:300, outside the membership:
/// the neighbor must be withdrawn P, not left holding the old route.
#[tokio::test]
async fn vpnv4_rtc_member_is_withdrawn_a_route_that_leaves_its_rts() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_rtc_peer(&mut bgp, VPNV4, &["65000:100"]);
    let rd = rt("65002:1");
    let prefix: Ipv4Net = "10.24.4.0/24".parse().unwrap();
    let held = |bgp: &Bgp| {
        bgp.peers
            .get_by_idx(c)
            .unwrap()
            .adj_out
            .v4vpn
            .get(&rd)
            .is_some_and(|t| t.0.contains_key(&prefix))
    };
    put_vpnv4(&mut bgp, 1, "65002:1", "10.24.4.0/24", &["65000:100"]);
    let selected = bgp.shard.select_best_path_vpn(&rd, prefix);
    {
        let (mut top, peers) = split(&mut bgp);
        route_advertise_to_peers(Some(rd), prefix, &selected, 1, &mut top, peers);
    }
    assert!(held(&bgp), "C holds P while P carries a member RT");
    let _ = vpn_withdrawn(&mut rc);

    put_vpnv4(&mut bgp, 1, "65002:1", "10.24.4.0/24", &["65000:300"]);
    let selected = bgp.shard.select_best_path_vpn(&rd, prefix);
    {
        let (mut top, peers) = split(&mut bgp);
        route_advertise_to_peers(Some(rd), prefix, &selected, 1, &mut top, peers);
    }
    bgp.flush_all_pending_withdraws();
    assert!(!held(&bgp), "C no longer holds P");
    assert_eq!(vpn_withdrawn(&mut rc), vec!["10.24.4.0/24".to_string()]);
}

/// The VPNv6 twin.
#[tokio::test]
async fn vpnv6_rtc_member_is_withdrawn_a_route_that_leaves_its_rts() {
    let mut bgp = fresh_bgp();
    let (c, mut rc) = add_rtc_peer(&mut bgp, VPNV6, &["65000:100"]);
    let rd = rt("65002:1");
    let prefix: Ipv6Net = "2001:db8:24:4::/64".parse().unwrap();
    let held = |bgp: &Bgp| {
        bgp.peers
            .get_by_idx(c)
            .unwrap()
            .adj_out
            .v6vpn
            .get(&rd)
            .is_some_and(|t| t.0.contains_key(&prefix))
    };
    put_vpnv6(&mut bgp, 1, "65002:1", "2001:db8:24:4::/64", &["65000:100"]);
    let selected = bgp.shard.select_best_path_vpn_v6(&rd, prefix);
    {
        let (mut top, peers) = split(&mut bgp);
        route_advertise_to_peers_vpnv6(rd, prefix, &selected, &mut top, peers);
    }
    assert!(held(&bgp), "C holds P while P carries a member RT");
    let _ = vpn_withdrawn(&mut rc);

    put_vpnv6(&mut bgp, 1, "65002:1", "2001:db8:24:4::/64", &["65000:300"]);
    let selected = bgp.shard.select_best_path_vpn_v6(&rd, prefix);
    {
        let (mut top, peers) = split(&mut bgp);
        route_advertise_to_peers_vpnv6(rd, prefix, &selected, &mut top, peers);
    }
    bgp.flush_all_pending_withdraws();
    assert!(!held(&bgp), "C no longer holds P");
    assert_eq!(
        vpn_withdrawn(&mut rc),
        vec!["2001:db8:24:4::/64".to_string()]
    );
}

// -------------------------------------------------------------------------
// Export-RT change toward AddPath neighbors
// -------------------------------------------------------------------------

/// The route-targets on the row `ident` holds for `prefix` under `rd`.
fn held_rts_v4(bgp: &Bgp, ident: usize, rd: &str, prefix: &str) -> Vec<String> {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    let adj = &bgp.peers.get_by_idx(ident).unwrap().adj_out;
    adj.v4vpn
        .get(&rt(rd))
        .and_then(|t| t.0.get(&prefix))
        .and_then(|rows| rows.first())
        .map_or(Vec::new(), |row| {
            route_rts_from_ecom(&row.attr.ecom)
                .iter()
                .map(|r| r.to_string())
                .collect()
        })
}

/// The VPNv6 twin of [`held_rts_v4`].
fn held_rts_v6(bgp: &Bgp, ident: usize, rd: &str, prefix: &str) -> Vec<String> {
    let prefix: Ipv6Net = prefix.parse().unwrap();
    let adj = &bgp.peers.get_by_idx(ident).unwrap().adj_out;
    adj.v6vpn
        .get(&rt(rd))
        .and_then(|t| t.0.get(&prefix))
        .and_then(|rows| rows.first())
        .map_or(Vec::new(), |row| {
            route_rts_from_ecom(&row.attr.ecom)
                .iter()
                .map(|r| r.to_string())
                .collect()
        })
}

/// VRF red's route, tagged 65000:100, is held by the AddPath VPNv4
/// neighbor C. Red's export RT becomes 65000:300: C must be sent the
/// re-tagged route — the re-tag re-advertised to plain neighbors only, so C
/// kept the old RT.
#[tokio::test]
async fn vpnv4_export_rt_change_re_tags_the_route_toward_addpath_neighbors() {
    let mut bgp = fresh_bgp();
    let _red = add_vrf(
        &mut bgp,
        "red",
        "65000:1",
        Rts {
            export_v4: &["65000:100"],
            ..Default::default()
        },
    );
    let (c, _rc) = add_vpn_peer(&mut bgp, VPNV4, true, &[]);
    put_vpnv4(
        &mut bgp,
        ORIGINATED_PEER,
        "65000:1",
        "10.24.5.0/24",
        &["65000:100"],
    );
    {
        let (mut top, peers) = split(&mut bgp);
        crate::bgp::route::route_sync_vpnv4(peers.get_mut_by_idx(c).unwrap(), &mut top);
    }
    assert_eq!(
        held_rts_v4(&bgp, c, "65000:1", "10.24.5.0/24"),
        vec!["65000:100".to_string()]
    );
    set_rts(
        &mut bgp,
        "red",
        Rts {
            export_v4: &["65000:300"],
            ..Default::default()
        },
    );
    assert_eq!(
        held_rts_v4(&bgp, c, "65000:1", "10.24.5.0/24"),
        vec!["65000:300".to_string()],
        "the AddPath neighbor holds the re-tagged route"
    );
}

/// The VPNv6 twin.
#[tokio::test]
async fn vpnv6_export_rt_change_re_tags_the_route_toward_addpath_neighbors() {
    let mut bgp = fresh_bgp();
    let _red = add_vrf(
        &mut bgp,
        "red",
        "65000:1",
        Rts {
            export_v6: &["65000:100"],
            ..Default::default()
        },
    );
    let (c, _rc) = add_vpn_peer(&mut bgp, VPNV6, true, &[]);
    put_vpnv6(
        &mut bgp,
        ORIGINATED_PEER,
        "65000:1",
        "2001:db8:24:5::/64",
        &["65000:100"],
    );
    {
        let (mut top, peers) = split(&mut bgp);
        crate::bgp::route::route_sync_vpnv6(peers.get_mut_by_idx(c).unwrap(), &mut top);
    }
    assert_eq!(
        held_rts_v6(&bgp, c, "65000:1", "2001:db8:24:5::/64"),
        vec!["65000:100".to_string()]
    );
    set_rts(
        &mut bgp,
        "red",
        Rts {
            export_v6: &["65000:300"],
            ..Default::default()
        },
    );
    assert_eq!(
        held_rts_v6(&bgp, c, "65000:1", "2001:db8:24:5::/64"),
        vec!["65000:300".to_string()],
        "the AddPath neighbor holds the re-tagged route"
    );
}
