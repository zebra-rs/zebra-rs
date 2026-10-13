//! Review finding #27: Flowspec (SAFI 133) and SR Policy (SAFI 73) egress
//! must pass the gates every other family's egress applies.
//!
//! Flowspec (`route_update_flowspec`, `route_advertise_flowspec_to_peers`):
//! NO_ADVERTISE and NO_EXPORT were not honoured (RFC 1997), an LLGR-stale
//! flow spec went to peers that did not negotiate LLGR (RFC 9494 §4.3), and
//! an out-policy bound on the family was accepted but never applied (gated
//! here, `#[ignore]`d until the follow-up that gives Flowspec an
//! attribute-only policy matcher). Found while gating: a peer the new best no longer reaches was skipped rather
//! than withdrawn, so it kept the previous flow spec; and the session-up
//! dump had no Flowspec step, so a peer that came up after a flow spec was
//! learned never got it.
//!
//! SR Policy (`srpolicy_reflect` / `sr_policy::reflect_attr`): NO_EXPORT
//! leaked to eBGP and the reflected policy went to eBGP without our AS on
//! the AS_PATH (RFC 4271 §5.1.2); the session-up dump replays local
//! policies only, so a late peer never got the reflected ones (gated here,
//! `#[ignore]`d until the follow-up that stores received policies to
//! replay them). Found while gating: our own policies went out with no AS_PATH at all (a missing
//! well-known attribute, RFC 7606 treat-as-withdraw) and no LOCAL_PREF
//! toward iBGP; an eBGP-learned policy was reflected to iBGP without
//! LOCAL_PREF.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{BgpRib, BgpRibType, route_from_peer, route_sync};
use crate::bgp::sr_policy::LocalSrPolicy;
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpPacket, CapMultiProtocol, Community, CommunityValue,
    ExtCommunity, ExtCommunityValue, FlowspecComponent, FlowspecNlri, FlowspecPrefix, LocalPref,
    MpReachAttr, MpUnreachAttr, Origin, ParseOption, Safi, SrPolicyNlri, UpdatePacket,
};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const OUR_AS: u32 = 65000;

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
    bgp.asn = OUR_AS;
    bgp.router_id = ROUTER_ID;
    bgp
}

/// An Established neighbor at `addr` in `remote_as` (iBGP when it is ours)
/// with `fams` negotiated, a route-reflector client when `client`.
fn add_peer(
    bgp: &mut Bgp,
    addr: &str,
    remote_as: u32,
    fams: &[AfiSafi],
    client: bool,
) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
    let mut peer = Peer::new(
        0,
        OUR_AS,
        ROUTER_ID,
        remote_as,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = if remote_as == OUR_AS {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    peer.reflector_client = client;
    peer.remote_id = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::new(10, 0, 0, 200),
    };
    // RFC 9117 validation needs a unicast route per flow spec; these
    // tests are about egress, so trust the neighbors' flow specs.
    peer.config.flowspec_validation = false;
    for fam in fams {
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
    (id, prx)
}

fn split(bgp: &mut Bgp) -> (BgpTop<'_>, &mut PeerMap) {
    (
        BgpTop {
            router_id: &bgp.router_id,
            srv6_ipv6_export: None,
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
            as_sets_withdraw: bgp.as_sets_withdraw,
        },
        &mut bgp.peers,
    )
}

/// What a neighbor was sent: Flowspec / SR Policy NLRI advertised (with
/// the attributes they came with) and withdrawn.
#[derive(Default, Debug)]
struct Sent {
    adv: Vec<(String, BgpAttr)>,
    wd: Vec<String>,
}

impl Sent {
    fn advertised(&self) -> Vec<String> {
        self.adv.iter().map(|(n, _)| n.clone()).collect()
    }
}

fn sent(rx: &mut Rx) -> Sent {
    let mut out = Sent::default();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(ParseOption::default()))
            .expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        let attr = update.bgp_attr.clone().unwrap_or_default();
        match &update.mp_update {
            Some(MpReachAttr::Flowspec { updates, .. }) => {
                out.adv
                    .extend(updates.iter().map(|n| (n.to_string(), attr.clone())));
            }
            Some(MpReachAttr::SrPolicy { updates, .. }) => {
                out.adv
                    .extend(updates.iter().map(|n| (srp_name(n), attr.clone())));
            }
            _ => {}
        }
        match &update.mp_withdraw {
            Some(MpUnreachAttr::Flowspec { withdraws, .. }) => {
                out.wd.extend(withdraws.iter().map(|n| n.to_string()));
            }
            Some(MpUnreachAttr::SrPolicy { withdraws, .. }) => {
                out.wd.extend(withdraws.iter().map(srp_name));
            }
            _ => {}
        }
    }
    out
}

fn aspath(s: &str) -> Option<As4Path> {
    Some(As4Path::from_str(s).unwrap())
}

fn coms(values: &[CommunityValue]) -> Option<Community> {
    (!values.is_empty()).then(|| Community::from_iter(values.iter().map(|c| c.value())))
}

// -------------------------------------------------------------------------
// Flowspec
// -------------------------------------------------------------------------

fn fs_fam(afi: Afi) -> AfiSafi {
    AfiSafi::new(afi, Safi::Flowspec)
}

/// Flow spec `n`: a destination-prefix rule, IPv4 or IPv6.
fn fs_nlri(afi: Afi, n: u8) -> FlowspecNlri {
    let prefix = if afi == Afi::Ip {
        FlowspecPrefix::V4(format!("10.27.{n}.0/24").parse().unwrap())
    } else {
        let addr: std::net::Ipv6Addr = format!("2001:db8:27:{n}::").parse().unwrap();
        FlowspecPrefix::V6 {
            length: 64,
            offset: 0,
            pattern: addr.octets()[..8].to_vec(),
        }
    };
    FlowspecNlri::new(afi, vec![FlowspecComponent::DestinationPrefix(prefix)])
}

/// Source A (eBGP, AS 65001) announces flow spec `n` with `cs`.
fn fs_announce(bgp: &mut Bgp, a: usize, afi: Afi, n: u8, cs: &[CommunityValue]) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: aspath("65001"),
        com: coms(cs),
        ..Default::default()
    });
    packet.mp_update = Some(MpReachAttr::Flowspec {
        afi,
        updates: vec![fs_nlri(afi, n)],
    });
    let (mut top, peers) = split(bgp);
    route_from_peer(a, packet, &mut top, peers, None);
}

/// A (eBGP source), B (eBGP), C (iBGP non-client), each with the family.
fn fs_topology(afi: Afi) -> (Bgp, usize, Rx, Rx) {
    let mut bgp = fresh_bgp();
    let fam = [fs_fam(afi)];
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.1", 65001, &fam, false);
    let (_b, rb) = add_peer(&mut bgp, "10.0.0.2", 65002, &fam, false);
    let (_c, rc) = add_peer(&mut bgp, "10.0.0.3", OUR_AS, &fam, false);
    (bgp, a, rb, rc)
}

fn fs_name(afi: Afi, n: u8) -> String {
    fs_nlri(afi, n).to_string()
}

/// A flow spec carrying NO_ADVERTISE is sent to no peer (RFC 1997).
fn check_fs_no_advertise(afi: Afi) {
    let (mut bgp, a, mut rb, mut rc) = fs_topology(afi);
    fs_announce(&mut bgp, a, afi, 1, &[CommunityValue::NO_ADVERTISE]);
    assert_eq!(sent(&mut rb).advertised(), Vec::<String>::new(), "eBGP");
    assert_eq!(sent(&mut rc).advertised(), Vec::<String>::new(), "iBGP");
}

#[tokio::test]
async fn flowspec_v4_with_no_advertise_is_sent_to_no_peer() {
    check_fs_no_advertise(Afi::Ip);
}

#[tokio::test]
async fn flowspec_v6_with_no_advertise_is_sent_to_no_peer() {
    check_fs_no_advertise(Afi::Ip6);
}

/// A flow spec carrying NO_EXPORT stays inside the AS: not sent to the
/// eBGP neighbor, still sent to the iBGP one.
fn check_fs_no_export(afi: Afi) {
    let (mut bgp, a, mut rb, mut rc) = fs_topology(afi);
    fs_announce(&mut bgp, a, afi, 1, &[CommunityValue::NO_EXPORT]);
    assert_eq!(sent(&mut rb).advertised(), Vec::<String>::new(), "eBGP");
    assert_eq!(sent(&mut rc).advertised(), vec![fs_name(afi, 1)], "iBGP");
}

#[tokio::test]
async fn flowspec_v4_with_no_export_stays_inside_the_as() {
    check_fs_no_export(Afi::Ip);
}

#[tokio::test]
async fn flowspec_v6_with_no_export_stays_inside_the_as() {
    check_fs_no_export(Afi::Ip6);
}

/// An LLGR-stale flow spec goes only to neighbors that negotiated LLGR
/// (RFC 9494 §4.3); B and C did not.
fn check_fs_stale(afi: Afi) {
    let (mut bgp, a, mut rb, mut rc) = fs_topology(afi);
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: aspath("65001"),
        ..Default::default()
    };
    let mut best = BgpRib::new(
        a,
        Ipv4Addr::new(10, 0, 0, 1),
        BgpRibType::EBGP,
        0,
        0,
        &attr,
        None,
        None,
        false,
    );
    best.stale = true;
    let (mut top, peers) = split(&mut bgp);
    crate::bgp::route::route_advertise_flowspec_to_peers(
        afi,
        &fs_nlri(afi, 1),
        &best,
        &mut top,
        peers,
    );
    assert_eq!(sent(&mut rb).advertised(), Vec::<String>::new());
    assert_eq!(sent(&mut rc).advertised(), Vec::<String>::new());
}

#[tokio::test]
async fn flowspec_v4_stale_goes_only_to_llgr_peers() {
    check_fs_stale(Afi::Ip);
}

#[tokio::test]
async fn flowspec_v6_stale_goes_only_to_llgr_peers() {
    check_fs_stale(Afi::Ip6);
}

/// Found while gating: A re-announces the flow spec with NO_ADVERTISE —
/// the new best reaches no peer, so B and C are withdrawn the copy they
/// hold. They were skipped and kept it.
fn check_fs_unreached_peer_withdrawn(afi: Afi) {
    let (mut bgp, a, mut rb, mut rc) = fs_topology(afi);
    fs_announce(&mut bgp, a, afi, 1, &[]);
    assert_eq!(sent(&mut rb).advertised(), vec![fs_name(afi, 1)], "setup");
    assert_eq!(sent(&mut rc).advertised(), vec![fs_name(afi, 1)], "setup");

    fs_announce(&mut bgp, a, afi, 1, &[CommunityValue::NO_ADVERTISE]);
    assert_eq!(sent(&mut rb).wd, vec![fs_name(afi, 1)]);
    assert_eq!(sent(&mut rc).wd, vec![fs_name(afi, 1)]);
}

#[tokio::test]
async fn flowspec_v4_a_peer_the_new_best_does_not_reach_is_withdrawn() {
    check_fs_unreached_peer_withdrawn(Afi::Ip);
}

#[tokio::test]
async fn flowspec_v6_a_peer_the_new_best_does_not_reach_is_withdrawn() {
    check_fs_unreached_peer_withdrawn(Afi::Ip6);
}

/// Found while gating: a neighbor that comes up after a flow spec was
/// learned is sent it at session-up. The dump had no Flowspec step.
fn check_fs_session_up(afi: Afi) {
    let (mut bgp, a, _rb, _rc) = fs_topology(afi);
    fs_announce(&mut bgp, a, afi, 1, &[]);
    let (d, mut rd) = add_peer(&mut bgp, "10.0.0.4", 65004, &[fs_fam(afi)], false);
    {
        let (mut top, peers) = split(&mut bgp);
        route_sync(peers.get_mut_by_idx(d).unwrap(), &mut top, false);
    }
    assert_eq!(sent(&mut rd).advertised(), vec![fs_name(afi, 1)]);
}

#[tokio::test]
async fn flowspec_v4_a_late_peer_is_sent_the_flowspecs_held() {
    check_fs_session_up(Afi::Ip);
}

#[tokio::test]
async fn flowspec_v6_a_late_peer_is_sent_the_flowspecs_held() {
    check_fs_session_up(Afi::Ip6);
}

/// An out-policy bound on the family applies: B's denies every route, so
/// B is sent nothing; C, with none bound, still gets the flow spec. It was
/// accepted and never applied.
fn check_fs_out_policy(afi: Afi) {
    use crate::policy::{PolicyAction, PolicyList};
    let (mut bgp, a, mut rb, mut rc) = fs_topology(afi);
    let mut deny = PolicyList::default();
    deny.entry(10).action = PolicyAction::Deny;
    let b = bgp.peers.get(&"10.0.0.2".parse().unwrap()).unwrap().ident;
    let output = &mut bgp
        .peers
        .get_mut_by_idx(b)
        .unwrap()
        .policy_list
        .entry(fs_fam(afi))
        .or_default()
        .output;
    output.name = Some("deny-all".into());
    output.policy_list = Some(deny);

    fs_announce(&mut bgp, a, afi, 1, &[]);
    assert_eq!(sent(&mut rb).advertised(), Vec::<String>::new(), "denied");
    assert_eq!(sent(&mut rc).advertised(), vec![fs_name(afi, 1)]);
}

#[tokio::test]
#[ignore = "review finding #27 follow-up: Flowspec out-policy needs an attribute-only matcher"]
async fn flowspec_v4_out_policy_applies() {
    check_fs_out_policy(Afi::Ip);
}

#[tokio::test]
#[ignore = "review finding #27 follow-up: Flowspec out-policy needs an attribute-only matcher"]
async fn flowspec_v6_out_policy_applies() {
    check_fs_out_policy(Afi::Ip6);
}

// -------------------------------------------------------------------------
// SR Policy
// -------------------------------------------------------------------------

fn srp_fam(afi: Afi) -> AfiSafi {
    AfiSafi::new(afi, Safi::SrTePolicy)
}

fn srp_nlri(afi: Afi, color: u32) -> SrPolicyNlri {
    SrPolicyNlri {
        id: 0,
        distinguisher: 1,
        color,
        endpoint: if afi == Afi::Ip {
            "10.0.0.50".parse().unwrap()
        } else {
            "2001:db8::50".parse().unwrap()
        },
    }
}

fn srp_name(n: &SrPolicyNlri) -> String {
    format!("color {} endpoint {}", n.color, n.endpoint)
}

/// An IPv4-address Route Target naming a headend that is not us, so the
/// policy is reflected (RFC 9830 §4.2) but not consumed here.
fn rt_elsewhere() -> Option<ExtCommunity> {
    let mut val = [0u8; 6];
    val[0..4].copy_from_slice(&[10, 0, 0, 77]);
    Some(ExtCommunity::from([ExtCommunityValue {
        high_type: 0x01,
        low_type: 0x02,
        val,
    }]))
}

/// Neighbor `src` sends SR Policy `color` with `attr`.
fn srp_announce(bgp: &mut Bgp, src: usize, afi: Afi, color: u32, attr: BgpAttr) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(attr);
    packet.mp_update = Some(MpReachAttr::SrPolicy {
        afi,
        snpa: 0,
        nhop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        updates: vec![srp_nlri(afi, color)],
    });
    let (mut top, peers) = split(bgp);
    route_from_peer(src, packet, &mut top, peers, None);
}

/// An iBGP-learned policy's attributes: empty AS_PATH, LOCAL_PREF.
fn ibgp_srp_attr(cs: &[CommunityValue]) -> BgpAttr {
    BgpAttr {
        origin: Some(Origin::Igp),
        aspath: aspath(""),
        local_pref: Some(LocalPref::default()),
        ecom: rt_elsewhere(),
        com: coms(cs),
        ..Default::default()
    }
}

/// A (iBGP client, the source), B (eBGP), C (iBGP non-client).
fn srp_topology(afi: Afi) -> (Bgp, usize, Rx, Rx) {
    let mut bgp = fresh_bgp();
    let fam = [srp_fam(afi)];
    let (a, _ra) = add_peer(&mut bgp, "10.0.0.1", OUR_AS, &fam, true);
    let (_b, rb) = add_peer(&mut bgp, "10.0.0.2", 65002, &fam, false);
    let (_c, rc) = add_peer(&mut bgp, "10.0.0.3", OUR_AS, &fam, false);
    (bgp, a, rb, rc)
}

fn srp_wire(afi: Afi, color: u32) -> String {
    srp_name(&srp_nlri(afi, color))
}

/// A reflected SR Policy carrying NO_EXPORT stays inside the AS: not sent
/// to the eBGP neighbor, still reflected to the iBGP one.
fn check_srp_no_export(afi: Afi) {
    let (mut bgp, a, mut rb, mut rc) = srp_topology(afi);
    srp_announce(
        &mut bgp,
        a,
        afi,
        100,
        ibgp_srp_attr(&[CommunityValue::NO_EXPORT]),
    );
    assert_eq!(sent(&mut rb).advertised(), Vec::<String>::new(), "eBGP");
    assert_eq!(sent(&mut rc).advertised(), vec![srp_wire(afi, 100)], "iBGP");
}

#[tokio::test]
async fn sr_policy_v4_with_no_export_is_not_reflected_to_ebgp() {
    check_srp_no_export(Afi::Ip);
}

#[tokio::test]
async fn sr_policy_v6_with_no_export_is_not_reflected_to_ebgp() {
    check_srp_no_export(Afi::Ip6);
}

/// A policy reflected to an eBGP neighbor carries our AS on the AS_PATH
/// (RFC 4271 §5.1.2) and no LOCAL_PREF.
fn check_srp_ebgp_prepend(afi: Afi) {
    let (mut bgp, a, mut rb, _rc) = srp_topology(afi);
    srp_announce(&mut bgp, a, afi, 100, ibgp_srp_attr(&[]));
    let got = sent(&mut rb);
    assert_eq!(got.advertised(), vec![srp_wire(afi, 100)]);
    let attr = &got.adv[0].1;
    assert_eq!(attr.aspath, aspath("65000"), "our AS");
    assert_eq!(attr.local_pref, None);
}

#[tokio::test]
async fn sr_policy_v4_reflected_to_ebgp_carries_our_as() {
    check_srp_ebgp_prepend(Afi::Ip);
}

#[tokio::test]
async fn sr_policy_v6_reflected_to_ebgp_carries_our_as() {
    check_srp_ebgp_prepend(Afi::Ip6);
}

/// Found while gating: a policy learned from an eBGP neighbor and
/// reflected to an iBGP one carries LOCAL_PREF (RFC 4271 §5.1.5).
fn check_srp_ibgp_local_pref(afi: Afi) {
    let (mut bgp, _a, _rb, mut rc) = srp_topology(afi);
    let (e, _re) = add_peer(&mut bgp, "10.0.0.5", 65005, &[srp_fam(afi)], false);
    srp_announce(
        &mut bgp,
        e,
        afi,
        200,
        BgpAttr {
            origin: Some(Origin::Igp),
            aspath: aspath("65005"),
            ecom: rt_elsewhere(),
            ..Default::default()
        },
    );
    let got = sent(&mut rc);
    assert_eq!(got.advertised(), vec![srp_wire(afi, 200)]);
    assert_eq!(got.adv[0].1.local_pref, Some(LocalPref::default()));
}

#[tokio::test]
async fn sr_policy_v4_from_ebgp_reflected_to_ibgp_carries_local_pref() {
    check_srp_ibgp_local_pref(Afi::Ip);
}

#[tokio::test]
async fn sr_policy_v6_from_ebgp_reflected_to_ibgp_carries_local_pref() {
    check_srp_ibgp_local_pref(Afi::Ip6);
}

/// Our policy `GREEN`, targeted at headend 10.0.0.77, endpoint per `afi`.
fn configure_local_policy(bgp: &mut Bgp, afi: Afi) {
    let mut policy = LocalSrPolicy {
        color: Some(300),
        endpoint: Some(srp_nlri(afi, 300).endpoint),
        route_target: Some(Ipv4Addr::new(10, 0, 0, 77)),
        ..Default::default()
    };
    policy.segments.insert(
        1,
        crate::bgp::sr_policy::LocalSegment {
            mpls_label: Some(16002),
            srv6_sid: None,
        },
    );
    bgp.local_rib
        .sr_policy_local
        .policies
        .insert("GREEN".into(), policy);
}

/// Found while gating: our own policy carries an AS_PATH — empty toward
/// iBGP, our AS toward eBGP — and LOCAL_PREF toward iBGP. It went out with
/// no AS_PATH, a missing well-known attribute (RFC 7606: a receiver treats
/// the UPDATE as a withdraw), on origination and on the session-up dump.
fn check_srp_local_attrs(afi: Afi) {
    let mut bgp = fresh_bgp();
    let fam = [srp_fam(afi)];
    let (_b, mut rb) = add_peer(&mut bgp, "10.0.0.2", 65002, &fam, false);
    let (c, mut rc) = add_peer(&mut bgp, "10.0.0.3", OUR_AS, &fam, false);
    configure_local_policy(&mut bgp, afi);
    crate::bgp::route::srpolicy_origin_sync(&mut bgp, "GREEN");

    let to_ebgp = sent(&mut rb);
    assert_eq!(to_ebgp.advertised().len(), 1, "setup");
    assert_eq!(to_ebgp.adv[0].1.aspath, aspath("65000"), "eBGP: our AS");
    assert_eq!(to_ebgp.adv[0].1.local_pref, None);
    let to_ibgp = sent(&mut rc);
    assert_eq!(to_ibgp.adv[0].1.aspath, aspath(""), "iBGP: empty");
    assert_eq!(to_ibgp.adv[0].1.local_pref, Some(LocalPref::default()));

    // The session-up dump sends the same attributes.
    {
        let (top, peers) = split(&mut bgp);
        crate::bgp::route::route_sync_srpolicy(peers.get_mut_by_idx(c).unwrap(), &top);
    }
    let dumped = sent(&mut rc);
    assert_eq!(dumped.adv[0].1.aspath, aspath(""), "dump: empty");
    assert_eq!(dumped.adv[0].1.local_pref, Some(LocalPref::default()));
}

#[tokio::test]
async fn sr_policy_v4_local_carries_an_as_path_and_local_pref() {
    check_srp_local_attrs(Afi::Ip);
}

#[tokio::test]
async fn sr_policy_v6_local_carries_an_as_path_and_local_pref() {
    check_srp_local_attrs(Afi::Ip6);
}

/// A neighbor that comes up after a policy was reflected is sent it at
/// session-up. The dump replayed only our own policies.
fn check_srp_session_up(afi: Afi) {
    let (mut bgp, a, _rb, _rc) = srp_topology(afi);
    srp_announce(&mut bgp, a, afi, 100, ibgp_srp_attr(&[]));
    let (d, mut rd) = add_peer(&mut bgp, "10.0.0.4", OUR_AS, &[srp_fam(afi)], false);
    {
        let (mut top, peers) = split(&mut bgp);
        route_sync(peers.get_mut_by_idx(d).unwrap(), &mut top, false);
    }
    assert_eq!(sent(&mut rd).advertised(), vec![srp_wire(afi, 100)]);
}

#[tokio::test]
#[ignore = "review finding #27 follow-up: reflected SR Policies need a received-policy store to replay"]
async fn sr_policy_v4_a_late_peer_is_sent_the_policies_reflected_before() {
    check_srp_session_up(Afi::Ip);
}

#[tokio::test]
#[ignore = "review finding #27 follow-up: reflected SR Policies need a received-policy store to replay"]
async fn sr_policy_v6_a_late_peer_is_sent_the_policies_reflected_before() {
    check_srp_session_up(Afi::Ip6);
}

/// Control: the session-up dump sends what the other peers were sent, not
/// every selected flow spec — one that fails RFC 9117 validation (an eBGP
/// source with validation on and no unicast route behind the rule) is held
/// in the Loc-RIB but goes to no peer, the late one included.
#[tokio::test]
async fn flowspec_a_late_peer_is_not_sent_an_invalid_flowspec() {
    let (mut bgp, a, mut rb, _rc) = fs_topology(Afi::Ip);
    bgp.peers
        .get_mut_by_idx(a)
        .unwrap()
        .config
        .flowspec_validation = true;
    fs_announce(&mut bgp, a, Afi::Ip, 1, &[]);
    assert!(
        bgp.local_rib
            .flowspec_v4
            .selected
            .contains_key(&fs_nlri(Afi::Ip, 1)),
        "held in the Loc-RIB"
    );
    assert_eq!(sent(&mut rb).advertised(), Vec::<String>::new(), "invalid");
    let (d, mut rd) = add_peer(&mut bgp, "10.0.0.4", 65004, &[fs_fam(Afi::Ip)], false);
    {
        let (mut top, peers) = split(&mut bgp);
        route_sync(peers.get_mut_by_idx(d).unwrap(), &mut top, false);
    }
    assert_eq!(sent(&mut rd).advertised(), Vec::<String>::new());
}
