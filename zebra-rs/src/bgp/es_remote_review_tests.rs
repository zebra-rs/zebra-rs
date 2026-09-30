//! Phase 3c review probes. Run with:
//! `cargo test -p zebra-rs es_remote_review_tests -- --nocapture`
//! Assertions describe the intended behavior; retained failures reproduce
//! the review findings without relying on BGP convergence timing.

use super::*;
use crate::bgp::ethernet_segment::SaSelectReason;
use tokio::sync::mpsc;

const ESI: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const BD: u32 = 10;

fn fresh_bgp() -> Bgp {
    let (rib_tx, _) = mpsc::unbounded_channel();
    let (rib_inbound_tx, _) = mpsc::unbounded_channel();
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    Bgp::new(
        crate::context::ProtoContext::default_table_no_rib(),
        mpsc::unbounded_channel().1,
        subscriber,
        mpsc::unbounded_channel().0,
        None,
        None,
        mpsc::channel(1).0,
    )
}

fn pe(n: u8) -> IpAddr {
    Ipv4Addr::new(192, 0, 2, n).into()
}

fn rd(n: u8) -> RouteDistinguisher {
    format!("65000:{n}").parse().unwrap()
}

fn add_member(bgp: &mut Bgp, n: u8, single_active: bool, primary: bool) {
    for eth_tag in [MAX_ET, 0] {
        let mut ec = ExtCommunity::default();
        ec.0.insert(ExtCommunityValue {
            high_type: 0,
            low_type: 2,
            val: [0xfd, 0xe8, 0, 0, 0, BD as u8],
        });
        ec.0.insert(if eth_tag == MAX_ET {
            ExtCommunityValue::esi_label(single_active, 0)
        } else {
            ExtCommunityValue::l2_attr(primary, !primary, false, 0)
        });
        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Evpn(pe(n))),
            ecom: Some(ec),
            ..Default::default()
        };
        let rib = BgpRib::new(
            n as usize,
            Ipv4Addr::new(10, 0, 0, n),
            BgpRibType::IBGP,
            0,
            0,
            &attr,
            None,
            None,
            false,
        );
        bgp.local_rib
            .update_evpn(rd(n), EvpnPrefix::EthernetAd { esi: ESI, eth_tag }, rib);
    }
}

#[tokio::test]
async fn generation_advances_on_an_ordinary_forwarder_move() {
    let mut bgp = fresh_bgp();
    add_member(&mut bgp, 1, true, true);
    add_member(&mut bgp, 2, true, false);
    bgp.evpn_es_nhg_sync();
    let before = bgp.es_remote[&(ESI, BD)].generation;
    add_member(&mut bgp, 1, true, false);
    add_member(&mut bgp, 2, true, true);
    bgp.evpn_es_nhg_sync();
    assert_eq!(bgp.es_remote[&(ESI, BD)].active, Some(pe(2)));
    assert_eq!(bgp.es_remote[&(ESI, BD)].generation, before + 1);
}

#[tokio::test]
async fn generation_is_not_reused_after_group_disappears() {
    let mut bgp = fresh_bgp();
    add_member(&mut bgp, 1, true, true);
    bgp.evpn_es_nhg_sync();
    let before = bgp.es_remote[&(ESI, BD)].generation;
    bgp.local_rib.evpn.clear();
    bgp.evpn_es_nhg_sync();
    assert!(!bgp.es_remote.contains_key(&(ESI, BD)));
    assert!(!bgp.es_nhg_sent.contains_key(&(ESI, BD)));
    add_member(&mut bgp, 2, true, true);
    bgp.evpn_es_nhg_sync();
    assert_eq!(bgp.es_remote[&(ESI, BD)].active, Some(pe(2)));
    assert!(
        bgp.es_remote[&(ESI, BD)].generation > before,
        "different forwarders must not reuse generation {before} across a disappearance"
    );
}

#[tokio::test]
async fn generation_is_not_reused_after_all_active_interval() {
    let mut bgp = fresh_bgp();
    add_member(&mut bgp, 1, true, true);
    bgp.evpn_es_nhg_sync();
    let before = bgp.es_remote[&(ESI, BD)].generation;
    add_member(&mut bgp, 1, false, true);
    bgp.evpn_es_nhg_sync();
    assert!(!bgp.es_remote.contains_key(&(ESI, BD)));
    assert!(!bgp.es_nhg_sent[&(ESI, BD)].0);
    add_member(&mut bgp, 1, true, false);
    add_member(&mut bgp, 2, true, true);
    bgp.evpn_es_nhg_sync();
    assert_eq!(bgp.es_remote[&(ESI, BD)].active, Some(pe(2)));
    assert!(
        bgp.es_remote[&(ESI, BD)].generation > before,
        "different forwarders must not reuse generation {before} across all-active mode"
    );
}

#[tokio::test]
async fn show_reason_matches_the_decision_that_installed_the_forwarder() {
    let mut bgp = fresh_bgp();
    add_member(&mut bgp, 1, true, true);
    add_member(&mut bgp, 2, true, true);
    bgp.evpn_es_nhg_sync();
    let chosen = &bgp.es_remote[&(ESI, BD)];
    assert_eq!(chosen.active, Some(pe(1)));
    assert_eq!(chosen.reason, Some(SaSelectReason::ConflictTieBreak));
    // This is the exact accessor used by write_es_nhg_groups for `show`.
    assert_eq!(
        bgp.es_group_selection(&ESI, BD),
        chosen.reason,
        "the newly chosen primary was not an incumbent when this decision was made"
    );
}

#[tokio::test]
async fn provenance_keeps_both_rr_copies_and_the_survivor() {
    let mut bgp = fresh_bgp();
    add_member(&mut bgp, 1, true, true);
    let prefix = EvpnPrefix::EthernetAd {
        esi: ESI,
        eth_tag: 0,
    };
    let mut copy = bgp.local_rib.evpn[&rd(1)].selected[&prefix].clone();
    copy.ident = 99;
    copy.router_id = Ipv4Addr::new(10, 0, 0, 99);
    copy.remote_id = 42;
    copy.stale = true;
    bgp.local_rib.update_evpn(rd(1), prefix.clone(), copy);
    bgp.evpn_es_nhg_sync();
    let paths = &bgp.es_remote[&(ESI, BD)].members[&pe(1)].paths;
    assert_eq!(paths.len(), 2);
    assert_eq!(paths.iter().filter(|p| p.best).count(), 1);
    assert!(paths.iter().any(|p| p.path_id == 42 && p.stale && !p.best));
    bgp.local_rib.remove_evpn(rd(1), &prefix, 0, 1);
    bgp.local_rib.select_best_path_evpn(&rd(1), &prefix);
    bgp.evpn_es_nhg_sync();
    let member = &bgp.es_remote[&(ESI, BD)].members[&pe(1)];
    assert_eq!(member.paths.len(), 1);
    assert!(member.paths[0].best && member.paths[0].stale);
    assert_eq!(member.paths[0].path_id, 42);
    assert_eq!(bgp.es_remote[&(ESI, BD)].active, Some(pe(1)));
}
