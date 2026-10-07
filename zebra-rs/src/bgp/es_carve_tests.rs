//! RFC 9722 synchronized service carving, driven through `evpn_es_df_sync`
//! rather than through BGP convergence — the deferral is a timing behaviour,
//! and a test that waited on real timers would be a race.
//!
//! `cargo test -p zebra-rs es_carve_tests`

use super::*;
use crate::bgp::ethernet_segment::{EsRedundancyMode, EthernetSegment, SctReject};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

const ESI: [u8; 10] = [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
const BD: u32 = 10;
const PORT: &str = "host0";
const IFINDEX: u32 = 42;

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

/// A local segment on `host0`, in bridge domain `BD`, single-active.
/// `fast_recovery` decides whether this PE synchronizes at all.
fn local_segment(bgp: &mut Bgp, fast_recovery: bool) {
    bgp.router_id = Ipv4Addr::new(192, 0, 2, 1);
    bgp.ethernet_segments.insert(
        "es1".to_string(),
        EthernetSegment {
            esi: Some(ESI),
            redundancy_mode: EsRedundancyMode::SingleActive,
            interface: Some(PORT.to_string()),
            fast_recovery,
            // 2 s window, 100 ms step-down lead — far enough apart that the
            // two deadlines are unambiguous.
            peering_time: Some(2),
            skew_ms: Some(100),
            ..Default::default()
        },
    );
    bgp.link_index_by_name.insert(PORT.to_string(), IFINDEX);
    bgp.l2_port_evis
        .insert(IFINDEX, std::iter::once(BD).collect());
}

fn me() -> IpAddr {
    Ipv4Addr::new(192, 0, 2, 1).into()
}

fn peer(n: u8) -> IpAddr {
    Ipv4Addr::new(192, 0, 2, n).into()
}

/// A Type-4 for `pe` carrying a DF Election EC — `pref` under Alg 2, `t`
/// deciding whether it signals RFC 9722, and `sct` its announced instant.
fn add_type4(bgp: &mut Bgp, pe: IpAddr, pref: u16, t: bool, sct: Option<bgp_packet::SctEc>) {
    let mut df = bgp_packet::DfElectionEc {
        df_alg: bgp_packet::DfElectionEc::ALG_PREF,
        bitmap: 0,
        pref,
    };
    df.set_time_sync(t);
    let mut ec = ExtCommunity::default();
    ec.0.insert(ExtCommunityValue::es_import_rt(&ESI));
    ec.0.insert(df.into());
    if let Some(sct) = sct {
        ec.0.insert(sct.into());
    }
    let attr = BgpAttr {
        nexthop: Some(BgpNexthop::Evpn(pe)),
        ecom: Some(ec),
        ..Default::default()
    };
    let last = match pe {
        IpAddr::V4(v4) => v4.octets()[3],
        _ => 0,
    };
    let rib = BgpRib::new(
        last as usize,
        Ipv4Addr::new(10, 0, 0, last),
        if pe == me() {
            BgpRibType::Originated
        } else {
            BgpRibType::IBGP
        },
        0,
        0,
        &attr,
        None,
        None,
        false,
    );
    let rd: RouteDistinguisher = format!("65000:{last}").parse().unwrap();
    bgp.local_rib
        .update_evpn(rd, EvpnPrefix::EthernetSeg { esi: ESI, orig: pe }, rib);
}

/// The DF role this PE last teed for `BD`.
fn teed_role(bgp: &Bgp) -> Option<bool> {
    bgp.es_df_sent
        .get(&ESI)
        .and_then(|s| s.roles.get(&BD))
        .map(|(df, _)| *df)
}

fn sct_in(ahead: Duration) -> bgp_packet::SctEc {
    bgp_packet::SctEc::from_system_time(SystemTime::now() + ahead)
}

/// Without `fast-recovery` nothing is synchronized: the election applies the
/// moment it moves, which is what every segment did before this phase.
#[tokio::test]
async fn a_segment_without_fast_recovery_carves_immediately() {
    let mut bgp = fresh_bgp();
    local_segment(&mut bgp, false);
    // Alone on the segment: this PE is the DF.
    add_type4(&mut bgp, me(), 200, false, None);
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(true));
    assert!(bgp.es_carve.is_empty(), "nothing to wait for");

    // A peer outranks us, announcing an instant 2 s out. We do not signal T,
    // so the segment cannot synchronize and the role moves at once.
    add_type4(
        &mut bgp,
        peer(2),
        300,
        true,
        Some(sct_in(Duration::from_secs(2))),
    );
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(false));
    assert!(bgp.es_carve.is_empty());
}

/// With the whole segment signalling T, a peer's announced instant holds this
/// PE's role where it is — and releases it once the moment has come.
#[tokio::test]
async fn a_pending_carve_holds_the_role_then_releases_it() {
    let mut bgp = fresh_bgp();
    local_segment(&mut bgp, true);
    add_type4(&mut bgp, me(), 200, true, None);
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(true), "DF while alone");

    // A peer joins with a better preference and announces 2 s out. The
    // election says we lose the role; the announcement says not yet.
    add_type4(
        &mut bgp,
        peer(2),
        300,
        true,
        Some(sct_in(Duration::from_secs(2))),
    );
    bgp.evpn_es_df_sync();
    assert_eq!(
        teed_role(&bgp),
        Some(true),
        "the role is HELD until the announced instant"
    );
    let carve = bgp.es_carve.get(&ESI).copied().expect("carve pending");
    assert!(!carve.own, "a peer announced it");

    // Reach the moment. Pushing the stored deadline into the past is how the
    // test stands in for the timer — the stored instant is kept for an
    // announcement already being waited on, which is what makes this stable.
    bgp.es_carve.get_mut(&ESI).unwrap().sct = Instant::now() - Duration::from_millis(1);
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(false), "released at its moment");
}

/// RFC 9722 §2.3: one PE that does not signal T takes the whole segment off
/// synchronized carving. Holding a role for an instant the others will ignore
/// opens a longer gap than not synchronizing at all.
#[tokio::test]
async fn one_pe_without_t_takes_the_segment_off_synchronization() {
    let mut bgp = fresh_bgp();
    local_segment(&mut bgp, true);
    add_type4(&mut bgp, me(), 200, true, None);
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(true));

    // The joining peer outranks us and announces an instant, but does NOT
    // signal the capability.
    add_type4(
        &mut bgp,
        peer(2),
        300,
        false,
        Some(sct_in(Duration::from_secs(2))),
    );
    bgp.evpn_es_df_sync();
    assert!(
        bgp.es_carve.is_empty(),
        "no synchronization without unanimity"
    );
    assert_eq!(teed_role(&bgp), Some(false), "so the role moves at once");
}

/// An instant outside our own peering window is not waited for: a peer with a
/// skewed clock must not be able to park the election. The rejection is
/// recorded, because "it carved immediately" is something an operator has to
/// be able to see.
#[tokio::test]
async fn an_instant_outside_the_window_is_rejected_and_recorded() {
    let mut bgp = fresh_bgp();
    local_segment(&mut bgp, true);
    add_type4(&mut bgp, me(), 200, true, None);
    bgp.evpn_es_df_sync();

    // Our peering interval is 2 s; the peer names an instant a minute out.
    add_type4(
        &mut bgp,
        peer(2),
        300,
        true,
        Some(sct_in(Duration::from_secs(60))),
    );
    bgp.evpn_es_df_sync();
    assert!(bgp.es_carve.is_empty());
    assert_eq!(bgp.es_sct_reject.get(&ESI), Some(&SctReject::TooFarAhead));
    assert_eq!(teed_role(&bgp), Some(false), "carved immediately");

    // An instant already gone is rejected the same way, and the reason
    // updates rather than sticking at the old one.
    add_type4(
        &mut bgp,
        peer(2),
        300,
        true,
        Some(bgp_packet::SctEc::from_system_time(
            SystemTime::now() - Duration::from_secs(5),
        )),
    );
    bgp.evpn_es_df_sync();
    assert_eq!(bgp.es_sct_reject.get(&ESI), Some(&SctReject::InThePast));
}

/// A wake-up for an instant that is no longer the one being waited for is
/// discarded: a later announcement supersedes an earlier one, and carving
/// against the old deadline would undo the synchronization.
#[tokio::test]
async fn a_superseded_wake_up_is_discarded() {
    let mut bgp = fresh_bgp();
    local_segment(&mut bgp, true);
    add_type4(&mut bgp, me(), 200, true, None);
    // Establish the role FIRST: a bridge domain with nothing programmed yet
    // has no role to hold, so a carve cannot defer anything there. Adding
    // both Type-4s before the first sync would test the wrong thing.
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(true), "DF while alone");
    add_type4(
        &mut bgp,
        peer(2),
        300,
        true,
        Some(sct_in(Duration::from_secs(2))),
    );
    bgp.evpn_es_df_sync();
    assert_eq!(teed_role(&bgp), Some(true), "held");
    let pending = bgp.es_carve.get(&ESI).copied().expect("carve pending");

    // A wake-up for some other deadline must not release the hold.
    bgp.es_carve_due(ESI, Instant::now() + Duration::from_secs(900));
    assert_eq!(teed_role(&bgp), Some(true), "still held");
    assert_eq!(bgp.es_carve.get(&ESI).copied(), Some(pending));

    // The real deadline retires the carve.
    bgp.es_carve_due(ESI, pending.sct);
    assert!(bgp.es_carve.is_empty(), "the instant retires the carve");
}
