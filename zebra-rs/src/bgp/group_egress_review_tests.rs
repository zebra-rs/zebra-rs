//! Review finding #22: the gate-on group egress engine
//! (`ZEBRA_BGP_EGRESS_GROUP_TASK=1`) must withdraw a route from every
//! member it was sent to.
//!
//! The engine's withdraw skipped the member the caller named as the
//! source. The next-hop re-evaluation (both RIB layouts), the
//! `suppress-fib-pending` release and the VRF import toward CE peers name
//! no source and pass a literal `0` — the `PeerMap` index of the first
//! configured neighbor — so that neighbor kept every route those paths
//! withdraw. The member that never received the route is the one whose
//! path it was, and the engine holds that path in its Adj-RIB-Out.
//!
//! Found while gating: the advertise side had the mirror-image gap. When
//! a member's own path became the best, the engine fanned it to the
//! others and skipped the member (split horizon), but the member still
//! held the previous best we had sent it; a best path the build filtered
//! withdrew the previous one from everyone except the new path's source.
//! The gate-off path (`V4Batch`, one outcome per peer) withdraws in both
//! cases.

use super::*;
use bgp_packet::{BgpAttr, BgpNexthop, BgpPacket, Community, CommunityValue, ParseOption};

use super::super::route::BgpRibType;

/// A best-path row from peer `ident`, next-hop `nh`. Its AS_PATH names the
/// peer, so two peers' paths stay distinct after the eBGP egress rewrite
/// (the engine dedups an advertise whose built attributes it already sent).
fn rib(ident: usize, nh: &str) -> BgpRib {
    let attr = BgpAttr {
        origin: Some(bgp_packet::Origin::Igp),
        aspath: Some(
            <bgp_packet::As4Path as std::str::FromStr>::from_str(
                &(65100 + ident % 100).to_string(),
            )
            .unwrap(),
        ),
        nexthop: Some(BgpNexthop::Ipv4(nh.parse().unwrap())),
        ..Default::default()
    };
    BgpRib::new_arc(
        ident,
        "10.0.0.1".parse().unwrap(),
        BgpRibType::EBGP,
        0,
        100,
        Arc::new(attr),
        None,
        None,
        false,
    )
}

/// Member `ident` joins with its own identity (a real member's `SyncCtx`
/// carries its `PeerMap` index) and a readable packet channel.
fn member(engine: &mut Engine, ident: usize, add_path: bool) -> mpsc::UnboundedReceiver<BytesMut> {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut ctx = SyncCtx::for_test();
    ctx.ident = ident;
    ctx.packet_tx = Some(tx);
    engine.handle(GroupEgressDeltaV4::AddMember {
        ident,
        ctx: Box::new(ctx),
        add_path,
        after: None,
    });
    engine.flush_withdraws();
    rx
}

/// What a member was sent: `(advertised, withdrawn)` prefixes, in order.
fn sent(rx: &mut mpsc::UnboundedReceiver<BytesMut>) -> (Vec<String>, Vec<String>) {
    sent_with(rx, false)
}

/// [`sent`], parsing path identifiers when `add_path` (RFC 7911).
fn sent_with(
    rx: &mut mpsc::UnboundedReceiver<BytesMut>,
    add_path: bool,
) -> (Vec<String>, Vec<String>) {
    let mut opt = ParseOption::default();
    if add_path {
        opt.add_path.insert(
            bgp_packet::AfiSafi::new(bgp_packet::Afi::Ip, bgp_packet::Safi::Unicast),
            bgp_packet::Direct {
                recv: true,
                send: true,
            },
        );
    }
    let (mut adv, mut wd) = (Vec::new(), Vec::new());
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) =
            BgpPacket::parse_packet(&bytes, true, Some(opt.clone())).expect("a well-formed UPDATE");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        adv.extend(update.ipv4_update.iter().map(|n| n.prefix.to_string()));
        wd.extend(update.ipv4_withdraw.iter().map(|n| n.prefix.to_string()));
    }
    (adv, wd)
}

const P: &str = "10.22.0.0/24";

fn prefix() -> Ipv4Net {
    P.parse().unwrap()
}

/// A withdraw whose caller names no source — the next-hop re-evaluation,
/// the FIB-pending release and the VRF import pass `0` — reaches the
/// member in slot 0 too: it was sent the route (from a non-member).
#[test]
fn a_withdraw_reaches_the_member_in_slot_0() {
    let mut engine = Engine::default();
    let mut rx0 = member(&mut engine, 0, false);
    let mut rx1 = member(&mut engine, 1, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(99, "192.0.2.1"),
    });
    engine.flush_withdraws();
    assert_eq!(sent(&mut rx0).0, vec![P.to_string()], "setup");
    assert_eq!(sent(&mut rx1).0, vec![P.to_string()], "setup");

    engine.handle(GroupEgressDeltaV4::Withdraw {
        prefix: prefix(),
        id: 0,
    });

    engine.flush_withdraws();
    assert_eq!(sent(&mut rx0), (vec![], vec![P.to_string()]));
    assert_eq!(sent(&mut rx1), (vec![], vec![P.to_string()]));
}

/// The AddPath twin: a per-path withdraw naming no source reaches slot 0.
#[test]
fn an_addpath_withdraw_reaches_the_member_in_slot_0() {
    let mut engine = Engine::default();
    let mut rx0 = member(&mut engine, 0, true);
    let mut path = rib(99, "192.0.2.1");
    path.local_id = 11;
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: path,
    });
    engine.flush_withdraws();
    assert_eq!(sent_with(&mut rx0, true).0, vec![P.to_string()], "setup");

    engine.handle(GroupEgressDeltaV4::Withdraw {
        prefix: prefix(),
        id: 11,
    });

    engine.flush_withdraws();
    assert_eq!(sent_with(&mut rx0, true), (vec![], vec![P.to_string()]));
}

/// The member left out of a withdraw is the one whose path was advertised
/// — it never received it — whatever source the caller names.
#[test]
fn a_withdraw_skips_only_the_member_whose_path_it_was() {
    let mut engine = Engine::default();
    let mut rx0 = member(&mut engine, 0, false);
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(1, "192.0.2.1"),
    });
    engine.flush_withdraws();
    assert!(sent(&mut rx1).0.is_empty(), "split horizon");
    sent(&mut rx0);
    sent(&mut rx2);

    engine.handle(GroupEgressDeltaV4::Withdraw {
        prefix: prefix(),
        id: 0,
    });

    engine.flush_withdraws();
    assert_eq!(sent(&mut rx0), (vec![], vec![P.to_string()]));
    assert_eq!(sent(&mut rx1), (vec![], vec![]), "never sent the route");
    assert_eq!(sent(&mut rx2), (vec![], vec![P.to_string()]));
}

/// Found while gating: member 1's own path becomes the best. Member 2 is
/// sent it; member 1 is not (split horizon) and must be withdrawn the
/// previous best we sent it — it kept that route.
#[test]
fn the_member_whose_path_becomes_best_is_withdrawn_the_route_it_held() {
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(99, "192.0.2.1"),
    });
    engine.flush_withdraws();
    sent(&mut rx1);
    sent(&mut rx2);

    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(1, "192.0.2.2"),
    });

    engine.flush_withdraws();
    assert_eq!(sent(&mut rx2), (vec![P.to_string()], vec![]));
    assert_eq!(
        sent(&mut rx1),
        (vec![], vec![P.to_string()]),
        "member 1 still held the previous best"
    );
}

/// Control: when the best moves back to a non-member, the member whose
/// path it was is sent the new best — it held nothing from us.
#[test]
fn the_member_whose_path_stops_being_best_is_sent_the_new_best() {
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(1, "192.0.2.2"),
    });
    engine.flush_withdraws();
    sent(&mut rx1);
    sent(&mut rx2);

    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(99, "192.0.2.1"),
    });

    engine.flush_withdraws();
    assert_eq!(sent(&mut rx1), (vec![P.to_string()], vec![]));
    assert_eq!(sent(&mut rx2), (vec![P.to_string()], vec![]));
}

/// Found while gating: member 1's own path becomes the best but the build
/// filters it (NO_ADVERTISE), so the previous best is withdrawn — from
/// member 1 too, which held it.
#[test]
fn a_filtered_best_path_withdraws_the_previous_route_from_its_source_member() {
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(99, "192.0.2.1"),
    });
    engine.flush_withdraws();
    sent(&mut rx1);
    sent(&mut rx2);

    let mut filtered = rib(1, "192.0.2.2");
    let mut attr = (*filtered.attr).clone();
    attr.com = Some(Community::from([CommunityValue::NO_ADVERTISE.value()]));
    filtered.attr = Arc::new(attr);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: filtered,
    });
    engine.flush_withdraws();
    assert_eq!(sent(&mut rx2), (vec![], vec![P.to_string()]));
    assert_eq!(
        sent(&mut rx1),
        (vec![], vec![P.to_string()]),
        "member 1 held the previous best"
    );
}

/// Found while gating, the dedup edge: member 1's path becomes the best
/// and builds the very UPDATE already sent (same AS_PATH; the eBGP egress
/// rewrites the next-hop). Member 2 is sent nothing new — it holds that
/// UPDATE — but member 1 still held the previous best and is withdrawn it.
#[test]
fn a_new_best_that_builds_the_same_update_still_withdraws_its_source_member() {
    let same_path = |ident: usize, nh: &str| {
        let mut r = rib(ident, nh);
        let mut attr = (*r.attr).clone();
        attr.aspath = Some(<bgp_packet::As4Path as std::str::FromStr>::from_str("65200").unwrap());
        r.attr = Arc::new(attr);
        r
    };
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: same_path(99, "192.0.2.1"),
    });
    engine.flush_withdraws();
    sent(&mut rx1);
    sent(&mut rx2);

    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: same_path(1, "192.0.2.2"),
    });

    engine.flush_withdraws();
    assert_eq!(
        sent(&mut rx2),
        (vec![], vec![]),
        "already holds this UPDATE"
    );
    assert_eq!(
        sent(&mut rx1),
        (vec![], vec![P.to_string()]),
        "member 1 still held the previous best"
    );
}

/// Found while gating, the sole-member edge: member 1 is the group's only
/// member and its own path becomes the best. Nobody is sent it, but member
/// 1 still held the previous best and is withdrawn it (the early return
/// for "no member to send to" left it standing).
#[test]
fn a_sole_member_whose_path_becomes_best_is_withdrawn_the_route_it_held() {
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(99, "192.0.2.1"),
    });
    engine.flush_withdraws();
    assert_eq!(sent(&mut rx1).0, vec![P.to_string()], "setup");

    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: rib(1, "192.0.2.2"),
    });

    engine.flush_withdraws();
    assert_eq!(sent(&mut rx1), (vec![], vec![P.to_string()]));
    assert!(
        !engine.adj_out.0.contains_key(&prefix()),
        "nothing is left advertised"
    );
}

/// Review follow-up: the best moves from member 1's path to member 2's and
/// builds the same UPDATE (same AS_PATH; the eBGP egress rewrites the
/// next-hop). Member 3 already holds it and is sent nothing; member 2 is
/// withdrawn the route (its own path now); member 1 — kept from the UPDATE
/// while the path was its own — is sent it. The dedup sent member 1
/// nothing, leaving it without the route until further churn.
#[test]
fn a_best_moving_between_members_with_the_same_update_reaches_the_previous_source() {
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    let mut rx3 = member(&mut engine, 3, false);
    let first = rib(1, "192.0.2.1");
    let mut second = first.clone();
    second.ident = 2;
    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: first,
    });
    engine.flush_withdraws();
    assert_eq!(sent(&mut rx1), (vec![], vec![]), "split horizon");
    assert_eq!(sent(&mut rx2), (vec![P.to_string()], vec![]));
    assert_eq!(sent(&mut rx3), (vec![P.to_string()], vec![]));

    engine.handle(GroupEgressDeltaV4::Advertise {
        prefix: prefix(),
        rib: second,
    });

    engine.flush_withdraws();
    assert_eq!(
        sent(&mut rx3),
        (vec![], vec![]),
        "already holds this UPDATE"
    );
    assert_eq!(sent(&mut rx2), (vec![], vec![P.to_string()]));
    assert_eq!(
        sent(&mut rx1),
        (vec![P.to_string()], vec![]),
        "member 1 was kept from the UPDATE while the path was its own"
    );
}

/// Control: member 1's own path, advertised again unchanged, still sends
/// member 1 nothing — the dedup's recipient check never hands a member its
/// own path.
#[test]
fn an_unchanged_re_advertise_of_a_members_own_path_sends_it_nothing() {
    let mut engine = Engine::default();
    let mut rx1 = member(&mut engine, 1, false);
    let mut rx2 = member(&mut engine, 2, false);
    for _ in 0..2 {
        engine.handle(GroupEgressDeltaV4::Advertise {
            prefix: prefix(),
            rib: rib(1, "192.0.2.1"),
        });
        engine.flush_withdraws();
    }
    assert_eq!(sent(&mut rx1), (vec![], vec![]), "split horizon");
    assert_eq!(sent(&mut rx2), (vec![P.to_string()], vec![]), "sent once");
}
