//! Retained regression probes for the BGP-LS egress review.
use super::*;
use crate::policy::{NumericMatch, PolicyAction, PolicyEntry};

fn entry(action: PolicyAction) -> PolicyEntry {
    PolicyEntry {
        action,
        ..Default::default()
    }
}

fn policy(entries: Vec<PolicyEntry>) -> PolicyList {
    PolicyList {
        entry: entries
            .into_iter()
            .enumerate()
            .map(|(i, e)| (i as u32 * 10, e))
            .collect(),
        ..Default::default()
    }
}

fn evaluate(list: &PolicyList) -> Option<BgpAttr> {
    let mut attr = BgpAttr::new();
    attr.origin = Some(Origin::Igp);
    policy_list_apply_bgpls(list, attr, 0, Ipv4Addr::UNSPECIFIED)
}

#[test]
fn bgpls_review_unresolved_match_sets_deny_before_fallback_permit() {
    for kind in 0..4 {
        let mut conditional = entry(PolicyAction::Permit);
        match kind {
            0 => conditional.community_set_name = Some("MISSING".into()),
            1 => conditional.ext_community_set_name = Some("MISSING".into()),
            2 => conditional.large_community_set_name = Some("MISSING".into()),
            _ => conditional.as_path_set_name = Some("MISSING".into()),
        }
        assert!(
            evaluate(&policy(vec![conditional, entry(PolicyAction::Permit)])).is_none(),
            "unresolved set kind {kind} must deny"
        );
    }
}

#[test]
fn bgpls_review_called_deny_is_not_rescued_by_fallback() {
    let mut caller = entry(PolicyAction::Next);
    caller.call_name = Some("DENY".into());
    caller.call_policy = Some(Arc::new(policy(vec![entry(PolicyAction::Deny)])));
    assert!(evaluate(&policy(vec![caller, entry(PolicyAction::Permit)])).is_none());
}

#[test]
fn bgpls_review_callee_color_reaches_subsequent_match() {
    let mut set = entry(PolicyAction::Permit);
    set.set_color = Some(100);
    let mut caller = entry(PolicyAction::Next);
    caller.call_name = Some("COLOR".into());
    caller.call_policy = Some(Arc::new(policy(vec![set])));
    let mut accept = entry(PolicyAction::Permit);
    accept.match_color = Some(100);
    let out = evaluate(&policy(vec![caller, accept, entry(PolicyAction::Deny)]))
        .expect("a callee's set color must be visible to the caller");
    assert!(
        out.ecom
            .unwrap()
            .0
            .iter()
            .filter_map(|v| v.as_color())
            .any(|c| c.color == 100)
    );
}

#[test]
fn bgpls_review_nonmatching_entry_does_not_execute_unresolved_call() {
    let mut conditional = entry(PolicyAction::Next);
    conditional.match_origin = Some(Origin::Egp);
    conditional.call_name = Some("MISSING".into());
    assert!(
        evaluate(&policy(vec![conditional, entry(PolicyAction::Permit)])).is_some(),
        "an IGP object must skip an EGP-only entry before executing its call"
    );
}

#[test]
fn bgpls_review_set_weight_is_visible_to_later_deny() {
    let mut set = entry(PolicyAction::Next);
    set.weight = Some(100);
    let mut deny = entry(PolicyAction::Deny);
    deny.match_weight = Some(NumericMatch::Eq(100));
    assert!(
        evaluate(&policy(vec![set, deny, entry(PolicyAction::Permit)])).is_none(),
        "set weight 100 must make the following match weight 100 deny fire"
    );
}

fn peer() -> Peer {
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    Peer::new(
        1,
        65001,
        "192.0.2.1".parse().unwrap(),
        65002,
        "192.0.2.2".parse().unwrap(),
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    )
}

#[test]
fn bgpls_review_oversized_replacement_withdraws_then_small_restores() {
    use bgp_packet::{LsNodeDescSub, LsNodeDescriptor, LsNodeNlri, LsProtocolId};
    let nlri = BgpLsNlri::Node(LsNodeNlri {
        protocol_id: LsProtocolId::IsisL2,
        identifier: 0,
        local_node: LsNodeDescriptor {
            subs: vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 1])],
        },
    });
    let mut peer = peer();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    peer.packet_tx = Some(tx);
    let nhop = IpAddr::V4(peer.router_id);
    let small = bgpls_egress_attr(&peer, &BgpAttr::new());
    bgpls_send_reach(&mut peer, nhop, &nlri, small.clone());
    let first = rx.try_recv().expect("initial advertisement");
    let (_, decoded) = UpdatePacket::parse_packet(&first, peer.as4, None).unwrap();
    assert!(matches!(
        decoded.mp_update,
        Some(MpReachAttr::LinkState { .. })
    ));
    assert!(peer.adj_out.bgp_ls.0.contains_key(&nlri));

    let mut large = small.clone();
    let mut ls = BgpLsAttr::new();
    ls.push(1024, vec![0; 5000]);
    large.bgp_ls = Some(ls);
    bgpls_send_reach(&mut peer, nhop, &nlri, large);
    let withdraw = rx
        .try_recv()
        .expect("oversized replacement must withdraw old copy");
    assert!(withdraw.len() <= 4096);
    let (_, decoded) = UpdatePacket::parse_packet(&withdraw, peer.as4, None).unwrap();
    assert!(
        matches!(decoded.mp_withdraw, Some(MpUnreachAttr::LinkState { withdraws }) if withdraws == vec![nlri.clone()])
    );
    assert!(!peer.adj_out.bgp_ls.0.contains_key(&nlri));
    assert!(rx.try_recv().is_err());

    bgpls_send_reach(&mut peer, nhop, &nlri, small);
    let restored = rx
        .try_recv()
        .expect("small replacement restores the object");
    let (_, decoded) = UpdatePacket::parse_packet(&restored, peer.as4, None).unwrap();
    assert!(
        matches!(decoded.mp_update, Some(MpReachAttr::LinkState { updates, .. }) if updates == vec![nlri.clone()])
    );
    assert!(peer.adj_out.bgp_ls.0.contains_key(&nlri));
}

#[test]
fn bgpls_review_callee_weight_reaches_subsequent_match() {
    let mut set = entry(PolicyAction::Permit);
    set.weight = Some(100);
    let mut caller = entry(PolicyAction::Next);
    caller.call_name = Some("WEIGHT".into());
    caller.call_policy = Some(Arc::new(policy(vec![set])));
    let mut deny = entry(PolicyAction::Deny);
    deny.match_weight = Some(NumericMatch::Eq(100));
    assert!(evaluate(&policy(vec![caller, deny, entry(PolicyAction::Permit)])).is_none());
}

#[test]
fn bgpls_review_set_tag_is_visible_to_later_deny() {
    let mut set = entry(PolicyAction::Next);
    set.set_tag = Some(100);
    let mut deny = entry(PolicyAction::Deny);
    deny.match_tag = Some(100);
    assert!(
        evaluate(&policy(vec![set, deny, entry(PolicyAction::Permit)])).is_none(),
        "set tag 100 must make the following match tag 100 deny fire"
    );
}

fn node() -> BgpLsNlri {
    use bgp_packet::{LsNodeDescSub, LsNodeDescriptor, LsNodeNlri, LsProtocolId};
    BgpLsNlri::Node(LsNodeNlri {
        protocol_id: LsProtocolId::IsisL2,
        identifier: 0,
        local_node: LsNodeDescriptor {
            subs: vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 1])],
        },
    })
}

#[test]
fn bgpls_review_policy_next_hop_reaches_mp_reach() {
    use crate::policy::SetNextHop;
    for address in ["192.0.2.99", "2001:db8::99"] {
        let expected: IpAddr = address.parse().unwrap();
        let mut set = entry(PolicyAction::Permit);
        set.set_next_hop = Some(SetNextHop::Address(expected));
        let mut peer = peer();
        let slot =
            peer.policy_list_slot(AfiSafi::new(Afi::LinkState, Safi::LinkState), InOut::Output);
        slot.name = Some("NEXTHOP".into());
        slot.policy_list = Some(policy(vec![set]));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        peer.packet_tx = Some(tx);
        let attr = bgpls_out_attr(&mut peer, &BgpAttr::new(), 0).expect("permitted");
        let default_nhop = IpAddr::V4(peer.router_id);
        // This is the same call shape used by delta and synchronization paths.
        bgpls_send_reach(&mut peer, default_nhop, &node(), attr);
        let bytes = rx.try_recv().expect("advertisement");
        let (_, decoded) = UpdatePacket::parse_packet(&bytes, peer.as4, None).unwrap();
        let Some(MpReachAttr::LinkState { nhop, .. }) = decoded.mp_update else {
            panic!("expected BGP-LS MP_REACH");
        };
        assert_eq!(nhop, expected, "policy next hop must reach MP_REACH");
    }
}

#[test]
fn bgpls_review_packet_size_boundaries_and_queue_drain() {
    for limit in [4096, 65535] {
        let make = |value_len| {
            let mut update = UpdatePacket::with_max_packet_size(limit);
            update.mp_update = Some(MpReachAttr::LinkState {
                nhop: "192.0.2.1".parse().unwrap(),
                updates: vec![node()],
            });
            let mut attr = BgpAttr::new();
            attr.origin = Some(Origin::Igp);
            attr.aspath = Some(As4Path::from(vec![65001]));
            let mut ls = BgpLsAttr::new();
            ls.push(1024, vec![0; value_len]);
            attr.bgp_ls = Some(ls);
            update.bgp_attr = Some(attr);
            update
        };
        // Use an extended-length attribute in both measurements so header size
        // stays constant at the exact limit and one byte beyond it.
        let baseline = make(300).pop_bgpls().unwrap();
        let overhead = baseline.len() - 300;
        let mut exact = make(limit - overhead);
        let bytes = exact.pop_bgpls().expect("exactly the limit fits");
        assert_eq!(bytes.len(), limit);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]) as usize, limit);
        assert!(
            exact.pop_bgpls().is_none(),
            "successful send drains the queue"
        );
        let mut over = make(limit - overhead + 1);
        assert!(
            over.pop_bgpls().is_none(),
            "one byte over the limit is rejected"
        );
        assert!(
            matches!(over.mp_update, Some(MpReachAttr::LinkState { updates, .. }) if updates.is_empty())
        );
    }
}

#[test]
fn bgpls_review_initial_weight_matches_originated_rib() {
    let nlri = node();
    let mut local_rib = LocalRib::default();
    let mut store = crate::bgp::BgpAttrStore::default();
    route_bgpls_originate(nlri.clone(), BgpLsAttr::new(), &mut local_rib, &mut store);
    let rib = local_rib
        .bgp_ls
        .selected
        .get(&nlri)
        .expect("originated object");
    assert_eq!(rib.weight, 32768);
    let mut permit = entry(PolicyAction::Permit);
    permit.match_weight = Some(NumericMatch::Eq(rib.weight));
    let mut peer = peer();
    let slot = peer.policy_list_slot(AfiSafi::new(Afi::LinkState, Safi::LinkState), InOut::Output);
    slot.name = Some("ORIGINATED".into());
    slot.policy_list = Some(policy(vec![permit, entry(PolicyAction::Deny)]));
    assert!(
        bgpls_out_attr(&mut peer, &rib.attr, rib.weight).is_some(),
        "outbound policy must see the originated object's actual weight"
    );
    // And the argument is what carries it, not a constant the evaluator
    // happens to seed: the same row evaluated as weight 0 must fail the
    // very same match.
    assert!(
        bgpls_out_attr(&mut peer, &rib.attr, 0).is_none(),
        "the weight argument must reach the match, not be ignored"
    );
}
