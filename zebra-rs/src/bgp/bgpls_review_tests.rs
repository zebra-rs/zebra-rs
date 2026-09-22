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
    policy_list_apply_bgpls(list, attr, Ipv4Addr::UNSPECIFIED)
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
