// BGP Link-State producer: IS-IS → BGP-LS NLRI translation (RFC 9552).
//
// This module is the headline BGP-LS feature's first slice: a *pure*
// translation of one IS-IS LSP's TLVs into the BGP Link-State NLRIs it
// implies (RFC 9552 §5.2 — Node, Link, IPv4/IPv6 Prefix). It performs no
// I/O, holds no channel, and is not yet wired into the IS-IS event loop;
// the channel to BGP, the LSDB walk, and withdraw-on-change land in a
// follow-up PR. Keeping the translation isolated makes it unit-testable
// against hand-built LSPs with zero behavior change.
//
// Mapping (per the locked plan):
//   - fragment-0, non-pseudonode LSP        → Node NLRI (local System-ID)
//   - TLV 22 / 222 (Ext/MT IS Reachability) → Link NLRI (+ interface/
//                                              neighbor address descriptors)
//   - TLV 135 / 235 (Ext/MT IPv4)           → IPv4 Prefix NLRI
//   - TLV 236 / 237 (IPv6 / MT IPv6)        → IPv6 Prefix NLRI
//   - Protocol-ID from the level: IS-IS L1 = 1, L2 = 2.
//
// Node *attributes* (hostname, TE-Router-ID, SR capabilities) and link/
// prefix attributes ride in the BGP-LS Attribute (type 29) and are a later
// phase; this slice emits NLRIs only.

use std::collections::BTreeMap;

use bgp_packet::{
    BGPLS_ATTR_ADMIN_GROUP, BGPLS_ATTR_IGP_METRIC, BGPLS_ATTR_PREFIX_METRIC,
    BGPLS_ATTR_TE_DEFAULT_METRIC, BgpLsAttr, BgpLsNlri, LsLinkDescriptor, LsLinkNlri,
    LsNodeDescSub, LsNodeDescriptor, LsNodeNlri, LsPrefixDescriptor, LsPrefixNlri, LsProtocolId,
};
use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::{
    IsisLsp, IsisSysId, IsisTlv, IsisTlvExtIpReachEntry, IsisTlvExtIsReachEntry,
    IsisTlvIpv6ReachEntry,
};
use tokio::sync::mpsc::Sender;

use super::level::Level;

/// BGP-LS Protocol-ID for an IS-IS level (RFC 9552 Table 1).
fn protocol_id(level: Level) -> LsProtocolId {
    match level {
        Level::L1 => LsProtocolId::IsisL1,
        Level::L2 => LsProtocolId::IsisL2,
    }
}

/// A Node Descriptor carrying just the IGP Router-ID (IS-IS System-ID,
/// 6 octets) — the minimal node identity (RFC 9552 §5.2.1.4).
fn node_descriptor(sys_id: &IsisSysId) -> LsNodeDescriptor {
    LsNodeDescriptor {
        subs: vec![LsNodeDescSub::IgpRouterId(sys_id.id.to_vec())],
    }
}

/// Minimal-octet IP Reachability prefix descriptor: the prefix length in
/// bits plus the high-order `ceil(len/8)` address octets (RFC 9552 §5.2.3).
fn ipv4_reach(net: &Ipv4Net) -> LsPrefixDescriptor {
    let prefix_len = net.prefix_len();
    let nbytes = prefix_len.div_ceil(8) as usize;
    let octets = net.network().octets();
    LsPrefixDescriptor::IpReachability {
        prefix_len,
        prefix: octets[..nbytes].to_vec(),
    }
}

fn ipv6_reach(net: &Ipv6Net) -> LsPrefixDescriptor {
    let prefix_len = net.prefix_len();
    let nbytes = prefix_len.div_ceil(8) as usize;
    let octets = net.network().octets();
    LsPrefixDescriptor::IpReachability {
        prefix_len,
        prefix: octets[..nbytes].to_vec(),
    }
}

/// The BGP-LS Attribute (path attribute type 29) carried alongside an NLRI.
/// Empty when the source TLV had no translatable attributes.
type Object = (BgpLsNlri, BgpLsAttr);

/// Build the Link Attribute TLVs (RFC 9552 §4.2) for one IS-IS adjacency:
/// IGP metric (1095, the base TLV-22 metric), and — when the entry carries
/// the corresponding sub-TLVs — admin-group (1088) and TE default metric
/// (1092). Max-link-bandwidth (1089) is omitted: the IS-IS link sub-TLV set
/// parsed here has no max-bandwidth variant (only residual/available/
/// utilized), so there is nothing to translate yet.
fn link_attr(e: &IsisTlvExtIsReachEntry) -> BgpLsAttr {
    let mut attr = BgpLsAttr::new();
    // IGP metric is a 3-octet value in BGP-LS (RFC 9552 §4.2; 1, 2, or 3
    // octets are allowed — IS-IS wide metrics use 3).
    attr.push(BGPLS_ATTR_IGP_METRIC, e.metric.to_be_bytes()[1..].to_vec());
    if let Some(ag) = e.admin_group() {
        attr.push(BGPLS_ATTR_ADMIN_GROUP, ag.to_be_bytes().to_vec());
    }
    if let Some(te) = e.te_metric() {
        attr.push(BGPLS_ATTR_TE_DEFAULT_METRIC, te.to_be_bytes().to_vec());
    }
    attr
}

/// Build the Prefix Attribute TLVs (RFC 9552 §4.3): the Prefix Metric
/// (1155), a 4-octet value carrying the IS-IS reachability metric.
fn prefix_attr(metric: u32) -> BgpLsAttr {
    let mut attr = BgpLsAttr::new();
    attr.push(BGPLS_ATTR_PREFIX_METRIC, metric.to_be_bytes().to_vec());
    attr
}

/// Translate one Extended IS Reachability entry (the same entry type backs
/// TLV 22 and TLV 222) into a Link NLRI plus its Link Attribute. The link
/// descriptors carry whatever interface/neighbor addresses the entry
/// advertises, so parallel links to the same neighbor stay distinct.
fn link_object(proto: LsProtocolId, local: &IsisSysId, e: &IsisTlvExtIsReachEntry) -> Object {
    let remote = e.neighbor_id.sys_id();
    let mut link_descs = Vec::new();
    if let Some(a) = e.ipv4_if_addr() {
        link_descs.push(LsLinkDescriptor::Ipv4InterfaceAddr(a));
    }
    if let Some(a) = e.ipv4_neigh_addr() {
        link_descs.push(LsLinkDescriptor::Ipv4NeighborAddr(a));
    }
    if let Some(a) = e.ipv6_if_addr() {
        link_descs.push(LsLinkDescriptor::Ipv6InterfaceAddr(a));
    }
    if let Some(a) = e.ipv6_neigh_addr() {
        link_descs.push(LsLinkDescriptor::Ipv6NeighborAddr(a));
    }
    let nlri = BgpLsNlri::Link(LsLinkNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        remote_node: node_descriptor(&remote),
        link_descs,
    });
    (nlri, link_attr(e))
}

fn ipv4_prefix_object(
    proto: LsProtocolId,
    local: &IsisSysId,
    e: &IsisTlvExtIpReachEntry,
) -> Object {
    let nlri = BgpLsNlri::Ipv4Prefix(LsPrefixNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        prefix_descs: vec![ipv4_reach(&e.prefix)],
    });
    (nlri, prefix_attr(e.metric))
}

fn ipv6_prefix_object(proto: LsProtocolId, local: &IsisSysId, e: &IsisTlvIpv6ReachEntry) -> Object {
    let nlri = BgpLsNlri::Ipv6Prefix(LsPrefixNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        prefix_descs: vec![ipv6_reach(&e.prefix)],
    });
    (nlri, prefix_attr(e.metric))
}

/// Translate every Link-State object implied by one IS-IS LSP into BGP-LS
/// NLRIs. The Node NLRI is emitted only for a node's own fragment-0,
/// non-pseudonode LSP; Link and Prefix NLRIs are emitted from whichever
/// fragment carries them. The caller walks the LSDB and unions the results
/// across all of a node's fragments.
pub fn lsp_to_objects(level: Level, lsp: &IsisLsp) -> Vec<Object> {
    let proto = protocol_id(level);
    let local = lsp.lsp_id.sys_id();
    let mut out = Vec::new();

    // Node NLRI: the node's own LSP (fragment 0, not a pseudonode).
    // Pseudonode LSPs (pseudo-id != 0) describe a LAN, not a node, and
    // their link TLVs are still translated below. Node attributes (hostname,
    // SR capabilities, …) are a later slice, so the attr is empty for now.
    if !lsp.lsp_id.is_pseudo() && lsp.lsp_id.fragment_id() == 0 {
        let node = BgpLsNlri::Node(LsNodeNlri {
            protocol_id: proto,
            identifier: 0,
            local_node: node_descriptor(&local),
        });
        out.push((node, BgpLsAttr::new()));
    }

    for tlv in &lsp.tlvs {
        match tlv {
            IsisTlv::ExtIsReach(t) => {
                for e in &t.entries {
                    out.push(link_object(proto, &local, e));
                }
            }
            IsisTlv::MtIsReach(t) => {
                for e in &t.entries {
                    out.push(link_object(proto, &local, e));
                }
            }
            IsisTlv::ExtIpReach(t) => {
                for e in &t.entries {
                    out.push(ipv4_prefix_object(proto, &local, e));
                }
            }
            IsisTlv::MtIpReach(t) => {
                for e in &t.entries {
                    out.push(ipv4_prefix_object(proto, &local, e));
                }
            }
            IsisTlv::Ipv6Reach(t) => {
                for e in &t.entries {
                    out.push(ipv6_prefix_object(proto, &local, e));
                }
            }
            IsisTlv::MtIpv6Reach(t) => {
                for e in &t.entries {
                    out.push(ipv6_prefix_object(proto, &local, e));
                }
            }
            _ => {}
        }
    }
    out
}

/// NLRI-only view of [`lsp_to_objects`], discarding the BGP-LS Attribute.
/// Only the tests need the topology keys without attributes today (the
/// producer consumes `lsp_to_objects` directly), so this is test-gated to
/// avoid a dead-code lint in the binary build.
#[cfg(test)]
fn lsp_to_nlris(level: Level, lsp: &IsisLsp) -> Vec<BgpLsNlri> {
    lsp_to_objects(level, lsp)
        .into_iter()
        .map(|(nlri, _attr)| nlri)
        .collect()
}

/// Walk both IS-IS levels' LSDBs, translate every LSP to its BGP-LS NLRIs,
/// diff the resulting set against `advertised` (what we last pushed to BGP),
/// and send only the add/withdraw deltas over `bgp_tx`. `advertised` is
/// updated to the new set. No-op when BGP is not wired (`bgp_tx` is `None`)
/// or nothing changed.
///
/// This is the producer trigger, called from the IS-IS event loop on
/// `SpfDone` (the LSDB is settled at that point). The diff gives RFC 9552
/// §5.2 withdraw-old-on-change for free: an object that disappears from the
/// LSDB (or whose descriptors change, making it a different NLRI key) shows
/// up in `withdraw`. The two-way connectivity check on Link NLRIs is a
/// deferred follow-up; today a link is advertised as soon as one endpoint's
/// LSP lists the adjacency.
pub fn produce(
    lsdb: &super::level::Levels<super::lsdb::Lsdb>,
    advertised: &mut BTreeMap<BgpLsNlri, BgpLsAttr>,
    bgp_tx: Option<&Sender<crate::bgp::inst::Message>>,
) {
    let Some(tx) = bgp_tx else {
        return;
    };

    let mut current: BTreeMap<BgpLsNlri, BgpLsAttr> = BTreeMap::new();
    for level in [super::level::Level::L1, super::level::Level::L2] {
        for lsa in lsdb.get(&level).values() {
            for (nlri, attr) in lsp_to_objects(level, &lsa.lsp) {
                // A node spans multiple LSP fragments; the same NLRI key may
                // recur. Keep the first non-empty attr (fragment 0 carries
                // the node/link attrs); later duplicates don't override it.
                current.entry(nlri).or_insert(attr);
            }
        }
    }

    // Add when the NLRI is new OR its attribute changed (re-advertise on a
    // metric/admin-group change — RFC 9552 §5.2 treats an attr change as a
    // new advertisement). Withdraw when the NLRI is gone entirely.
    let add: Vec<Object> = current
        .iter()
        .filter(|(nlri, attr)| advertised.get(*nlri) != Some(*attr))
        .map(|(nlri, attr)| (nlri.clone(), attr.clone()))
        .collect();
    let withdraw: Vec<BgpLsNlri> = advertised
        .keys()
        .filter(|nlri| !current.contains_key(*nlri))
        .cloned()
        .collect();
    if add.is_empty() && withdraw.is_empty() {
        return;
    }

    // BGP's inbox is a bounded channel and the IS-IS event loop is sync, so
    // use `try_send`. On the rare full-channel case, skip the update without
    // touching `advertised` so the next trigger re-diffs and retries the
    // whole delta (idempotent — add/withdraw are keyed operations).
    match tx.try_send(crate::bgp::inst::Message::BgpLs { add, withdraw }) {
        Ok(()) => *advertised = current,
        Err(e) => {
            tracing::warn!("bgp-ls producer: BGP inbox send failed, will retry: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-entry L2 LSDB level wrapper from a single LSP.
    fn levels_with_l2(lsp: IsisLsp) -> crate::isis::level::Levels<crate::isis::lsdb::Lsdb> {
        let mut l2 = crate::isis::lsdb::Lsdb::default();
        l2.map.insert(
            lsp.lsp_id,
            crate::isis::lsdb::Lsa {
                lsp,
                originated: true,
                hold_timer: None,
                refresh_timer: None,
                ifindex: 0,
                bytes: vec![],
                last_received: None,
            },
        );
        crate::isis::level::Levels {
            l1: crate::isis::lsdb::Lsdb::default(),
            l2,
        }
    }

    #[test]
    fn produce_emits_add_then_diff_then_withdraw() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mut advertised: std::collections::BTreeMap<BgpLsNlri, BgpLsAttr> =
            std::collections::BTreeMap::new();

        // First trigger: one node LSP → one add, nothing withdrawn.
        let levels = levels_with_l2(lsp(sysid(1), 0, 0, vec![]));
        produce(&levels, &mut advertised, Some(&tx));
        assert_eq!(advertised.len(), 1);
        match rx.try_recv() {
            Ok(crate::bgp::inst::Message::BgpLs { add, withdraw }) => {
                assert_eq!(add.len(), 1);
                assert!(withdraw.is_empty());
            }
            other => panic!("expected BgpLs add, got {other:?}"),
        }

        // Second trigger, identical LSDB: no delta, no message.
        produce(&levels, &mut advertised, Some(&tx));
        assert!(rx.try_recv().is_err(), "no message expected on no-op diff");

        // Topology gone: the node is withdrawn.
        let empty = crate::isis::level::Levels::<crate::isis::lsdb::Lsdb>::default();
        produce(&empty, &mut advertised, Some(&tx));
        assert!(advertised.is_empty());
        match rx.try_recv() {
            Ok(crate::bgp::inst::Message::BgpLs { add, withdraw }) => {
                assert!(add.is_empty());
                assert_eq!(withdraw.len(), 1);
            }
            other => panic!("expected BgpLs withdraw, got {other:?}"),
        }
    }

    #[test]
    fn produce_readvertises_on_attr_change() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mut advertised: std::collections::BTreeMap<BgpLsNlri, BgpLsAttr> =
            std::collections::BTreeMap::new();

        // A link with metric 10 → one add carrying an IGP-metric attr.
        let entry = |metric| {
            IsisTlv::ExtIsReach(IsisTlvExtIsReach {
                entries: vec![IsisTlvExtIsReachEntry {
                    neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
                    metric,
                    subs: vec![],
                }],
            })
        };
        let levels = levels_with_l2(lsp(sysid(1), 0, 0, vec![entry(10)]));
        produce(&levels, &mut advertised, Some(&tx));
        let _ = rx.try_recv().expect("first add");

        // Same NLRI keys, but the link metric changed → re-advertise the
        // link (its attr differs). The Node NLRI is unchanged (empty attr)
        // so it must NOT re-advertise.
        let levels2 = levels_with_l2(lsp(sysid(1), 0, 0, vec![entry(20)]));
        produce(&levels2, &mut advertised, Some(&tx));
        match rx.try_recv() {
            Ok(crate::bgp::inst::Message::BgpLs { add, withdraw }) => {
                assert_eq!(add.len(), 1, "only the changed link re-advertises");
                assert!(matches!(add[0].0, BgpLsNlri::Link(_)));
                assert!(withdraw.is_empty());
            }
            other => panic!("expected BgpLs re-advertise, got {other:?}"),
        }
    }

    /// `produce` is a no-op when BGP isn't wired (`bgp_tx` is `None`).
    #[test]
    fn produce_noop_without_bgp() {
        let mut advertised = std::collections::BTreeMap::new();
        let levels = levels_with_l2(lsp(sysid(1), 0, 0, vec![]));
        produce(&levels, &mut advertised, None);
        assert!(advertised.is_empty());
    }
    use isis_packet::{
        IsisLspId, IsisNeighborId, IsisTlvExtIpReach, IsisTlvExtIsReach, IsisTlvExtIsReachEntry,
    };

    fn sysid(last: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, last],
        }
    }

    fn lsp(sys: IsisSysId, pseudo: u8, frag: u8, tlvs: Vec<IsisTlv>) -> IsisLsp {
        IsisLsp {
            lsp_id: IsisLspId::new(sys, pseudo, frag),
            tlvs,
            ..Default::default()
        }
    }

    #[test]
    fn node_nlri_from_fragment_zero() {
        let nlris = lsp_to_nlris(Level::L2, &lsp(sysid(1), 0, 0, vec![]));
        assert_eq!(nlris.len(), 1);
        match &nlris[0] {
            BgpLsNlri::Node(n) => {
                assert_eq!(n.protocol_id, LsProtocolId::IsisL2);
                assert_eq!(
                    n.local_node.subs,
                    vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 1])]
                );
            }
            other => panic!("expected Node, got {other:?}"),
        }
    }

    #[test]
    fn no_node_nlri_for_pseudonode_or_nonzero_fragment() {
        // Pseudonode LSP (pseudo-id != 0): no Node NLRI.
        assert!(lsp_to_nlris(Level::L1, &lsp(sysid(1), 1, 0, vec![])).is_empty());
        // Fragment != 0: no Node NLRI.
        assert!(lsp_to_nlris(Level::L1, &lsp(sysid(1), 0, 1, vec![])).is_empty());
    }

    #[test]
    fn link_nlri_from_ext_is_reach() {
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![],
        };
        let tlv = IsisTlv::ExtIsReach(IsisTlvExtIsReach {
            entries: vec![entry],
        });
        let nlris = lsp_to_nlris(Level::L2, &lsp(sysid(1), 0, 0, vec![tlv]));
        // One Node NLRI (fragment 0) + one Link NLRI.
        assert_eq!(nlris.len(), 2);
        let link = nlris
            .iter()
            .find_map(|n| match n {
                BgpLsNlri::Link(l) => Some(l),
                _ => None,
            })
            .expect("link nlri");
        assert_eq!(link.protocol_id, LsProtocolId::IsisL2);
        assert_eq!(
            link.local_node.subs,
            vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 1])]
        );
        assert_eq!(
            link.remote_node.subs,
            vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 2])]
        );
    }

    #[test]
    fn ipv4_prefix_nlri_from_ext_ip_reach() {
        let entry = IsisTlvExtIpReachEntry {
            metric: 10,
            flags: Default::default(),
            prefix: "10.0.0.0/24".parse().unwrap(),
            subs: vec![],
        };
        let tlv = IsisTlv::ExtIpReach(IsisTlvExtIpReach {
            entries: vec![entry],
        });
        // Use a pseudonode LSP so only the prefix NLRI is produced (no Node).
        let nlris = lsp_to_nlris(Level::L1, &lsp(sysid(1), 1, 0, vec![tlv]));
        assert_eq!(nlris.len(), 1);
        match &nlris[0] {
            BgpLsNlri::Ipv4Prefix(p) => {
                assert_eq!(p.protocol_id, LsProtocolId::IsisL1);
                assert_eq!(
                    p.prefix_descs,
                    vec![LsPrefixDescriptor::IpReachability {
                        prefix_len: 24,
                        prefix: vec![10, 0, 0],
                    }]
                );
            }
            other => panic!("expected Ipv4Prefix, got {other:?}"),
        }
    }
}
