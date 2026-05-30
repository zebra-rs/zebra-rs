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

use std::collections::BTreeSet;

use bgp_packet::{
    BgpLsNlri, LsLinkDescriptor, LsLinkNlri, LsNodeDescSub, LsNodeDescriptor, LsNodeNlri,
    LsPrefixDescriptor, LsPrefixNlri, LsProtocolId,
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

/// Translate one Extended IS Reachability entry (the same entry type backs
/// TLV 22 and TLV 222) into a Link NLRI. The link descriptors carry whatever
/// interface/neighbor addresses the entry advertises, so parallel links to
/// the same neighbor stay distinct.
fn link_nlri(proto: LsProtocolId, local: &IsisSysId, e: &IsisTlvExtIsReachEntry) -> BgpLsNlri {
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
    BgpLsNlri::Link(LsLinkNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        remote_node: node_descriptor(&remote),
        link_descs,
    })
}

fn ipv4_prefix_nlri(
    proto: LsProtocolId,
    local: &IsisSysId,
    e: &IsisTlvExtIpReachEntry,
) -> BgpLsNlri {
    BgpLsNlri::Ipv4Prefix(LsPrefixNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        prefix_descs: vec![ipv4_reach(&e.prefix)],
    })
}

fn ipv6_prefix_nlri(
    proto: LsProtocolId,
    local: &IsisSysId,
    e: &IsisTlvIpv6ReachEntry,
) -> BgpLsNlri {
    BgpLsNlri::Ipv6Prefix(LsPrefixNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        prefix_descs: vec![ipv6_reach(&e.prefix)],
    })
}

/// Translate every Link-State object implied by one IS-IS LSP into BGP-LS
/// NLRIs. The Node NLRI is emitted only for a node's own fragment-0,
/// non-pseudonode LSP; Link and Prefix NLRIs are emitted from whichever
/// fragment carries them. The caller walks the LSDB and unions the results
/// across all of a node's fragments.
pub fn lsp_to_nlris(level: Level, lsp: &IsisLsp) -> Vec<BgpLsNlri> {
    let proto = protocol_id(level);
    let local = lsp.lsp_id.sys_id();
    let mut out = Vec::new();

    // Node NLRI: the node's own LSP (fragment 0, not a pseudonode).
    // Pseudonode LSPs (pseudo-id != 0) describe a LAN, not a node, and
    // their link TLVs are still translated below.
    if !lsp.lsp_id.is_pseudo() && lsp.lsp_id.fragment_id() == 0 {
        out.push(BgpLsNlri::Node(LsNodeNlri {
            protocol_id: proto,
            identifier: 0,
            local_node: node_descriptor(&local),
        }));
    }

    for tlv in &lsp.tlvs {
        match tlv {
            IsisTlv::ExtIsReach(t) => {
                for e in &t.entries {
                    out.push(link_nlri(proto, &local, e));
                }
            }
            IsisTlv::MtIsReach(t) => {
                for e in &t.entries {
                    out.push(link_nlri(proto, &local, e));
                }
            }
            IsisTlv::ExtIpReach(t) => {
                for e in &t.entries {
                    out.push(ipv4_prefix_nlri(proto, &local, e));
                }
            }
            IsisTlv::MtIpReach(t) => {
                for e in &t.entries {
                    out.push(ipv4_prefix_nlri(proto, &local, e));
                }
            }
            IsisTlv::Ipv6Reach(t) => {
                for e in &t.entries {
                    out.push(ipv6_prefix_nlri(proto, &local, e));
                }
            }
            IsisTlv::MtIpv6Reach(t) => {
                for e in &t.entries {
                    out.push(ipv6_prefix_nlri(proto, &local, e));
                }
            }
            _ => {}
        }
    }
    out
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
    advertised: &mut BTreeSet<BgpLsNlri>,
    bgp_tx: Option<&Sender<crate::bgp::inst::Message>>,
) {
    let Some(tx) = bgp_tx else {
        return;
    };

    let mut current: BTreeSet<BgpLsNlri> = BTreeSet::new();
    for level in [super::level::Level::L1, super::level::Level::L2] {
        for lsa in lsdb.get(&level).values() {
            for nlri in lsp_to_nlris(level, &lsa.lsp) {
                current.insert(nlri);
            }
        }
    }

    let add: Vec<BgpLsNlri> = current.difference(advertised).cloned().collect();
    let withdraw: Vec<BgpLsNlri> = advertised.difference(&current).cloned().collect();
    if add.is_empty() && withdraw.is_empty() {
        return;
    }

    // BGP's inbox is a bounded channel and the IS-IS event loop is sync, so
    // use `try_send`. On the rare full-channel case, skip the update without
    // touching `advertised` so the next trigger re-diffs and retries the
    // whole delta (idempotent — add/withdraw are set operations).
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
        let mut advertised: std::collections::BTreeSet<BgpLsNlri> =
            std::collections::BTreeSet::new();

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

    /// `produce` is a no-op when BGP isn't wired (`bgp_tx` is `None`).
    #[test]
    fn produce_noop_without_bgp() {
        let mut advertised = std::collections::BTreeSet::new();
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
