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

// Phase 6a is the translation only; the IS-IS event loop does not call
// `lsp_to_nlris` until the producer wiring lands in 6b. `zebra-rs` is a
// binary crate, so these not-yet-called items would trip `dead_code` under
// CI's `-D warnings`. Allow it here with this note rather than scatter
// per-item attributes; 6b removes the need.
#![allow(dead_code)]

use bgp_packet::{
    BgpLsNlri, LsLinkDescriptor, LsLinkNlri, LsNodeDescSub, LsNodeDescriptor, LsNodeNlri,
    LsPrefixDescriptor, LsPrefixNlri, LsProtocolId,
};
use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::{
    IsisLsp, IsisSysId, IsisTlv, IsisTlvExtIpReachEntry, IsisTlvExtIsReachEntry,
    IsisTlvIpv6ReachEntry,
};

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

#[cfg(test)]
mod tests {
    use super::*;
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
