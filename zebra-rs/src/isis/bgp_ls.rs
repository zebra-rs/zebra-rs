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
    BGPLS_ATTR_ADMIN_GROUP, BGPLS_ATTR_ASLA, BGPLS_ATTR_AVAILABLE_BANDWIDTH,
    BGPLS_ATTR_DELAY_VARIATION, BGPLS_ATTR_EXT_ADMIN_GROUP, BGPLS_ATTR_IGP_METRIC,
    BGPLS_ATTR_LINK_LOSS, BGPLS_ATTR_MIN_MAX_LINK_DELAY, BGPLS_ATTR_PREFIX_METRIC,
    BGPLS_ATTR_RESIDUAL_BANDWIDTH, BGPLS_ATTR_TE_DEFAULT_METRIC, BGPLS_ATTR_UNI_LINK_DELAY,
    BGPLS_ATTR_UTILIZED_BANDWIDTH, BgpLsAttr, BgpLsAttrTlv, BgpLsNlri, LsLinkDescriptor,
    LsLinkNlri, LsNodeDescSub, LsNodeDescriptor, LsNodeNlri, LsPrefixDescriptor, LsPrefixNlri,
    LsProtocolId, bgpls_asla_value,
};
use ipnet::IpNet;
use isis_packet::{IsisLsp, IsisSysId, IsisTlv, IsisTlvExtIsReachEntry, PerfMetrics};
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
fn ip_reach(net: IpNet) -> LsPrefixDescriptor {
    let prefix_len = net.prefix_len();
    let nbytes = prefix_len.div_ceil(8) as usize;
    let prefix = match net {
        IpNet::V4(n) => n.network().octets()[..nbytes].to_vec(),
        IpNet::V6(n) => n.network().octets()[..nbytes].to_vec(),
    };
    LsPrefixDescriptor::IpReachability { prefix_len, prefix }
}

/// The BGP-LS Attribute (path attribute type 29) carried alongside an NLRI.
/// Empty when the source TLV had no translatable attributes.
type Object = (BgpLsNlri, BgpLsAttr);

/// Build the Link Attribute TLVs (RFC 9552 §4.2, RFC 8571) for one IS-IS
/// adjacency: IGP metric (1095, the base TLV-22 metric), and — when the entry
/// carries the corresponding sub-TLVs — admin-group (1088), extended
/// admin-group (1173), TE default metric (1092), and the RFC 8571 performance
/// set (1114-1120) translated from the RFC 8570 sub-TLVs 33-39.
///
/// Max-link-bandwidth (1089) stays omitted: the IS-IS link sub-TLV set has no
/// max-bandwidth variant, only residual/available/utilized, and those have
/// their own code points.
///
/// The performance values are re-emitted byte-for-byte — RFC 8571 reuses the
/// IGP field layout, A bit included — so a controller sees exactly what the
/// IGP advertised, anomalies and all.
fn link_attr(e: &IsisTlvExtIsReachEntry) -> BgpLsAttr {
    let mut attr = BgpLsAttr::new();
    // IGP metric is a 3-octet value in BGP-LS (RFC 9552 §4.2; 1, 2, or 3
    // octets are allowed — IS-IS wide metrics use 3).
    attr.push(BGPLS_ATTR_IGP_METRIC, e.metric.to_be_bytes()[1..].to_vec());
    if let Some(ag) = e.admin_group() {
        attr.push(BGPLS_ATTR_ADMIN_GROUP, ag.to_be_bytes().to_vec());
    }
    // A peer's zero-length EAG sub-TLV parses to an empty word list;
    // RFC 9104's value mirrors the IGP's 32-bit blocks, so an empty
    // TLV 1173 is meaningless — skip it rather than emit it.
    if let Some(ag) = e.ext_admin_group()
        && !ag.is_empty()
    {
        let value = ag.iter().flat_map(|word| word.to_be_bytes()).collect();
        attr.push(BGPLS_ATTR_EXT_ADMIN_GROUP, value);
    }
    if let Some(te) = e.te_metric() {
        attr.push(BGPLS_ATTR_TE_DEFAULT_METRIC, te.to_be_bytes().to_vec());
    }
    push_te_performance(&mut attr, e);
    attr
}

/// `A` in the top bit, the value in the low 24 — the shared shape of
/// RFC 8571's delay and loss TLVs.
fn anomalous_u24(anomalous: bool, value: u32) -> u32 {
    let a = if anomalous { 0x8000_0000 } else { 0 };
    a | (value & 0x00FF_FFFF)
}

/// RFC 9479 §4.2 SABM bit 0 — the RSVP-TE application.
const SABM_RSVP_TE: u8 = 0x80;

/// Translate one sub-TLV list's RFC 8570 metrics into RFC 8571 BGP-LS
/// TLVs. The encodings are byte-identical between the two — same A bit,
/// same 24-bit fields, same IEEE 754 bandwidths — so this is a re-emit,
/// anomalies included. Only metrics actually present are produced, so a
/// link with no measurement yields an empty list rather than a run of
/// zeroes a controller would read as "0 us".
fn perf_tlvs(m: &PerfMetrics<'_>) -> Vec<BgpLsAttrTlv> {
    let mut out = Vec::new();
    if let Some(d) = m.uni_delay {
        let v = anomalous_u24(d.anomalous, d.delay);
        out.push(BgpLsAttrTlv::new(
            BGPLS_ATTR_UNI_LINK_DELAY,
            v.to_be_bytes().to_vec(),
        ));
    }
    if let Some(d) = m.min_max_delay {
        // One A bit covering both bounds; the max word's top octet is
        // reserved and sent as zero.
        let mut v = anomalous_u24(d.anomalous, d.min_delay)
            .to_be_bytes()
            .to_vec();
        v.extend_from_slice(&(d.max_delay & 0x00FF_FFFF).to_be_bytes());
        out.push(BgpLsAttrTlv::new(BGPLS_ATTR_MIN_MAX_LINK_DELAY, v));
    }
    if let Some(v) = m.variation {
        // No A bit here — RFC 8571 §2.3 leaves the octet reserved.
        let value = v.variation & 0x00FF_FFFF;
        out.push(BgpLsAttrTlv::new(
            BGPLS_ATTR_DELAY_VARIATION,
            value.to_be_bytes().to_vec(),
        ));
    }
    if let Some(l) = m.loss {
        let v = anomalous_u24(l.anomalous, l.loss);
        out.push(BgpLsAttrTlv::new(
            BGPLS_ATTR_LINK_LOSS,
            v.to_be_bytes().to_vec(),
        ));
    }
    for (tlv, bw) in [
        (BGPLS_ATTR_RESIDUAL_BANDWIDTH, m.residual_bw),
        (BGPLS_ATTR_AVAILABLE_BANDWIDTH, m.available_bw),
        (BGPLS_ATTR_UTILIZED_BANDWIDTH, m.utilized_bw),
    ] {
        if let Some(bw) = bw {
            out.push(BgpLsAttrTlv::new(tlv, bw.to_bits().to_be_bytes().to_vec()));
        }
    }
    out
}

/// Append the RFC 8571 performance metrics this entry can supply,
/// keeping each one's application scope (RFC 9294 §2).
///
/// Three sources, three destinations:
///
/// * inline (legacy) attributes are application-independent and go to
///   the top-level TLVs;
/// * every ASLA's attributes are re-encoded inside a BGP-LS ASLA TLV
///   (1122) carrying that ASLA's own bit masks — flattening them would
///   advertise, say, a Flex-Algorithm-only delay as an RSVP-TE
///   attribute, and with two ASLAs present would silently pick one by
///   sub-TLV order;
/// * an ASLA that includes RSVP-TE additionally goes to the top-level
///   TLVs, which RFC 9294 §3 requires for that application. The
///   duplication is anticipated: RFC 9294 §2 says the ASLA TLV takes
///   precedence where both appear.
fn push_te_performance(attr: &mut BgpLsAttr, e: &IsisTlvExtIsReachEntry) {
    for tlv in perf_tlvs(&e.inline_perf()) {
        attr.push(tlv.typ, tlv.value);
    }
    for asla in e.aslas() {
        let nested = perf_tlvs(&PerfMetrics::from_subs(&asla.subs));
        if nested.is_empty() {
            continue;
        }
        if asla.sabm.first().is_some_and(|b| b & SABM_RSVP_TE != 0) {
            for tlv in &nested {
                attr.push(tlv.typ, tlv.value.clone());
            }
        }
        attr.push(
            BGPLS_ATTR_ASLA,
            bgpls_asla_value(&asla.sabm, &asla.udabm, &nested),
        );
    }
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

fn prefix_object(proto: LsProtocolId, local: &IsisSysId, prefix: IpNet, metric: u32) -> Object {
    let is_v4 = matches!(prefix, IpNet::V4(_));
    let inner = LsPrefixNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        prefix_descs: vec![ip_reach(prefix)],
    };
    let nlri = if is_v4 {
        BgpLsNlri::Ipv4Prefix(inner)
    } else {
        BgpLsNlri::Ipv6Prefix(inner)
    };
    (nlri, prefix_attr(metric))
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
                    out.push(prefix_object(proto, &local, e.prefix.into(), e.metric));
                }
            }
            IsisTlv::MtIpReach(t) => {
                for e in &t.entries {
                    out.push(prefix_object(proto, &local, e.prefix.into(), e.metric));
                }
            }
            IsisTlv::Ipv6Reach(t) => {
                for e in &t.entries {
                    out.push(prefix_object(proto, &local, e.prefix.into(), e.metric));
                }
            }
            IsisTlv::MtIpv6Reach(t) => {
                for e in &t.entries {
                    out.push(prefix_object(proto, &local, e.prefix.into(), e.metric));
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
        IsisLspId, IsisNeighborId, IsisSubAdminGrp, IsisTlvExtIpReach, IsisTlvExtIpReachEntry,
        IsisTlvExtIsReach, IsisTlvExtIsReachEntry,
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
    fn link_attr_maps_extended_admin_group_to_1173() {
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![
                IsisSubAdminGrp {
                    groups: vec![0x0102_0304, 0xaabb_ccdd],
                }
                .into(),
            ],
        };

        let attr = link_attr(&entry);
        assert_eq!(
            attr.get(BGPLS_ATTR_EXT_ADMIN_GROUP),
            Some(&[0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd][..])
        );
        assert_eq!(attr.get(BGPLS_ATTR_ADMIN_GROUP), None);
    }

    /// A peer's zero-length EAG sub-TLV (parseable from the wire) must
    /// not become a zero-length TLV 1173.
    #[test]
    fn link_attr_skips_empty_extended_admin_group() {
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![IsisSubAdminGrp { groups: vec![] }.into()],
        };

        let attr = link_attr(&entry);
        assert_eq!(attr.get(BGPLS_ATTR_EXT_ADMIN_GROUP), None);
    }

    /// The RFC 8571 performance TLVs are a byte-for-byte re-emit of the
    /// RFC 8570 sub-TLVs, A bit included — the whole point is that a
    /// controller sees what the IGP advertised.
    #[test]
    fn link_attr_maps_te_performance_to_1114_1117() {
        use isis_packet::{
            IsisSubDelayVariation, IsisSubLinkLoss, IsisSubMinMaxLinkDelay, IsisSubUniLinkDelay,
        };
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![
                IsisSubUniLinkDelay {
                    anomalous: true,
                    delay: 0x0012_3456,
                }
                .into(),
                IsisSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay: 0x0000_0900,
                    max_delay: 0x0000_1200,
                }
                .into(),
                IsisSubDelayVariation { variation: 0x32 }.into(),
                IsisSubLinkLoss {
                    anomalous: true,
                    loss: 0x0000_0333,
                }
                .into(),
            ],
        };

        let attr = link_attr(&entry);
        // A bit in the top bit of octet 0, value in the low 24.
        assert_eq!(
            attr.get(BGPLS_ATTR_UNI_LINK_DELAY),
            Some(&[0x80, 0x12, 0x34, 0x56][..])
        );
        // One A bit for both bounds; the max word's top octet reserved.
        assert_eq!(
            attr.get(BGPLS_ATTR_MIN_MAX_LINK_DELAY),
            Some(&[0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x12, 0x00][..])
        );
        // Delay variation has no A bit — octet 0 stays reserved.
        assert_eq!(
            attr.get(BGPLS_ATTR_DELAY_VARIATION),
            Some(&[0x00, 0x00, 0x00, 0x32][..])
        );
        assert_eq!(
            attr.get(BGPLS_ATTR_LINK_LOSS),
            Some(&[0x80, 0x00, 0x03, 0x33][..])
        );
    }

    /// A link with no measurement contributes no performance TLVs,
    /// rather than a run of zeroes a controller would read as "0 us".
    #[test]
    fn link_attr_omits_absent_te_performance() {
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![],
        };
        let attr = link_attr(&entry);
        for tlv in [
            BGPLS_ATTR_UNI_LINK_DELAY,
            BGPLS_ATTR_MIN_MAX_LINK_DELAY,
            BGPLS_ATTR_DELAY_VARIATION,
            BGPLS_ATTR_LINK_LOSS,
            BGPLS_ATTR_RESIDUAL_BANDWIDTH,
            BGPLS_ATTR_AVAILABLE_BANDWIDTH,
            BGPLS_ATTR_UTILIZED_BANDWIDTH,
        ] {
            assert_eq!(attr.get(tlv), None, "tlv {tlv}");
        }
    }

    /// RFC 9294 §2: attributes received in an IGP ASLA MUST be
    /// re-encoded in the BGP-LS ASLA TLV, not flattened to top level.
    /// A Flex-Algorithm-only delay promoted to a top-level TLV would
    /// read as an RSVP-TE attribute as well.
    #[test]
    fn asla_scoped_metrics_go_to_tlv_1122_not_top_level() {
        use isis_packet::{IsisSubAsla, IsisSubMinMaxLinkDelay};
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![
                IsisSubAsla {
                    l_flag: false,
                    sabm: vec![0x10], // X-bit: Flex-Algorithm only
                    udabm: vec![],
                    subs: vec![
                        IsisSubMinMaxLinkDelay {
                            anomalous: true,
                            min_delay: 0x0000_0900,
                            max_delay: 0x0000_1200,
                        }
                        .into(),
                    ],
                }
                .into(),
            ],
        };
        let attr = link_attr(&entry);
        assert_eq!(
            attr.get(BGPLS_ATTR_MIN_MAX_LINK_DELAY),
            None,
            "a Flex-Algo-scoped metric must not appear at top level"
        );
        // SABM len 1, UDABM len 0, 2 reserved zero octets, the mask,
        // then the nested TLV in BGP-LS type/length form.
        assert_eq!(
            attr.get(BGPLS_ATTR_ASLA),
            Some(
                &[
                    0x01, 0x00, 0x00, 0x00, // lengths + reserved
                    0x10, // SABM: X-bit
                    0x04, 0x5b, 0x00, 0x08, // TLV 1115, length 8
                    0x80, 0x00, 0x09, 0x00, 0x00, 0x00, 0x12, 0x00,
                ][..]
            )
        );
    }

    /// RFC 9294 §3 carves out RSVP-TE: those attributes are REQUIRED at
    /// top level. They are also encoded in the ASLA TLV, which §2 makes
    /// authoritative where both appear.
    #[test]
    fn rsvp_te_scoped_metrics_also_go_top_level() {
        use isis_packet::{IsisSubAsla, IsisSubUniLinkDelay};
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![
                IsisSubAsla {
                    l_flag: false,
                    sabm: vec![0x80], // R-bit: RSVP-TE
                    udabm: vec![],
                    subs: vec![
                        IsisSubUniLinkDelay {
                            anomalous: false,
                            delay: 0x0000_03e8,
                        }
                        .into(),
                    ],
                }
                .into(),
            ],
        };
        let attr = link_attr(&entry);
        assert_eq!(
            attr.get(BGPLS_ATTR_UNI_LINK_DELAY),
            Some(&[0x00, 0x00, 0x03, 0xe8][..])
        );
        assert!(attr.get(BGPLS_ATTR_ASLA).is_some());
    }

    /// Two applications advertising different values for one link must
    /// both survive, and neither may depend on sub-TLV order.
    #[test]
    fn two_aslas_keep_their_own_values() {
        use isis_packet::{IsisSubAsla, IsisSubMinMaxLinkDelay};
        let scoped = |sabm: u8, min: u32| -> isis_packet::neigh::IsisSubTlv {
            IsisSubAsla {
                l_flag: false,
                sabm: vec![sabm],
                udabm: vec![],
                subs: vec![
                    IsisSubMinMaxLinkDelay {
                        anomalous: false,
                        min_delay: min,
                        max_delay: min + 100,
                    }
                    .into(),
                ],
            }
            .into()
        };
        for subs in [
            vec![scoped(0x10, 100), scoped(0x80, 900)],
            vec![scoped(0x80, 900), scoped(0x10, 100)],
        ] {
            let entry = IsisTlvExtIsReachEntry {
                neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
                metric: 10,
                subs,
            };
            let attr = link_attr(&entry);
            let aslas: Vec<_> = attr
                .tlvs
                .iter()
                .filter(|t| t.typ == BGPLS_ATTR_ASLA)
                .collect();
            assert_eq!(aslas.len(), 2, "one ASLA TLV per application scope");
            // The RSVP-TE one, and only it, is mirrored top-level with
            // its own 900 us — not the Flex-Algo 100 us.
            assert_eq!(
                attr.get(BGPLS_ATTR_MIN_MAX_LINK_DELAY),
                Some(&[0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0xe8][..])
            );
        }
    }

    /// Legacy inline attributes carry no application scope, so they are
    /// the ones that belong at top level.
    #[test]
    fn inline_metrics_stay_top_level() {
        use isis_packet::IsisSubUniLinkDelay;
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![
                IsisSubUniLinkDelay {
                    anomalous: false,
                    delay: 0x0000_03e8,
                }
                .into(),
            ],
        };
        let attr = link_attr(&entry);
        assert_eq!(
            attr.get(BGPLS_ATTR_UNI_LINK_DELAY),
            Some(&[0x00, 0x00, 0x03, 0xe8][..])
        );
        assert_eq!(attr.get(BGPLS_ATTR_ASLA), None);
    }

    /// Bandwidth values are IEEE 754 on both sides, so the bit pattern
    /// crosses unchanged. We never originate these, but peers do.
    #[test]
    fn link_attr_maps_bandwidths_to_1118_1120() {
        use isis_packet::{IsisSubAvailableBw, IsisSubResidualBw, IsisSubUtilizedBw};
        let bw = |v: f32| isis_packet::IsisSubBandwidthMetric { bw_bps: v };
        let entry = IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sysid(2), 0),
            metric: 10,
            subs: vec![
                IsisSubResidualBw { bw: bw(1.25e9) }.into(),
                IsisSubAvailableBw { bw: bw(1.0e9) }.into(),
                IsisSubUtilizedBw { bw: bw(2.5e8) }.into(),
            ],
        };
        let attr = link_attr(&entry);
        for (tlv, expect) in [
            (BGPLS_ATTR_RESIDUAL_BANDWIDTH, 1.25e9f32),
            (BGPLS_ATTR_AVAILABLE_BANDWIDTH, 1.0e9f32),
            (BGPLS_ATTR_UTILIZED_BANDWIDTH, 2.5e8f32),
        ] {
            assert_eq!(
                attr.get(tlv),
                Some(&expect.to_bits().to_be_bytes()[..]),
                "tlv {tlv}"
            );
        }
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
