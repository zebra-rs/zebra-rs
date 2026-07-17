use std::fmt;

use bytes::BytesMut;

use crate::{
    Aggregator, Aigp, As4Path, AtomicAggregate, AttrEmitter, BgpLsAttr, BgpNexthop, ClusterList,
    Color, Community, ExtCommunity, LargeCommunity, LocalPref, Med, NexthopAttr, Origin,
    OriginatorId, PmsiTunnel, PrefixSid, PrefixSidTlv, TunnelEncap, UnknownAttr,
};

// BGP Attribute for quick access to each attribute. This would be used for
// consolidating route advertisement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BgpAttr {
    /// Origin type
    pub origin: Option<Origin>,
    /// AS Path
    pub aspath: Option<As4Path>,
    /// Nexthop
    pub nexthop: Option<BgpNexthop>,
    /// Multi-Exit Discriminator
    pub med: Option<Med>,
    /// Local preference (IBGP only)
    pub local_pref: Option<LocalPref>,
    /// Atomic Aggregate
    pub atomic_aggregate: Option<AtomicAggregate>,
    /// Aggregator.
    pub aggregator: Option<Aggregator>,
    /// Community
    pub com: Option<Community>,
    /// Originator ID
    pub originator_id: Option<OriginatorId>,
    /// Cluster List
    pub cluster_list: Option<ClusterList>,
    /// Extended Community
    pub ecom: Option<ExtCommunity>,
    /// PMSI Tunnel
    pub pmsi_tunnel: Option<PmsiTunnel>,
    /// AIGP
    pub aigp: Option<Aigp>,
    /// Large Community
    pub lcom: Option<LargeCommunity>,
    /// BGP Prefix-SID (RFC 8669) — Label-Index, Originator-SRGB, and
    /// the RFC 9252 SRv6 Service TLVs. Parse-only for v1; semantics
    /// land in follow-up PRs (SR-MPLS labeled unicast, SRv6 services).
    pub prefix_sid: Option<PrefixSid>,
    /// BGP Tunnel Encapsulation (RFC 9012). Carries SR Policy
    /// candidate-path encoding (Color, Preference, Binding-SID,
    /// Segment List, ...) and other tunnel endpoint signalling.
    /// Sub-TLV bodies are opaque in v1; structural framing is bit-
    /// exact for forward-propagation.
    pub tunnel_encap: Option<TunnelEncap>,
    /// BGP-LS Attribute (path attribute type 29, RFC 9552).
    pub bgp_ls: Option<BgpLsAttr>,
    /// Unrecognized **optional transitive** path attributes (RFC 4271
    /// §9). Retained verbatim so they can be re-advertised to other peers
    /// with the Partial bit set. Unrecognized optional non-transitive
    /// attributes are dropped at parse time and never land here.
    pub unknown: Vec<UnknownAttr>,
}

impl BgpAttr {
    pub fn new() -> Self {
        BgpAttr {
            origin: Some(Origin::default()),
            aspath: Some(As4Path::default()),
            med: Some(Med::default()),
            ..Default::default()
        }
    }

    pub fn attr_emit(&self, buf: &mut BytesMut) {
        if let Some(v) = &self.origin {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.aspath {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.nexthop
            && let BgpNexthop::Ipv4(addr) = v
        {
            let nexthop = NexthopAttr { nexthop: *addr };
            nexthop.attr_emit(buf);
        }
        if let Some(v) = &self.med {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.local_pref {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.atomic_aggregate {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.aggregator {
            v.attr_emit(buf);
        }
        // An empty set would emit a zero-length attribute, which RFC 7606 §7.8
        // makes malformed (the length must be a *non-zero* multiple of 4) and
        // our own parser now rejects. An emptied set means "no attribute".
        if let Some(v) = &self.com
            && !v.0.is_empty()
        {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.originator_id {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.cluster_list {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.ecom {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.pmsi_tunnel {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.aigp {
            v.attr_emit(buf);
        }
        // Likewise RFC 8092 §3: a non-zero multiple of 12.
        if let Some(v) = &self.lcom
            && !v.0.is_empty()
        {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.prefix_sid {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.tunnel_encap {
            v.attr_emit(buf);
        }
        // Unrecognized optional transitive attributes (RFC 4271 §9):
        // re-advertised verbatim with the Partial bit (set when stored).
        for v in &self.unknown {
            v.attr_emit(buf);
        }
    }

    pub fn neighboring_as(&self) -> Option<u32> {
        self.aspath
            .as_ref()
            .and_then(|aspath| aspath.neighboring_as())
    }

    /// Extract the Label-Index value carried in the BGP Prefix-SID
    /// attribute (RFC 8669 §3.1). Returns `None` when the attribute
    /// is absent or carries only non-LabelIndex TLVs (Originator-SRGB,
    /// SRv6 service). When multiple Label-Index TLVs are present
    /// (malformed per RFC 8669 §3.1.1 but tolerated on receive) the
    /// first one wins so consumers see a deterministic value.
    pub fn prefix_sid_label_index(&self) -> Option<u32> {
        self.prefix_sid.as_ref()?.tlvs.iter().find_map(|t| match t {
            PrefixSidTlv::LabelIndex { label_index, .. } => Some(*label_index),
            _ => None,
        })
    }

    /// The first SRv6 L3 Service SID (value + endpoint behavior) carried
    /// in the Prefix-SID attribute — RFC 9252 L3VPN-over-SRv6. `None`
    /// when the attribute is absent or carries no SRv6 L3 Service TLV.
    /// An originator may carry several service SIDs (e.g. a split
    /// `End.DT4` + `End.DT6` pair instead of one `End.DT46`); consumers
    /// that steer traffic should select by destination address family
    /// ([`crate::srv6_l3_sid_for_dest`] over [`Self::srv6_l3_sids`])
    /// rather than take the first.
    pub fn srv6_l3_sid(&self) -> Option<(std::net::Ipv6Addr, u16)> {
        self.srv6_l3_sids().next()
    }

    /// Every SRv6 L3 Service SID (value + endpoint behavior) carried in
    /// the Prefix-SID attribute, in wire order across all SRv6 L3
    /// Service TLVs and their SID Information sub-TLVs. Empty when the
    /// attribute is absent or carries no SRv6 L3 Service TLV.
    pub fn srv6_l3_sids(&self) -> impl Iterator<Item = (std::net::Ipv6Addr, u16)> + '_ {
        self.prefix_sid
            .iter()
            .flat_map(|ps| ps.tlvs.iter())
            .filter_map(|t| match t {
                PrefixSidTlv::Srv6L3Service(svc) => Some(svc),
                _ => None,
            })
            .flat_map(|svc| svc.sids.iter().map(|s| (s.sid, s.behavior)))
    }

    /// The first SRv6 L2 Service SID (value + endpoint behavior) carried
    /// in the Prefix-SID attribute — RFC 9252 EVPN-over-SRv6 (e.g. an
    /// `End.DT2M` SID on a Type-3 IMET route). `None` when the attribute
    /// is absent or carries no SRv6 L2 Service TLV.
    pub fn srv6_l2_sid(&self) -> Option<(std::net::Ipv6Addr, u16)> {
        self.prefix_sid.as_ref()?.tlvs.iter().find_map(|t| match t {
            PrefixSidTlv::Srv6L2Service(svc) => svc.sids.first().map(|s| (s.sid, s.behavior)),
            _ => None,
        })
    }

    /// Iterate every Color extended community (RFC 9012 §4.3, type
    /// 0x03 0x0b) attached to the route. Returns an empty iterator
    /// when the route has no EXT_COMMUNITIES or the attribute carries
    /// no Color entries. Multiple Colors are allowed (RFC 9256 §2.5);
    /// `ExtCommunity` stores values as a sorted set, so they are
    /// yielded in ascending (flags, color) order — a deterministic
    /// fallback order for the resolver regardless of how the
    /// originator arranged them on the wire.
    pub fn colors(&self) -> impl Iterator<Item = Color> + '_ {
        self.ecom
            .iter()
            .flat_map(|ec| ec.0.iter())
            .filter_map(|v| v.as_color())
    }
}

impl fmt::Display for BgpAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v) = &self.origin {
            writeln!(f, " Origin: {}", v)?;
        }
        if let Some(v) = &self.aspath {
            writeln!(f, " AS Path: {}", v)?;
        }
        if let Some(v) = &self.med {
            writeln!(f, " MED: {}", v)?;
        }
        if let Some(v) = &self.local_pref {
            writeln!(f, " LocalPref: {}", v)?;
        }
        if self.atomic_aggregate.is_some() {
            writeln!(f, " Atomic Aggregate")?;
        }
        if let Some(v) = &self.aggregator {
            writeln!(f, " Aggregator: {}", v)?;
        }
        if let Some(v) = &self.com {
            writeln!(f, " Community: {}", v)?;
        }
        if let Some(v) = &self.originator_id {
            writeln!(f, " OriginatorId: {}", v)?;
        }
        if let Some(v) = &self.cluster_list {
            writeln!(f, " ClusterList: {}", v)?;
        }
        if let Some(v) = &self.ecom {
            writeln!(f, " ExtCommunity: {}", v)?;
        }
        if let Some(v) = &self.pmsi_tunnel {
            writeln!(f, " PMSI Tunnel: {}", v)?;
        }
        if let Some(v) = &self.aigp {
            writeln!(f, " AIGP: {}", v)?;
        }
        if let Some(v) = &self.lcom {
            writeln!(f, " LargeCommunity: {}", v)?;
        }
        if let Some(v) = &self.prefix_sid {
            writeln!(f, " PrefixSid: {}", v)?;
        }
        if let Some(v) = &self.tunnel_encap {
            writeln!(f, " TunnelEncap: {}", v)?;
        }
        for v in &self.unknown {
            writeln!(f, " Unknown: {}", v)?;
        }
        // Nexthop
        if let Some(v) = &self.nexthop {
            match v {
                BgpNexthop::Ipv4(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
                BgpNexthop::Ipv6(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
                BgpNexthop::Vpnv4(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
                BgpNexthop::Vpnv6(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
                BgpNexthop::Evpn(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_bgp_attr_to_from_roundtrip() {
        // Create a BgpAttr with various attributes
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.nexthop = Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        bgp_attr.local_pref = Some(LocalPref { local_pref: 100 });
        bgp_attr.com = Some(Community::from([CommunityValue::from_readable_str(
            "100:200",
        )
        .unwrap()
        .0]));
    }

    #[test]
    fn test_bgp_attr_new() {
        let bgp_attr = BgpAttr::new();
        assert!(bgp_attr.origin.is_some());
        assert!(bgp_attr.aspath.is_some());
        assert!(bgp_attr.med.is_some());
        assert_eq!(bgp_attr.origin.unwrap(), Origin::Igp);
        assert_eq!(bgp_attr.aspath.unwrap().length(), 0);
    }

    #[test]
    fn prefix_sid_label_index_returns_none_when_attr_absent() {
        let attr = BgpAttr::default();
        assert!(attr.prefix_sid_label_index().is_none());
    }

    #[test]
    fn prefix_sid_label_index_returns_value_from_label_index_tlv() {
        let attr = BgpAttr {
            prefix_sid: Some(PrefixSid {
                tlvs: vec![PrefixSidTlv::LabelIndex {
                    flags: 0,
                    label_index: 128,
                }],
            }),
            ..Default::default()
        };
        assert_eq!(attr.prefix_sid_label_index(), Some(128));
    }

    #[test]
    fn prefix_sid_label_index_skips_non_label_index_tlvs() {
        // Originator-SRGB present but no Label-Index → None.
        let attr = BgpAttr {
            prefix_sid: Some(PrefixSid {
                tlvs: vec![PrefixSidTlv::OriginatorSrgb {
                    flags: 0,
                    srgbs: vec![SrgbRange {
                        base: 16000,
                        range: 8000,
                    }],
                }],
            }),
            ..Default::default()
        };
        assert!(attr.prefix_sid_label_index().is_none());
    }

    #[test]
    fn prefix_sid_label_index_picks_first_when_multiple() {
        let attr = BgpAttr {
            prefix_sid: Some(PrefixSid {
                tlvs: vec![
                    PrefixSidTlv::LabelIndex {
                        flags: 0,
                        label_index: 42,
                    },
                    PrefixSidTlv::LabelIndex {
                        flags: 0,
                        label_index: 99,
                    },
                ],
            }),
            ..Default::default()
        };
        assert_eq!(attr.prefix_sid_label_index(), Some(42));
    }

    #[test]
    fn srv6_l3_sids_yields_every_sid_across_tlvs_in_wire_order() {
        // A split End.DT4 + End.DT6 pair: one TLV carrying two SID
        // Information sub-TLVs plus a second L3 Service TLV — all three
        // SIDs must surface, in wire order, with the L2 TLV skipped.
        let dt4: std::net::Ipv6Addr = "fcbb:1::4".parse().unwrap();
        let dt6: std::net::Ipv6Addr = "fcbb:1::6".parse().unwrap();
        let dt46: std::net::Ipv6Addr = "fcbb:1::46".parse().unwrap();
        let l2: std::net::Ipv6Addr = "fcbb:1::2".parse().unwrap();
        let attr = BgpAttr {
            prefix_sid: Some(PrefixSid {
                tlvs: vec![
                    PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                        sids: vec![
                            Srv6SidInfo::new(dt4, 0, SRV6_BEHAVIOR_END_DT4, None),
                            Srv6SidInfo::new(dt6, 0, SRV6_BEHAVIOR_END_DT6, None),
                        ],
                        ..Default::default()
                    }),
                    PrefixSidTlv::Srv6L2Service(Srv6ServiceTlv {
                        sids: vec![Srv6SidInfo::new(l2, 0, SRV6_BEHAVIOR_END_DT2M, None)],
                        ..Default::default()
                    }),
                    PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                        sids: vec![Srv6SidInfo::new(dt46, 0, SRV6_BEHAVIOR_END_DT46, None)],
                        ..Default::default()
                    }),
                ],
            }),
            ..Default::default()
        };
        let sids: Vec<_> = attr.srv6_l3_sids().collect();
        assert_eq!(
            sids,
            vec![
                (dt4, SRV6_BEHAVIOR_END_DT4),
                (dt6, SRV6_BEHAVIOR_END_DT6),
                (dt46, SRV6_BEHAVIOR_END_DT46),
            ]
        );
        // The single-SID accessor stays the first-in-wire-order SID.
        assert_eq!(attr.srv6_l3_sid(), Some((dt4, SRV6_BEHAVIOR_END_DT4)));
    }

    #[test]
    fn srv6_l3_sids_empty_when_attr_absent_or_l3_free() {
        assert_eq!(BgpAttr::default().srv6_l3_sids().count(), 0);
        let attr = BgpAttr {
            prefix_sid: Some(PrefixSid {
                tlvs: vec![PrefixSidTlv::LabelIndex {
                    flags: 0,
                    label_index: 7,
                }],
            }),
            ..Default::default()
        };
        assert_eq!(attr.srv6_l3_sids().count(), 0);
    }

    #[test]
    fn colors_returns_empty_iterator_when_ecom_absent() {
        let attr = BgpAttr::default();
        assert_eq!(attr.colors().count(), 0);
    }

    #[test]
    fn colors_yields_color_extcomms_in_sorted_order() {
        // Inserted high-color-first; the set yields ascending
        // (flags, color) order.
        let attr = BgpAttr {
            ecom: Some(ExtCommunity::from([
                ExtCommunityValue::from_color(0b10, 200),
                ExtCommunityValue::from_color(0, 100),
            ])),
            ..Default::default()
        };
        let cols: Vec<Color> = attr.colors().collect();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].color, 100);
        assert_eq!(cols[0].co_bits(), 0);
        assert_eq!(cols[1].color, 200);
        assert_eq!(cols[1].co_bits(), 0b10);
    }

    #[test]
    fn colors_skips_non_color_extcomms() {
        // RTs + Color — only the Color should surface in colors().
        let rt1 = ExtCommunity::from_str("rt:65001:100").unwrap();
        let rt2 = ExtCommunity::from_str("rt:65001:200").unwrap();
        let combined: ExtCommunity = rt1
            .0
            .into_iter()
            .chain(rt2.0)
            .chain([ExtCommunityValue::from_color(0, 42)])
            .collect();
        let attr = BgpAttr {
            ecom: Some(combined),
            ..Default::default()
        };
        let cols: Vec<Color> = attr.colors().collect();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].color, 42);
    }
}
