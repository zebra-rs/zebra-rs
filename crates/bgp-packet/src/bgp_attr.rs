use std::fmt;

use bytes::BytesMut;

use crate::{
    Aggregator, Aigp, As4Path, AtomicAggregate, AttrEmitter, BgpLsAttr, BgpNexthop, ClusterList,
    Color, Community, ExtCommunity, LargeCommunity, LocalPref, Med, NexthopAttr, Origin,
    OriginatorId, PmsiTunnel, PrefixSid, PrefixSidTlv, TunnelEncap,
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
    // TODO: Unknown Attributes.
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
        if let Some(v) = &self.com {
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
        if let Some(v) = &self.lcom {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.prefix_sid {
            v.attr_emit(buf);
        }
        if let Some(v) = &self.tunnel_encap {
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
    pub fn srv6_l3_sid(&self) -> Option<(std::net::Ipv6Addr, u16)> {
        self.prefix_sid.as_ref()?.tlvs.iter().find_map(|t| match t {
            PrefixSidTlv::Srv6L3Service(svc) => svc.sids.first().map(|s| (s.sid, s.behavior)),
            _ => None,
        })
    }

    /// Iterate every Color extended community (RFC 9012 §4.3, type
    /// 0x03 0x0b) attached to the route, in attribute order. Returns
    /// an empty iterator when the route has no EXT_COMMUNITIES or
    /// the attribute carries no Color entries. Multiple Colors are
    /// allowed (RFC 9256 §2.5 fallback ordering) and are yielded in
    /// the order the originator placed them — preserving that order
    /// matters for fallback semantics in the resolver.
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
        bgp_attr.com = Some(Community(vec![
            CommunityValue::from_readable_str("100:200").unwrap().0,
        ]));
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
    fn colors_returns_empty_iterator_when_ecom_absent() {
        let attr = BgpAttr::default();
        assert_eq!(attr.colors().count(), 0);
    }

    #[test]
    fn colors_yields_color_extcomms_in_attribute_order() {
        let attr = BgpAttr {
            ecom: Some(ExtCommunity(vec![
                ExtCommunityValue::from_color(0, 100),
                ExtCommunityValue::from_color(0b10, 200),
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
        // RT + Color + RT — only the Color in the middle should
        // surface in colors().
        let rt = ExtCommunity::from_str("rt:65001:100").unwrap().0;
        let combined = vec![
            rt[0].clone(),
            ExtCommunityValue::from_color(0, 42),
            rt[0].clone(),
        ];
        let attr = BgpAttr {
            ecom: Some(ExtCommunity(combined)),
            ..Default::default()
        };
        let cols: Vec<Color> = attr.colors().collect();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].color, 42);
    }
}
