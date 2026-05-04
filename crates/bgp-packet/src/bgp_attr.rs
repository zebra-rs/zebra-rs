use std::fmt;

use bytes::BytesMut;

use crate::{
    Aggregator, Aigp, As4Path, AtomicAggregate, AttrEmitter, BgpNexthop, ClusterList, Community,
    ExtCommunity, LargeCommunity, LocalPref, Med, NexthopAttr, Origin, OriginatorId, PmsiTunnel,
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
    }

    pub fn neighboring_as(&self) -> Option<u32> {
        self.aspath
            .as_ref()
            .and_then(|aspath| aspath.neighboring_as())
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
        // Nexthop
        if let Some(v) = &self.nexthop {
            match v {
                BgpNexthop::Ipv4(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
                BgpNexthop::Vpnv4(v) => {
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
}
