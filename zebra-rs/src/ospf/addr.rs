use crate::rib::link::LinkAddr;

use super::OspfVersion;

/// A configured address on an OSPF interface. Generic over the
/// address family so v3 (`Ipv6Net`) can reuse the wrapper unchanged.
#[derive(Debug, Clone)]
pub struct OspfAddr<V: OspfVersion> {
    pub prefix: V::Prefix,
}

impl<V: OspfVersion> OspfAddr<V> {
    pub fn from(_addr: &LinkAddr, prefix: &V::Prefix) -> Self {
        Self { prefix: *prefix }
    }
}

impl<V: OspfVersion> Default for OspfAddr<V>
where
    V::Prefix: Default,
{
    fn default() -> Self {
        Self {
            prefix: V::Prefix::default(),
        }
    }
}

/// Append `addr` to a link's address list only when no entry with the
/// same prefix exists; returns whether it pushed.
///
/// The RIB redistributes every AddrAdd *event*, not every address —
/// one configured address arrives several times (config-exec push,
/// kernel netlink echo, DAD re-notify, link-bounce re-install), so
/// consumers must be idempotent (IS-IS guards the same way in
/// `isis::link::addr_add`). Without this, every duplicate delivery
/// adds another copy of the prefix to the Router-LSA stub networks
/// (v2) / Intra-Area-Prefix-LSA (v3).
pub fn link_addr_push_unique<V: OspfVersion>(
    addrs: &mut Vec<OspfAddr<V>>,
    addr: OspfAddr<V>,
) -> bool {
    if addrs.iter().any(|a| a.prefix == addr.prefix) {
        return false;
    }
    addrs.push(addr);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ospf::version::{Ospfv2, Ospfv3};

    #[test]
    fn push_unique_dedups_v6_prefix() {
        let mut addrs: Vec<OspfAddr<Ospfv3>> = Vec::new();
        let lo: ipnet::Ipv6Net = "2001:db8::1/128".parse().unwrap();
        let transit: ipnet::Ipv6Net = "2001:db8:1::1/64".parse().unwrap();

        assert!(link_addr_push_unique(&mut addrs, OspfAddr { prefix: lo }));
        // Same prefix delivered again (kernel echo / DAD re-notify) —
        // must not grow the list.
        assert!(!link_addr_push_unique(&mut addrs, OspfAddr { prefix: lo }));
        assert_eq!(addrs.len(), 1);

        assert!(link_addr_push_unique(
            &mut addrs,
            OspfAddr { prefix: transit }
        ));
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn push_unique_dedups_v4_prefix() {
        let mut addrs: Vec<OspfAddr<Ospfv2>> = Vec::new();
        let p: ipnet::Ipv4Net = "10.0.0.1/24".parse().unwrap();

        assert!(link_addr_push_unique(&mut addrs, OspfAddr { prefix: p }));
        assert!(!link_addr_push_unique(&mut addrs, OspfAddr { prefix: p }));
        assert_eq!(addrs.len(), 1);
    }
}
