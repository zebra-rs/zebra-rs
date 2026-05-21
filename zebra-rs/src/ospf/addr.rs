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
