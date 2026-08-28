use std::collections::BTreeMap;
use std::fmt;

use bytes::BytesMut;

use crate::{
    AddPathValue, AfiSafi, CapAddPath, CapAs4, CapDynamic, CapEmit, CapEnhancedRefresh,
    CapExtended, CapExtendedNextHop, CapFqdn, CapLlgr, CapMultiProtocol, CapPathLimit, CapRefresh,
    CapRefreshCisco, CapRestart, CapRole, CapVersion, CapabilityPacket, LlgrValue, PathLimitValue,
};

#[derive(Default, Debug, PartialEq, Clone)]
pub struct BgpCap {
    pub mp: BTreeMap<AfiSafi, CapMultiProtocol>,
    pub refresh: Option<CapRefresh>,
    pub refresh_cisco: Option<CapRefreshCisco>,
    pub enhanced_refresh: Option<CapEnhancedRefresh>,
    pub extended: Option<CapExtended>,
    pub extended_nexthop: Option<CapExtendedNextHop>,
    pub restart: Option<CapRestart>,
    pub as4: Option<CapAs4>,
    pub dynamic: Option<CapDynamic>,
    pub addpath: BTreeMap<AfiSafi, AddPathValue>,
    pub llgr: BTreeMap<AfiSafi, LlgrValue>,
    pub fqdn: Option<CapFqdn>,
    pub version: Option<CapVersion>,
    pub path_limit: BTreeMap<AfiSafi, PathLimitValue>,
    /// RFC 9234 BGP Role (code 9). On the receive side this is the first
    /// Role capability in the OPEN; see [`Self::role_conflict`].
    pub role: Option<CapRole>,
    /// RFC 9234 §4.2: "If multiple BGP Role Capabilities are received and
    /// not all of them have the same value, then the BGP speaker MUST
    /// reject the connection using the Role Mismatch Notification."
    /// Set when a later Role capability disagreed with [`Self::role`];
    /// identical duplicates are collapsed silently.
    pub role_conflict: bool,
}

impl BgpCap {
    pub fn emit(&self, buf: &mut BytesMut) {
        for v in self.mp.values() {
            v.emit(buf, false);
        }
        if let Some(v) = &self.refresh {
            v.emit(buf, false);
        }
        if let Some(v) = &self.refresh_cisco {
            v.emit(buf, false);
        }
        if let Some(v) = &self.enhanced_refresh {
            v.emit(buf, false);
        }
        if let Some(v) = &self.extended {
            v.emit(buf, false);
        }
        if let Some(v) = &self.extended_nexthop {
            v.emit(buf, false);
        }
        if let Some(v) = &self.restart {
            v.emit(buf, false);
        }
        if let Some(v) = &self.as4 {
            v.emit(buf, false);
        }
        if let Some(v) = &self.dynamic {
            v.emit(buf, false);
        }
        if !self.addpath.is_empty() {
            let mut v = CapAddPath::default();
            for val in self.addpath.values() {
                v.values.push(val.clone());
            }
            v.emit(buf, false);
        }
        if !self.llgr.is_empty() {
            let mut v = CapLlgr::default();
            for val in self.llgr.values() {
                v.values.push(val.clone());
            }
            v.emit(buf, false);
        }
        if let Some(v) = &self.fqdn {
            v.emit(buf, false);
        }
        if let Some(v) = &self.version {
            v.emit(buf, false);
        }
        if !self.path_limit.is_empty() {
            let mut v = CapPathLimit::default();
            for val in self.path_limit.values() {
                v.values.push(val.clone());
            }
            v.emit(buf, false);
        }
        if let Some(v) = &self.role {
            v.emit(buf, false);
        }
    }

    pub fn from(caps: Vec<Vec<CapabilityPacket>>) -> Self {
        let mut bgp_cap = BgpCap::default();
        for cap in caps.into_iter() {
            for c in cap.into_iter() {
                match c {
                    CapabilityPacket::As4(v) => {
                        bgp_cap.as4 = Some(v);
                    }
                    CapabilityPacket::MultiProtocol(v) => {
                        let key = AfiSafi::new(v.afi, v.safi);
                        bgp_cap.mp.insert(key, v);
                    }
                    CapabilityPacket::RouteRefresh(v) => {
                        bgp_cap.refresh = Some(v);
                    }
                    CapabilityPacket::ExtendedMessage(v) => {
                        bgp_cap.extended = Some(v);
                    }
                    CapabilityPacket::ExtendedNextHop(v) => {
                        bgp_cap.extended_nexthop = Some(v);
                    }
                    CapabilityPacket::GracefulRestart(v) => {
                        bgp_cap.restart = Some(v);
                    }
                    CapabilityPacket::DynamicCapability(v) => {
                        bgp_cap.dynamic = Some(v);
                    }
                    CapabilityPacket::AddPath(v) => {
                        for addpath in v.values.into_iter() {
                            let key = AfiSafi::new(addpath.afi, addpath.safi);
                            bgp_cap.addpath.insert(key, addpath);
                        }
                    }
                    CapabilityPacket::EnhancedRouteRefresh(v) => {
                        bgp_cap.enhanced_refresh = Some(v);
                    }
                    CapabilityPacket::Llgr(v) => {
                        for llgr in v.values.into_iter() {
                            let key = AfiSafi::new(llgr.afi, llgr.safi);
                            bgp_cap.llgr.insert(key, llgr);
                        }
                    }
                    CapabilityPacket::Fqdn(v) => {
                        bgp_cap.fqdn = Some(v);
                    }
                    CapabilityPacket::SoftwareVersion(v) => {
                        bgp_cap.version = Some(v);
                    }
                    CapabilityPacket::PathLimit(v) => {
                        for limit in v.values.into_iter() {
                            let key = AfiSafi::new(limit.afi, limit.safi);
                            bgp_cap.path_limit.insert(key, limit);
                        }
                    }
                    CapabilityPacket::RouteRefreshCisco(v) => {
                        bgp_cap.refresh_cisco = Some(v);
                    }
                    CapabilityPacket::LlgrOld(v) => {
                        for llgr in v.values.into_iter() {
                            let key = AfiSafi::new(llgr.afi, llgr.safi);
                            bgp_cap.llgr.insert(key, llgr);
                        }
                    }
                    CapabilityPacket::Role(v) => match bgp_cap.role {
                        Some(first) if first.value != v.value => bgp_cap.role_conflict = true,
                        _ => bgp_cap.role = Some(v),
                    },
                    CapabilityPacket::Unknown(_v) => {
                        // Ignore unknown capability.
                    }
                }
            }
        }
        bgp_cap
    }
}

impl fmt::Display for BgpCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self.mp.values() {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.refresh {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.refresh_cisco {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.enhanced_refresh {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.extended {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.restart {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.as4 {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.dynamic {
            writeln!(f, " {}", v)?;
        }
        if !self.addpath.is_empty() {
            let mut v = CapAddPath::default();
            for val in self.addpath.values() {
                v.values.push(val.clone());
            }
            writeln!(f, " {}", v)?;
        }
        if !self.llgr.is_empty() {
            let mut v = CapLlgr::default();
            for val in self.llgr.values() {
                v.values.push(val.clone());
            }
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.fqdn {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.version {
            writeln!(f, " {}", v)?;
        }
        if !self.path_limit.is_empty() {
            let mut v = CapPathLimit::default();
            for val in self.path_limit.values() {
                v.values.push(val.clone());
            }
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.role {
            writeln!(f, " {}", v)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BgpRole;

    fn role(r: BgpRole) -> CapabilityPacket {
        CapabilityPacket::Role(CapRole::new(r))
    }

    #[test]
    fn single_role_capability_is_recorded() {
        let cap = BgpCap::from(vec![vec![role(BgpRole::Provider)]]);
        assert_eq!(cap.role.and_then(|r| r.role()), Some(BgpRole::Provider));
        assert!(!cap.role_conflict);
    }

    /// RFC 9234 §4.2: identical duplicates count as one Role capability.
    #[test]
    fn identical_duplicate_roles_collapse() {
        let cap = BgpCap::from(vec![
            vec![role(BgpRole::Customer)],
            vec![role(BgpRole::Customer)],
        ]);
        assert_eq!(cap.role.and_then(|r| r.role()), Some(BgpRole::Customer));
        assert!(!cap.role_conflict);
    }

    /// RFC 9234 §4.2: differing duplicates are a Role Mismatch. The first
    /// value is kept for display; the conflict flag carries the verdict.
    #[test]
    fn differing_duplicate_roles_flag_a_conflict() {
        let cap = BgpCap::from(vec![vec![role(BgpRole::Customer), role(BgpRole::Provider)]]);
        assert_eq!(cap.role.and_then(|r| r.role()), Some(BgpRole::Customer));
        assert!(cap.role_conflict);
    }

    #[test]
    fn role_capability_is_emitted_and_displayed() {
        let cap = BgpCap {
            role: Some(CapRole::new(BgpRole::Peer)),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        cap.emit(&mut buf);
        assert_eq!(&buf[..], &[2u8, 3, 9, 1, 4]);
        assert_eq!(cap.to_string(), " Role: Peer\n");
    }
}
