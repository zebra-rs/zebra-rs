use std::collections::BTreeMap;
use std::fmt;

use bytes::BytesMut;

use crate::{
    AddPathValue, AfiSafi, CapAddPath, CapAs4, CapDynamic, CapEmit, CapEnhancedRefresh,
    CapExtended, CapFqdn, CapLlgr, CapMultiProtocol, CapPathLimit, CapRefresh, CapRefreshCisco,
    CapRestart, CapVersion, CapabilityPacket, LlgrValue, PathLimitValue, RestartValue,
};

#[derive(Default, Debug, PartialEq, Clone)]
pub struct BgpCap {
    pub mp: BTreeMap<AfiSafi, CapMultiProtocol>,
    pub refresh: Option<CapRefresh>,
    pub refresh_cisco: Option<CapRefreshCisco>,
    pub enhanced_refresh: Option<CapEnhancedRefresh>,
    pub extended: Option<CapExtended>,
    pub restart: BTreeMap<AfiSafi, RestartValue>,
    pub as4: Option<CapAs4>,
    pub dynamic: Option<CapDynamic>,
    pub addpath: BTreeMap<AfiSafi, AddPathValue>,
    pub llgr: BTreeMap<AfiSafi, LlgrValue>,
    pub fqdn: Option<CapFqdn>,
    pub version: Option<CapVersion>,
    pub path_limit: BTreeMap<AfiSafi, PathLimitValue>,
}

impl BgpCap {
    pub fn emit(&self, buf: &mut BytesMut) {
        for (_, v) in self.mp.iter() {
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
        if !self.restart.is_empty() {
            let mut v = CapRestart::default();
            for (_, val) in self.restart.iter() {
                v.values.push(val.clone());
            }
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
            for (_, val) in self.addpath.iter() {
                v.values.push(val.clone());
            }
            v.emit(buf, false);
        }
        if !self.llgr.is_empty() {
            let mut v = CapLlgr::default();
            for (_, val) in self.llgr.iter() {
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
            for (_, val) in self.path_limit.iter() {
                v.values.push(val.clone());
            }
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
                    CapabilityPacket::GracefulRestart(v) => {
                        for restart in v.values.into_iter() {
                            let key = AfiSafi::new(restart.afi, restart.safi);
                            bgp_cap.restart.insert(key, restart);
                        }
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
        for (_, v) in self.mp.iter() {
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
        if !self.restart.is_empty() {
            let mut v = CapRestart::default();
            for (_, val) in self.restart.iter() {
                v.values.push(val.clone());
            }
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
            for (_, val) in self.addpath.iter() {
                v.values.push(val.clone());
            }
            writeln!(f, " {}", v)?;
        }
        if !self.llgr.is_empty() {
            let mut v = CapLlgr::default();
            for (_, val) in self.llgr.iter() {
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
            for (_, val) in self.path_limit.iter() {
                v.values.push(val.clone());
            }
            writeln!(f, " {}", v)?;
        }
        Ok(())
    }
}
