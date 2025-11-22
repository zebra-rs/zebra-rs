pub use nom_derive::*;

#[derive(NomBE)]
pub struct IsisCodeLen {
    pub code: u8,
    pub len: u8,
}

pub mod cap;
pub use cap::{
    IsisSubNodeMaxSidDepth, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisSubSrv6, IsisTlvRouterCap, SegmentRoutingCapFlags, SidLabelTlv,
};
pub mod cap_code;
pub use cap_code::IsisCapCode;
pub mod cap_disp;

pub mod neigh;
pub use neigh::{
    AdjSidFlags, IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr, IsisSubIpv6IfAddr, IsisSubIpv6NeighAddr,
    IsisSubLanAdjSid, IsisSubSrv6EndXSid, IsisSubSrv6LanEndXSid, IsisSubWideMetric,
    IsisTlvExtIsReach, IsisTlvExtIsReachEntry,
};
pub mod neigh_code;
pub use neigh_code::IsisNeighCode;
pub mod neigh_disp;

pub mod prefix;
pub use prefix::{
    IsisSub2Tlv, IsisSubPrefixSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry, IsisTlvIpv6Reach,
    IsisTlvIpv6ReachEntry, IsisTlvMtIpReach, IsisTlvMtIpv6Reach, IsisTlvSrv6, PrefixSidFlags,
};
pub mod prefix_code;
pub use prefix_code::{IsisPrefixCode, IsisSrv6SidSub2Code};
pub mod prefix_disp;

pub mod srv6;
pub use srv6::Behavior;

pub mod unknown;
pub use unknown::IsisSubTlvUnknown;
