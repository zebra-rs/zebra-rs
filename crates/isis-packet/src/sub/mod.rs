pub use nom_derive::*;

#[derive(NomBE)]
pub struct IsisCodeLen {
    pub code: u8,
    pub len: u8,
}

pub mod cap;
pub use cap::{
    ExtAdminGroup, FadSubCode, FadSubTlv, IsisSubFadExcludeAg, IsisSubFadExcludeSrlg,
    IsisSubFadFlags, IsisSubFadIncludeAllAg, IsisSubFadIncludeAnyAg, IsisSubFlexAlgoDef,
    IsisSubNodeMaxSidDepth, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisSubSrv6, IsisSubTlv, IsisTlvRouterCap, SegmentRoutingCapFlags,
};
pub use packet_utils::SidLabelTlv;
pub mod cap_code;
pub use cap_code::IsisCapCode;
pub mod cap_disp;

pub mod neigh;
pub use neigh::{
    AdjSidFlags, IsisSubAdminGrp, IsisSubAsla, IsisSubAvailableBw, IsisSubBandwidthMetric,
    IsisSubDelayVariation, IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr, IsisSubIpv6IfAddr,
    IsisSubIpv6NeighAddr, IsisSubLanAdjSid, IsisSubLinkLoss, IsisSubMinMaxLinkDelay,
    IsisSubResidualBw, IsisSubSrv6EndXSid, IsisSubSrv6LanEndXSid, IsisSubTeMetric,
    IsisSubUniLinkDelay, IsisSubUtilizedBw, IsisTlvExtIsReach, IsisTlvExtIsReachEntry,
    IsisTlvMtIsReach,
};
pub mod neigh_code;
pub use neigh_code::IsisNeighCode;
pub mod neigh_disp;

pub mod prefix;
pub use prefix::{
    IsisMirrorSub2Tlv, IsisSub2ProtectedLocators, IsisSub2SidStructure, IsisSub2Tlv,
    IsisSubIpv4SourceRouterId, IsisSubIpv6SourceRouterId, IsisSubPrefixSid, IsisSubSrv6EndSid,
    IsisSubSrv6MirrorSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry, IsisTlvIpv6Reach,
    IsisTlvIpv6ReachEntry, IsisTlvMtIpReach, IsisTlvMtIpv6Reach, IsisTlvMultiTopology, IsisTlvSrv6,
    MultiTopologyId, PrefixSidFlags, Srv6Locator,
};
pub mod prefix_code;
pub use prefix_code::{IsisPrefixCode, IsisSrv6MirrorSub2Code, IsisSrv6SidSub2Code};
pub mod prefix_disp;

pub mod srv6;
pub use srv6::Behavior;

pub mod restart;
pub use restart::{
    ISIS_RESTART_FLAG_RA, ISIS_RESTART_FLAG_RR, ISIS_RESTART_FLAG_SA, IsisTlvRestart,
};

pub mod unknown;
pub use unknown::IsisSubTlvUnknown;
