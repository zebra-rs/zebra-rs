pub use nom_derive::*;

#[derive(NomBE)]
pub struct IsisCodeLen {
    pub code: u8,
    pub len: u8,
}

/// Implements the shared sub-TLV registry walk for a `#[nom(Selector)]`
/// enum with an `Unknown(IsisSubTlvUnknown)` variant: read {code, len},
/// slice the value, dispatch on the code, and degrade a malformed
/// *known* sub-TLV to Unknown with its bytes preserved — mirroring the
/// top-level TLV loop — so the sub-TLVs after it still parse. One
/// definition instead of six hand-kept copies; a new registry gets the
/// degrade and the Unknown code/len patch for free.
macro_rules! impl_parse_subs {
    ($($ty:ty),+ $(,)?) => {$(
        impl $ty {
            pub fn parse_subs(input: &[u8]) -> nom::IResult<&[u8], Self> {
                let (input, cl) = crate::sub::IsisCodeLen::parse_be(input)?;
                let (input, sub) = packet_utils::safe_split_at(input, cl.len as usize)?;
                let mut val = match Self::parse_be(sub, cl.code.into()) {
                    Ok((_, val)) => val,
                    Err(_) => Self::Unknown(crate::sub::IsisSubTlvUnknown {
                        code: cl.code,
                        len: cl.len,
                        data: sub.to_vec(),
                    }),
                };
                if let Self::Unknown(ref mut v) = val {
                    v.code = cl.code;
                    v.len = cl.len;
                }
                Ok((input, val))
            }
        }
    )+};
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
    AdjSidFlags, IsisSubAdminGroup, IsisSubAdminGrp, IsisSubAsla, IsisSubAvailableBw,
    IsisSubBandwidthMetric, IsisSubDelayVariation, IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr,
    IsisSubIpv6IfAddr, IsisSubIpv6NeighAddr, IsisSubLanAdjSid, IsisSubLinkLoss,
    IsisSubMinMaxLinkDelay, IsisSubResidualBw, IsisSubSrv6EndXSid, IsisSubSrv6LanEndXSid,
    IsisSubTeMetric, IsisSubUniLinkDelay, IsisSubUtilizedBw, IsisTlvExtIsReach,
    IsisTlvExtIsReachEntry, IsisTlvMtIsReach,
};
pub mod neigh_code;
pub use neigh_code::IsisNeighCode;
pub mod neigh_disp;

pub mod prefix;
pub use prefix::{
    BindingFlags, BindingPrefix, IsisBindingSubTlv, IsisMirrorSub2Tlv, IsisSub2ProtectedLocators,
    IsisSub2SidStructure, IsisSub2Tlv, IsisSubIpv4SourceRouterId, IsisSubIpv6SourceRouterId,
    IsisSubPrefixSid, IsisSubSrv6EndSid, IsisSubSrv6MirrorSid, IsisTlvExtIpReach,
    IsisTlvExtIpReachEntry, IsisTlvIpv6Reach, IsisTlvIpv6ReachEntry, IsisTlvMtIpReach,
    IsisTlvMtIpv6Reach, IsisTlvMultiTopology, IsisTlvSidLabelBinding, IsisTlvSrv6, MultiTopologyId,
    PrefixSidFlags, Srv6Locator,
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
