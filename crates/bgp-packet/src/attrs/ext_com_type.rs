use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::{Display, EnumString};

#[repr(u8)]
pub enum ExtCommunityType {
    TransTwoOctetAS = 0x00,
    // TransIpv4Addr = 0x01,
    // TransFourOctetAS = 0x03,
    TransOpaque = 0x03,
}

#[derive(Debug, PartialEq, TryFromPrimitive, IntoPrimitive, EnumString, Display)]
#[repr(u8)]
pub enum ExtCommunitySubType {
    #[strum(serialize = "rt")]
    RouteTarget = 0x02,
    #[strum(serialize = "soo")]
    RouteOrigin = 0x03,
    #[strum(serialize = "opqque")]
    Opaque = 0x0c,
}

impl ExtCommunitySubType {
    pub fn display(val: u8) -> String {
        if let Ok(sub_type) = Self::try_from(val) {
            format!("{sub_type}")
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(TryFromPrimitive, IntoPrimitive, EnumString, Display)]
#[repr(u16)]
pub enum TunnelType {
    #[strum(serialize = "L2TPv3")]
    L2tpv3 = 1,
    #[strum(serialize = "GRE")]
    Gre = 2,
    #[strum(serialize = "VXLAN")]
    Vxlan = 8,
    #[strum(serialize = "NVGRE")]
    Nvgre = 9,
    #[strum(serialize = "MPLS-in-GRE")]
    MplsGre = 11,
}
