use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::{Display, EnumString};

#[repr(u8)]
pub enum ExtCommunityType {
    TransTwoOctetAS = 0x00,
    // TransIpv4Addr = 0x01,
    // TransFourOctetAS = 0x03,
    TransOpaque = 0x03,
    /// RFC 9833 — BGP MUP Extended Community high-type byte. Sub-type
    /// decode is deferred to a later phase; raw 8-byte value passes
    /// through the generic ExtCommunity path for now.
    Mup = 0x0c,
}

#[derive(
    Debug,
    Clone,
    Copy,
    TryFromPrimitive,
    IntoPrimitive,
    EnumString,
    Display,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum ExtCommunitySubType {
    #[strum(serialize = "rt")]
    RouteTarget = 0x02,
    #[strum(serialize = "soo")]
    RouteOrigin = 0x03,
    /// RFC 9012 §4.3 Color extended community. Sub-Type 0x0b when
    /// carried inside Transitive Opaque extcomm type 0x03.
    #[strum(serialize = "color")]
    Color = 0x0b,
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
