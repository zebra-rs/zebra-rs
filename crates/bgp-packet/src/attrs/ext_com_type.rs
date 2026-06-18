use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::{Display, EnumString};

#[repr(u8)]
pub enum ExtCommunityType {
    TransTwoOctetAS = 0x00,
    // TransIpv4Addr = 0x01,
    // TransFourOctetAS = 0x03,
    TransOpaque = 0x03,
    /// RFC 7153 / RFC 9251 — EVPN Extended Community high-type byte.
    /// Sub-type 0x09 is the Multicast Flags EC (IGMP/MLD proxy
    /// capability); see `ExtCommunityValue::as_evpn_mcast_flags`.
    Evpn = 0x06,
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

/// MUP Extended Community sub-type values (high-type 0x0c, RFC 9833 §5).
///
/// Names are kept numeric for now because the exact IANA-assigned
/// names and payload layouts in RFC 9833 §5 haven't been confirmed
/// against the spec in-tree; the 6-octet value travels as opaque
/// bytes via `ExtCommunityValue::val`. A follow-up phase will rename
/// these and add typed accessors once the per-sub-type layout is
/// pinned down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MupExtComSubType {
    Sub00,
    Sub01,
    Sub02,
    Sub03,
    Unknown(u8),
}

impl From<MupExtComSubType> for u8 {
    fn from(val: MupExtComSubType) -> u8 {
        use MupExtComSubType::*;
        match val {
            Sub00 => 0x00,
            Sub01 => 0x01,
            Sub02 => 0x02,
            Sub03 => 0x03,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for MupExtComSubType {
    fn from(val: u8) -> Self {
        use MupExtComSubType::*;
        match val {
            0x00 => Sub00,
            0x01 => Sub01,
            0x02 => Sub02,
            0x03 => Sub03,
            v => Unknown(v),
        }
    }
}

impl std::fmt::Display for MupExtComSubType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw: u8 = (*self).into();
        write!(f, "mup-sub-0x{raw:02x}")
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
