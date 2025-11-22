use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsisTlvType {
    #[default]
    AreaAddr = 1,
    IsNeighbor = 6,
    Padding = 8,
    LspEntries = 9,
    ExtIsReach = 22,
    Srv6 = 27,
    ProtSupported = 129,
    Ipv4IfAddr = 132,
    TeRouterId = 134,
    ExtIpReach = 135,
    DynamicHostname = 137,
    Ipv6TeRouterId = 140,
    Ipv6IfAddr = 232,
    Ipv6GlobalIfAddr = 233,
    MtIpReach = 235,
    Ipv6Reach = 236,
    MtIpv6Reach = 237,
    P2p3Way = 240,
    RouterCap = 242,
    Unknown(u8),
}

impl IsisTlvType {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let tlv_type: Self = typ.into();
        Ok((input, tlv_type))
    }
}

impl IsisTlvType {
    pub fn is_known(&self) -> bool {
        use IsisTlvType::*;
        matches!(
            self,
            AreaAddr
                | IsNeighbor
                | Padding
                | LspEntries
                | ExtIsReach
                | Srv6
                | ProtSupported
                | Ipv4IfAddr
                | TeRouterId
                | ExtIpReach
                | DynamicHostname
                | Ipv6TeRouterId
                | Ipv6IfAddr
                | Ipv6GlobalIfAddr
                | MtIpReach
                | Ipv6Reach
                | MtIpv6Reach
                | P2p3Way
                | RouterCap
        )
    }
}

impl From<IsisTlvType> for u8 {
    fn from(typ: IsisTlvType) -> Self {
        use IsisTlvType::*;
        match typ {
            AreaAddr => 1,
            IsNeighbor => 6,
            Padding => 8,
            LspEntries => 9,
            ExtIsReach => 22,
            Srv6 => 27,
            ProtSupported => 129,
            Ipv4IfAddr => 132,
            TeRouterId => 134,
            ExtIpReach => 135,
            DynamicHostname => 137,
            Ipv6TeRouterId => 140,
            Ipv6IfAddr => 232,
            Ipv6GlobalIfAddr => 233,
            MtIpReach => 235,
            Ipv6Reach => 236,
            MtIpv6Reach => 237,
            P2p3Way => 240,
            RouterCap => 242,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisTlvType {
    fn from(typ: u8) -> Self {
        use IsisTlvType::*;
        match typ {
            1 => AreaAddr,
            6 => IsNeighbor,
            8 => Padding,
            9 => LspEntries,
            22 => ExtIsReach,
            27 => Srv6,
            129 => ProtSupported,
            132 => Ipv4IfAddr,
            134 => TeRouterId,
            135 => ExtIpReach,
            137 => DynamicHostname,
            140 => Ipv6TeRouterId,
            232 => Ipv6IfAddr,
            233 => Ipv6GlobalIfAddr,
            235 => MtIpReach,
            236 => Ipv6Reach,
            237 => MtIpv6Reach,
            240 => P2p3Way,
            242 => RouterCap,
            v => Unknown(v),
        }
    }
}
