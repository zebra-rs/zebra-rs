use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisNeighCode {
    /// RFC 5305 §3.1 — classic Administrative Group / link color
    /// (fixed 4 octets). Distinct from the RFC 7308 Extended
    /// Administrative Groups at code 14.
    AdminGroup = 3,
    #[default]
    Ipv4IfAddr = 6,
    Ipv4NeighAddr = 8,
    Ipv6IfAddr = 12,
    Ipv6NeighAddr = 13,
    AdminGrp = 14,
    Asla = 16,
    TeMetric = 18,
    AdjSid = 31,
    LanAdjSid = 32,
    /// RFC 8570 §4.1 — Unidirectional Link Delay (4 octets, µs).
    UniLinkDelay = 33,
    /// RFC 8570 §4.2 — Min/Max Unidirectional Link Delay (8 octets).
    MinMaxLinkDelay = 34,
    /// RFC 8570 §4.3 — Unidirectional Delay Variation (4 octets, µs).
    DelayVariation = 35,
    /// RFC 8570 §4.4 — Unidirectional Link Loss (4 octets, 0.000003 %).
    LinkLoss = 36,
    /// RFC 8570 §4.5 — Unidirectional Residual Bandwidth (4 octets,
    /// IEEE 754 single-precision, B/s).
    ResidualBw = 37,
    /// RFC 8570 §4.6 — Unidirectional Available Bandwidth.
    AvailableBw = 38,
    /// RFC 8570 §4.7 — Unidirectional Utilized Bandwidth.
    UtilizedBw = 39,
    Srv6EndXSid = 43,
    Srv6LanEndXSid = 44,
    Unknown(u8),
}

impl From<IsisNeighCode> for u8 {
    fn from(typ: IsisNeighCode) -> Self {
        use IsisNeighCode::*;
        match typ {
            AdminGroup => 3,
            Ipv4IfAddr => 6,
            Ipv4NeighAddr => 8,
            Ipv6IfAddr => 12,
            Ipv6NeighAddr => 13,
            AdminGrp => 14,
            Asla => 16,
            TeMetric => 18,
            AdjSid => 31,
            LanAdjSid => 32,
            UniLinkDelay => 33,
            MinMaxLinkDelay => 34,
            DelayVariation => 35,
            LinkLoss => 36,
            ResidualBw => 37,
            AvailableBw => 38,
            UtilizedBw => 39,
            Srv6EndXSid => 43,
            Srv6LanEndXSid => 44,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisNeighCode {
    fn from(typ: u8) -> Self {
        use IsisNeighCode::*;
        match typ {
            3 => AdminGroup,
            6 => Ipv4IfAddr,
            8 => Ipv4NeighAddr,
            12 => Ipv6IfAddr,
            13 => Ipv6NeighAddr,
            14 => AdminGrp,
            16 => Asla,
            18 => TeMetric,
            31 => AdjSid,
            32 => LanAdjSid,
            33 => UniLinkDelay,
            34 => MinMaxLinkDelay,
            35 => DelayVariation,
            36 => LinkLoss,
            37 => ResidualBw,
            38 => AvailableBw,
            39 => UtilizedBw,
            43 => Srv6EndXSid,
            44 => Srv6LanEndXSid,
            v => Unknown(v),
        }
    }
}

impl IsisNeighCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}
