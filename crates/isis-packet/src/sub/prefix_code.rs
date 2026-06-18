use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisPrefixCode {
    #[default]
    PrefixSid = 3,
    Srv6EndSid = 5,
    /// draft-ietf-rtgwg-srv6-egress-protection — SRv6 Mirror SID
    /// sub-TLV inside the SRv6 Locator TLV (RFC 9352). Carries the
    /// protector's End.M SID plus the protected egress locator(s).
    Srv6MirrorSid = 8,
    /// RFC 7794 §3.1 — 32-bit TE Router ID of the prefix originator.
    Ipv4SourceRouterId = 11,
    /// RFC 7794 §3.2 — 128-bit IPv6 TE Router ID of the prefix originator.
    Ipv6SourceRouterId = 12,
    Unknown(u8),
}

impl From<IsisPrefixCode> for u8 {
    fn from(typ: IsisPrefixCode) -> Self {
        use IsisPrefixCode::*;
        match typ {
            PrefixSid => 3,
            Srv6EndSid => 5,
            Srv6MirrorSid => 8,
            Ipv4SourceRouterId => 11,
            Ipv6SourceRouterId => 12,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisPrefixCode {
    fn from(typ: u8) -> Self {
        use IsisPrefixCode::*;
        match typ {
            3 => PrefixSid,
            5 => Srv6EndSid,
            8 => Srv6MirrorSid,
            11 => Ipv4SourceRouterId,
            12 => Ipv6SourceRouterId,
            v => Unknown(v),
        }
    }
}

impl IsisPrefixCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisSrv6SidSub2Code {
    #[default]
    SidStructure = 1,
    Unknown(u8),
}

impl From<IsisSrv6SidSub2Code> for u8 {
    fn from(typ: IsisSrv6SidSub2Code) -> Self {
        use IsisSrv6SidSub2Code::*;
        match typ {
            SidStructure => 1,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisSrv6SidSub2Code {
    fn from(typ: u8) -> Self {
        use IsisSrv6SidSub2Code::*;
        match typ {
            1 => SidStructure,
            v => Unknown(v),
        }
    }
}

/// Sub-sub-TLV code points inside the SRv6 Mirror SID sub-TLV
/// (draft-ietf-rtgwg-srv6-egress-protection). This is a distinct
/// registry from [`IsisSrv6SidSub2Code`]; here code 1 is Protected
/// Locators, not SID Structure.
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisSrv6MirrorSub2Code {
    #[default]
    ProtectedLocators = 1,
    Unknown(u8),
}

impl From<IsisSrv6MirrorSub2Code> for u8 {
    fn from(typ: IsisSrv6MirrorSub2Code) -> Self {
        use IsisSrv6MirrorSub2Code::*;
        match typ {
            ProtectedLocators => 1,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisSrv6MirrorSub2Code {
    fn from(typ: u8) -> Self {
        use IsisSrv6MirrorSub2Code::*;
        match typ {
            1 => ProtectedLocators,
            v => Unknown(v),
        }
    }
}
