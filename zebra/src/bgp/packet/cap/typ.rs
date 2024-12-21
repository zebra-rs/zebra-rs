use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum CapabilityCode {
    #[default]
    MultiProtocol = 1,
    RouteRefresh = 2,
    ExtendedNextHop = 5,
    ExtendedMessage = 6,
    Role = 9,
    GracefulRestart = 64,
    As4 = 65,
    DynamicCapability = 67,
    AddPath = 69,
    EnhancedRouteRefresh = 70,
    Llgr = 71,
    Fqdn = 73,
    SoftwareVersion = 75,
    PathLimit = 76,
    RouteRefreshCisco = 128,
    Unknown(u8),
}

impl From<CapabilityCode> for u8 {
    fn from(typ: CapabilityCode) -> Self {
        use CapabilityCode::*;
        match typ {
            MultiProtocol => 1,
            RouteRefresh => 2,
            ExtendedNextHop => 5,
            ExtendedMessage => 6,
            Role => 9,
            GracefulRestart => 64,
            As4 => 65,
            DynamicCapability => 67,
            AddPath => 69,
            EnhancedRouteRefresh => 70,
            Llgr => 71,
            Fqdn => 73,
            SoftwareVersion => 75,
            PathLimit => 76,
            RouteRefreshCisco => 128,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for CapabilityCode {
    fn from(typ: u8) -> Self {
        use CapabilityCode::*;
        match typ {
            1 => MultiProtocol,
            2 => RouteRefresh,
            5 => ExtendedNextHop,
            6 => ExtendedMessage,
            9 => Role,
            64 => GracefulRestart,
            65 => As4,
            67 => DynamicCapability,
            69 => AddPath,
            70 => EnhancedRouteRefresh,
            71 => Llgr,
            73 => Fqdn,
            75 => SoftwareVersion,
            76 => PathLimit,
            128 => RouteRefreshCisco,
            v => Unknown(v),
        }
    }
}

impl CapabilityCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let cap_type: Self = typ.into();
        Ok((input, cap_type))
    }
}
