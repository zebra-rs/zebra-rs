use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum CapCode {
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
    LlgrOld = 129,
    Unknown(u8),
}

impl From<CapCode> for u8 {
    fn from(typ: CapCode) -> Self {
        use CapCode::*;
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
            LlgrOld => 129,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for CapCode {
    fn from(typ: u8) -> Self {
        use CapCode::*;
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
            129 => LlgrOld,
            v => Unknown(v),
        }
    }
}

impl CapCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let cap_type: Self = typ.into();
        Ok((input, cap_type))
    }
}
