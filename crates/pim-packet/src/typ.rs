use std::fmt::Display;

/// PIM message type, the low nibble of the first header octet
/// (RFC 7761 §4.9, RFC 8736 registry).
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum PimType {
    #[default]
    Hello = 0,
    Register = 1,
    RegisterStop = 2,
    JoinPrune = 3,
    Bootstrap = 4,
    Assert = 5,
    Graft = 6,
    GraftAck = 7,
    CandRpAdv = 8,
    Unknown(u8),
}

impl Display for PimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use PimType::*;
        let str = match self {
            Hello => "Hello",
            Register => "Register",
            RegisterStop => "Register-Stop",
            JoinPrune => "Join/Prune",
            Bootstrap => "Bootstrap",
            Assert => "Assert",
            Graft => "Graft",
            GraftAck => "Graft-Ack",
            CandRpAdv => "Candidate-RP-Advertisement",
            Unknown(_) => "Unknown",
        };
        write!(f, "{str}")
    }
}

impl From<PimType> for u8 {
    fn from(typ: PimType) -> Self {
        use PimType::*;
        match typ {
            Hello => 0,
            Register => 1,
            RegisterStop => 2,
            JoinPrune => 3,
            Bootstrap => 4,
            Assert => 5,
            Graft => 6,
            GraftAck => 7,
            CandRpAdv => 8,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for PimType {
    fn from(val: u8) -> Self {
        use PimType::*;
        match val {
            0 => Hello,
            1 => Register,
            2 => RegisterStop,
            3 => JoinPrune,
            4 => Bootstrap,
            5 => Assert,
            6 => Graft,
            7 => GraftAck,
            8 => CandRpAdv,
            v => Unknown(v),
        }
    }
}
