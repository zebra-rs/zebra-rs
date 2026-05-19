use std::fmt::Display;

/// BFD session state (RFC 5880 §4.1, 2-bit field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum State {
    #[default]
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

impl State {
    /// Convert the 2-bit on-wire value to a [`State`].
    pub fn from_bits(v: u8) -> Self {
        match v & 0b11 {
            0 => State::AdminDown,
            1 => State::Down,
            2 => State::Init,
            3 => State::Up,
            _ => unreachable!(),
        }
    }
}

impl From<State> for u8 {
    fn from(s: State) -> u8 {
        s as u8
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            State::AdminDown => "AdminDown",
            State::Down => "Down",
            State::Init => "Init",
            State::Up => "Up",
        };
        f.write_str(s)
    }
}

/// BFD diagnostic code (RFC 5880 §4.1, 5-bit field).
///
/// Codes 0–8 are defined by RFC 5880; code 9 is added by RFC 6428.
/// Values 10–31 are reserved and surface as `Reserved(v)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Diag {
    #[default]
    None,
    ControlDetectionTimeExpired,
    EchoFunctionFailed,
    NeighborSignaledSessionDown,
    ForwardingPlaneReset,
    PathDown,
    ConcatenatedPathDown,
    AdministrativelyDown,
    ReverseConcatenatedPathDown,
    MisConnectivityDefect,
    Reserved(u8),
}

impl From<u8> for Diag {
    fn from(v: u8) -> Self {
        match v & 0b0001_1111 {
            0 => Diag::None,
            1 => Diag::ControlDetectionTimeExpired,
            2 => Diag::EchoFunctionFailed,
            3 => Diag::NeighborSignaledSessionDown,
            4 => Diag::ForwardingPlaneReset,
            5 => Diag::PathDown,
            6 => Diag::ConcatenatedPathDown,
            7 => Diag::AdministrativelyDown,
            8 => Diag::ReverseConcatenatedPathDown,
            9 => Diag::MisConnectivityDefect,
            v => Diag::Reserved(v),
        }
    }
}

impl From<Diag> for u8 {
    fn from(d: Diag) -> u8 {
        match d {
            Diag::None => 0,
            Diag::ControlDetectionTimeExpired => 1,
            Diag::EchoFunctionFailed => 2,
            Diag::NeighborSignaledSessionDown => 3,
            Diag::ForwardingPlaneReset => 4,
            Diag::PathDown => 5,
            Diag::ConcatenatedPathDown => 6,
            Diag::AdministrativelyDown => 7,
            Diag::ReverseConcatenatedPathDown => 8,
            Diag::MisConnectivityDefect => 9,
            Diag::Reserved(v) => v & 0b0001_1111,
        }
    }
}

impl Display for Diag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Diag::None => "None",
            Diag::ControlDetectionTimeExpired => "ControlDetectionTimeExpired",
            Diag::EchoFunctionFailed => "EchoFunctionFailed",
            Diag::NeighborSignaledSessionDown => "NeighborSignaledSessionDown",
            Diag::ForwardingPlaneReset => "ForwardingPlaneReset",
            Diag::PathDown => "PathDown",
            Diag::ConcatenatedPathDown => "ConcatenatedPathDown",
            Diag::AdministrativelyDown => "AdministrativelyDown",
            Diag::ReverseConcatenatedPathDown => "ReverseConcatenatedPathDown",
            Diag::MisConnectivityDefect => "MisConnectivityDefect",
            Diag::Reserved(_) => "Reserved",
        };
        f.write_str(s)
    }
}

/// BFD authentication type (RFC 5880 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    SimplePassword,
    KeyedMd5,
    MeticulousKeyedMd5,
    KeyedSha1,
    MeticulousKeyedSha1,
    Reserved(u8),
}

impl From<u8> for AuthType {
    fn from(v: u8) -> Self {
        match v {
            1 => AuthType::SimplePassword,
            2 => AuthType::KeyedMd5,
            3 => AuthType::MeticulousKeyedMd5,
            4 => AuthType::KeyedSha1,
            5 => AuthType::MeticulousKeyedSha1,
            v => AuthType::Reserved(v),
        }
    }
}

impl From<AuthType> for u8 {
    fn from(t: AuthType) -> u8 {
        match t {
            AuthType::SimplePassword => 1,
            AuthType::KeyedMd5 => 2,
            AuthType::MeticulousKeyedMd5 => 3,
            AuthType::KeyedSha1 => 4,
            AuthType::MeticulousKeyedSha1 => 5,
            AuthType::Reserved(v) => v,
        }
    }
}

impl Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthType::SimplePassword => "SimplePassword",
            AuthType::KeyedMd5 => "KeyedMd5",
            AuthType::MeticulousKeyedMd5 => "MeticulousKeyedMd5",
            AuthType::KeyedSha1 => "KeyedSha1",
            AuthType::MeticulousKeyedSha1 => "MeticulousKeyedSha1",
            AuthType::Reserved(_) => "Reserved",
        };
        f.write_str(s)
    }
}
