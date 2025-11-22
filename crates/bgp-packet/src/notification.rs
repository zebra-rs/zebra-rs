use std::fmt::Display;

use super::{BGP_HEADER_LEN, BgpHeader, BgpType};
use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::{IResult, number::complete::be_u8};
use nom_derive::*;
use serde::Serialize;

#[derive(Debug, NomBE)]
pub struct NotificationPacket {
    pub header: BgpHeader,
    pub code: NotifyCode,
    pub sub_code: u8,
    #[nom(Ignore)]
    pub data: Vec<u8>,
}

impl Display for NotificationPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Notification").unwrap();
        writeln!(f, " Code: {}", self.code).unwrap();
        writeln!(
            f,
            " Sub Code: {}",
            notify_sub_code_str(self.code, self.sub_code)
        )
        .unwrap();
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotifyCode {
    MsgHeaderError = 1,
    OpenMsgError = 2,
    UpdateMsgError = 3,
    HoldTimerExpired = 4,
    FsmError = 5,
    Cease = 6,
    RouteRefreshError = 7,
    SendHoldTimeError = 8,
    Unknown(u8),
}

impl NotifyCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, code) = be_u8(input)?;
        let code: Self = code.into();
        Ok((input, code))
    }
}

impl From<NotifyCode> for u8 {
    fn from(code: NotifyCode) -> Self {
        use NotifyCode::*;
        match code {
            MsgHeaderError => 1,
            OpenMsgError => 2,
            UpdateMsgError => 3,
            HoldTimerExpired => 4,
            FsmError => 5,
            Cease => 6,
            RouteRefreshError => 7,
            SendHoldTimeError => 8,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for NotifyCode {
    fn from(code: u8) -> Self {
        use NotifyCode::*;
        match code {
            1 => MsgHeaderError,
            2 => OpenMsgError,
            3 => UpdateMsgError,
            4 => HoldTimerExpired,
            5 => FsmError,
            6 => Cease,
            7 => RouteRefreshError,
            8 => SendHoldTimeError,
            v => Unknown(v),
        }
    }
}

impl Display for NotifyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use NotifyCode::*;
        match self {
            MsgHeaderError => write!(f, "MsgHeaderError"),
            OpenMsgError => write!(f, "OpenMsgError"),
            UpdateMsgError => write!(f, "UpdateMsgError"),
            HoldTimerExpired => write!(f, "HoldTimerExpired"),
            FsmError => write!(f, "FsmError"),
            Cease => write!(f, "Cease"),
            RouteRefreshError => write!(f, "RouteRefreshError"),
            SendHoldTimeError => write!(f, "SendHoldTimeError"),
            Unknown(v) => write!(f, "Unknown {}", v),
        }
    }
}

fn notify_sub_code_str(code: NotifyCode, sub_code: u8) -> String {
    use NotifyCode::*;
    match code {
        MsgHeaderError => sub_header_error_str(sub_code.into()),
        OpenMsgError => sub_open_error_str(sub_code.into()),
        UpdateMsgError => sub_update_error_str(sub_code.into()),
        HoldTimerExpired => "Hold Timer Expired".into(),
        FsmError => sub_fsm_error_str(sub_code.into()),
        Cease => sub_cease_error_str(sub_code.into()),
        RouteRefreshError => sub_route_refresh_error_str(sub_code.into()),
        SendHoldTimeError => "Send HoldTime Error".into(),
        Unknown(v) => format!("Unknown {}", v),
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum HeaderError {
    ConnectionNotSynced = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
    Unknown(u8),
}

impl From<u8> for HeaderError {
    fn from(sub_code: u8) -> Self {
        use HeaderError::*;
        match sub_code {
            1 => ConnectionNotSynced,
            2 => BadMessageLength,
            3 => BadMessageType,
            v => Unknown(v),
        }
    }
}

fn sub_header_error_str(sub_code: HeaderError) -> String {
    use HeaderError::*;
    match sub_code {
        ConnectionNotSynced => "Connection Not Synced".into(),
        BadMessageLength => "Bad Message Length".into(),
        BadMessageType => "Bad Message Type".into(),
        Unknown(v) => format!("Unknown({})", v),
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum OpenError {
    UnsupportedVersionNumber = 1,
    BadPeerAS = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    // [Deprecated] = 5
    UnacceptableHoldTime = 6,
    UnsupportedCapability = 7, // RFC5492
    // [Deprecated] = 8 - 10
    RoleMismatch = 11, // RFC9234
    Unknown(u8),
}

impl From<u8> for OpenError {
    fn from(sub_code: u8) -> Self {
        use OpenError::*;
        match sub_code {
            1 => UnsupportedVersionNumber,
            2 => BadPeerAS,
            3 => BadBgpIdentifier,
            4 => UnsupportedOptionalParameter,
            6 => UnacceptableHoldTime,
            7 => UnsupportedCapability,
            11 => RoleMismatch,
            v => Unknown(v),
        }
    }
}

impl From<OpenError> for u8 {
    fn from(error: OpenError) -> Self {
        use OpenError::*;
        match error {
            UnsupportedVersionNumber => 1,
            BadPeerAS => 2,
            BadBgpIdentifier => 3,
            UnsupportedOptionalParameter => 4,
            UnacceptableHoldTime => 6,
            UnsupportedCapability => 7,
            RoleMismatch => 11,
            Unknown(v) => v,
        }
    }
}

fn sub_open_error_str(sub_code: OpenError) -> String {
    use OpenError::*;
    match sub_code {
        UnsupportedVersionNumber => "Unsupported Version Number".into(),
        BadPeerAS => "Bad Peer AS".into(),
        BadBgpIdentifier => "Bad BGP Identifier".into(),
        UnsupportedOptionalParameter => "Unsupported Optional Parameter".into(),
        UnacceptableHoldTime => "Unacceptable Hold Time".into(),
        UnsupportedCapability => "Unsupported Capability".into(),
        RoleMismatch => "Role Mismatch".into(),
        Unknown(v) => format!("Unknown({})", v),
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum UpdateError {
    MalformedAttributeList = 1,
    UnrecognizedWellknownAttribute = 2,
    MissingWellknownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    // [Deprecated] = 7,
    InvalidNexthopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAspath = 11,
    Unknown(u8),
}

impl From<u8> for UpdateError {
    fn from(sub_code: u8) -> Self {
        use UpdateError::*;
        match sub_code {
            1 => MalformedAttributeList,
            2 => UnrecognizedWellknownAttribute,
            3 => MissingWellknownAttribute,
            4 => AttributeFlagsError,
            5 => AttributeLengthError,
            6 => InvalidOriginAttribute,
            8 => InvalidNexthopAttribute,
            9 => OptionalAttributeError,
            10 => InvalidNetworkField,
            11 => MalformedAspath,
            v => Unknown(v),
        }
    }
}

fn sub_update_error_str(sub_code: UpdateError) -> String {
    use UpdateError::*;
    match sub_code {
        MalformedAttributeList => "Malformed Attribute List".into(),
        UnrecognizedWellknownAttribute => "Unrecognized Wellknown Attribute".into(),
        MissingWellknownAttribute => "Missing Wellknown Attribute".into(),
        AttributeFlagsError => "Attribute Flags Error".into(),
        AttributeLengthError => "Attribute Length Error".into(),
        InvalidOriginAttribute => "Invalid Origin Attribute".into(),
        InvalidNexthopAttribute => "Invalid Nexthop Attribute".into(),
        OptionalAttributeError => "Optional Attribute Error".into(),
        InvalidNetworkField => "Invalid Network Field".into(),
        MalformedAspath => "Malformed Aspath".into(),
        Unknown(v) => format!("Unknown({})", v),
    }
}

#[repr(u8)]
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum FsmError {
    UnexpectedMessageInOpenSent = 1,    // RFC6608
    UnexpectedMessageInOpenConfirm = 2, // RFC6608
    UnexpectedMessageInEstablished = 3, // RFC6608
    Unknown(u8),
}

impl From<u8> for FsmError {
    fn from(sub_code: u8) -> Self {
        use FsmError::*;
        match sub_code {
            1 => UnexpectedMessageInOpenSent,
            2 => UnexpectedMessageInOpenConfirm,
            3 => UnexpectedMessageInEstablished,
            v => Unknown(v),
        }
    }
}

fn sub_fsm_error_str(sub_code: FsmError) -> String {
    use FsmError::*;
    match sub_code {
        UnexpectedMessageInOpenSent => "Unexpected Message in OpenSent State".into(),
        UnexpectedMessageInOpenConfirm => "Unexpected Message in OpenConfirm State".into(),
        UnexpectedMessageInEstablished => "Unexpected Message in Established State".into(),
        Unknown(v) => format!("Unknown({})", v),
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum CeaseError {
    MaximumNumberOfPrefixReached = 1,  // RFC4486
    AdministrativeShutdown = 2,        // RFC4486|RFC9003
    PeerDeConfigured = 3,              // RFC4486
    AdministrativeReset = 4,           // RFC4486|RFC9003
    ConnectionRejected = 5,            // RFC4486
    OtherConfigChange = 6,             // RFC4486
    ConnectionCollisionResolution = 7, // RFC4486
    OutOfResources = 8,                // RFC4486
    HardReset = 9,                     // RFC4486
    BfdDown = 10,                      // RFC4486
    Unknown(u8),
}

impl From<u8> for CeaseError {
    fn from(sub_code: u8) -> Self {
        use CeaseError::*;
        match sub_code {
            1 => MaximumNumberOfPrefixReached,
            2 => AdministrativeShutdown,
            3 => PeerDeConfigured,
            4 => AdministrativeReset,
            5 => ConnectionRejected,
            6 => OtherConfigChange,
            7 => ConnectionCollisionResolution,
            8 => OutOfResources,
            9 => HardReset,
            10 => BfdDown,
            v => Unknown(v),
        }
    }
}

fn sub_cease_error_str(sub_code: CeaseError) -> String {
    use CeaseError::*;
    match sub_code {
        MaximumNumberOfPrefixReached => "Maximum Number of Prefixes Reached".into(),
        AdministrativeShutdown => "Administrative Shutdown".into(),
        PeerDeConfigured => "Peer De-configured".into(),
        AdministrativeReset => "Administrative Reset".into(),
        ConnectionRejected => "Connection Rejected".into(),
        OtherConfigChange => "Other Configuration Change".into(),
        ConnectionCollisionResolution => "Connection Collision Resolution".into(),
        OutOfResources => "Out of Resources".into(),
        HardReset => "Hard Reset".into(),
        BfdDown => "BFD Down".into(),
        Unknown(v) => format!("Unknown({})", v),
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum RouteRefreshError {
    InvalidMessageLength = 1, // RFC7313
    Unknown(u8),
}

impl From<u8> for RouteRefreshError {
    fn from(sub_code: u8) -> Self {
        use RouteRefreshError::*;
        match sub_code {
            1 => InvalidMessageLength,
            v => Unknown(v),
        }
    }
}

fn sub_route_refresh_error_str(sub_code: RouteRefreshError) -> String {
    use RouteRefreshError::*;
    match sub_code {
        InvalidMessageLength => "Invalid Message Length".into(),
        Unknown(v) => format!("Unknown({})", v),
    }
}

impl NotificationPacket {
    pub fn new(code: NotifyCode, sub_code: u8, data: Vec<u8>) -> Self {
        Self {
            header: BgpHeader::new(BgpType::Notification, BGP_HEADER_LEN),
            code,
            sub_code,
            data,
        }
    }
}

impl From<NotificationPacket> for BytesMut {
    fn from(notification: NotificationPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = notification.header.into();
        buf.put(&header[..]);
        buf.put_u8(notification.code.into());
        buf.put_u8(notification.sub_code);
        buf.put(&notification.data[..]);

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl NotificationPacket {
    pub fn parse_packet(input: &[u8]) -> IResult<&[u8], NotificationPacket> {
        let (input, packet) = NotificationPacket::parse_be(input)?;
        let len = packet.header.length - BGP_HEADER_LEN - 2;
        let (input, _data) = take(len as usize).parse(input)?;
        Ok((input, packet))
    }
}
