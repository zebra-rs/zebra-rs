#![allow(dead_code)]
use super::{BgpHeader, BgpType, BGP_HEADER_LEN};
use nom_derive::*;
use rusticata_macros::newtype_enum;

#[derive(Debug, NomBE)]
pub struct NotificationPacket {
    pub header: BgpHeader,
    pub code: NotificationCode,
    pub sub_code: u8,
    #[nom(Ignore)]
    pub data: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, NomBE, Clone)]
pub struct NotificationCode(pub u8);

newtype_enum! {
    impl display NotificationCode {
        MessageHeaderError = 1,
        OpenMessageError = 2,
        UpdateMessageError = 3,
        HoldTimerExpired = 4,
        FiniteStateMachineError = 5,
        Cease = 6,
        RouteRefreshError = 7,  // RFC7313
        SendHoldTimeError = 8,  // draft-ietf-idr-bgp-sendholdtimer-01
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum MessageError {
    ConnectionNotSynced = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
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
}

#[repr(u8)]
#[derive(Debug)]
pub enum UpdateError {
    MalformedAttributeList = 1,
    UnrecognizedWellknownAttribute = 2,
    MissingWellknownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidORIGINAttribute = 6,
    // [Deprecated] = 7,
    InvalidNexthopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAspath = 11,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum FsmError {
    UnexpectedMessageInOpenSent = 1,    // RFC6608
    UnexpectedMessageInOpenConfirm = 2, // RFC6608
    UnexpectedMessageInEstablished = 3, // RFC6608
}

#[repr(u8)]
#[derive(Debug)]
pub enum NotificationError {
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
}

#[repr(u8)]
#[derive(Debug)]
pub enum RouteRefreshError {
    InvalidMessageLength = 1, // RFC7313
}

impl NotificationPacket {
    pub fn new(code: NotificationCode, sub_code: u8, data: Vec<u8>) -> Self {
        Self {
            header: BgpHeader::new(BgpType::Notification, BGP_HEADER_LEN),
            code,
            sub_code,
            data,
        }
    }
}
