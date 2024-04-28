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
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum OpenError {
    UnsupportedVersionNumber = 1,
    BadPeerAS = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
}

// impl From<OpenMessageError> for NotificationError {
//     fn from(error: OpenMessageError) -> NotificationError {
//         NotificationError::OpenMessage(error)
//     }
// }

// #[derive(Debug, Eq, PartialEq, NomBE)]
// pub struct NotificationMessageSubCode(pub u8);

// newtype_enum! {
//     impl display NotificationMessageSubCode {
//         ConnectionNotSynchronized = 1,
//         BadMessageLength = 2,
//         BadMessageType = 3,
//     }
// }

// #[derive(Debug, Eq, PartialEq, NomBE)]
// pub struct NotificationOpenSubCode(pub u8);

// newtype_enum! {
//     impl display NotificationOpenSubCode {
//         UnsupportedVersionNumber = 1,
//         BadPeerAS = 2,
//         BadBGPIdentifier = 3,
//         UnsupportedOptionalParameter = 4,
//         // [Deprecated] = 5,
//         UnacceptableHoldTime = 6,
// }}

// #[derive(Debug, Eq, PartialEq, NomBE)]
// pub struct NotificationUpdateSubCode(pub u8);

// newtype_enum! {
//     impl display NotificationUpdateSubCode {
//         MalformedAttributeList = 1,
//         UnrecognizedWellknownAttribute = 2,
//         MissingWellknownAttribute = 3,
//         AttributeFlagsError = 4,
//         AttributeLengthError = 5,
//         InvalidORIGINAttribute = 6,
//         // [Deprecated] = 7,
//         InvalidNEXT_HOPAttribute = 8,
//         OptionalAttributeError = 9,
//         InvalidNetworkField = 10,
//         MalformedAS_PATH =  11,
//     }
// }

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
