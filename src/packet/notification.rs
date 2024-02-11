use crate::{BgpHeader, BgpPacketType, BGP_PACKET_HEADER_LEN};
use nom_derive::*;
use rusticata_macros::newtype_enum;

#[derive(Debug, NomBE)]
pub struct NotificationPacket {
    pub header: BgpHeader,
    pub code: u8,
    pub sub_code: u8,
    #[nom(Ignore)]
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum NotificationError {
    OpenMessage(OpenMessageError),
}

#[derive(Debug)]
pub enum OpenMessageError {
    UnsupportedVersionNumber = 1,
    BadPeerAS = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
}

impl From<OpenMessageError> for NotificationError {
    fn from(error: OpenMessageError) -> NotificationError {
        NotificationError::OpenMessage(error)
    }
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct NotificationCode(u8);

newtype_enum! {
    impl display NotificationCode {
        MessageHeaderError = 1,
        OPENMessageError = 2,
        UPDATEMessageError = 3,
        HoldTimerExpired = 4,
        FiniteStateMachineError = 5,
        Cease = 6,
    }
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct NotificationMessageSubCode(u8);

newtype_enum! {
    impl display NotificationMessageSubCode {
        ConnectionNotSynchronized = 1,
        BadMessageLength = 2,
        BadMessageType = 3,
    }
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct NotificationOpenSubCode(u8);

newtype_enum! {
    impl display NotificationOpenSubCode {
        UnsupportedVersionNumber = 1,
        BadPeerAS = 2,
        BadBGPIdentifier = 3,
        UnsupportedOptionalParameter = 4,
        // [Deprecated] = 5,
        UnacceptableHoldTime = 6,
}}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct NotificationUpdateSubCode(u8);

newtype_enum! {
    impl display NotificationUpdateSubCode {
        MalformedAttributeList = 1,
        UnrecognizedWellknownAttribute = 2,
        MissingWellknownAttribute = 3,
        AttributeFlagsError = 4,
        AttributeLengthError = 5,
        InvalidORIGINAttribute = 6,
        // [Deprecated] = 7,
        InvalidNEXT_HOPAttribute = 8,
        OptionalAttributeError = 9,
        InvalidNetworkField = 10,
        MalformedAS_PATH =  11,
    }
}

impl NotificationPacket {
    pub fn new(code: u8, sub_code: u8) -> Self {
        Self {
            header: BgpHeader::new(BgpPacketType::Notification, BGP_PACKET_HEADER_LEN),
            code,
            sub_code,
            data: Vec::new(),
        }
    }
}

use bytes::{BufMut, BytesMut};

impl From<NotificationPacket> for BytesMut {
    fn from(notification: NotificationPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = notification.header.into();
        buf.put(&header[..]);
        buf.put_u8(notification.code);
        buf.put_u8(notification.sub_code);
        buf
    }
}
