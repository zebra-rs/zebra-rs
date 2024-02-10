use crate::BgpHeader;
use nom_derive::*;
use rusticata_macros::newtype_enum;

#[derive(Debug, NomBE)]
pub struct NotificationPacket {
    pub header: BgpHeader,
    pub err_code: u8,
    pub err_subcode: u8,
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
