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
        writeln!(f, "Notification")?;
        writeln!(f, " Code: {}", self.code)?;
        writeln!(
            f,
            " Sub Code: {}",
            notify_sub_code_str(self.code, self.sub_code)
        )?;
        if let Some(msg) = self.shutdown_communication() {
            // The operator's own words for why the session went down
            // (RFC 9003) — the whole reason the Data field is worth keeping.
            writeln!(f, " Shutdown Communication: {msg}")?;
        } else if !self.data.is_empty() {
            // Everything else — RFC 4486 Maximum Prefixes' AFI/SAFI and count,
            // or the offending octets of the attribute the peer objected to —
            // has no decoder here, so show it raw rather than drop it again.
            writeln!(f, " Data: {}", data_hex(&self.data))?;
        }
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

/// Human-readable sub-code name for `code`, e.g. "Administrative Shutdown".
pub fn notify_sub_code_str(code: NotifyCode, sub_code: u8) -> String {
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

impl From<UpdateError> for u8 {
    fn from(sub_code: UpdateError) -> Self {
        use UpdateError::*;
        match sub_code {
            MalformedAttributeList => 1,
            UnrecognizedWellknownAttribute => 2,
            MissingWellknownAttribute => 3,
            AttributeFlagsError => 4,
            AttributeLengthError => 5,
            InvalidOriginAttribute => 6,
            InvalidNexthopAttribute => 8,
            OptionalAttributeError => 9,
            InvalidNetworkField => 10,
            MalformedAspath => 11,
            Unknown(v) => v,
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

impl From<CeaseError> for u8 {
    fn from(error: CeaseError) -> Self {
        use CeaseError::*;
        match error {
            MaximumNumberOfPrefixReached => 1,
            AdministrativeShutdown => 2,
            PeerDeConfigured => 3,
            AdministrativeReset => 4,
            ConnectionRejected => 5,
            OtherConfigChange => 6,
            ConnectionCollisionResolution => 7,
            OutOfResources => 8,
            HardReset => 9,
            BfdDown => 10,
            Unknown(v) => v,
        }
    }
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
        let (input, mut packet) = NotificationPacket::parse_be(input)?;
        let len = packet
            .header
            .length
            .saturating_sub(BGP_HEADER_LEN)
            .saturating_sub(2);
        let (input, data) = take(len as usize).parse(input)?;
        // Keep the Data field. `data` is `#[nom(Ignore)]`, so the derived parse
        // leaves it empty and these octets used to be read into a discarded
        // binding — a peer's RFC 9003 shutdown message, or the offending bytes
        // of the attribute it objected to, reached the process and were dropped
        // before anyone could see them.
        packet.data = data.to_vec();
        Ok((input, packet))
    }

    /// The RFC 9003 Shutdown Communication, if this is one and it is well
    /// formed.
    ///
    /// Only Cease subcodes 2 (Administrative Shutdown) and 4 (Administrative
    /// Reset) may carry it. The Data field is a 1-octet length followed by that
    /// many octets of UTF-8 — RFC 9003 raised the cap from RFC 8203's 128 to
    /// 255, so any length fits the octet.
    ///
    /// RFC 9003 §4 says a receiver finding invalid UTF-8 SHOULD log the fact and
    /// MUST NOT interpret the malformed sequence, but must not reject the
    /// NOTIFICATION over it — so this renders lossily and only declines when the
    /// length field disagrees with the octets present.
    pub fn shutdown_communication(&self) -> Option<String> {
        if self.code != NotifyCode::Cease {
            return None;
        }
        if !matches!(
            CeaseError::from(self.sub_code),
            CeaseError::AdministrativeShutdown | CeaseError::AdministrativeReset
        ) {
            return None;
        }
        let (&len, rest) = self.data.split_first()?;
        let len = len as usize;
        if len == 0 || rest.len() < len {
            return None;
        }
        Some(String::from_utf8_lossy(&rest[..len]).into_owned())
    }
}

/// Render the NOTIFICATION Data octets for a human, used when no subcode-
/// specific decoder applies.
fn data_hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::CeaseError;
    use super::*;

    /// Build the wire form of a NOTIFICATION with the given Data.
    fn wire(code: u8, sub_code: u8, data: &[u8]) -> BytesMut {
        let packet = NotificationPacket::new(NotifyCode::from(code), sub_code, data.to_vec());
        packet.into()
    }

    /// The Data field must survive parsing. Regression: `data` is
    /// `#[nom(Ignore)]`, so the derived parse left it empty and `parse_packet`
    /// read the octets into a discarded binding — every NOTIFICATION arrived
    /// with `data` empty, whatever the peer sent.
    #[test]
    fn notification_data_survives_round_trip() {
        let buf = wire(6, 2, &[0x04, b'b', b'y', b'e', b'!']);
        let (rest, parsed) = NotificationPacket::parse_packet(&buf).expect("must parse");
        assert!(rest.is_empty());
        assert_eq!(parsed.code, NotifyCode::Cease);
        assert_eq!(parsed.sub_code, 2);
        assert_eq!(
            parsed.data,
            vec![0x04, b'b', b'y', b'e', b'!'],
            "Data must not be dropped"
        );
    }

    /// RFC 9003: a Cease/Administrative Shutdown (2) or Administrative Reset (4)
    /// carries a 1-octet length then that many octets of UTF-8.
    #[test]
    fn shutdown_communication_is_decoded() {
        for sub in [2u8, 4] {
            let msg = "maintenance window";
            let mut data = vec![msg.len() as u8];
            data.extend_from_slice(msg.as_bytes());
            let buf = wire(6, sub, &data);
            let (_, parsed) = NotificationPacket::parse_packet(&buf).expect("must parse");
            assert_eq!(parsed.shutdown_communication().as_deref(), Some(msg));
            assert!(parsed.to_string().contains(msg), "Display surfaces it");
        }
    }

    /// The shutdown communication is only defined for those two Cease subcodes;
    /// elsewhere the Data means something else and must not be read as text.
    #[test]
    fn shutdown_communication_only_for_its_subcodes() {
        let data = [0x03, b'a', b'b', b'c'];
        // Cease, but subcode 1 (Maximum Number of Prefixes Reached).
        let buf = wire(6, 1, &data);
        let (_, parsed) = NotificationPacket::parse_packet(&buf).unwrap();
        assert_eq!(parsed.shutdown_communication(), None);
        assert!(
            parsed.to_string().contains("Data: 03 61 62 63"),
            "shown raw"
        );

        // Not a Cease at all.
        let buf = wire(3, 2, &data);
        let (_, parsed) = NotificationPacket::parse_packet(&buf).unwrap();
        assert_eq!(parsed.shutdown_communication(), None);
    }

    /// A length field disagreeing with the octets present is not interpreted.
    /// RFC 9003 §4 still forbids rejecting the NOTIFICATION over it, so the
    /// packet parses and the Data is shown raw.
    #[test]
    fn inconsistent_shutdown_length_is_not_interpreted() {
        // Claims 9 octets, carries 3.
        let buf = wire(6, 2, &[0x09, b'a', b'b', b'c']);
        let (_, parsed) = NotificationPacket::parse_packet(&buf).expect("must still parse");
        assert_eq!(parsed.shutdown_communication(), None);
        assert_eq!(parsed.data, vec![0x09, b'a', b'b', b'c'], "kept verbatim");
    }

    /// Invalid UTF-8 is rendered lossily rather than rejected (RFC 9003 §4:
    /// log it, do not interpret the malformed sequence, do not reject).
    #[test]
    fn invalid_utf8_shutdown_is_lossy_not_fatal() {
        let buf = wire(6, 2, &[0x02, 0xff, 0xfe]);
        let (_, parsed) = NotificationPacket::parse_packet(&buf).expect("must still parse");
        assert!(
            parsed.shutdown_communication().is_some(),
            "rendered lossily, not dropped"
        );
    }

    /// Every Cease sub-code round-trips u8 → CeaseError → u8, including
    /// the Unknown passthrough.
    #[test]
    fn cease_error_subcode_round_trip() {
        for raw in [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 42, 255] {
            let err = CeaseError::from(raw);
            assert_eq!(u8::from(err), raw);
        }
        assert_eq!(u8::from(CeaseError::ConnectionRejected), 5);
        assert_eq!(u8::from(CeaseError::ConnectionCollisionResolution), 7);
    }
}
