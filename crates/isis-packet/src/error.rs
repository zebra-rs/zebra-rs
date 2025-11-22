use crate::{IsisTlvType, IsisType};
use nom::{ErrorConvert, error::ParseError};
use thiserror::Error;

/// Custom error type for IS-IS packet parsing
#[derive(Error, Debug, Clone, PartialEq)]
pub enum IsisParseError {
    /// Error parsing a specific TLV
    #[error("TLV parse error: {tlv_type:?} - {message}")]
    TlvParseError {
        tlv_type: IsisTlvType,
        message: String,
    },

    /// Error parsing a specific PDU
    #[error("PDU parse error: {pdu_type:?} - {message}")]
    PduParseError { pdu_type: IsisType, message: String },

    /// Invalid packet length
    #[error("Invalid packet length: expected {expected}, found {found}")]
    InvalidPacketLength { expected: usize, found: usize },

    /// Invalid TLV length
    #[error("Invalid TLV length: TLV type {tlv_type:?}, expected {expected}, found {found}")]
    InvalidTlvLength {
        tlv_type: IsisTlvType,
        expected: usize,
        found: usize,
    },

    /// Invalid discriminator
    #[error("Invalid IS-IS discriminator: expected 0x83, found {found:#x}")]
    InvalidDiscriminator { found: u8 },

    /// Invalid PDU type
    #[error("Invalid PDU type: {pdu_type:#x}")]
    InvalidPduType { pdu_type: u8 },

    /// Invalid TLV type
    #[error("Unknown TLV type: {tlv_type:#x}")]
    UnknownTlvType { tlv_type: u8 },

    /// Invalid checksum
    #[error("Invalid checksum: expected {expected:#x}, found {found:#x}")]
    InvalidChecksum { expected: u16, found: u16 },

    /// Incomplete data during parsing
    #[error("Incomplete data: needed {needed} more bytes")]
    IncompleteData { needed: usize },

    /// Generic nom parsing error
    #[error("Nom parsing error: {message}")]
    NomError { message: String },

    /// Invalid IP address format
    #[error("Invalid IP address format: {message}")]
    InvalidIpAddress { message: String },

    /// Invalid NSAP address format
    #[error("Invalid NSAP address format: {message}")]
    InvalidNsapAddress { message: String },

    /// Invalid sub-TLV
    #[error("Invalid sub-TLV: {message}")]
    InvalidSubTlv { message: String },

    /// Invalid SID/Label value
    #[error("Invalid SID/Label value: {message}")]
    InvalidSidLabel { message: String },

    /// Invalid prefix length
    #[error("Invalid prefix length: {length} for address family")]
    InvalidPrefixLength { length: u8 },

    /// Invalid neighbor ID format
    #[error("Invalid neighbor ID format: {message}")]
    InvalidNeighborId { message: String },

    /// Invalid LSP ID format
    #[error("Invalid LSP ID format: {message}")]
    InvalidLspId { message: String },

    /// Buffer overflow
    #[error("Buffer overflow: attempted to read {attempted} bytes, only {available} available")]
    BufferOverflow { attempted: usize, available: usize },
}

impl IsisParseError {
    /// Create a new TLV parse error
    pub fn tlv_parse_error(tlv_type: IsisTlvType, message: impl Into<String>) -> Self {
        Self::TlvParseError {
            tlv_type,
            message: message.into(),
        }
    }

    /// Create a new PDU parse error
    pub fn pdu_parse_error(pdu_type: IsisType, message: impl Into<String>) -> Self {
        Self::PduParseError {
            pdu_type,
            message: message.into(),
        }
    }

    /// Create a new incomplete data error
    pub fn incomplete_data(needed: usize) -> Self {
        Self::IncompleteData { needed }
    }

    /// Create a new nom error
    pub fn nom_error(message: impl Into<String>) -> Self {
        Self::NomError {
            message: message.into(),
        }
    }

    /// Create a new invalid checksum error
    pub fn invalid_checksum(expected: u16, found: u16) -> Self {
        Self::InvalidChecksum { expected, found }
    }

    /// Create a new buffer overflow error
    pub fn buffer_overflow(attempted: usize, available: usize) -> Self {
        Self::BufferOverflow {
            attempted,
            available,
        }
    }
}

impl<I> ParseError<I> for IsisParseError {
    fn from_error_kind(_input: I, kind: nom::error::ErrorKind) -> Self {
        Self::nom_error(format!("Nom error kind: {:?}", kind))
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        // For simplicity, we'll just return the original error
        // In a more sophisticated implementation, we might chain errors
        other
    }
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for IsisParseError {
    fn from(err: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        match err {
            nom::Err::Incomplete(needed) => {
                let needed_bytes = match needed {
                    nom::Needed::Size(size) => size.get(),
                    nom::Needed::Unknown => 0,
                };
                Self::incomplete_data(needed_bytes)
            }
            nom::Err::Error(e) | nom::Err::Failure(e) => {
                Self::nom_error(format!("Nom error: {:?}", e))
            }
        }
    }
}

impl From<nom::Err<IsisParseError>> for IsisParseError {
    fn from(err: nom::Err<IsisParseError>) -> Self {
        match err {
            nom::Err::Incomplete(needed) => {
                let needed_bytes = match needed {
                    nom::Needed::Size(size) => size.get(),
                    nom::Needed::Unknown => 0,
                };
                Self::incomplete_data(needed_bytes)
            }
            nom::Err::Error(e) | nom::Err::Failure(e) => e,
        }
    }
}

impl ErrorConvert<IsisParseError> for nom::error::Error<&[u8]> {
    fn convert(self) -> IsisParseError {
        IsisParseError::nom_error(format!("Nom error: {:?}", self))
    }
}

impl ErrorConvert<nom::error::Error<&'static [u8]>> for IsisParseError {
    fn convert(self) -> nom::error::Error<&'static [u8]> {
        // This is a placeholder - in practice, we'd need to maintain input reference
        nom::error::Error::new(&[], nom::error::ErrorKind::Fail)
    }
}

/// Result type for IS-IS parsing operations
pub type IsisParseResult<T> = Result<T, IsisParseError>;

/// nom IResult type using IsisParseError
pub type IsisIResult<I, O> = nom::IResult<I, O, IsisParseError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = IsisParseError::tlv_parse_error(IsisTlvType::AreaAddr, "test error");
        assert!(matches!(err, IsisParseError::TlvParseError { .. }));
        assert!(err.to_string().contains("TLV parse error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_incomplete_data_error() {
        let err = IsisParseError::incomplete_data(42);
        assert!(matches!(err, IsisParseError::IncompleteData { needed: 42 }));
        assert!(err.to_string().contains("needed 42 more bytes"));
    }

    #[test]
    fn test_invalid_checksum_error() {
        let err = IsisParseError::invalid_checksum(0x1234, 0x5678);
        assert!(matches!(
            err,
            IsisParseError::InvalidChecksum {
                expected: 0x1234,
                found: 0x5678
            }
        ));
        assert!(err.to_string().contains("expected 0x1234"));
        assert!(err.to_string().contains("found 0x5678"));
    }

    #[test]
    fn test_buffer_overflow_error() {
        let err = IsisParseError::buffer_overflow(100, 50);
        assert!(matches!(
            err,
            IsisParseError::BufferOverflow {
                attempted: 100,
                available: 50
            }
        ));
        assert!(err.to_string().contains("attempted to read 100 bytes"));
        assert!(err.to_string().contains("only 50 available"));
    }

    #[test]
    fn test_nom_error_conversion() {
        let nom_err: nom::Err<nom::error::Error<&[u8]>> = nom::Err::Error(nom::error::Error::new(
            &b"test"[..],
            nom::error::ErrorKind::Tag,
        ));
        let isis_err: IsisParseError = nom_err.into();
        assert!(matches!(isis_err, IsisParseError::NomError { .. }));
    }

    #[test]
    fn test_incomplete_conversion() {
        let nom_err: nom::Err<nom::error::Error<&[u8]>> =
            nom::Err::Incomplete(nom::Needed::Size(std::num::NonZeroUsize::new(10).unwrap()));
        let isis_err: IsisParseError = nom_err.into();
        assert!(matches!(
            isis_err,
            IsisParseError::IncompleteData { needed: 10 }
        ));
    }
}
