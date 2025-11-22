use thiserror::Error;

use crate::AttrType;

#[derive(Error, Debug)]
pub enum BgpParseError {
    #[error("Failed to parse BGP attribute {attr_type:?}: {source}")]
    AttributeParseError {
        attr_type: AttrType,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Invalid attribute length for {attr_type:?}: expected {expected}, got {actual}")]
    InvalidAttributeLength {
        attr_type: AttrType,
        expected: usize,
        actual: usize,
    },

    #[error("Nom parsing error: {0}")]
    NomError(String),

    #[error("Incomplete data: need {needed} more bytes")]
    IncompleteData { needed: usize },

    #[error("Unknown attribute type: {attr_type}")]
    UnknownAttributeType { attr_type: u8 },

    #[error("Header length is smaller than expected: got {actual}, expected {expected}")]
    InvalidHeaderLength { expected: usize, actual: usize },
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for BgpParseError {
    fn from(err: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        match err {
            nom::Err::Incomplete(needed) => {
                let needed_bytes = match needed {
                    nom::Needed::Unknown => 0,
                    nom::Needed::Size(size) => size.get(),
                };
                BgpParseError::IncompleteData {
                    needed: needed_bytes,
                }
            }
            nom::Err::Error(e) | nom::Err::Failure(e) => {
                BgpParseError::NomError(format!("{:?}: {:?}", e.code, e.input))
            }
        }
    }
}

impl<I> nom::error::ParseError<I> for BgpParseError {
    fn from_error_kind(_input: I, kind: nom::error::ErrorKind) -> Self {
        BgpParseError::NomError(format!("Parse error: {:?}", kind))
    }

    fn append(_input: I, kind: nom::error::ErrorKind, other: Self) -> Self {
        match other {
            BgpParseError::NomError(msg) => BgpParseError::NomError(format!("{}, {:?}", msg, kind)),
            _ => other,
        }
    }
}
