use std::fmt;

use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapExtended {}

impl CapEmit for CapExtended {
    fn code(&self) -> CapCode {
        CapCode::ExtendedMessage
    }
}

impl fmt::Display for CapExtended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extended Message")
    }
}
