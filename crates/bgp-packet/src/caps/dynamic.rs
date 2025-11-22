use std::fmt;

use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapDynamic {}

impl CapEmit for CapDynamic {
    fn code(&self) -> CapCode {
        CapCode::DynamicCapability
    }
}

impl fmt::Display for CapDynamic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Dynamic Capability")
    }
}
