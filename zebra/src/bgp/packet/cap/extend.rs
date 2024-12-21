use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityExtendedMessage {}

impl Emit for CapabilityExtendedMessage {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::ExtendedMessage
    }
}
