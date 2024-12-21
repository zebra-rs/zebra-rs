use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityDynamicCapability {}

impl Emit for CapabilityDynamicCapability {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::DynamicCapability
    }
}
