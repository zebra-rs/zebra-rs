use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefresh {}

impl Emit for CapabilityRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::RouteRefresh
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityEnhancedRouteRefresh {}

impl Emit for CapabilityEnhancedRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::EnhancedRouteRefresh
    }
}
