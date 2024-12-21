use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilitySoftwareVersion {
    pub version: Vec<u8>,
}

impl CapabilitySoftwareVersion {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.into(),
        }
    }
}

impl Emit for CapabilitySoftwareVersion {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::SoftwareVersion
    }

    fn len(&self) -> u8 {
        self.version.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.version[..]);
    }
}
