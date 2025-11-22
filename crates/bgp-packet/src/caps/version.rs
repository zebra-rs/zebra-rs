use std::{borrow::Cow, fmt};

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapVersion {
    pub version: Vec<u8>,
}

impl CapVersion {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.into(),
        }
    }

    pub fn version(&self) -> Cow<'_, str> {
        if self.version.is_empty() {
            Cow::Borrowed("n/a")
        } else {
            String::from_utf8_lossy(&self.version)
        }
    }
}

impl CapEmit for CapVersion {
    fn code(&self) -> CapCode {
        CapCode::SoftwareVersion
    }

    fn len(&self) -> u8 {
        self.version.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.version[..]);
    }
}

impl fmt::Display for CapVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Software Version: {}",
            String::from_utf8_lossy(&self.version)
        )
    }
}
