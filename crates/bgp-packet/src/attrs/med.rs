use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, NomBE, PartialEq, PartialOrd, Default)]
pub struct Med {
    pub med: u32,
}

impl Med {
    pub fn new(med: u32) -> Self {
        Self { med }
    }
}

impl AttrEmitter for Med {
    fn attr_flags(&self) -> super::AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> crate::AttrType {
        AttrType::Med
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.med);
    }
}

impl fmt::Display for Med {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.med)
    }
}

impl fmt::Debug for Med {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Med: {}", self)
    }
}
