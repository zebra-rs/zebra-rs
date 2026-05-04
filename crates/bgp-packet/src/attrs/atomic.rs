use std::fmt;

use bytes::BytesMut;
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, NomBE, PartialEq, Eq, Hash)]
pub struct AtomicAggregate {}

impl AtomicAggregate {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for AtomicAggregate {
    fn default() -> Self {
        Self::new()
    }
}

impl AttrEmitter for AtomicAggregate {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::AtomicAggregate
    }

    fn len(&self) -> Option<usize> {
        Some(0)
    }

    fn emit(&self, _buf: &mut BytesMut) {
        // AtomicAggregate has no data, just presence
    }
}

impl fmt::Display for AtomicAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl fmt::Debug for AtomicAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " Atomic Aggregate")
    }
}
