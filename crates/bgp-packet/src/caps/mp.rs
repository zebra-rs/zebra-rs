use std::fmt;
use std::hash::{Hash, Hasher};

use bytes::{BufMut, BytesMut};
use nom_derive::*;
use serde::Serialize;

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct CapMultiProtocol {
    pub afi: Afi,
    res: u8,
    pub safi: Safi,
}

// The Reserved octet is not part of what the capability names: RFC 4760
// §8 has the sender set it to 0 and the receiver ignore it. A capability
// parsed with it set is the same family as one built by `new()`, which
// is how a received capability is looked up.
impl PartialEq for CapMultiProtocol {
    fn eq(&self, other: &Self) -> bool {
        self.afi == other.afi && self.safi == other.safi
    }
}

impl Eq for CapMultiProtocol {}

impl Hash for CapMultiProtocol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.afi.hash(state);
        self.safi.hash(state);
    }
}

impl CapMultiProtocol {
    pub fn new(afi: &Afi, safi: &Safi) -> Self {
        Self {
            afi: *afi,
            res: 0,
            safi: *safi,
        }
    }
}

impl CapEmit for CapMultiProtocol {
    fn code(&self) -> CapCode {
        CapCode::MultiProtocol
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.afi.into());
        buf.put_u8(0);
        buf.put_u8(self.safi.into());
    }
}

impl fmt::Display for CapMultiProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiProtocol: {}/{}", self.afi, self.safi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A neighbor that sets the Reserved octet still names the family: the
    /// parsed capability equals, and hashes as, the one `new()` builds.
    #[test]
    fn the_reserved_octet_is_ignored() {
        let (rest, wire) = CapMultiProtocol::parse_be(&[0, 1, 0xff, 1]).unwrap();
        assert!(rest.is_empty());
        let ours = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
        assert_eq!(wire, ours);
        assert!(HashSet::from([ours]).contains(&wire));
        assert_ne!(wire, CapMultiProtocol::new(&Afi::Ip6, &Safi::Unicast));
    }

    /// We send the octet as 0, whatever was received.
    #[test]
    fn the_reserved_octet_is_sent_as_zero() {
        let (_, wire) = CapMultiProtocol::parse_be(&[0, 1, 0xff, 1]).unwrap();
        let mut buf = BytesMut::new();
        wire.emit_value(&mut buf);
        assert_eq!(&buf[..], &[0, 1, 0, 1]);
    }
}
