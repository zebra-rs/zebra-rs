use std::{borrow::Cow, fmt};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u8;
use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, Default, PartialEq, Clone)]
pub struct CapFqdn {
    pub hostname: Vec<u8>,
    pub domain: Vec<u8>,
}

impl CapFqdn {
    pub fn new(hostname: &str, domain: &str) -> Self {
        Self {
            hostname: hostname.into(),
            domain: domain.into(),
        }
    }

    pub fn hostname(&self) -> Cow<'_, str> {
        if self.hostname.is_empty() {
            Cow::Borrowed("n/a")
        } else {
            String::from_utf8_lossy(&self.hostname)
        }
    }

    pub fn domain(&self) -> Cow<'_, str> {
        if self.domain.is_empty() {
            Cow::Borrowed("n/a")
        } else {
            String::from_utf8_lossy(&self.domain)
        }
    }

    /// A capability value is at most 253 octets on the wire: the BGP
    /// optional-parameter that carries it has a single length octet covering
    /// `code(1) + length(1) + value` (`emit.rs` writes `put_u8(len() + 2)`),
    /// so `value <= 255 - 2`. Two of those value octets are the
    /// Hostname-Length and Domain-Length fields, leaving a 251-octet budget
    /// shared by the hostname and domain strings.
    const VALUE_MAX: usize = 253;
    const STRINGS_BUDGET: usize = Self::VALUE_MAX - 2; // 251

    /// Hostname and domain octet counts actually written on the wire. The
    /// hostname is given priority (it is the primary identifier); the domain
    /// fills whatever budget remains. Both length octets are always emitted —
    /// possibly 0 — so a peer can still parse the structure even when an
    /// over-long value is clamped here. Keeping `len()` and `emit_value()`
    /// both derived from this guarantees the declared length matches the bytes
    /// written.
    fn wire_lengths(&self) -> (usize, usize) {
        let hostname = self.hostname.len().min(Self::STRINGS_BUDGET);
        let domain = self.domain.len().min(Self::STRINGS_BUDGET - hostname);
        (hostname, domain)
    }
}

impl CapEmit for CapFqdn {
    fn code(&self) -> CapCode {
        CapCode::Fqdn
    }

    fn len(&self) -> u8 {
        let (hostname, domain) = self.wire_lengths();
        // hostname + domain <= 251, so 2 + that <= 253 fits a u8 and leaves
        // room for the optional-parameter framing's `len() + 2`.
        (2 + hostname + domain) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        let (hostname, domain) = self.wire_lengths();
        // Both counts are <= 251, so the `as u8` casts cannot truncate, and
        // the length octets always match the bytes that follow them.
        buf.put_u8(hostname as u8);
        buf.put(&self.hostname[..hostname]);
        buf.put_u8(domain as u8);
        buf.put(&self.domain[..domain]);
    }
}

impl CapFqdn {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hostname_len) = be_u8(input)?;
        let (input, hostname) = take(hostname_len).parse(input)?;
        let hostname = hostname.to_vec();
        let (input, domain_len) = be_u8(input)?;
        let (input, domain) = take(domain_len).parse(input)?;
        let domain = domain.to_vec();

        let fqdn = Self { hostname, domain };
        Ok((input, fqdn))
    }
}

impl fmt::Display for CapFqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hostname = String::from_utf8_lossy(&self.hostname);
        let domain = String::from_utf8_lossy(&self.domain);
        write!(f, "FQDN: {} {}", hostname, domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Emit the value, assert the declared `len()` matches the bytes written,
    /// and parse it back. Returns `(len(), parsed)`.
    fn emit_and_parse(cap: &CapFqdn) -> (u8, CapFqdn) {
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(
            cap.len() as usize,
            buf.len(),
            "len() must equal the emitted byte count"
        );
        // The optional-parameter framing writes `len() + 2`; it must not
        // overflow a u8 (emit.rs `buf.put_u8(self.len() + 2)`).
        assert!(
            cap.len().checked_add(2).is_some(),
            "len() + 2 must fit a u8"
        );
        let (rest, parsed) = CapFqdn::parse_be(&buf).expect("parse emitted value");
        assert!(
            rest.is_empty(),
            "emit_value must be fully consumed by parse"
        );
        (cap.len(), parsed)
    }

    #[test]
    fn normal_round_trip() {
        let cap = CapFqdn::new("router1", "example.com");
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len as usize, 2 + 7 + 11);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn both_empty_preserves_length_fields() {
        let cap = CapFqdn::default();
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(
            &buf[..],
            &[0, 0],
            "two zero length octets are still emitted"
        );
        assert_eq!(cap.len(), 2);
        let (_, parsed) = emit_and_parse(&cap);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn oversized_hostname_clamped_to_budget() {
        // 300-octet hostname, empty domain: hostname -> 251, domain -> 0.
        let cap = CapFqdn::new(&"a".repeat(300), "");
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(parsed.hostname.len(), 251);
        assert_eq!(parsed.domain.len(), 0);
        assert_eq!(len, 253, "2 + 251 + 0");
        assert_eq!(len + 2, 255, "optional-parameter length stays within a u8");
    }

    #[test]
    fn hostname_priority_domain_takes_remainder() {
        // hostname 200 + domain 100: hostname -> 200, domain -> 51 (251 - 200).
        let cap = CapFqdn::new(&"h".repeat(200), &"d".repeat(100));
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(parsed.hostname.len(), 200);
        assert_eq!(parsed.domain.len(), 51);
        assert_eq!(len, 253);
    }

    #[test]
    fn oversized_domain_alone_clamped() {
        // Empty hostname, 300-octet domain: hostname -> 0, domain -> 251.
        let cap = CapFqdn::new("", &"d".repeat(300));
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(parsed.hostname.len(), 0);
        assert_eq!(parsed.domain.len(), 251);
        assert_eq!(len, 253);
    }
}
