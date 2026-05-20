//! RFC 4861 §4.6 Neighbor Discovery options.

use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};

use crate::packet::ParseError;

/// ND option type codes registered with IANA. Only the variants this
/// codec recognises are typed; anything else round-trips as
/// [`NdOption::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    Mtu = 5,
}

impl OptionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::SourceLinkLayerAddress),
            2 => Some(Self::TargetLinkLayerAddress),
            3 => Some(Self::PrefixInformation),
            5 => Some(Self::Mtu),
            _ => None,
        }
    }
}

impl From<OptionType> for u8 {
    fn from(t: OptionType) -> Self {
        t as u8
    }
}

/// Source / Target Link-Layer Address option (RFC 4861 §4.6.1).
///
/// The length field on the wire is in units of 8 octets including the
/// TLV header; for a 6-byte (Ethernet) MAC the wire length is 1. We
/// store the variable-length link-layer address as a vector so other
/// link types (e.g. Infiniband, 20 bytes) round-trip cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLayerAddress {
    pub addr: Vec<u8>,
}

impl LinkLayerAddress {
    pub fn ethernet(mac: [u8; 6]) -> Self {
        Self { addr: mac.to_vec() }
    }
}

bitflags::bitflags! {
    /// Flags from the Prefix Information option (RFC 4861 §4.6.2).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct PrefixInfoFlags: u8 {
        /// On-link.
        const L = 0b1000_0000;
        /// Autonomous address-configuration.
        const A = 0b0100_0000;
    }
}

/// Prefix Information option (RFC 4861 §4.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixInfo {
    pub prefix_length: u8,
    pub flags: PrefixInfoFlags,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Addr,
}

/// One parsed Neighbor Discovery option. Unknown option codes are
/// preserved verbatim so emit/parse round-trip works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdOption {
    SourceLinkLayerAddress(LinkLayerAddress),
    TargetLinkLayerAddress(LinkLayerAddress),
    PrefixInformation(PrefixInfo),
    Mtu(u32),
    Unknown { typ: u8, value: Vec<u8> },
}

impl NdOption {
    /// Parse one option from `input`, returning the option and the
    /// remaining slice. Length-zero options are rejected (RFC 4861
    /// §4.6 mandates "MUST silently discard"); we surface them as a
    /// [`ParseError::ZeroLengthOption`] so the caller can drop the
    /// whole packet.
    pub fn parse(input: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if input.len() < 2 {
            return Err(ParseError::TruncatedOption);
        }
        let typ = input[0];
        let len_units = input[1];
        if len_units == 0 {
            return Err(ParseError::ZeroLengthOption);
        }
        let total = (len_units as usize) * 8;
        if input.len() < total {
            return Err(ParseError::TruncatedOption);
        }
        let value = &input[2..total];
        let rest = &input[total..];

        let opt = match OptionType::from_u8(typ) {
            Some(OptionType::SourceLinkLayerAddress) => {
                NdOption::SourceLinkLayerAddress(LinkLayerAddress {
                    addr: value.to_vec(),
                })
            }
            Some(OptionType::TargetLinkLayerAddress) => {
                NdOption::TargetLinkLayerAddress(LinkLayerAddress {
                    addr: value.to_vec(),
                })
            }
            Some(OptionType::PrefixInformation) => {
                if value.len() < 30 {
                    return Err(ParseError::TruncatedOption);
                }
                let prefix_length = value[0];
                let flags = PrefixInfoFlags::from_bits_truncate(value[1]);
                let valid_lifetime = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
                let preferred_lifetime =
                    u32::from_be_bytes([value[6], value[7], value[8], value[9]]);
                // value[10..14] = reserved2
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&value[14..30]);
                NdOption::PrefixInformation(PrefixInfo {
                    prefix_length,
                    flags,
                    valid_lifetime,
                    preferred_lifetime,
                    prefix: Ipv6Addr::from(prefix_bytes),
                })
            }
            Some(OptionType::Mtu) => {
                if value.len() < 6 {
                    return Err(ParseError::TruncatedOption);
                }
                // value[0..2] = reserved
                let mtu = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
                NdOption::Mtu(mtu)
            }
            None => NdOption::Unknown {
                typ,
                value: value.to_vec(),
            },
        };
        Ok((opt, rest))
    }

    /// Emit the option to `buf`, including the TLV header. Pads the
    /// link-layer address options up to the next 8-byte boundary as
    /// RFC 4861 §4.6.1 requires.
    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            NdOption::SourceLinkLayerAddress(lla) => {
                emit_lla(buf, OptionType::SourceLinkLayerAddress, lla)
            }
            NdOption::TargetLinkLayerAddress(lla) => {
                emit_lla(buf, OptionType::TargetLinkLayerAddress, lla)
            }
            NdOption::PrefixInformation(pi) => {
                buf.put_u8(OptionType::PrefixInformation.into());
                buf.put_u8(4); // 4 * 8 = 32 bytes total
                buf.put_u8(pi.prefix_length);
                buf.put_u8(pi.flags.bits());
                buf.put_u32(pi.valid_lifetime);
                buf.put_u32(pi.preferred_lifetime);
                buf.put_u32(0); // reserved2
                buf.put_slice(&pi.prefix.octets());
            }
            NdOption::Mtu(mtu) => {
                buf.put_u8(OptionType::Mtu.into());
                buf.put_u8(1); // 1 * 8 = 8 bytes total
                buf.put_u16(0); // reserved
                buf.put_u32(*mtu);
            }
            NdOption::Unknown { typ, value } => {
                // Wire length must include the 2-byte header and pad
                // to an 8-byte multiple; preserve whatever the caller
                // round-tripped, padding with zeros.
                let total = round_up_to_8(2 + value.len());
                buf.put_u8(*typ);
                buf.put_u8((total / 8) as u8);
                buf.put_slice(value);
                for _ in (2 + value.len())..total {
                    buf.put_u8(0);
                }
            }
        }
    }
}

fn emit_lla(buf: &mut BytesMut, typ: OptionType, lla: &LinkLayerAddress) {
    let total = round_up_to_8(2 + lla.addr.len());
    buf.put_u8(typ.into());
    buf.put_u8((total / 8) as u8);
    buf.put_slice(&lla.addr);
    for _ in (2 + lla.addr.len())..total {
        buf.put_u8(0);
    }
}

fn round_up_to_8(n: usize) -> usize {
    (n + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn parse_emit_source_lla_ethernet() {
        // Type=1, Len=1 (8 bytes total), 6-byte MAC.
        let wire = hex!("01 01 aa bb cc dd ee ff");
        let (opt, rest) = NdOption::parse(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            opt,
            NdOption::SourceLinkLayerAddress(LinkLayerAddress::ethernet([
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            ]))
        );

        let mut buf = BytesMut::new();
        opt.emit(&mut buf);
        assert_eq!(&buf[..], &wire);
    }

    #[test]
    fn parse_mtu_option() {
        let wire = hex!("05 01 00 00 00 00 05 dc"); // MTU = 1500
        let (opt, rest) = NdOption::parse(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(opt, NdOption::Mtu(1500));
    }

    #[test]
    fn parse_prefix_information() {
        // PIO: type 3, len 4 (32 bytes), /64 L+A, 2592000 / 604800,
        // 2001:db8::/64
        let wire = hex!(
            "03 04 40 c0 00 27 8d 00 00 09 3a 80 00 00 00 00 "
            "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 00"
        );
        let (opt, rest) = NdOption::parse(&wire).unwrap();
        assert!(rest.is_empty());
        match opt {
            NdOption::PrefixInformation(pi) => {
                assert_eq!(pi.prefix_length, 64);
                assert!(pi.flags.contains(PrefixInfoFlags::L));
                assert!(pi.flags.contains(PrefixInfoFlags::A));
                assert_eq!(pi.valid_lifetime, 2592000);
                assert_eq!(pi.preferred_lifetime, 604800);
                assert_eq!(pi.prefix, "2001:db8::".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("expected PIO, got {:?}", other),
        }
    }

    #[test]
    fn unknown_option_round_trips() {
        // Type=99 (unassigned at time of writing), len=1, 6 bytes value.
        let wire = hex!("63 01 de ad be ef ca fe");
        let (opt, rest) = NdOption::parse(&wire).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(opt, NdOption::Unknown { typ: 99, .. }));

        let mut buf = BytesMut::new();
        opt.emit(&mut buf);
        assert_eq!(&buf[..], &wire);
    }

    #[test]
    fn zero_length_option_is_rejected() {
        let wire = hex!("01 00");
        assert_eq!(NdOption::parse(&wire), Err(ParseError::ZeroLengthOption));
    }

    #[test]
    fn truncated_option_is_rejected() {
        // Length says 2 (16 bytes) but only 8 bytes provided.
        let wire = hex!("01 02 aa bb cc dd ee ff");
        assert_eq!(NdOption::parse(&wire), Err(ParseError::TruncatedOption));
    }
}
