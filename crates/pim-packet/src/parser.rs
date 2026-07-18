//! PIM message header and per-type payloads (RFC 7761 §4.9).

use bytes::{BufMut, BytesMut};
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{Err, IResult};

use crate::addr::{EncodedGroup, EncodedUnicast};
use crate::bsr::{PimBootstrap, PimCandRpAdv};
use crate::checksum::pim_fill_checksum;
use crate::hello::PimHello;
use crate::joinprune::PimJoinPrune;
use crate::typ::PimType;

pub const PIM_VERSION: u8 = 2;

// Register flags word (RFC 7761 §4.9.3).
const REGISTER_FLAG_BORDER: u32 = 0x8000_0000;
const REGISTER_FLAG_NULL: u32 = 0x4000_0000;

// Assert metric-preference field: top bit is the RPT bit
// (RFC 7761 §4.9.6).
const ASSERT_RPT_BIT: u32 = 0x8000_0000;

/// Register: flags word + the encapsulated data packet (a full IP
/// packet, or nothing for a Null-Register probe). The PIM checksum
/// covers only the header and flags word, so `data` round-trips
/// byte-exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimRegister {
    pub border: bool,
    pub null_register: bool,
    pub data: Vec<u8>,
}

impl PimRegister {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u32(input)?;
        Ok((
            &input[input.len()..],
            Self {
                border: flags & REGISTER_FLAG_BORDER != 0,
                null_register: flags & REGISTER_FLAG_NULL != 0,
                data: input.to_vec(),
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        let mut flags = 0u32;
        if self.border {
            flags |= REGISTER_FLAG_BORDER;
        }
        if self.null_register {
            flags |= REGISTER_FLAG_NULL;
        }
        buf.put_u32(flags);
        buf.put(&self.data[..]);
    }
}

/// Register-Stop (RFC 7761 §4.9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimRegisterStop {
    pub group: EncodedGroup,
    pub source: EncodedUnicast,
}

impl PimRegisterStop {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = EncodedGroup::parse_be(input)?;
        let (input, source) = EncodedUnicast::parse_be(input)?;
        Ok((input, Self { group, source }))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
        self.source.emit(buf);
    }
}

/// Assert (RFC 7761 §4.9.6). For a (*,G) assert the source address is
/// zero and the RPT bit is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimAssert {
    pub group: EncodedGroup,
    pub source: EncodedUnicast,
    pub rpt_bit: bool,
    pub metric_preference: u32,
    pub metric: u32,
}

impl PimAssert {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = EncodedGroup::parse_be(input)?;
        let (input, source) = EncodedUnicast::parse_be(input)?;
        let (input, pref) = be_u32(input)?;
        let (input, metric) = be_u32(input)?;
        Ok((
            input,
            Self {
                group,
                source,
                rpt_bit: pref & ASSERT_RPT_BIT != 0,
                metric_preference: pref & !ASSERT_RPT_BIT,
                metric,
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
        self.source.emit(buf);
        let mut pref = self.metric_preference & !ASSERT_RPT_BIT;
        if self.rpt_bit {
            pref |= ASSERT_RPT_BIT;
        }
        buf.put_u32(pref);
        buf.put_u32(self.metric);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PimPayload {
    Hello(PimHello),
    Register(PimRegister),
    RegisterStop(PimRegisterStop),
    JoinPrune(PimJoinPrune),
    Assert(PimAssert),
    Bootstrap(PimBootstrap),
    CandRpAdv(PimCandRpAdv),
    Unknown { typ: PimType, data: Vec<u8> },
}

impl PimPayload {
    pub fn typ(&self) -> PimType {
        use PimPayload::*;
        match self {
            Hello(_) => PimType::Hello,
            Register(_) => PimType::Register,
            RegisterStop(_) => PimType::RegisterStop,
            JoinPrune(_) => PimType::JoinPrune,
            Assert(_) => PimType::Assert,
            Bootstrap(_) => PimType::Bootstrap,
            CandRpAdv(_) => PimType::CandRpAdv,
            Unknown { typ, .. } => *typ,
        }
    }

    fn parse_be(input: &[u8], typ: PimType) -> IResult<&[u8], Self> {
        match typ {
            PimType::Hello => {
                let (input, hello) = PimHello::parse_be(input)?;
                Ok((input, Self::Hello(hello)))
            }
            PimType::Register => {
                let (input, register) = PimRegister::parse_be(input)?;
                Ok((input, Self::Register(register)))
            }
            PimType::RegisterStop => {
                let (input, stop) = PimRegisterStop::parse_be(input)?;
                Ok((input, Self::RegisterStop(stop)))
            }
            PimType::JoinPrune => {
                let (input, jp) = PimJoinPrune::parse_be(input)?;
                Ok((input, Self::JoinPrune(jp)))
            }
            PimType::Assert => {
                let (input, assert) = PimAssert::parse_be(input)?;
                Ok((input, Self::Assert(assert)))
            }
            PimType::Bootstrap => {
                let (input, bsm) = PimBootstrap::parse_be(input)?;
                Ok((input, Self::Bootstrap(bsm)))
            }
            PimType::CandRpAdv => {
                let (input, adv) = PimCandRpAdv::parse_be(input)?;
                Ok((input, Self::CandRpAdv(adv)))
            }
            typ => Ok((
                &input[input.len()..],
                Self::Unknown {
                    typ,
                    data: input.to_vec(),
                },
            )),
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        use PimPayload::*;
        match self {
            Hello(v) => v.emit(buf),
            Register(v) => v.emit(buf),
            RegisterStop(v) => v.emit(buf),
            JoinPrune(v) => v.emit(buf),
            Assert(v) => v.emit(buf),
            Bootstrap(v) => v.emit(buf),
            CandRpAdv(v) => v.emit(buf),
            Unknown { data, .. } => buf.put(&data[..]),
        }
    }
}

/// A PIM message: 4-octet header (version/type, reserved, checksum)
/// followed by the type-specific payload. `parse_be` takes the whole
/// IP payload; checksum verification is a separate step
/// (`pim_verify_checksum`) done on the raw bytes before parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimPacket {
    pub version: u8,
    pub typ: PimType,
    pub checksum: u16,
    pub payload: PimPayload,
}

impl PimPacket {
    pub fn new(payload: PimPayload) -> Self {
        Self {
            version: PIM_VERSION,
            typ: payload.typ(),
            checksum: 0,
            payload,
        }
    }

    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, ver_type) = be_u8(input)?;
        let version = ver_type >> 4;
        if version != PIM_VERSION {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let typ = PimType::from(ver_type & 0x0f);
        let (input, _reserved) = be_u8(input)?;
        let (input, checksum) = be_u16(input)?;
        let (input, payload) = PimPayload::parse_be(input, typ)?;
        Ok((
            input,
            Self {
                version,
                typ,
                checksum,
                payload,
            },
        ))
    }

    /// Emit the message into an empty buffer and fill in the
    /// checksum. The message must start at offset 0 of `buf`.
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8((self.version << 4) | u8::from(self.typ));
        buf.put_u8(0);
        buf.put_u16(0);
        self.payload.emit(buf);
        pim_fill_checksum(self.typ, buf);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hex_literal::hex;

    use super::*;
    use crate::addr::EncodedSource;
    use crate::checksum::pim_verify_checksum;
    use crate::hello::HelloTlv;

    fn round_trip(wire: &[u8]) -> PimPacket {
        assert!(pim_verify_checksum(wire), "fixture checksum invalid");
        let (rest, packet) = PimPacket::parse_be(wire).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);
        assert_eq!(&buf[..], wire, "emit does not round-trip");
        packet
    }

    #[test]
    fn hello_round_trip() {
        let wire = hex!(
            "20 00 6a f9"             // v2 Hello, checksum
            "00 01 00 02 00 69"       // Holdtime 105
            "00 13 00 04 00 00 00 01" // DR Priority 1
            "00 14 00 04 12 34 56 78" // Generation ID
            "00 02 00 04 01 f4 09 c4" // LAN Prune Delay 500/2500
        );
        let packet = round_trip(&wire);
        assert_eq!(packet.typ, PimType::Hello);
        let PimPayload::Hello(hello) = &packet.payload else {
            panic!("not a hello");
        };
        assert_eq!(hello.holdtime(), Some(105));
        assert_eq!(hello.dr_priority(), Some(1));
        assert_eq!(hello.generation_id(), Some(0x12345678));
        assert_eq!(hello.lan_prune_delay(), Some((false, 500, 2500)));
        assert_eq!(hello.address_list(), None);
    }

    #[test]
    fn hello_unknown_tlv_preserved() {
        // Unknown option 65001 with 2 bytes of data must survive a
        // parse/emit round-trip byte-exact.
        let hello = PimHello {
            tlvs: vec![
                HelloTlv::Holdtime(105),
                HelloTlv::Unknown {
                    typ: 65001,
                    data: vec![0xde, 0xad],
                },
            ],
        };
        let packet = PimPacket::new(PimPayload::Hello(hello));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);
        assert!(pim_verify_checksum(&buf));
        let (_, reparsed) = PimPacket::parse_be(&buf).expect("parse");
        assert_eq!(reparsed.payload, packet.payload);
    }

    #[test]
    fn join_prune_round_trip() {
        // (*,G) join for 239.1.1.1 toward RP 10.0.0.1, upstream
        // neighbor 10.0.0.1, holdtime 210.
        let wire = hex!(
            "23 00 cd e6"             // v2 Join/Prune, checksum
            "01 00 0a 00 00 01"       // upstream neighbor 10.0.0.1
            "00 01"                   // reserved, num groups 1
            "00 d2"                   // holdtime 210
            "01 00 00 20 ef 01 01 01" // group 239.1.1.1/32
            "00 01 00 00"             // 1 join, 0 prunes
            "01 00 07 20 0a 00 00 01" // (*,G) join source: RP, S|W|R
        );
        let packet = round_trip(&wire);
        let PimPayload::JoinPrune(jp) = &packet.payload else {
            panic!("not a join/prune");
        };
        assert_eq!(
            jp.upstream_neighbor.addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(jp.holdtime, 210);
        assert_eq!(jp.groups.len(), 1);
        let group = &jp.groups[0];
        assert_eq!(group.group.addr, IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)));
        assert_eq!(group.group.masklen, 32);
        assert_eq!(
            group.joins,
            vec![EncodedSource::star_g(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 1
            )))]
        );
        assert!(group.prunes.is_empty());
    }

    #[test]
    fn register_checksum_covers_first_8_bytes_only() {
        // Null bit set, 4 bytes of encapsulated data excluded from
        // the checksum.
        let wire = hex!(
            "21 00 9e ff"  // v2 Register, checksum over first 8 bytes
            "40 00 00 00"  // B=0 N=1
            "de ad be ef"  // encapsulated data (not checksummed)
        );
        let packet = round_trip(&wire);
        let PimPayload::Register(register) = &packet.payload else {
            panic!("not a register");
        };
        assert!(!register.border);
        assert!(register.null_register);
        assert_eq!(register.data, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn register_stop_round_trip() {
        let wire = hex!(
            "22 00 e1 da"             // v2 Register-Stop, checksum
            "01 00 00 20 ef 01 01 01" // group 239.1.1.1/32
            "01 00 0a 00 00 02"       // source 10.0.0.2
        );
        let packet = round_trip(&wire);
        let PimPayload::RegisterStop(stop) = &packet.payload else {
            panic!("not a register-stop");
        };
        assert_eq!(stop.group.addr, IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)));
        assert_eq!(stop.source.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn assert_round_trip() {
        let wire = hex!(
            "25 00 de 62"             // v2 Assert, checksum
            "01 00 00 20 ef 01 01 01" // group 239.1.1.1/32
            "01 00 0a 00 00 02"       // source 10.0.0.2
            "00 00 00 64"             // R=0, preference 100
            "00 00 00 14"             // metric 20
        );
        let packet = round_trip(&wire);
        let PimPayload::Assert(assert_msg) = &packet.payload else {
            panic!("not an assert");
        };
        assert!(!assert_msg.rpt_bit);
        assert_eq!(assert_msg.metric_preference, 100);
        assert_eq!(assert_msg.metric, 20);
    }

    #[test]
    fn bootstrap_round_trip() {
        // BSR 10.1.22.2 prio 100, tag 1, hash-mask 10; one range
        // 224.0.0.0/4 with one C-RP (10.1.22.2, holdtime 150).
        let wire = hex!(
            "24 00 ac f8"             // v2 Bootstrap, checksum
            "00 01 0a 64"             // tag 1, hash 10, prio 100
            "01 00 0a 01 16 02"       // BSR 10.1.22.2
            "01 00 00 04 e0 00 00 00" // group 224.0.0.0/4
            "01 01 00 00"             // rp count 1, frag rp count 1
            "01 00 0a 01 16 02"       // RP 10.1.22.2
            "00 96 00 00"             // holdtime 150, prio 0
        );
        let packet = round_trip(&wire);
        let PimPayload::Bootstrap(bsm) = &packet.payload else {
            panic!("not a bootstrap");
        };
        assert_eq!(bsm.fragment_tag, 1);
        assert_eq!(bsm.hash_mask_len, 10);
        assert_eq!(bsm.bsr_priority, 100);
        assert_eq!(bsm.bsr_v4(), Some(Ipv4Addr::new(10, 1, 22, 2)));
        assert_eq!(bsm.groups.len(), 1);
        assert_eq!(bsm.groups[0].group.masklen, 4);
        assert_eq!(bsm.groups[0].rps.len(), 1);
        assert_eq!(bsm.groups[0].rps[0].holdtime, 150);
    }

    #[test]
    fn cand_rp_adv_round_trip() {
        let wire = hex!(
            "28 00 d4 61"             // v2 Candidate-RP-Adv, checksum
            "01 00 00 96"             // 1 prefix, prio 0, holdtime 150
            "01 00 0a 01 16 02"       // RP 10.1.22.2
            "01 00 00 04 e0 00 00 00" // group 224.0.0.0/4
        );
        let packet = round_trip(&wire);
        let PimPayload::CandRpAdv(adv) = &packet.payload else {
            panic!("not a cand-rp-adv");
        };
        assert_eq!(adv.priority, 0);
        assert_eq!(adv.holdtime, 150);
        assert_eq!(adv.rp_addr.addr, IpAddr::V4(Ipv4Addr::new(10, 1, 22, 2)));
        assert_eq!(adv.groups.len(), 1);
    }

    #[test]
    fn bad_version_rejected() {
        // Version 1 in the top nibble.
        let wire = hex!("10 00 ef ff");
        assert!(PimPacket::parse_be(&wire).is_err());
    }

    #[test]
    fn corrupted_checksum_detected() {
        let mut wire = hex!(
            "20 00 6a f9"
            "00 01 00 02 00 69"
            "00 13 00 04 00 00 00 01"
            "00 14 00 04 12 34 56 78"
            "00 02 00 04 01 f4 09 c4"
        )
        .to_vec();
        wire[5] ^= 0x01;
        assert!(!pim_verify_checksum(&wire));
    }
}
