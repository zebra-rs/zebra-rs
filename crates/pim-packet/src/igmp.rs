//! IGMP wire formats: v2 (RFC 2236) and v3 (RFC 3376) — queries,
//! reports and leaves as needed by the PIM module's querier and
//! membership tracking. IGMPv1 reports (RFC 1112) parse into the
//! same 8-octet shape as v2.

use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom::Err;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u16};
use packet_utils::ParseBe;

use crate::checksum::igmp_fill_checksum;

pub const IGMP_MEMBERSHIP_QUERY: u8 = 0x11;
pub const IGMP_V1_REPORT: u8 = 0x12;
pub const IGMP_V2_REPORT: u8 = 0x16;
pub const IGMP_V2_LEAVE: u8 = 0x17;
pub const IGMP_V3_REPORT: u8 = 0x22;

/// An 8-octet query is v2 (or v1 when max_resp is zero); 12 octets or
/// more is a v3 query.
const IGMP_V2_QUERY_LEN: usize = 8;

// V3 query S/QRV octet: Resv(4) | S | QRV(3).
const V3_QUERY_S_FLAG: u8 = 0x08;
const V3_QUERY_QRV_MASK: u8 = 0x07;

/// The common 8-octet IGMP message: v2 query/report/leave and the v1
/// report. `max_resp` is only meaningful for queries (in v1 reports
/// it is zero on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpGroupMessage {
    pub max_resp: u8,
    pub group: Ipv4Addr,
}

impl IgmpGroupMessage {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, max_resp) = be_u8(input)?;
        let (input, _checksum) = be_u16(input)?;
        let (input, group) = Ipv4Addr::parse_be(input)?;
        Ok((input, Self { max_resp, group }))
    }
}

/// IGMPv3 membership query (RFC 3376 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpV3Query {
    pub max_resp_code: u8,
    pub group: Ipv4Addr,
    pub suppress: bool,
    pub qrv: u8,
    pub qqic: u8,
    pub sources: Vec<Ipv4Addr>,
}

impl IgmpV3Query {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, max_resp_code) = be_u8(input)?;
        let (input, _checksum) = be_u16(input)?;
        let (input, group) = Ipv4Addr::parse_be(input)?;
        let (input, s_qrv) = be_u8(input)?;
        let (input, qqic) = be_u8(input)?;
        let (mut input, num_sources) = be_u16(input)?;
        let mut sources = Vec::with_capacity(num_sources as usize);
        for _ in 0..num_sources {
            let (rest, source) = Ipv4Addr::parse_be(input)?;
            sources.push(source);
            input = rest;
        }
        Ok((
            input,
            Self {
                max_resp_code,
                group,
                suppress: s_qrv & V3_QUERY_S_FLAG != 0,
                qrv: s_qrv & V3_QUERY_QRV_MASK,
                qqic,
                sources,
            },
        ))
    }
}

/// IGMPv3 group record type (RFC 3376 §4.2.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpRecordType {
    ModeIsInclude,
    ModeIsExclude,
    ChangeToInclude,
    ChangeToExclude,
    AllowNewSources,
    BlockOldSources,
    Unknown(u8),
}

impl From<u8> for IgmpRecordType {
    fn from(val: u8) -> Self {
        use IgmpRecordType::*;
        match val {
            1 => ModeIsInclude,
            2 => ModeIsExclude,
            3 => ChangeToInclude,
            4 => ChangeToExclude,
            5 => AllowNewSources,
            6 => BlockOldSources,
            v => Unknown(v),
        }
    }
}

impl From<IgmpRecordType> for u8 {
    fn from(typ: IgmpRecordType) -> Self {
        use IgmpRecordType::*;
        match typ {
            ModeIsInclude => 1,
            ModeIsExclude => 2,
            ChangeToInclude => 3,
            ChangeToExclude => 4,
            AllowNewSources => 5,
            BlockOldSources => 6,
            Unknown(v) => v,
        }
    }
}

/// IGMPv3 group record (RFC 3376 §4.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpGroupRecord {
    pub rec_type: IgmpRecordType,
    pub group: Ipv4Addr,
    pub sources: Vec<Ipv4Addr>,
    /// Auxiliary data, preserved for round-trip (RFC 3376 says
    /// receivers must ignore it). Length must be a multiple of 4.
    pub aux: Vec<u8>,
}

impl IgmpGroupRecord {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, rec_type) = be_u8(input)?;
        let (input, aux_len) = be_u8(input)?;
        let (input, num_sources) = be_u16(input)?;
        let (mut input, group) = Ipv4Addr::parse_be(input)?;
        let mut sources = Vec::with_capacity(num_sources as usize);
        for _ in 0..num_sources {
            let (rest, source) = Ipv4Addr::parse_be(input)?;
            sources.push(source);
            input = rest;
        }
        let (input, aux) = take(aux_len as usize * 4)(input)?;
        Ok((
            input,
            Self {
                rec_type: rec_type.into(),
                group,
                sources,
                aux: aux.to_vec(),
            },
        ))
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.rec_type.into());
        buf.put_u8((self.aux.len() / 4) as u8);
        buf.put_u16(self.sources.len() as u16);
        buf.put(&self.group.octets()[..]);
        for source in &self.sources {
            buf.put(&source.octets()[..]);
        }
        buf.put(&self.aux[..]);
    }
}

/// IGMPv3 membership report (RFC 3376 §4.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgmpV3Report {
    pub records: Vec<IgmpGroupRecord>,
}

impl IgmpV3Report {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _reserved8) = be_u8(input)?;
        let (input, _checksum) = be_u16(input)?;
        let (input, _reserved16) = be_u16(input)?;
        let (mut input, num_records) = be_u16(input)?;
        let mut records = Vec::with_capacity(num_records as usize);
        for _ in 0..num_records {
            let (rest, record) = IgmpGroupRecord::parse_be(input)?;
            records.push(record);
            input = rest;
        }
        Ok((input, Self { records }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgmpPacket {
    QueryV2(IgmpGroupMessage),
    QueryV3(IgmpV3Query),
    ReportV1(IgmpGroupMessage),
    ReportV2(IgmpGroupMessage),
    LeaveV2(IgmpGroupMessage),
    ReportV3(IgmpV3Report),
    Unknown { typ: u8, data: Vec<u8> },
}

impl IgmpPacket {
    pub fn typ(&self) -> u8 {
        use IgmpPacket::*;
        match self {
            QueryV2(_) | QueryV3(_) => IGMP_MEMBERSHIP_QUERY,
            ReportV1(_) => IGMP_V1_REPORT,
            ReportV2(_) => IGMP_V2_REPORT,
            LeaveV2(_) => IGMP_V2_LEAVE,
            ReportV3(_) => IGMP_V3_REPORT,
            Unknown { typ, .. } => *typ,
        }
    }

    /// Parse a whole IGMP message (IP payload). Checksum
    /// verification is a separate step (`igmp_verify_checksum`) done
    /// on the raw bytes.
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let total_len = input.len();
        let (rest, typ) = be_u8(input)?;
        let (rest, packet) = match typ {
            IGMP_MEMBERSHIP_QUERY if total_len == IGMP_V2_QUERY_LEN => {
                let (rest, msg) = IgmpGroupMessage::parse_be(rest)?;
                (rest, Self::QueryV2(msg))
            }
            IGMP_MEMBERSHIP_QUERY if total_len > IGMP_V2_QUERY_LEN => {
                let (rest, query) = IgmpV3Query::parse_be(rest)?;
                (rest, Self::QueryV3(query))
            }
            IGMP_MEMBERSHIP_QUERY => {
                return Err(Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            IGMP_V1_REPORT => {
                let (rest, msg) = IgmpGroupMessage::parse_be(rest)?;
                (rest, Self::ReportV1(msg))
            }
            IGMP_V2_REPORT => {
                let (rest, msg) = IgmpGroupMessage::parse_be(rest)?;
                (rest, Self::ReportV2(msg))
            }
            IGMP_V2_LEAVE => {
                let (rest, msg) = IgmpGroupMessage::parse_be(rest)?;
                (rest, Self::LeaveV2(msg))
            }
            IGMP_V3_REPORT => {
                let (rest, report) = IgmpV3Report::parse_be(rest)?;
                (rest, Self::ReportV3(report))
            }
            typ => (
                &rest[rest.len()..],
                Self::Unknown {
                    typ,
                    data: rest.to_vec(),
                },
            ),
        };
        Ok((rest, packet))
    }

    /// Emit the message into an empty buffer and fill in the
    /// checksum. The message must start at offset 0 of `buf`.
    pub fn emit(&self, buf: &mut BytesMut) {
        use IgmpPacket::*;
        buf.put_u8(self.typ());
        match self {
            QueryV2(msg) | ReportV1(msg) | ReportV2(msg) | LeaveV2(msg) => {
                buf.put_u8(msg.max_resp);
                buf.put_u16(0);
                buf.put(&msg.group.octets()[..]);
            }
            QueryV3(query) => {
                buf.put_u8(query.max_resp_code);
                buf.put_u16(0);
                buf.put(&query.group.octets()[..]);
                let mut s_qrv = query.qrv & V3_QUERY_QRV_MASK;
                if query.suppress {
                    s_qrv |= V3_QUERY_S_FLAG;
                }
                buf.put_u8(s_qrv);
                buf.put_u8(query.qqic);
                buf.put_u16(query.sources.len() as u16);
                for source in &query.sources {
                    buf.put(&source.octets()[..]);
                }
            }
            ReportV3(report) => {
                buf.put_u8(0);
                buf.put_u16(0);
                buf.put_u16(0);
                buf.put_u16(report.records.len() as u16);
                for record in &report.records {
                    record.emit(buf);
                }
            }
            Unknown { data, .. } => {
                buf.put(&data[..]);
            }
        }
        igmp_fill_checksum(buf);
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::checksum::igmp_verify_checksum;

    fn round_trip(wire: &[u8]) -> IgmpPacket {
        assert!(igmp_verify_checksum(wire), "fixture checksum invalid");
        let (rest, packet) = IgmpPacket::parse_be(wire).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);
        assert_eq!(&buf[..], wire, "emit does not round-trip");
        packet
    }

    #[test]
    fn v2_general_query_round_trip() {
        // General query, max resp 10.0s, group 0.0.0.0.
        let wire = hex!("11 64 ee 9b 00 00 00 00");
        let packet = round_trip(&wire);
        let IgmpPacket::QueryV2(query) = packet else {
            panic!("not a v2 query");
        };
        assert_eq!(query.max_resp, 0x64);
        assert_eq!(query.group, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn v3_general_query_round_trip() {
        // General query: QRV=2, QQIC=125, no sources.
        let wire = hex!("11 64 ec 1e 00 00 00 00 02 7d 00 00");
        let packet = round_trip(&wire);
        let IgmpPacket::QueryV3(query) = packet else {
            panic!("not a v3 query");
        };
        assert!(!query.suppress);
        assert_eq!(query.qrv, 2);
        assert_eq!(query.qqic, 125);
        assert!(query.sources.is_empty());
    }

    #[test]
    fn v3_report_change_to_include_round_trip() {
        // SSM join: CHANGE_TO_INCLUDE {10.0.0.2} for 232.1.1.1.
        let wire = hex!(
            "22 00 e7 f8 00 00 00 01" // v3 report, 1 record
            "03 00 00 01 e8 01 01 01" // CHANGE_TO_INCLUDE, 1 source
            "0a 00 00 02"
        );
        let packet = round_trip(&wire);
        let IgmpPacket::ReportV3(report) = packet else {
            panic!("not a v3 report");
        };
        assert_eq!(report.records.len(), 1);
        let record = &report.records[0];
        assert_eq!(record.rec_type, IgmpRecordType::ChangeToInclude);
        assert_eq!(record.group, Ipv4Addr::new(232, 1, 1, 1));
        assert_eq!(record.sources, vec![Ipv4Addr::new(10, 0, 0, 2)]);
        assert!(record.aux.is_empty());
    }

    #[test]
    fn v2_report_and_leave() {
        let report = IgmpPacket::ReportV2(IgmpGroupMessage {
            max_resp: 0,
            group: Ipv4Addr::new(239, 1, 1, 1),
        });
        let mut buf = BytesMut::new();
        report.emit(&mut buf);
        assert!(igmp_verify_checksum(&buf));
        let (_, reparsed) = IgmpPacket::parse_be(&buf).expect("parse");
        assert_eq!(reparsed, report);

        let leave = IgmpPacket::LeaveV2(IgmpGroupMessage {
            max_resp: 0,
            group: Ipv4Addr::new(239, 1, 1, 1),
        });
        let mut buf = BytesMut::new();
        leave.emit(&mut buf);
        assert!(igmp_verify_checksum(&buf));
        let (_, reparsed) = IgmpPacket::parse_be(&buf).expect("parse");
        assert_eq!(reparsed, leave);
    }

    #[test]
    fn corrupted_checksum_detected() {
        let mut wire = hex!("11 64 ee 9b 00 00 00 00").to_vec();
        wire[7] = 0x01;
        assert!(!igmp_verify_checksum(&wire));
    }
}
