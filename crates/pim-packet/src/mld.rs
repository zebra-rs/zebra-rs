//! MLD wire formats: MLDv1 (RFC 2710) and MLDv2 (RFC 3810), carried
//! over ICMPv6. The MLDv2 group-record model is numerically
//! identical to IGMPv3's, so [`IgmpRecordType`] is reused; only the
//! addresses widen to `Ipv6Addr` and the on-wire framing differs
//! (ICMPv6 type/code header, 16-byte addresses, ICMPv6 checksum).

use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16};
use packet_utils::ParseBe;

use crate::checksum::mld_fill_checksum;
use crate::igmp::IgmpRecordType;

/// ICMPv6 type numbers used by MLD.
pub const MLD_QUERY: u8 = 130;
pub const MLD_V1_REPORT: u8 = 131;
pub const MLD_V1_DONE: u8 = 132;
pub const MLD_V2_REPORT: u8 = 143;

/// An MLDv1 query is exactly 24 octets; a longer query is MLDv2.
const MLD_V1_QUERY_LEN: usize = 24;

// MLDv2 query S/QRV octet: Resv(4) | S | QRV(3).
const V2_QUERY_S_FLAG: u8 = 0x08;
const V2_QUERY_QRV_MASK: u8 = 0x07;

/// The common 24-octet MLD message body (after the ICMPv6
/// type/code/checksum): MLDv1 query/report/done. `max_resp_code` is
/// meaningful only for queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldGroupMessage {
    pub max_resp_code: u16,
    pub group: Ipv6Addr,
}

impl MldGroupMessage {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, max_resp_code) = be_u16(input)?;
        let (input, _reserved) = be_u16(input)?;
        let (input, group) = Ipv6Addr::parse_be(input)?;
        Ok((
            input,
            Self {
                max_resp_code,
                group,
            },
        ))
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.max_resp_code);
        buf.put_u16(0);
        buf.put(&self.group.octets()[..]);
    }
}

/// MLDv2 membership query (RFC 3810 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldV2Query {
    pub max_resp_code: u16,
    pub group: Ipv6Addr,
    pub suppress: bool,
    pub qrv: u8,
    pub qqic: u8,
    pub sources: Vec<Ipv6Addr>,
}

impl MldV2Query {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, max_resp_code) = be_u16(input)?;
        let (input, _reserved) = be_u16(input)?;
        let (input, group) = Ipv6Addr::parse_be(input)?;
        let (input, s_qrv) = be_u8(input)?;
        let (input, qqic) = be_u8(input)?;
        let (mut input, num_sources) = be_u16(input)?;
        let mut sources = Vec::with_capacity(num_sources as usize);
        for _ in 0..num_sources {
            let (rest, s) = Ipv6Addr::parse_be(input)?;
            sources.push(s);
            input = rest;
        }
        Ok((
            input,
            Self {
                max_resp_code,
                group,
                suppress: s_qrv & V2_QUERY_S_FLAG != 0,
                qrv: s_qrv & V2_QUERY_QRV_MASK,
                qqic,
                sources,
            },
        ))
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.max_resp_code);
        buf.put_u16(0);
        buf.put(&self.group.octets()[..]);
        let mut s_qrv = self.qrv & V2_QUERY_QRV_MASK;
        if self.suppress {
            s_qrv |= V2_QUERY_S_FLAG;
        }
        buf.put_u8(s_qrv);
        buf.put_u8(self.qqic);
        buf.put_u16(self.sources.len() as u16);
        for s in &self.sources {
            buf.put(&s.octets()[..]);
        }
    }
}

/// MLDv2 multicast address record (RFC 3810 §5.2.4) — the IPv6 twin
/// of `IgmpGroupRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldGroupRecord {
    pub rec_type: IgmpRecordType,
    pub group: Ipv6Addr,
    pub sources: Vec<Ipv6Addr>,
    /// Auxiliary data (multiple of 4 octets), preserved round-trip.
    pub aux: Vec<u8>,
}

impl MldGroupRecord {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, rec_type) = be_u8(input)?;
        let (input, aux_len) = be_u8(input)?;
        let (input, num_sources) = be_u16(input)?;
        let (mut input, group) = Ipv6Addr::parse_be(input)?;
        let mut sources = Vec::with_capacity(num_sources as usize);
        for _ in 0..num_sources {
            let (rest, s) = Ipv6Addr::parse_be(input)?;
            sources.push(s);
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
        for s in &self.sources {
            buf.put(&s.octets()[..]);
        }
        buf.put(&self.aux[..]);
    }
}

/// MLDv2 membership report (RFC 3810 §5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MldV2Report {
    pub records: Vec<MldGroupRecord>,
}

impl MldV2Report {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _reserved) = be_u16(input)?;
        let (mut input, num_records) = be_u16(input)?;
        let mut records = Vec::with_capacity(num_records as usize);
        for _ in 0..num_records {
            let (rest, r) = MldGroupRecord::parse_be(input)?;
            records.push(r);
            input = rest;
        }
        Ok((input, Self { records }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MldPacket {
    QueryV1(MldGroupMessage),
    QueryV2(MldV2Query),
    ReportV1(MldGroupMessage),
    DoneV1(MldGroupMessage),
    ReportV2(MldV2Report),
    Unknown { typ: u8, data: Vec<u8> },
}

impl MldPacket {
    pub fn typ(&self) -> u8 {
        use MldPacket::*;
        match self {
            QueryV1(_) | QueryV2(_) => MLD_QUERY,
            ReportV1(_) => MLD_V1_REPORT,
            DoneV1(_) => MLD_V1_DONE,
            ReportV2(_) => MLD_V2_REPORT,
            Unknown { typ, .. } => *typ,
        }
    }

    /// Parse a whole MLD message (the ICMPv6 payload). Checksum
    /// verification is a separate step (`mld_verify_checksum`).
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let total = input.len();
        let (rest, typ) = be_u8(input)?;
        let (rest, _code) = be_u8(rest)?;
        let (rest, _checksum) = be_u16(rest)?;
        let (rest, packet) = match typ {
            MLD_QUERY if total == MLD_V1_QUERY_LEN => {
                let (rest, m) = MldGroupMessage::parse_be(rest)?;
                (rest, Self::QueryV1(m))
            }
            MLD_QUERY if total > MLD_V1_QUERY_LEN => {
                let (rest, q) = MldV2Query::parse_be(rest)?;
                (rest, Self::QueryV2(q))
            }
            MLD_V1_REPORT => {
                let (rest, m) = MldGroupMessage::parse_be(rest)?;
                (rest, Self::ReportV1(m))
            }
            MLD_V1_DONE => {
                let (rest, m) = MldGroupMessage::parse_be(rest)?;
                (rest, Self::DoneV1(m))
            }
            MLD_V2_REPORT => {
                let (rest, r) = MldV2Report::parse_be(rest)?;
                (rest, Self::ReportV2(r))
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

    /// Emit the message and fill the ICMPv6 checksum from the outer
    /// (src, dst). The message must start at offset 0 of `buf`.
    pub fn emit(&self, buf: &mut BytesMut, src: Ipv6Addr, dst: Ipv6Addr) {
        use MldPacket::*;
        buf.put_u8(self.typ());
        buf.put_u8(0);
        buf.put_u16(0);
        match self {
            QueryV1(m) | ReportV1(m) | DoneV1(m) => m.emit(buf),
            QueryV2(q) => q.emit(buf),
            ReportV2(r) => {
                buf.put_u16(0);
                buf.put_u16(r.records.len() as u16);
                for rec in &r.records {
                    rec.emit(buf);
                }
            }
            Unknown { data, .. } => buf.put(&data[..]),
        }
        mld_fill_checksum(buf, src, dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::mld_verify_checksum;

    const SRC: &str = "fe80::1";
    const DST: &str = "ff02::16";

    fn round_trip(p: &MldPacket) -> MldPacket {
        let src: Ipv6Addr = SRC.parse().unwrap();
        let dst: Ipv6Addr = DST.parse().unwrap();
        let mut buf = BytesMut::new();
        p.emit(&mut buf, src, dst);
        assert!(mld_verify_checksum(&buf, src, dst), "bad checksum");
        let (rest, parsed) = MldPacket::parse_be(&buf).expect("parse");
        assert!(rest.is_empty(), "trailing bytes");
        assert_eq!(&parsed, p);
        parsed
    }

    #[test]
    fn v1_query_report_done() {
        let g: Ipv6Addr = "ff3e::1234".parse().unwrap();
        // General query: group unspecified, 24 octets.
        round_trip(&MldPacket::QueryV1(MldGroupMessage {
            max_resp_code: 10000,
            group: Ipv6Addr::UNSPECIFIED,
        }));
        round_trip(&MldPacket::ReportV1(MldGroupMessage {
            max_resp_code: 0,
            group: g,
        }));
        round_trip(&MldPacket::DoneV1(MldGroupMessage {
            max_resp_code: 0,
            group: g,
        }));
    }

    #[test]
    fn v2_query_with_sources() {
        let q = MldV2Query {
            max_resp_code: 10000,
            group: "ff3e::1".parse().unwrap(),
            suppress: false,
            qrv: 2,
            qqic: 125,
            sources: vec![
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ],
        };
        let out = round_trip(&MldPacket::QueryV2(q));
        let MldPacket::QueryV2(q) = out else {
            panic!("not v2 query");
        };
        assert_eq!(q.qrv, 2);
        assert_eq!(q.sources.len(), 2);
    }

    #[test]
    fn v2_report_all_record_types() {
        let g: Ipv6Addr = "ff3e::5".parse().unwrap();
        let s: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let records = [
            IgmpRecordType::ModeIsInclude,
            IgmpRecordType::ModeIsExclude,
            IgmpRecordType::ChangeToInclude,
            IgmpRecordType::ChangeToExclude,
            IgmpRecordType::AllowNewSources,
            IgmpRecordType::BlockOldSources,
        ]
        .into_iter()
        .map(|rec_type| MldGroupRecord {
            rec_type,
            group: g,
            sources: vec![s],
            aux: vec![],
        })
        .collect();
        let out = round_trip(&MldPacket::ReportV2(MldV2Report { records }));
        let MldPacket::ReportV2(r) = out else {
            panic!("not v2 report");
        };
        assert_eq!(r.records.len(), 6);
        assert_eq!(r.records[0].rec_type, IgmpRecordType::ModeIsInclude);
    }

    #[test]
    fn bad_checksum_detected() {
        let src: Ipv6Addr = SRC.parse().unwrap();
        let dst: Ipv6Addr = DST.parse().unwrap();
        let mut buf = BytesMut::new();
        MldPacket::ReportV1(MldGroupMessage {
            max_resp_code: 0,
            group: "ff3e::1".parse().unwrap(),
        })
        .emit(&mut buf, src, dst);
        // A different destination invalidates the pseudo-header sum.
        assert!(!mld_verify_checksum(&buf, src, "ff02::1".parse().unwrap()));
    }
}
