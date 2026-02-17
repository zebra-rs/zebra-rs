use std::fmt;

use bytes::BytesMut;
use nom::bytes::complete::take;
use nom::number::complete::be_u8;
use nom_derive::*;

use crate::{BgpAttr, BgpNexthop, BgpParseError, ParseBe, ParseOption};

use super::*;

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    Med = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Community = 8,
    OriginatorId = 9,
    ClusterList = 10,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    ExtendedCom = 16,
    PmsiTunnel = 22,
    ExtendedIpv6Com = 25,
    Aigp = 26,
    LargeCom = 32,
    Unknown(u8),
}

impl From<u8> for AttrType {
    fn from(attr_type: u8) -> Self {
        use AttrType::*;
        match attr_type {
            1 => Origin,
            2 => AsPath,
            3 => NextHop,
            4 => Med,
            5 => LocalPref,
            6 => AtomicAggregate,
            7 => Aggregator,
            8 => Community,
            9 => OriginatorId,
            10 => ClusterList,
            14 => MpReachNlri,
            15 => MpUnreachNlri,
            16 => ExtendedCom,
            22 => PmsiTunnel,
            25 => ExtendedIpv6Com,
            26 => Aigp,
            32 => LargeCom,
            v => Unknown(v),
        }
    }
}

impl From<AttrType> for u8 {
    fn from(attr_type: AttrType) -> Self {
        use AttrType::*;
        match attr_type {
            Origin => 1,
            AsPath => 2,
            NextHop => 3,
            Med => 4,
            LocalPref => 5,
            AtomicAggregate => 6,
            Aggregator => 7,
            Community => 8,
            OriginatorId => 9,
            ClusterList => 10,
            MpReachNlri => 14,
            MpUnreachNlri => 15,
            ExtendedCom => 16,
            PmsiTunnel => 22,
            ExtendedIpv6Com => 25,
            Aigp => 26,
            LargeCom => 32,
            Unknown(v) => v,
        }
    }
}

struct AttrSelector(AttrType, Option<bool>);

#[derive(NomBE, Clone)]
#[nom(Selector = "AttrSelector")]
pub enum Attr {
    #[nom(Selector = "AttrSelector(AttrType::Origin, None)")]
    Origin(Origin),
    #[nom(Selector = "AttrSelector(AttrType::AsPath, Some(false))")]
    As2Path(As2Path),
    #[nom(Selector = "AttrSelector(AttrType::AsPath, Some(true))")]
    As4Path(As4Path),
    #[nom(Selector = "AttrSelector(AttrType::NextHop, None)")]
    NextHop(NexthopAttr),
    #[nom(Selector = "AttrSelector(AttrType::Med, None)")]
    Med(Med),
    #[nom(Selector = "AttrSelector(AttrType::LocalPref, None)")]
    LocalPref(LocalPref),
    #[nom(Selector = "AttrSelector(AttrType::AtomicAggregate, None)")]
    AtomicAggregate(AtomicAggregate),
    #[nom(Selector = "AttrSelector(AttrType::Aggregator, Some(false))")]
    Aggregator2(Aggregator2),
    #[nom(Selector = "AttrSelector(AttrType::Aggregator, Some(true))")]
    Aggregator(Aggregator),
    #[nom(Selector = "AttrSelector(AttrType::Community, None)")]
    Community(Community),
    #[nom(Selector = "AttrSelector(AttrType::OriginatorId, None)")]
    OriginatorId(OriginatorId),
    #[nom(Selector = "AttrSelector(AttrType::ClusterList, None)")]
    ClusterList(ClusterList),
    #[nom(Selector = "AttrSelector(AttrType::MpReachNlri, None)")]
    MpReachNlri(MpReachAttr),
    #[nom(Selector = "AttrSelector(AttrType::MpUnreachNlri, None)")]
    MpUnreachNlri(MpUnreachAttr),
    #[nom(Selector = "AttrSelector(AttrType::ExtendedCom, None)")]
    ExtendedCom(ExtCommunity),
    #[nom(Selector = "AttrSelector(AttrType::PmsiTunnel, None)")]
    PmsiTunnel(PmsiTunnel),
    #[nom(Selector = "AttrSelector(AttrType::Aigp, None)")]
    Aigp(Aigp),
    #[nom(Selector = "AttrSelector(AttrType::LargeCom, None)")]
    LargeCom(LargeCommunity),
}

impl Attr {
    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Attr::Origin(v) => v.attr_emit(buf),
            Attr::As4Path(v) => v.attr_emit(buf),
            Attr::NextHop(v) => v.attr_emit(buf),
            Attr::Med(v) => v.attr_emit(buf),
            Attr::LocalPref(v) => v.attr_emit(buf),
            Attr::AtomicAggregate(v) => v.attr_emit(buf),
            Attr::Aggregator(v) => v.attr_emit(buf),
            Attr::Aggregator2(v) => v.attr_emit(buf),
            Attr::OriginatorId(v) => v.attr_emit(buf),
            Attr::ClusterList(v) => v.attr_emit(buf),
            // Attr::MpReachNlri(v) => v.attr_emit(buf),
            Attr::Community(v) => v.attr_emit(buf),
            Attr::ExtendedCom(v) => v.attr_emit(buf),
            Attr::PmsiTunnel(v) => v.attr_emit(buf),
            Attr::LargeCom(v) => v.attr_emit(buf),
            Attr::Aigp(v) => v.attr_emit(buf),
            _ => {
                //
            }
        }
    }
}

impl fmt::Display for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attr::Origin(v) => write!(f, "{}", v),
            Attr::As4Path(v) => write!(f, "{}", v),
            Attr::NextHop(v) => write!(f, "{}", v),
            Attr::Med(v) => write!(f, "{}", v),
            Attr::LocalPref(v) => write!(f, "{}", v),
            Attr::AtomicAggregate(v) => write!(f, "{}", v),
            Attr::Aggregator(v) => write!(f, "{}", v),
            Attr::Aggregator2(v) => write!(f, "{}", v),
            Attr::OriginatorId(v) => write!(f, "{}", v),
            Attr::ClusterList(v) => write!(f, "{}", v),
            Attr::MpReachNlri(v) => write!(f, "{}", v),
            Attr::MpUnreachNlri(v) => write!(f, "{}", v),
            Attr::Community(v) => write!(f, "{}", v),
            Attr::ExtendedCom(v) => write!(f, "{}", v),
            Attr::PmsiTunnel(v) => write!(f, "{}", v),
            Attr::LargeCom(v) => write!(f, "{}", v),
            Attr::Aigp(v) => write!(f, "{}", v),
            _ => write!(f, "Unknown"),
        }
    }
}

impl fmt::Debug for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attr::Origin(v) => write!(f, "{:?}", v),
            Attr::As4Path(v) => write!(f, "{:?}", v),
            Attr::NextHop(v) => write!(f, "{:?}", v),
            Attr::Med(v) => write!(f, "{:?}", v),
            Attr::LocalPref(v) => write!(f, "{:?}", v),
            Attr::AtomicAggregate(v) => write!(f, "{:?}", v),
            Attr::Aggregator(v) => write!(f, "{:?}", v),
            Attr::Aggregator2(v) => write!(f, "{:?}", v),
            Attr::OriginatorId(v) => write!(f, "{:?}", v),
            Attr::ClusterList(v) => write!(f, "{:?}", v),
            Attr::MpReachNlri(v) => write!(f, "{:?}", v),
            Attr::MpUnreachNlri(v) => write!(f, "{:?}", v),
            Attr::Community(v) => write!(f, "{:?}", v),
            Attr::ExtendedCom(v) => write!(f, "{:?}", v),
            Attr::PmsiTunnel(v) => write!(f, "{:?}", v),
            Attr::LargeCom(v) => write!(f, "{:?}", v),
            Attr::Aigp(v) => write!(f, "{:?}", v),
            _ => write!(f, "Unknown"),
        }
    }
}

impl Attr {
    pub fn parse_attr<'a>(
        input: &'a [u8],
        as4: bool,
        opt: &'a Option<ParseOption>,
    ) -> Result<(&'a [u8], Attr), BgpParseError> {
        // Parse the attribute flags and type code
        let (input, flags_byte) = be_u8(input)?;
        let flags = AttributeFlags::from_bits(flags_byte).unwrap();
        let (input, attr_type_byte) = be_u8(input)?;
        let attr_type: AttrType = attr_type_byte.into();

        // Decide extended length presence and parse length
        let (input, length_bytes) = if flags.is_extended() {
            take(2usize).parse(input)?
        } else {
            take(1usize).parse(input)?
        };
        let attr_len = u16::from_be_bytes(if length_bytes.len() == 2 {
            [length_bytes[0], length_bytes[1]]
        } else {
            [0, length_bytes[0]]
        });

        // Only AS_PATH or AGGREGATOR care about as4 extension
        let as4_opt = matches!(attr_type, AttrType::AsPath | AttrType::Aggregator).then_some(as4);

        // Split out the payload for this attribute
        if input.len() < attr_len as usize {
            return Err(BgpParseError::IncompleteData {
                needed: attr_len as usize - input.len(),
            });
        }
        let (attr_payload, input) = input.split_at(attr_len as usize);

        // Parse the attribute using the appropriate selector with error context
        let (_, attr) = match attr_type {
            AttrType::MpReachNlri => {
                let (remaining, mp_reach) = MpReachAttr::parse_nlri_opt(attr_payload, opt.clone())
                    .map_err(|e| BgpParseError::AttributeParseError {
                        attr_type,
                        source: Box::new(BgpParseError::from(e)),
                    })?;
                (remaining, Attr::MpReachNlri(mp_reach))
            }
            AttrType::MpUnreachNlri => {
                let (remaining, mp_unreach) =
                    MpUnreachAttr::parse_nlri_opt(attr_payload, opt.clone()).map_err(|e| {
                        BgpParseError::AttributeParseError {
                            attr_type,
                            source: Box::new(BgpParseError::from(e)),
                        }
                    })?;
                (remaining, Attr::MpUnreachNlri(mp_unreach))
            }
            _ => Attr::parse_be(attr_payload, AttrSelector(attr_type, as4_opt)).map_err(|e| {
                BgpParseError::AttributeParseError {
                    attr_type,
                    source: Box::new(BgpParseError::from(e)),
                }
            })?,
        };

        Ok((input, attr))
    }
}

type ParsedAttributes<'a> = Result<
    (
        &'a [u8],
        Option<BgpAttr>,
        Option<MpReachAttr>,
        Option<MpUnreachAttr>,
    ),
    BgpParseError,
>;

pub fn parse_bgp_update_attribute(
    input: &[u8],
    length: u16,
    as4: bool,
    opt: Option<ParseOption>,
) -> ParsedAttributes<'_> {
    let (attr, input) = input.split_at(length as usize);
    let mut remaining = attr;
    let mut bgp_attr = BgpAttr::default();
    let mut mp_update: Option<MpReachAttr> = None;
    let mut mp_withdraw: Option<MpUnreachAttr> = None;

    while !remaining.is_empty() {
        let (new_remaining, attr) = Attr::parse_attr(remaining, as4, &opt)?;
        match attr {
            Attr::Origin(v) => {
                bgp_attr.origin = Some(v);
            }
            Attr::As2Path(_v) => {
                // TODO.
            }
            Attr::As4Path(v) => {
                bgp_attr.aspath = Some(v);
            }
            Attr::NextHop(v) => {
                bgp_attr.nexthop = Some(BgpNexthop::Ipv4(v.nexthop));
            }
            Attr::Med(v) => {
                bgp_attr.med = Some(v);
            }
            Attr::LocalPref(v) => {
                bgp_attr.local_pref = Some(v);
            }
            Attr::AtomicAggregate(v) => {
                bgp_attr.atomic_aggregate = Some(v);
            }
            Attr::Aggregator(v) => {
                bgp_attr.aggregator = Some(v);
            }
            Attr::Aggregator2(_v) => {
                // TODO
            }
            Attr::Community(v) => {
                bgp_attr.com = Some(v);
            }
            Attr::OriginatorId(v) => {
                bgp_attr.originator_id = Some(v);
            }
            Attr::ClusterList(v) => {
                bgp_attr.cluster_list = Some(v);
            }
            Attr::MpReachNlri(v) => {
                match v {
                    MpReachAttr::Vpnv4(nlri) => {
                        bgp_attr.nexthop = Some(BgpNexthop::Vpnv4(nlri.nhop.clone()));
                        mp_update = Some(MpReachAttr::Vpnv4(nlri));
                    }
                    MpReachAttr::Evpn {
                        snpa,
                        nhop,
                        updates,
                    } => {
                        bgp_attr.nexthop = Some(BgpNexthop::Evpn(nhop.clone()));
                        mp_update = Some(MpReachAttr::Evpn {
                            snpa,
                            nhop,
                            updates,
                        })
                    }
                    _ => {
                        //
                    }
                }
            }
            Attr::MpUnreachNlri(v) => {
                mp_withdraw = Some(v);
            }
            Attr::ExtendedCom(v) => {
                bgp_attr.ecom = Some(v);
            }
            Attr::PmsiTunnel(v) => {
                bgp_attr.pmsi_tunnel = Some(v);
            }
            Attr::Aigp(v) => {
                bgp_attr.aigp = Some(v);
            }
            Attr::LargeCom(v) => {
                bgp_attr.lcom = Some(v);
            }
        }
        remaining = new_remaining;
    }

    Ok((input, Some(bgp_attr), mp_update, mp_withdraw))
}
