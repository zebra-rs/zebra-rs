use super::*;
use crate::bgp::{Afi, Safi};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::bytes::streaming::take;
use nom::combinator::{map, peek};
use nom::error::{make_error, ErrorKind};
use nom::multi::count;
use nom::number::streaming::{be_u128, be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::*;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

fn parse_bgp_capability_packet(input: &[u8]) -> IResult<&[u8], CapabilityPacket> {
    let (_, header) = peek(CapabilityPeekHeader::parse)(input)?;
    match CapabilityType(header.typ) {
        CapabilityType::MultiProtocol => map(
            CapabilityMultiProtocol::parse,
            CapabilityPacket::MultiProtocol,
        )(input),
        CapabilityType::RouteRefresh | CapabilityType::RouteRefreshCisco => map(
            CapabilityRouteRefresh::parse,
            CapabilityPacket::RouteRefresh,
        )(input),
        CapabilityType::GracefulRestart => map(
            CapabilityGracefulRestart::parse,
            CapabilityPacket::GracefulRestart,
        )(input),
        CapabilityType::As4 => map(CapabilityAs4::parse, CapabilityPacket::As4)(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

fn parse_bgp_open_packet(input: &[u8]) -> IResult<&[u8], OpenPacket> {
    let (input, mut packet) = OpenPacket::parse(input)?;
    let (input, mut caps) = many0(parse_bgp_capability_packet)(input)?;
    packet.caps.append(&mut caps);
    Ok((input, packet))
}

fn parse_bgp_attr_as_segment(input: &[u8]) -> IResult<&[u8], AsSegment> {
    let (input, header) = AsSegmentHeader::parse(input)?;
    let (input, asns) = count(be_u16, header.length as usize)(input)?;
    let segment = AsSegment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as_path(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, segments) = many0(parse_bgp_attr_as_segment)(attr)?;
    let as_path = AsPathAttr { segments };
    Ok((input, Attribute::AsPath(as_path)))
}

fn parse_bgp_attr_as4_segment(input: &[u8]) -> IResult<&[u8], As4Segment> {
    let (input, header) = AsSegmentHeader::parse(input)?;
    let (input, asns) = count(be_u32, header.length as usize)(input)?;
    let segment = As4Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as4_path(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, segments) = many0(parse_bgp_attr_as4_segment)(attr)?;
    let as_path = As4PathAttr { segments };
    Ok((input, Attribute::As4Path(as_path)))
}

fn parse_bgp_attr_community(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, community) = CommunityAttr::parse(attr)?;
    Ok((input, Attribute::Community(community)))
}

fn parse_bgp_attr_mp_reach(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    if input.len() < size_of::<MpNlriReachHeader>() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (attr, input) = input.split_at(length as usize);
    let (attr, header) = MpNlriReachHeader::parse(attr)?;
    if header.afi != Afi::IP6 || header.safi != Safi::Unicast {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    if header.nhop_len != 16 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    let (attr, nhop) = be_u128(attr)?;
    let nhop: Ipv6Addr = Ipv6Addr::from(nhop);
    let (attr, _snpa) = be_u8(attr)?;
    let (_, updates) = many0(parse_bgp_nlri_ipv6_prefix)(attr)?;
    let mp_nlri = MpNlriAttr {
        next_hop: Some(nhop),
        prefix: updates,
    };
    Ok((input, Attribute::MpReachNlri(mp_nlri)))
}

fn parse_bgp_attr_mp_unreach(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    if input.len() < size_of::<MpNlriUnreachHeader>() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (attr, input) = input.split_at(length as usize);
    let (attr, header) = MpNlriUnreachHeader::parse(attr)?;
    if header.afi != Afi::IP6 || header.safi != Safi::Unicast {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    let (_, withdrawal) = many0(parse_bgp_nlri_ipv6_prefix)(attr)?;
    let mp_nlri = MpNlriAttr {
        next_hop: None,
        prefix: withdrawal,
    };
    Ok((input, Attribute::MpReachNlri(mp_nlri)))
}

fn parse_bgp_attr_large_com(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, lcom) = LargeComAttr::parse(attr)?;
    Ok((input, Attribute::LargeCom(lcom)))
}

fn parse_bgp_attribute(input: &[u8], as4: bool) -> IResult<&[u8], Attribute> {
    let (input, header) = AttributeHeader::parse(input)?;
    let ext_len: usize = if header.is_extended() { 2 } else { 1 };
    let (input, exts) = take(ext_len)(input)?;
    let attr_len = if exts.len() == 1 {
        exts[0] as u16
    } else {
        ((exts[0] as u16) << 8) + exts[1] as u16
    };
    match AttributeType(header.type_code) {
        AttributeType::Origin => map(OriginAttr::parse, Attribute::Origin)(input),
        AttributeType::AsPath => {
            if as4 {
                parse_bgp_attr_as4_path(input, attr_len)
            } else {
                parse_bgp_attr_as_path(input, attr_len)
            }
        }
        AttributeType::NextHop => map(NextHopAttr::parse, Attribute::NextHop)(input),
        AttributeType::Med => map(MedAttr::parse, Attribute::Med)(input),
        AttributeType::LocalPref => map(LocalPrefAttr::parse, Attribute::LocalPref)(input),
        AttributeType::AtomicAggregate => {
            map(AtomicAggregateAttr::parse, Attribute::AtomicAggregate)(input)
        }
        AttributeType::Aggregator => {
            if as4 {
                map(Aggregator4Attr::parse, Attribute::Aggregator4)(input)
            } else {
                map(AggregatorAttr::parse, Attribute::Aggregator)(input)
            }
        }
        AttributeType::Community => parse_bgp_attr_community(input, attr_len),
        AttributeType::MpReachNlri => parse_bgp_attr_mp_reach(input, attr_len),
        AttributeType::MpUnreachNlri => parse_bgp_attr_mp_unreach(input, attr_len),
        AttributeType::LargeCom => parse_bgp_attr_large_com(input, attr_len),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

pub fn parse_bgp_attribute_as(as4: bool) -> impl Fn(&[u8]) -> IResult<&[u8], attr::Attribute> {
    move |i: &[u8]| parse_bgp_attribute(i, as4)
}

fn parse_bgp_update_attribute(
    input: &[u8],
    length: u16,
    as4: bool,
) -> IResult<&[u8], Vec<Attribute>> {
    let (attr, input) = input.split_at(length as usize);
    let (_, attrs) = many0(parse_bgp_attribute_as(as4))(attr)?;
    Ok((input, attrs))
}

fn plen2size(plen: u8) -> usize {
    ((plen + 7) / 8) as usize
}

pub fn parse_ipv4_prefix(input: &[u8]) -> IResult<&[u8], Ipv4Net> {
    let (input, plen) = be_u8(input)?;
    let psize = plen2size(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net crete error");
    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv6_prefix(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
    let (input, plen) = be_u8(input)?;
    let psize = plen2size(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 16];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv4(input: &[u8], length: u16) -> IResult<&[u8], Vec<Ipv4Net>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, prefix) = many0(parse_ipv4_prefix)(nlri)?;
    Ok((input, prefix))
}

fn parse_bgp_update_packet(input: &[u8], as4: bool) -> IResult<&[u8], UpdatePacket> {
    let (input, mut packet) = UpdatePacket::parse(input)?;
    let (input, withdraw_len) = be_u16(input)?;
    let (input, mut withdrawal) = parse_bgp_nlri_ipv4(input, withdraw_len)?;
    packet.ipv4_withdraw.append(&mut withdrawal);
    let (input, attr_len) = be_u16(input)?;
    let (input, mut attrs) = parse_bgp_update_attribute(input, attr_len, as4)?;
    packet.attrs.append(&mut attrs);
    let nlri_len = packet.header.length - BGP_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
    let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len)?;
    packet.ipv4_update.append(&mut updates);
    Ok((input, packet))
}

fn parse_bgp_notification_packet(input: &[u8]) -> IResult<&[u8], NotificationPacket> {
    let (input, packet) = NotificationPacket::parse(input)?;
    let len = packet.header.length - BGP_HEADER_LEN - 2;
    let (input, _data) = take(len as usize)(input)?;
    Ok((input, packet))
}

pub fn peek_bgp_length(input: &[u8]) -> usize {
    if let Some(len) = input.get(16..18) {
        let len = u16::from_be_bytes(len.try_into().unwrap()) as usize;
        len
    } else {
        0
    }
}

pub fn parse_bgp_packet(input: &[u8], as4: bool) -> IResult<&[u8], BgpPacket> {
    let (_, header) = peek(BgpHeader::parse)(input)?;
    match header.typ {
        BgpType::Open => map(parse_bgp_open_packet, BgpPacket::Open)(input),
        BgpType::Update => {
            let (input, p) = parse_bgp_update_packet(input, as4)?;
            Ok((input, BgpPacket::Update(p)))
        }
        BgpType::Notification => map(parse_bgp_notification_packet, BgpPacket::Notification)(input),
        BgpType::Keepalive => map(BgpHeader::parse, BgpPacket::Keepalive)(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Eof))),
    }
}
