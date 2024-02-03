use crate::*;
use ipnet::Ipv4Net;
use nom::bytes::streaming::take;
use nom::combinator::{map, peek};
use nom::error::{make_error, ErrorKind};
use nom::multi::{count, many0};
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;
use nom_derive::*;
use std::net::Ipv4Addr;

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
    if input.is_empty() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (input, header) = AsSegmentHeader::parse(input)?;
    let (input, asns) = count(be_u16, header.length as usize)(input)?;
    let segment = AsSegment {
        typ: header.typ,
        asn: asns.into_iter().map(|val| val as u32).collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as_path(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, segments) = many0(parse_bgp_attr_as_segment)(attr)?;
    let as_path = AsPathAttr { segments };
    Ok((input, Attribute::AsPath(as_path)))
}

fn parse_bgp_attr_community(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, community) = CommunityAttr::parse(attr)?;
    Ok((input, Attribute::Community(community)))
}

fn parse_bgp_attribute(input: &[u8]) -> IResult<&[u8], Attribute> {
    if input.is_empty() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
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
        AttributeType::AsPath => parse_bgp_attr_as_path(input, attr_len),
        AttributeType::NextHop => map(NextHopAttr::parse, Attribute::NextHop)(input),
        AttributeType::Med => map(MedAttr::parse, Attribute::Med)(input),
        AttributeType::LocalPref => map(LocalPrefAttr::parse, Attribute::LocalPref)(input),
        AttributeType::AtomicAggregate => {
            map(AtomicAggregateAttr::parse, Attribute::AtomicAggregate)(input)
        }
        AttributeType::Aggregator => map(AggregatorAttr::parse, Attribute::Aggregator)(input),
        AttributeType::Community => parse_bgp_attr_community(input, attr_len),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

fn parse_bgp_update_attribute(input: &[u8], length: u16) -> IResult<&[u8], Vec<Attribute>> {
    let (attr, input) = input.split_at(length as usize);
    let (_, attrs) = many0(parse_bgp_attribute)(attr)?;
    Ok((input, attrs))
}

fn plen2size(plen: u8) -> usize {
    ((plen + 7) / 8) as usize
}

fn parse_bgp_nlri_ipv4_prefix(input: &[u8]) -> IResult<&[u8], Ipv4Net> {
    if input.is_empty() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (input, plen) = be_u8(input)?;
    let psize = plen2size(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let prefix =
        Ipv4Net::new(Ipv4Addr::new(paddr[0], paddr[1], paddr[2], paddr[3]), plen).expect("err");
    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv4(input: &[u8], length: u16) -> IResult<&[u8], Vec<Ipv4Net>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, prefix) = many0(parse_bgp_nlri_ipv4_prefix)(nlri)?;
    Ok((input, prefix))
}

fn parse_bgp_update_packet(input: &[u8]) -> IResult<&[u8], UpdatePacket> {
    let (input, mut packet) = UpdatePacket::parse(input)?;
    let (input, withdraw_len) = be_u16(input)?;
    let (input, mut withdrawal) = parse_bgp_nlri_ipv4(input, withdraw_len)?;
    packet.ipv4_withdraw.append(&mut withdrawal);
    let (input, attr_len) = be_u16(input)?;
    let (input, mut attrs) = parse_bgp_update_attribute(input, attr_len)?;
    packet.attrs.append(&mut attrs);
    let nlri_len = packet.header.length - BGP_PACKET_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
    let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len)?;
    packet.ipv4_update.append(&mut updates);
    Ok((input, packet))
}

fn parse_bgp_notification_packet(input: &[u8]) -> IResult<&[u8], NotificationPacket> {
    let (input, packet) = NotificationPacket::parse(input)?;
    let len = packet.header.length - BGP_PACKET_HEADER_LEN;
    let (input, _data) = take(len as usize)(input)?;
    Ok((input, packet))
}

pub fn parse_bgp_packet(input: &[u8]) -> IResult<&[u8], BgpPacket> {
    let (_, header) = peek(BgpHeader::parse)(input)?;
    match header.typ {
        BgpPacketType::Open => map(parse_bgp_open_packet, BgpPacket::Open)(input),
        BgpPacketType::Update => map(parse_bgp_update_packet, BgpPacket::Update)(input),
        BgpPacketType::Notification => {
            map(parse_bgp_notification_packet, BgpPacket::Notification)(input)
        }
        BgpPacketType::Keepalive => map(BgpHeader::parse, BgpPacket::Keepalive)(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Eof))),
    }
}
