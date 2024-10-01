use std::net::Ipv6Addr;
use std::str::FromStr;

use netlink_packet_route::route::{
    Ipv6SrHdr, RouteAttribute, RouteHeader, RouteLwEnCapType, RouteLwTunnelEncap, RouteMessage,
    RouteSeg6IpTunnel, Seg6IpTunnelEncap, Seg6IpTunnelMode, VecIpv6SrHdr,
};
use rtnetlink::RouteMessageBuilder;

pub struct RouteLwRequest {
    message: RouteMessage,
}

pub async fn srv6_encap_add(handle: &rtnetlink::Handle) {
    // IPv6 segments.
    let seg1: Ipv6Addr = Ipv6Addr::from_str("fd00:c::").unwrap();
    let seg2: Ipv6Addr = Ipv6Addr::from_str("fd00:b::").unwrap();
    let seg3: Ipv6Addr = Ipv6Addr::from_str("3001:2003::2").unwrap();
    let segments: Vec<Ipv6Addr> = vec![seg1, seg2, seg3];
    let ipv6_sr_hdr = Ipv6SrHdr {
        nexthdr: 0,
        hdrlen: 6,
        typ: 4,
        segments_left: (segments.len() - 1) as u8,
        first_segment: (segments.len() - 1) as u8,
        flags: 0,
        tag: 0,
        segments,
    };
    let seg6encap = Seg6IpTunnelEncap {
        mode: Seg6IpTunnelMode::Encap.into(),
        ipv6_sr_hdr: VecIpv6SrHdr(vec![ipv6_sr_hdr]),
    };
    let seg6_ip_tunnel = RouteSeg6IpTunnel::Seg6IpTunnel(seg6encap);
    let lwencap = RouteLwTunnelEncap::Seg6(seg6_ip_tunnel);
    let encap = RouteAttribute::Encap(vec![lwencap]);
    let encap_type = RouteAttribute::EncapType(RouteLwEnCapType::Seg6);

    let mut attributes: Vec<RouteAttribute> = vec![encap, encap_type];

    let mut message = RouteMessageBuilder::<Ipv6Addr>::new()
        .output_interface(3)
        .destination_prefix(Ipv6Addr::from_str("fd00:beeb::").unwrap(), 32)
        .build();
    message.attributes.append(&mut attributes);

    let route = handle.route();
    match route.add(message).execute().await {
        Ok(v) => {
            println!("Ok {:?}", v);
        }
        Err(v) => {
            println!("Err {:?}", v);
        }
    }
}

pub async fn srv6_encap_del(handle: &rtnetlink::Handle) {
    // IPv6 segments.
    let seg1: Ipv6Addr = Ipv6Addr::from_str("fd00:c::").unwrap();
    let seg2: Ipv6Addr = Ipv6Addr::from_str("fd00:b::").unwrap();
    let seg3: Ipv6Addr = Ipv6Addr::from_str("3001:2003::2").unwrap();
    let segments: Vec<Ipv6Addr> = vec![seg1, seg2, seg3];
    let ipv6_sr_hdr = Ipv6SrHdr {
        nexthdr: 0,
        hdrlen: 6,
        typ: 4,
        segments_left: (segments.len() - 1) as u8,
        first_segment: (segments.len() - 1) as u8,
        flags: 0,
        tag: 0,
        segments,
    };
    let seg6encap = Seg6IpTunnelEncap {
        mode: Seg6IpTunnelMode::Encap.into(),
        ipv6_sr_hdr: VecIpv6SrHdr(vec![ipv6_sr_hdr]),
    };
    let seg6_ip_tunnel = RouteSeg6IpTunnel::Seg6IpTunnel(seg6encap);
    let lwencap = RouteLwTunnelEncap::Seg6(seg6_ip_tunnel);
    let encap = RouteAttribute::Encap(vec![lwencap]);
    let encap_type = RouteAttribute::EncapType(RouteLwEnCapType::Seg6);

    let mut attributes: Vec<RouteAttribute> = vec![encap, encap_type];

    let mut message = RouteMessageBuilder::<Ipv6Addr>::new()
        .output_interface(3)
        .destination_prefix(Ipv6Addr::from_str("fd00:beeb::").unwrap(), 32)
        .build();
    message.attributes.append(&mut attributes);

    let route = handle.route();
    match route.del(message).execute().await {
        Ok(v) => {
            println!("Ok {:?}", v);
        }
        Err(v) => {
            println!("Err {:?}", v);
        }
    }
}
