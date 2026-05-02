// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::net::Ipv6Addr;

use anyhow::{Context, Result, bail};
use ipnet::Ipv6Net;
use isis_packet::srv6::EncapType;
use netlink_packet_route::route::{
    Ipv6SrHdr, RouteAttribute, RouteLwEnCapType, RouteLwTunnelEncap, RouteSeg6IpTunnel,
    Seg6IpTunnelEncap, Seg6IpTunnelMode, VecIpv6SrHdr,
};
use rtnetlink::RouteMessageBuilder;

// Build the seg6 lwtunnel encap for an SRv6 H.Encap policy. Callers wrap the
// returned encap in either RouteAttribute::Encap (for embedded route-message
// encap) or NexthopAttribute::Encap (for nexthop-table entries).
//
// HEncap carries every segment in the SRH. HEncapRed (RFC 8986 §5.2) drops
// the first segment from the SRH because the kernel's outer IPv6 destination
// already encodes it; the remaining segments must be non-empty. Other
// EncapType variants are rejected here so callers surface a useful error
// instead of silently flattening behavior.
pub fn build_seg6_lwtunnel(
    segments: &[Ipv6Addr],
    encap_type: EncapType,
) -> Result<RouteLwTunnelEncap> {
    if segments.is_empty() {
        bail!("SRv6 encap requires at least one segment");
    }
    let sr_segments: Vec<Ipv6Addr> = match encap_type {
        EncapType::HEncap => segments.to_vec(),
        EncapType::HEncapRed => {
            if segments.len() < 2 {
                bail!("H.Encap.Red requires at least two segments");
            }
            segments[1..].to_vec()
        }
        other => bail!("unsupported SRv6 encap type: {other}"),
    };

    let n = sr_segments.len() as u8;
    let ipv6_sr_hdr = Ipv6SrHdr {
        nexthdr: 0,
        hdrlen: n.saturating_mul(2),
        typ: 4,
        segments_left: n - 1,
        first_segment: n - 1,
        flags: 0,
        tag: 0,
        segments: sr_segments,
        ..Default::default()
    };
    let seg6 = Seg6IpTunnelEncap {
        mode: Seg6IpTunnelMode::Encap,
        ipv6_sr_hdr: VecIpv6SrHdr(vec![ipv6_sr_hdr]),
    };
    Ok(RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6IpTunnel(
        seg6,
    )))
}

// Route-message wrapper around build_seg6_lwtunnel. Used by the embedded-encap
// fallback path (use_nhid=false) and by srv6_encap_add. PR 4 will retire this
// once the route-level bypass is replaced by Nhid references.
fn build_seg6_attrs(
    segments: &[Ipv6Addr],
    encap_type: EncapType,
) -> Result<(RouteAttribute, RouteAttribute)> {
    let lwencap = build_seg6_lwtunnel(segments, encap_type)?;
    Ok((
        RouteAttribute::Encap(vec![lwencap]),
        RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
    ))
}

pub async fn srv6_encap_add(
    handle: &rtnetlink::Handle,
    prefix: &Ipv6Net,
    segments: &[Ipv6Addr],
    encap_type: EncapType,
    ifindex: u32,
) -> Result<()> {
    let (encap, encap_type_attr) = build_seg6_attrs(segments, encap_type)?;
    let mut message = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(prefix.addr(), prefix.prefix_len())
        .build();
    if ifindex != 0 {
        message.attributes.push(RouteAttribute::Oif(ifindex));
    }
    message.attributes.push(encap);
    message.attributes.push(encap_type_attr);

    handle
        .route()
        .add(message)
        .execute()
        .await
        .context("netlink seg6 encap add")
}

pub async fn srv6_encap_del(handle: &rtnetlink::Handle, prefix: &Ipv6Net) -> Result<()> {
    let message = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(prefix.addr(), prefix.prefix_len())
        .build();
    handle
        .route()
        .del(message)
        .execute()
        .await
        .context("netlink seg6 encap del")
}
