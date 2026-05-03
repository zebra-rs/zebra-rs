// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::net::Ipv6Addr;

use anyhow::{Result, bail};
use isis_packet::srv6::EncapType;
use netlink_packet_route::route::{
    Ipv6SrHdr, RouteAttribute, RouteHeader, RouteLwEnCapType, RouteLwTunnelEncap,
    RouteSeg6IpTunnel, RouteSeg6LocalIpTunnel, Seg6IpTunnelEncap, Seg6IpTunnelMode,
    Seg6LocalAction, Seg6LocalFlavorOps, Seg6LocalFlavors, VecIpv6SrHdr,
};

use crate::rib::{SidBehavior, SidStructure};

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

// Route-message wrapper around build_seg6_lwtunnel for the embedded-encap
// fallback path used when the kernel doesn't support nexthop-table lwtunnel
// encap (use_nhid=false, kernels < 5.3). The Nhid path uses
// build_seg6_lwtunnel directly so it can wrap the encap as a NexthopAttribute.
pub fn build_seg6_attrs(
    segments: &[Ipv6Addr],
    encap_type: EncapType,
) -> Result<(RouteAttribute, RouteAttribute)> {
    let lwencap = build_seg6_lwtunnel(segments, encap_type)?;
    Ok((
        RouteAttribute::Encap(vec![lwencap]),
        RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
    ))
}

// Map a SidBehavior to its kernel SEG6_LOCAL_ACTION_*. uSID variants
// reuse the same kernel actions as their classic counterparts; the
// NEXT-C-SID flavor rides as a separate Flavors attribute. End.DT4 /
// End.DT6 today install without an explicit table-id arg — the
// kernel uses the route's own table, which is good enough for
// statically configured terminals; richer table selection is a
// follow-up.
fn seg6local_action(behavior: SidBehavior) -> Seg6LocalAction {
    match behavior {
        SidBehavior::End | SidBehavior::UN => Seg6LocalAction::End,
        SidBehavior::EndX | SidBehavior::UA => Seg6LocalAction::EndX,
        SidBehavior::EndDT4 => Seg6LocalAction::EndDt4,
        SidBehavior::EndDT6 => Seg6LocalAction::EndDt6,
    }
}

// Build the Flavors attribute for a uSID install. The kernel needs the
// NEXT-CSID operation flag plus the lblen / nflen parameters so it
// knows where to split the destination address when shifting the next
// uSID into position. Returns None for classic behaviors — they don't
// need a Flavors attribute at all.
fn build_seg6local_flavors(
    behavior: SidBehavior,
    structure: Option<SidStructure>,
) -> Option<RouteSeg6LocalIpTunnel> {
    if !matches!(behavior, SidBehavior::UN | SidBehavior::UA) {
        return None;
    }
    let s = structure?;
    // Nflen is the *node* portion of a uSID — the bits the kernel
    // shifts on each hop to expose the next uSID identifier. The
    // function bits belong to the uSID that's being consumed (they
    // pick the action), not to the next one's position, so they don't
    // count toward the shift width. Lblen is the shared block portion
    // that stays put.
    Some(RouteSeg6LocalIpTunnel::Flavors(vec![
        Seg6LocalFlavors::Operation(Seg6LocalFlavorOps::NextCsid),
        Seg6LocalFlavors::Lblen(s.lb_bits),
        Seg6LocalFlavors::Nflen(s.ln_bits),
    ]))
}

// Build the inner Vec<RouteLwTunnelEncap> for a seg6local install.
//
// End / uN needs only the Action attribute (uN additionally carries a
// Flavors block). End.X / uA also nests Nh6 (the IPv6 nexthop).
// End.DT4 / End.DT6 nest a VrfTable id — the kernel rejects the
// install with EINVAL otherwise. We default to RT_TABLE_MAIN since
// zebra-rs doesn't model VRFs yet; once it does, the operator-set
// table id flows through here. The kernel's required oif rides on
// the outer route / nexthop message rather than inside the encap,
// so we don't add it here.
//
// Returns None when the operator hasn't supplied the data End.X / uA
// needs (no IPv6 nexthop) — caller treats that as "skip FIB install
// for this SID; the registry row stays so the LSP advertisement is
// unaffected".
fn build_seg6local_lwtunnel(
    behavior: SidBehavior,
    nh6: Option<Ipv6Addr>,
    structure: Option<SidStructure>,
) -> Option<Vec<RouteLwTunnelEncap>> {
    let mut attrs: Vec<RouteSeg6LocalIpTunnel> =
        vec![RouteSeg6LocalIpTunnel::Action(seg6local_action(behavior))];
    if matches!(behavior, SidBehavior::EndX | SidBehavior::UA) {
        let nh = nh6?;
        attrs.push(RouteSeg6LocalIpTunnel::Nh6(nh));
    }
    if matches!(behavior, SidBehavior::EndDT4 | SidBehavior::EndDT6) {
        attrs.push(RouteSeg6LocalIpTunnel::VrfTable(
            RouteHeader::RT_TABLE_MAIN as u32,
        ));
    }
    if let Some(flavors) = build_seg6local_flavors(behavior, structure) {
        attrs.push(flavors);
    }
    Some(
        attrs
            .into_iter()
            .map(RouteLwTunnelEncap::Seg6Local)
            .collect(),
    )
}

// Build seg6local route-attribute pair (Encap + EncapType) for the
// embedded-encap route install path.
pub fn build_seg6local_attrs(
    behavior: SidBehavior,
    nh6: Option<Ipv6Addr>,
    structure: Option<SidStructure>,
) -> Option<(RouteAttribute, RouteAttribute)> {
    let encaps = build_seg6local_lwtunnel(behavior, nh6, structure)?;
    Some((
        RouteAttribute::Encap(encaps),
        RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
    ))
}

// (build_seg6local_nh_attrs removed: the kernel rejects seg6local
// lwtunnel encaps in the nexthop table, so we always embed the encap
// on the route message via build_seg6local_attrs.)
