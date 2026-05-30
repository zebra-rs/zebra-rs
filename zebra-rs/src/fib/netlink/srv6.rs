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
        SidBehavior::EndDT46 => Seg6LocalAction::EndDt46,
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
// End.DT4 / End.DT6 nest a Table id — `iproute2`'s `table N` keyword,
// `SEG6_LOCAL_TABLE` on the wire — telling the kernel which IPv4 /
// IPv6 fib to look up the decapsulated inner packet in. `table_id`
// of 0 means RT_TABLE_MAIN (the static / IS-IS default); a non-zero
// id (a VRF's kernel table) flows straight through. End.DT46 is the
// dual-family variant: it carries the table as `SEG6_LOCAL_VRFTABLE`
// (`iproute2`'s `vrftable N`) so the kernel resolves the inner v4 or
// v6 packet in the VRF — this is the per-VRF SID BGP L3VPN-over-SRv6
// programs. The kernel's required oif rides on the outer route /
// nexthop message rather than inside the encap, so we don't add it
// here.
//
// Returns None when the operator hasn't supplied the data End.X / uA
// needs (no IPv6 nexthop) — caller treats that as "skip FIB install
// for this SID; the registry row stays so the LSP advertisement is
// unaffected".
fn build_seg6local_lwtunnel(
    behavior: SidBehavior,
    nh6: Option<Ipv6Addr>,
    structure: Option<SidStructure>,
    table_id: u32,
) -> Option<Vec<RouteLwTunnelEncap>> {
    let mut attrs: Vec<RouteSeg6LocalIpTunnel> =
        vec![RouteSeg6LocalIpTunnel::Action(seg6local_action(behavior))];
    if matches!(behavior, SidBehavior::EndX | SidBehavior::UA) {
        let nh = nh6?;
        attrs.push(RouteSeg6LocalIpTunnel::Nh6(nh));
    }
    if matches!(behavior, SidBehavior::EndDT4 | SidBehavior::EndDT6) {
        // `SEG6_LOCAL_TABLE`: 0 maps to RT_TABLE_MAIN to preserve the
        // existing static / IS-IS terminal behavior.
        let table = if table_id == 0 {
            RouteHeader::RT_TABLE_MAIN as u32
        } else {
            table_id
        };
        attrs.push(RouteSeg6LocalIpTunnel::Table(table));
    }
    if matches!(behavior, SidBehavior::EndDT46) {
        // `SEG6_LOCAL_VRFTABLE`: the dual-family decap resolves the
        // inner packet in a VRF table, so it needs a real (non-MAIN)
        // table id — BGP passes the VRF's kernel table.
        attrs.push(RouteSeg6LocalIpTunnel::VrfTable(table_id));
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
// embedded-encap route install path. `table_id` selects the decap
// lookup table for the End.DT* behaviors (0 = RT_TABLE_MAIN); see
// `build_seg6local_lwtunnel`.
pub fn build_seg6local_attrs(
    behavior: SidBehavior,
    nh6: Option<Ipv6Addr>,
    structure: Option<SidStructure>,
    table_id: u32,
) -> Option<(RouteAttribute, RouteAttribute)> {
    let encaps = build_seg6local_lwtunnel(behavior, nh6, structure, table_id)?;
    Some((
        RouteAttribute::Encap(encaps),
        RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
    ))
}

// (build_seg6local_nh_attrs removed: the kernel rejects seg6local
// lwtunnel encaps in the nexthop table, so we always embed the encap
// on the route message via build_seg6local_attrs.)

#[cfg(test)]
mod tests {
    use super::*;

    fn table_attr(encaps: &[RouteLwTunnelEncap]) -> Option<u32> {
        encaps.iter().find_map(|e| match e {
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Table(t)) => Some(*t),
            _ => None,
        })
    }

    fn vrftable_attr(encaps: &[RouteLwTunnelEncap]) -> Option<u32> {
        encaps.iter().find_map(|e| match e {
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::VrfTable(t)) => Some(*t),
            _ => None,
        })
    }

    #[test]
    fn end_dt46_uses_vrftable_with_given_table() {
        // BGP L3VPN-over-SRv6: an End.DT46 SID decaps into the VRF's
        // kernel table via SEG6_LOCAL_VRFTABLE, never a plain table.
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndDT46, None, None, 100).expect("encap built");
        assert!(
            encaps.iter().any(|e| matches!(
                e,
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDt46
                ))
            )),
            "End.DT46 action present"
        );
        assert_eq!(vrftable_attr(&encaps), Some(100));
        assert_eq!(table_attr(&encaps), None, "no plain SEG6_LOCAL_TABLE");
    }

    #[test]
    fn end_dt6_table_zero_maps_to_main() {
        // table_id 0 must preserve the legacy static / IS-IS default.
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndDT6, None, None, 0).expect("encap built");
        assert_eq!(table_attr(&encaps), Some(RouteHeader::RT_TABLE_MAIN as u32));
        assert_eq!(vrftable_attr(&encaps), None);
    }

    #[test]
    fn end_dt4_honors_nonzero_table() {
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndDT4, None, None, 42).expect("encap built");
        assert_eq!(table_attr(&encaps), Some(42));
    }
}
