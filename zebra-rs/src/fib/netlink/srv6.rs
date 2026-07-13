use std::net::{Ipv4Addr, Ipv6Addr};

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
// already encodes it; the remaining segments must be non-empty. HInsert
// (kernel `mode inline`) inserts the SRH into the existing IPv6 packet with
// the original destination as the final segment — see build_srh_inline.
// Other EncapType variants are rejected here so callers surface a useful
// error instead of silently flattening behavior.
pub fn build_seg6_lwtunnel(
    segments: &[Ipv6Addr],
    encap_type: EncapType,
) -> Result<RouteLwTunnelEncap> {
    if segments.is_empty() {
        bail!("SRv6 encap requires at least one segment");
    }
    let (mode, ipv6_sr_hdr) = match encap_type {
        EncapType::HEncap => (Seg6IpTunnelMode::Encap, build_srh(segments)),
        EncapType::HEncapRed => {
            if segments.len() < 2 {
                bail!("H.Encap.Red requires at least two segments");
            }
            (Seg6IpTunnelMode::Encap, build_srh(&segments[1..]))
        }
        EncapType::HInsert => (Seg6IpTunnelMode::Inline, build_srh_inline(segments)),
        other => bail!("unsupported SRv6 encap type: {other}"),
    };

    let seg6 = Seg6IpTunnelEncap {
        mode,
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

// Build the tunnel-info SRH for the inline (H.Insert) mode. The kernel
// inserts this SRH into the existing IPv6 packet and overwrites
// segments[0] with the packet's original destination, so the wire
// layout is
//   segments = [orig-DA placeholder, s_n, ..., s_1]
//   segments_left = first_segment = n
// (the active segment indexes from the top, so the initial destination
// rewrite lands on s_1, and the original destination becomes the final
// segment). `segments` arrives in forwarding order (s_1 first).
fn build_srh_inline(segments: &[Ipv6Addr]) -> Ipv6SrHdr {
    let n = segments.len() as u8;
    let mut segs: Vec<Ipv6Addr> = Vec::with_capacity(segments.len() + 1);
    segs.push(Ipv6Addr::UNSPECIFIED);
    segs.extend(segments.iter().rev().copied());
    Ipv6SrHdr {
        nexthdr: 0,
        hdrlen: (n + 1).saturating_mul(2),
        typ: 4,
        segments_left: n,
        first_segment: n,
        flags: 0,
        tag: 0,
        segments: segs,
        ..Default::default()
    }
}

// Build the SRH (`Ipv6SrHdr`) carrying `segments` in forwarding order,
// shared by the H.Encap encap path and the End.B6.Encaps seg6local
// push. `segments` must be non-empty (callers guarantee it).
fn build_srh(segments: &[Ipv6Addr]) -> Ipv6SrHdr {
    let n = segments.len() as u8;
    Ipv6SrHdr {
        nexthdr: 0,
        hdrlen: n.saturating_mul(2),
        typ: 4,
        segments_left: n - 1,
        first_segment: n - 1,
        flags: 0,
        tag: 0,
        segments: segments.to_vec(),
        ..Default::default()
    }
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
        // End.T has a native kernel action (+ SEG6_LOCAL_TABLE). uT never
        // reaches the kernel (no NEXT-CSID composition with End.T exists;
        // route_sid_install returns after the cradle tee) — map like the
        // other cradle-only behaviors so a stray call is a visible no-op.
        SidBehavior::EndT => Seg6LocalAction::EndT,
        SidBehavior::UT => Seg6LocalAction::End,
        SidBehavior::EndDX4 => Seg6LocalAction::EndDx4,
        SidBehavior::EndDX6 => Seg6LocalAction::EndDx6,
        // EVPN L2 SIDs never reach the kernel (route_sid_install returns
        // after the cradle tee — no End.DT2U/DT2M/DX2/DX2V seg6local action
        // exists); map to End so an unexpected call is a visible no-op
        // rather than a panic.
        SidBehavior::EndDT2U
        | SidBehavior::EndDT2M
        | SidBehavior::EndDX2
        | SidBehavior::EndDX2V
        // End.Replicate is cradle-tee-only (RFC 9524 SR-P2MP; no kernel
        // seg6local action) — map to End so a stray call is a visible no-op.
        | SidBehavior::EndReplicate => Seg6LocalAction::End,
        SidBehavior::EndX | SidBehavior::UA | SidBehavior::UALib => Seg6LocalAction::EndX,
        // REPLACE-C-SID never reaches the kernel (route_sid_install
        // returns after the cradle tee — no kernel flavor op exists);
        // map like DT2U/DT2M so an unexpected call is a visible no-op.
        SidBehavior::EndRep => Seg6LocalAction::End,
        SidBehavior::EndXRep => Seg6LocalAction::EndX,
        SidBehavior::EndDT4 => Seg6LocalAction::EndDt4,
        // End.M reuses the End.DT6 kernel action: decapsulate and look the
        // inner IPv6 packet up in a table — for End.M that is the
        // mirror-context table (`Sid::table_id`) rather than a VRF.
        SidBehavior::EndDT6 | SidBehavior::EndM => Seg6LocalAction::EndDt6,
        SidBehavior::EndDT46 => Seg6LocalAction::EndDt46,
        SidBehavior::EndB6Encap => Seg6LocalAction::EndB6Encap,
    }
}

// Build the Flavors attribute for a uSID install. The kernel needs the
// NEXT-CSID operation flag plus the lblen / nflen parameters so it
// knows where to split the destination address when shifting the next
// uSID into position. Returns None for classic behaviors — they don't
// need a Flavors attribute at all.
//
// Only uN gets the flavor. uN is a *prefix* install (LB+LN), so a uSID
// carrier with more bits after the node id legitimately matches it and
// must shift; a carrier whose argument is exhausted falls back to
// classic End, which also processes a full-SID SRH hop correctly. uA
// installs at /128 — only the exact B:N:F address can match, so there
// is never a next uSID to shift into position. Worse, NEXT-CSID with
// nflen covering only the node bits makes the kernel read the uA's
// *function* bits as a pending argument and "shift" the DA into the
// garbage address LB:F:: instead of running End.X — so a uA referenced
// as a full SID from an SRH (e.g. a TI-LFA repair list) blackholes.
// Classic End.X is the correct kernel programming for a /128 full-SID
// install.
fn build_seg6local_flavors(
    behavior: SidBehavior,
    structure: Option<SidStructure>,
    flavors: u8,
) -> Option<RouteSeg6LocalIpTunnel> {
    // `SEG6_LOCAL_FLV_OPERATION` is ONE u32 NLA carrying an OR'd bitmask
    // of operations — composing NEXT-CSID with PSP/USP/USD means one
    // `Operation` attribute holding the combined mask (`Other`), never two.
    let mut flavor_mask = 0u32;
    if flavors & crate::rib::FLAVOR_PSP != 0 {
        flavor_mask |= u32::from(Seg6LocalFlavorOps::Psp);
    }
    if flavors & crate::rib::FLAVOR_USP != 0 {
        flavor_mask |= u32::from(Seg6LocalFlavorOps::Usp);
    }
    if flavors & crate::rib::FLAVOR_USD != 0 {
        flavor_mask |= u32::from(Seg6LocalFlavorOps::Usd);
    }

    // Nflen is the width of the uSID identifier being consumed at this
    // entry — the bits the kernel shifts out to expose the next uSID.
    // Lblen is the shared block portion that stays put. For uN that
    // identifier is the locator-node id (LN); for the LIB twin of a uA
    // it is the function. The remaining bits to the right are the
    // carrier's pending uSIDs.
    let nflen = match behavior {
        SidBehavior::UN => structure?.ln_bits,
        SidBehavior::UALib => structure?.fun_bits,
        _ => {
            // Classic End / End.X: a flavor-only Operation attribute (the
            // kernel supports PSP on End from ~6.6; unsupported combos
            // fail the install, which the caller logs non-fatally).
            if flavor_mask == 0 {
                return None;
            }
            return Some(RouteSeg6LocalIpTunnel::Flavors(vec![
                Seg6LocalFlavors::Operation(Seg6LocalFlavorOps::Other(flavor_mask)),
            ]));
        }
    };
    let s = structure?;
    let op = if flavor_mask == 0 {
        Seg6LocalFlavorOps::NextCsid
    } else {
        Seg6LocalFlavorOps::Other(u32::from(Seg6LocalFlavorOps::NextCsid) | flavor_mask)
    };
    Some(RouteSeg6LocalIpTunnel::Flavors(vec![
        Seg6LocalFlavors::Operation(op),
        Seg6LocalFlavors::Lblen(s.lb_bits),
        Seg6LocalFlavors::Nflen(nflen),
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
    nh4: Option<Ipv4Addr>,
    structure: Option<SidStructure>,
    table_id: u32,
    segs: &[Ipv6Addr],
    flavors: u8,
) -> Option<Vec<RouteLwTunnelEncap>> {
    let mut attrs: Vec<RouteSeg6LocalIpTunnel> =
        vec![RouteSeg6LocalIpTunnel::Action(seg6local_action(behavior))];
    if matches!(
        behavior,
        SidBehavior::EndX | SidBehavior::UA | SidBehavior::UALib | SidBehavior::EndDX6
    ) {
        let nh = nh6?;
        attrs.push(RouteSeg6LocalIpTunnel::Nh6(nh));
    }
    if matches!(behavior, SidBehavior::EndDX4) {
        // `SEG6_LOCAL_NH4`: the IPv4 cross-connect adjacency. Missing →
        // skip the FIB install (the registry row is harmless).
        let nh = nh4?;
        attrs.push(RouteSeg6LocalIpTunnel::Nh4(nh));
    }
    if matches!(behavior, SidBehavior::EndB6Encap) {
        // `SEG6_LOCAL_SRH`: the SR Policy segment list this Binding SID
        // encapsulates onto. No segments → nothing to push, so skip the
        // FIB install (the registry row is harmless).
        if segs.is_empty() {
            return None;
        }
        attrs.push(RouteSeg6LocalIpTunnel::Srh(build_srh(segs)));
    }
    if matches!(
        behavior,
        SidBehavior::EndDT4 | SidBehavior::EndDT6 | SidBehavior::EndM | SidBehavior::EndT
    ) {
        // `SEG6_LOCAL_TABLE`: 0 maps to RT_TABLE_MAIN to preserve the
        // existing static / IS-IS terminal behavior. End.M passes the
        // mirror-context table id, which is always non-zero.
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
    if let Some(flavors) = build_seg6local_flavors(behavior, structure, flavors) {
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
    nh4: Option<Ipv4Addr>,
    structure: Option<SidStructure>,
    table_id: u32,
    segs: &[Ipv6Addr],
    flavors: u8,
) -> Option<(RouteAttribute, RouteAttribute)> {
    let encaps = build_seg6local_lwtunnel(behavior, nh6, nh4, structure, table_id, segs, flavors)?;
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
        let encaps = build_seg6local_lwtunnel(SidBehavior::EndDT46, None, None, None, 100, &[], 0)
            .expect("encap built");
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
        let encaps = build_seg6local_lwtunnel(SidBehavior::EndDT6, None, None, None, 0, &[], 0)
            .expect("encap built");
        assert_eq!(table_attr(&encaps), Some(RouteHeader::RT_TABLE_MAIN as u32));
        assert_eq!(vrftable_attr(&encaps), None);
    }

    #[test]
    fn end_dt4_honors_nonzero_table() {
        let encaps = build_seg6local_lwtunnel(SidBehavior::EndDT4, None, None, None, 42, &[], 0)
            .expect("encap built");
        assert_eq!(table_attr(&encaps), Some(42));
    }

    #[test]
    fn end_m_decaps_via_mirror_context_table() {
        // End.M (egress protection): reuses the End.DT6 kernel action and
        // looks the inner packet up in the mirror-context table via a
        // plain SEG6_LOCAL_TABLE — never a VRF table.
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndM, None, None, None, 0x4D00_0000, &[], 0)
                .expect("encap built");
        assert!(
            encaps.iter().any(|e| matches!(
                e,
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDt6
                ))
            )),
            "End.M uses the End.DT6 kernel action"
        );
        assert_eq!(table_attr(&encaps), Some(0x4D00_0000));
        assert_eq!(vrftable_attr(&encaps), None, "no VRF table for End.M");
    }

    #[test]
    fn end_b6_encaps_pushes_srh_segment_list() {
        // SR Policy Binding SID: End.B6.Encaps carries the policy's
        // segment list as a SEG6_LOCAL_SRH attribute.
        let segs = vec!["fc00:0:2::".parse().unwrap(), "fc00:0:9::".parse().unwrap()];
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndB6Encap, None, None, None, 0, &segs, 0)
                .expect("encap built");
        assert!(encaps.iter().any(|e| matches!(
            e,
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                Seg6LocalAction::EndB6Encap
            ))
        )));
        let srh = encaps.iter().find_map(|e| match e {
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Srh(h)) => Some(h),
            _ => None,
        });
        assert_eq!(srh.expect("SRH present").segments, segs);
    }

    #[test]
    fn end_b6_encaps_without_segments_skips_install() {
        // No segment list → no SRH to push → skip the FIB install.
        assert!(
            build_seg6local_lwtunnel(SidBehavior::EndB6Encap, None, None, None, 0, &[], 0)
                .is_none()
        );
    }

    #[test]
    fn end_dx6_pushes_nh6_adjacency() {
        // End.DX6 (RFC 8986 §4.4): decap + v6 cross-connect — the
        // adjacency rides as SEG6_LOCAL_NH6; without one there is
        // nothing to cross-connect to, so the install is skipped.
        let nh6: Ipv6Addr = "fc00:0:2::1".parse().unwrap();
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndDX6, Some(nh6), None, None, 0, &[], 0)
                .expect("encap built");
        assert!(encaps.iter().any(|e| matches!(
            e,
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(Seg6LocalAction::EndDx6))
        )));
        assert!(encaps.iter().any(
            |e| matches!(e, RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Nh6(a)) if *a == nh6)
        ));
        assert!(
            build_seg6local_lwtunnel(SidBehavior::EndDX6, None, None, None, 0, &[], 0).is_none()
        );
    }

    #[test]
    fn end_dx4_pushes_nh4_adjacency() {
        // End.DX4 (RFC 8986 §4.5): the IPv4 sibling — SEG6_LOCAL_NH4.
        let nh4: Ipv4Addr = "10.0.2.1".parse().unwrap();
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::EndDX4, None, Some(nh4), None, 0, &[], 0)
                .expect("encap built");
        assert!(encaps.iter().any(|e| matches!(
            e,
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(Seg6LocalAction::EndDx4))
        )));
        assert!(encaps.iter().any(
            |e| matches!(e, RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Nh4(a)) if *a == nh4)
        ));
        assert!(
            build_seg6local_lwtunnel(SidBehavior::EndDX4, None, None, None, 0, &[], 0).is_none()
        );
    }

    #[test]
    fn h_insert_builds_inline_srh_with_orig_da_placeholder() {
        // TI-LFA repair: forwarding-order [s1, s2] must become the wire
        // layout [::, s2, s1] with SL = first_segment = 2 — the kernel
        // overwrites segments[0] with the packet's original destination
        // and starts at s1.
        let s1: Ipv6Addr = "fcbb:bbbb:2::".parse().unwrap();
        let s2: Ipv6Addr = "fcbb:bbbb:2:e000::".parse().unwrap();
        let encap = build_seg6_lwtunnel(&[s1, s2], EncapType::HInsert).expect("encap built");
        let RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6IpTunnel(seg6)) = encap else {
            panic!("expected seg6 iptunnel encap");
        };
        assert_eq!(seg6.mode, Seg6IpTunnelMode::Inline);
        let srh = &seg6.ipv6_sr_hdr.0[0];
        assert_eq!(srh.segments, vec![Ipv6Addr::UNSPECIFIED, s2, s1]);
        assert_eq!(srh.segments_left, 2);
        assert_eq!(srh.first_segment, 2);
        assert_eq!(srh.hdrlen, 6);
    }

    #[test]
    fn ua_installs_classic_end_x_without_flavors() {
        // A uA is a /128 full-SID install: NEXT-CSID would misread the
        // function bits as a shift argument and forward to LB:F::
        // instead of running End.X, so the flavor must be omitted.
        let nh6: Ipv6Addr = "fe80::2".parse().unwrap();
        let structure = Some(SidStructure {
            lb_bits: 32,
            ln_bits: 16,
            fun_bits: 16,
            arg_bits: 64,
        });
        let encaps =
            build_seg6local_lwtunnel(SidBehavior::UA, Some(nh6), None, structure, 0, &[], 0)
                .expect("encap built");
        assert!(
            !encaps.iter().any(|e| matches!(
                e,
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Flavors(_))
            )),
            "uA must not carry a NEXT-CSID Flavors attribute"
        );
        assert!(encaps.iter().any(|e| matches!(
            e,
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(Seg6LocalAction::EndX))
        )));

        // uN keeps the flavor — it is a prefix install where carriers
        // with a remaining argument legitimately shift.
        let encaps = build_seg6local_lwtunnel(SidBehavior::UN, None, None, structure, 0, &[], 0)
            .expect("encap built");
        assert!(encaps.iter().any(|e| matches!(
            e,
            RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Flavors(_))
        )));
    }
}
