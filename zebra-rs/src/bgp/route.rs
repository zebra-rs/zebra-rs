use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};

use crate::bgp::timer::{start_adv_timer_evpn, start_stale_timer};
use crate::policy::{AsPathPrependConfig, CommunityMatcher, PolicyList, StandardMatcher};
use crate::rib::tracing::fib_l2_fdb;
use crate::rib::{self, MacAddr, api::FdbEntry};
use crate::{bgp_adj_in_trace, bgp_adj_out_trace};

use super::cap::CapAfiMap;
use super::peer::{AllowAsIn, BgpTop, Event, Peer, PeerType};
use super::peer_map::PeerMap;
use super::shard::msg::{ShardUpdateV4, ShardUpdateV6};
use super::shard::{ShardMsg, ShardOut};
use super::timer::{start_adv_timer_vpnv4, start_adv_timer_vpnv6};
use super::{Bgp, InOut, Message};

pub const ORIGINATED_PEER: usize = usize::MAX;

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub enum BgpRibType {
    IBGP,
    EBGP,
    Originated,
}

impl BgpRibType {
    pub fn is_originated(&self) -> bool {
        *self == BgpRibType::Originated
    }
}

/// RFC 4271 inbound AS_PATH loop check, relaxed per-neighbor by
/// `allowas-in` (zebra-bgp-allowas-in.yang). Returns `true` when the
/// update must be dropped because the local AS appears in the AS_PATH
/// more often than the neighbor's `allowas-in` setting permits.
///
/// * `None` — strict RFC 4271: any occurrence is a loop.
/// * `Count(n)` — accept while the local AS appears at most `n` times.
/// * `Origin` — accept only when every occurrence of the local AS is the
///   originating (right-most) AS; a local AS in any transit position is
///   still a loop.
fn aspath_local_as_loop(aspath: &As4Path, local_as: u32, allow: Option<AllowAsIn>) -> bool {
    let occurrences = aspath
        .segs
        .iter()
        .flat_map(|seg| seg.asn.iter())
        .filter(|asn| **asn == local_as)
        .count();
    if occurrences == 0 {
        return false;
    }
    match allow {
        None => true,
        Some(AllowAsIn::Count(max)) => occurrences > max as usize,
        Some(AllowAsIn::Origin) => !local_as_only_at_origin(aspath, local_as),
    }
}

/// RFC 4271 inbound AS_PATH loop detection for `peer`, covering both
/// the router's own AS and — when a `local-as` substitute is active on
/// the session — the substitute AS (FRR's "AS path local-as loop
/// check" in `bgp_update`, bgp_route.c). Returns `true` when the
/// update must be dropped.
///
/// The substitute check's occurrence budget mirrors FRR: a configured
/// `allowas-in` count replaces it; otherwise it is 1 while the ingress
/// prepend is on (the prepend in [`route_from_peer`] put exactly one
/// occurrence there) and 0 under `no-prepend`. One deliberate
/// divergence: with `allowas-in origin` and the ingress prepend both
/// active, FRR's budget of 0 drops every route from the peer (our own
/// leftmost prepend can never be at the origin); the substitute check
/// is skipped instead.
fn aspath_own_as_loop(peer: &Peer, aspath: &As4Path) -> bool {
    if aspath_local_as_loop(aspath, peer.local_as, peer.config.allowas_in) {
        return true;
    }
    let Some(substitute) = peer.change_local_as() else {
        return false;
    };
    let no_prepend = peer.config.local_as.is_some_and(|la| la.no_prepend);
    let allow = match peer.config.allowas_in {
        // FRR parity: a configured allowas-in budget replaces the
        // prepend allowance (the ingress prepend counts against it).
        Some(AllowAsIn::Count(n)) => Some(AllowAsIn::Count(n)),
        Some(AllowAsIn::Origin) if !no_prepend => return false,
        Some(AllowAsIn::Origin) => Some(AllowAsIn::Origin),
        // The ingress prepend itself put one occurrence in the path.
        None if !no_prepend => Some(AllowAsIn::Count(1)),
        None => None,
    };
    aspath_local_as_loop(aspath, substitute, allow)
}

/// True when every occurrence of `local_as` is the trailing originating
/// AS (prepends at the origin are allowed) — i.e. it never appears as a
/// transit AS. Used by [`AllowAsIn::Origin`].
fn local_as_only_at_origin(aspath: &As4Path, local_as: u32) -> bool {
    let flat: Vec<u32> = aspath
        .segs
        .iter()
        .flat_map(|seg| seg.asn.iter().copied())
        .collect();
    // The origin is the right-most ASN; it must be the local AS.
    if flat.last() != Some(&local_as) {
        return false;
    }
    // Skip the trailing run of local-AS prepends; the remaining prefix
    // must not contain the local AS anywhere else.
    let trailing = flat.iter().rev().take_while(|&&a| a == local_as).count();
    !flat[..flat.len() - trailing].contains(&local_as)
}

/// FRR-style `enforce-first-as` (zebra-bgp-enforce-first-as.yang) inbound
/// check. Returns `true` when the UPDATE must be dropped because the
/// neighbor is eBGP, has `enforce-first-as` enabled, and the left-most
/// AS_PATH segment is not an `AS_SEQUENCE` whose first ASN is the
/// neighbor's own AS (`peer.remote_as`).
///
/// Always `false` for iBGP peers and when the knob is off — iBGP never
/// prepends, so it has no first-AS guarantee to enforce.
fn aspath_enforce_first_as_violation(peer: &Peer, aspath: Option<&As4Path>) -> bool {
    if !peer.config.enforce_first_as || !peer.is_ebgp() {
        return false;
    }
    aspath_first_as_mismatch(aspath, peer.remote_as)
}

/// True when `aspath`'s left-most segment is not an `AS_SEQUENCE` whose
/// first ASN is `expected_as`. The pure core of
/// [`aspath_enforce_first_as_violation`], mirroring FRR's
/// `aspath_firstas_check`: an absent/empty AS_PATH, a leading `AS_SET`
/// (or confederation segment), or a leading `AS_SEQUENCE` whose first ASN
/// is not `expected_as` all count as a mismatch. Unit-tested directly,
/// independent of `Peer` construction.
fn aspath_first_as_mismatch(aspath: Option<&As4Path>, expected_as: u32) -> bool {
    match aspath.and_then(|path| path.segs.front()) {
        Some(seg) => seg.typ != AS_SEQ || seg.asn.first() != Some(&expected_as),
        None => true,
    }
}

/// Apply the egress AS_PATH transformation for an eBGP announcement to
/// `peer`. Three stages run in FRR's order, all *before* the local-AS
/// prepend (iBGP peers and routes without an AS_PATH are left
/// untouched):
///
/// 1. `remove-private-as`: strip (or, with `replace-as`, rewrite to the
///    local AS) private ASNs. The bare form only fires when the whole
///    path is private; `all` fires on any path. The neighbor's own AS is
///    always kept for loop prevention. Mirrors FRR's
///    `bgp_peer_remove_private_as`.
/// 2. `as-override`: replace the peer's own AS with the local AS so its
///    RFC 4271 loop check accepts a route that transited its AS. Mirrors
///    FRR's `bgp_peer_as_override`, which runs after remove-private-as.
/// 3. the mandatory local-AS prepend. With a `local-as` substitute
///    active on the session, the real AS is prepended first and the
///    substitute on top of it (the receiver sees `substitute, real, …`);
///    `replace-as` skips the real AS so only the substitute appears.
///    Mirrors FRR's `bgp_packet_attribute` (bgp_attr.c).
///
/// Call this at every eBGP egress site instead of prepending inline, so
/// the transforms apply uniformly across address families.
fn ebgp_egress_aspath(peer: &Peer, attrs: &mut BgpAttr) {
    if !peer.is_ebgp() {
        return;
    }
    let Some(aspath) = attrs.aspath.as_mut() else {
        return;
    };
    if let Some(rpa) = peer.config.remove_private_as {
        // Bare form acts only on an all-private path; `all` acts on any.
        if rpa.all || aspath.is_all_private() {
            if rpa.replace_as {
                aspath.replace_private_as_mut(peer.local_as, peer.remote_as);
            } else {
                aspath.remove_private_as_mut(peer.remote_as);
            }
        }
    }
    if peer.config.as_override {
        aspath.replace_as_mut(peer.remote_as, peer.local_as);
    }
    match peer.change_local_as() {
        Some(substitute) => {
            let replace_as = peer.config.local_as.is_some_and(|la| la.replace_as);
            if !replace_as {
                aspath.prepend_mut(As4Path::from(vec![peer.local_as]));
            }
            aspath.prepend_mut(As4Path::from(vec![substitute]));
        }
        None => aspath.prepend_mut(As4Path::from(vec![peer.local_as])),
    }
}

/// Build a `rib::entry::RibEntry` from the BGP best-path winner for an
/// IPv4 unicast prefix. Returns `None` when the BGP route has no
/// installable next-hop — VPNv4 / EVPN have their own install paths,
/// and a 0.0.0.0 next-hop (originated routes that never got a self
/// next-hop rewrite) shouldn't reach the kernel FIB.
///
/// When the route was received via RFC 8950 ENHE (MP_REACH with an
/// IPv6 next-hop for an IPv4 prefix), the kernel install programs the
/// v6 link-local as the gateway, pinned to the receiving interface
/// (`via inet6 fe80::.. dev N`, RFC 5549 style — the kernel resolves
/// the MAC through ND). The v4 NEXT_HOP attribute (which RFC 8950 §4
/// says the receiver MUST ignore) is irrelevant. `ifindex_origin`
/// makes the RIB resolver accept the nexthop as-is — a link-local
/// can't be disambiguated by table walk anyway.
fn make_bgp_rib_entry_v4(best: &BgpRib) -> Option<rib::entry::RibEntry> {
    // Administrative distance per Cisco / FRR convention. eBGP=20,
    // iBGP=200; originated paths take the iBGP value since they're
    // local-precedence work and we don't currently expose a knob.
    let distance = match best.typ {
        BgpRibType::EBGP => 20,
        BgpRibType::IBGP | BgpRibType::Originated => 200,
    };
    let metric = best.attr.med.as_ref().map(|m| m.med).unwrap_or(0);

    let nexthop = if let Some((nh6, ifindex)) = best.enhe_egress {
        rib::Nexthop::Uni(rib::NexthopUni {
            addr: IpAddr::V6(nh6),
            metric,
            weight: 1,
            valid: true,
            ifindex_origin: Some(ifindex),
            ..Default::default()
        })
    } else {
        let nh = match best.attr.nexthop.as_ref()? {
            BgpNexthop::Ipv4(addr) => *addr,
            // VPNv4 / EVPN nexthops are handled by their own per-AFI
            // install paths; the plain v4 Loc-RIB shouldn't be carrying
            // them but be defensive.
            _ => return None,
        };
        if nh.is_unspecified() {
            return None;
        }
        rib::Nexthop::Uni(rib::NexthopUni {
            addr: IpAddr::V4(nh),
            metric,
            weight: 1,
            valid: true,
            ..Default::default()
        })
    };

    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = distance;
    entry.metric = metric;
    entry.valid = true;
    entry.nexthop = nexthop;
    Some(entry)
}

/// Build the VRF FIB entry for an imported VPN route. The label stack
/// is transport-labels (outer, from the resolved egress) with the VPN
/// service `service_label` pushed innermost (bottom of stack) — the
/// order the netlink encoder treats as top-of-stack-first. One
/// `NexthopUni` per resolved egress (`Multi` for transport ECMP),
/// installed as a `Bgp` route at iBGP administrative distance (imported
/// VPN routes arrive via MP-iBGP). Address-family-agnostic: the egress
/// `addr` is v4 for VPNv4 and v6 for VPNv6.
///
/// Returns `None` when there's no resolved transport — nothing is
/// installable and the caller withdraws instead. The label-less
/// baseline (`labels` empty, `service_label == 0`) yields a bare
/// `via addr dev ifindex`.
fn build_vpn_fib_entry(
    service_label: u32,
    transport: &[rib::nht::ResolvedNexthop],
) -> Option<rib::entry::RibEntry> {
    if transport.is_empty() {
        return None;
    }
    let mk_uni = |egress: &rib::nht::ResolvedNexthop| {
        let mut labels: Vec<rib::Label> = egress
            .labels
            .iter()
            .copied()
            .map(rib::Label::Explicit)
            .collect();
        if service_label != 0 {
            labels.push(rib::Label::Explicit(service_label));
        }
        let mut uni = rib::NexthopUni::new(egress.addr, 0, labels);
        if egress.ifindex != 0 {
            uni.ifindex_origin = Some(egress.ifindex);
        }
        uni.valid = true;
        uni
    };
    let nexthop = if transport.len() == 1 {
        rib::Nexthop::Uni(mk_uni(&transport[0]))
    } else {
        let mut multi = rib::NexthopMulti::default();
        for egress in transport {
            multi.nexthops.push(mk_uni(egress));
        }
        rib::Nexthop::Multi(multi)
    };
    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = 200;
    entry.metric = 0;
    entry.valid = true;
    entry.nexthop = nexthop;
    Some(entry)
}

/// Build the VRF FIB entry for an imported SRv6 L3VPN route (RFC 9252).
/// The remote PE's End.DT46 `sid` is the single SRv6 segment: the kernel
/// H.Encaps matched traffic (outer IPv6 destination = the SID, SRH =
/// `[sid]`) and L2-forwards the encapped packet to the resolved on-link
/// underlay next-hop, which routes it on toward the SID's locator. One
/// `NexthopUni` per resolved underlay egress (`Multi` for ECMP), where
/// `addr` / `ifindex_origin` are the underlay next-hop and egress link
/// (exactly like [`build_vpn_fib_entry`]) and `segs` carries the SID for
/// the seg6 encap.
///
/// Returns `None` when the underlay next-hop hasn't resolved — nothing
/// is installable and the caller withdraws instead. This is the SRv6
/// analogue of [`build_vpn_fib_entry`]; the SID + seg6 encap replace the
/// `{transport,service}` MPLS label stack.
fn build_srv6_vpn_fib_entry(
    sid: std::net::Ipv6Addr,
    transport: &[rib::nht::ResolvedNexthop],
) -> Option<rib::entry::RibEntry> {
    if transport.is_empty() {
        return None;
    }
    let mk_uni = |egress: &rib::nht::ResolvedNexthop| {
        // `via egress.addr dev egress.ifindex encap seg6 segs [sid]`:
        // the on-link underlay next-hop carries the packet, the seg6
        // encap sets the outer IPv6 DA + SRH to the SID.
        let mut uni = rib::NexthopUni::new(egress.addr, 0, Vec::new());
        uni.segs = vec![sid];
        uni.encap_type = Some(isis_packet::srv6::EncapType::HEncap);
        if egress.ifindex != 0 {
            uni.ifindex_origin = Some(egress.ifindex);
        }
        uni.valid = true;
        uni
    };
    let nexthop = if transport.len() == 1 {
        rib::Nexthop::Uni(mk_uni(&transport[0]))
    } else {
        let mut multi = rib::NexthopMulti::default();
        for egress in transport {
            multi.nexthops.push(mk_uni(egress));
        }
        rib::Nexthop::Multi(multi)
    };
    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = 200;
    entry.metric = 0;
    entry.valid = true;
    entry.nexthop = nexthop;
    Some(entry)
}

/// Whether `best` should install as a labelled VPN tunnel entry: an
/// imported route (`Originated`) for which the VRF holds a resolved
/// `transport`. `transport` is `None` outside a VRF (global instance),
/// so this is always `false` there.
fn is_vpn_fib_winner(best: &BgpRib, transport: Option<&[rib::nht::ResolvedNexthop]>) -> bool {
    best.typ == BgpRibType::Originated && transport.is_some_and(|t| !t.is_empty())
}

/// Choose the IPv4 FIB entry for a best-path winner in a (possibly VRF)
/// context. An imported VPN winner installs the `{transport,service}`
/// labelled tunnel entry; a CE-learned / locally-originated / global
/// route installs the plain next-hop entry. `transport` is `None`
/// outside a VRF, so this reduces to `make_bgp_rib_entry_v4`.
fn select_fib_entry_v4(
    best: &BgpRib,
    transport: Option<&[rib::nht::ResolvedNexthop]>,
) -> Option<rib::entry::RibEntry> {
    // SRv6 L3VPN: an imported route carrying an SRv6 L3 Service SID
    // installs an H.Encap entry toward that SID instead of an MPLS
    // label stack — gated on the underlay next-hop resolving, like the
    // MPLS path. CE-learned routes carry no Prefix-SID, so this never
    // fires for them.
    if best.typ == BgpRibType::Originated
        && let Some((sid, _behavior)) = best.attr.srv6_l3_sid()
    {
        return transport
            .filter(|t| !t.is_empty())
            .and_then(|t| build_srv6_vpn_fib_entry(sid, t));
    }
    if is_vpn_fib_winner(best, transport) {
        build_vpn_fib_entry(best.label.map(|l| l.label).unwrap_or(0), transport.unwrap())
    } else {
        make_bgp_rib_entry_v4(best)
    }
}

/// Run the family's `table-map` over a best path about to be FIB-
/// installed. The family is the prefix's: `IpNet::V4` consults the
/// v4-unicast binding, `IpNet::V6` the v6-unicast one. Pass-through
/// when no binding exists for the family. With a binding: an
/// unresolved policy denies everything (FRR parity), a policy deny
/// returns `None` (the caller's withdraw branch reconciles the FIB),
/// and a permit returns a rewritten *copy* of the `BgpRib` — the
/// Loc-RIB original and what peers see are never touched. Useful set
/// clauses at install time are `set med` (-> RIB metric) and
/// `set next-hop` (v4 routes; the v6 next-hop rewrite waits on the
/// same plumbing as `policy in/out`); others execute harmlessly on
/// the discarded copy.
fn table_map_apply<'a>(
    table_map: &BTreeMap<AfiSafi, BgpTableMap>,
    router_id: Ipv4Addr,
    prefix: IpNet,
    best: Option<&'a BgpRib>,
) -> Option<std::borrow::Cow<'a, BgpRib>> {
    use std::borrow::Cow;
    let afi = match prefix {
        IpNet::V4(_) => Afi::Ip,
        IpNet::V6(_) => Afi::Ip6,
    };
    let Some(tm) = table_map.get(&AfiSafi::new(afi, Safi::Unicast)) else {
        return best.map(Cow::Borrowed);
    };
    let best = best?;
    // Bound name doesn't resolve to a policy: deny-all.
    let policy = tm.policy.as_ref()?;
    let decision =
        policy_list_apply_net(policy, prefix, (*best.attr).clone(), best.weight, router_id)?;
    let mut mapped = best.clone();
    // Transient install-time copy — never enters the attr store or
    // the Loc-RIB, so a free-floating Arc is fine.
    mapped.attr = Arc::new(decision.attr);
    Some(Cow::Owned(mapped))
}

/// Reconcile the kernel FIB state for `prefix` with the BGP best-path
/// outcome. `selected` is the `select_best_path` return: at most one
/// `BgpRib` after best-path selection. Empty means every candidate
/// just disappeared — emit a withdraw.
///
/// In a per-VRF task this is the single install path for `rd == None`
/// winners: imported VPN routes (carried in `bgp.vrf_transport_v4`)
/// install their labelled tunnel entry, CE-learned routes install the
/// plain next-hop entry, so whichever wins best-path is programmed
/// correctly. On the global instance `vrf_transport_v4` is `None`, so
/// this is plain IPv4 unicast install (VPNv4 / EVPN take other paths).
pub(super) fn fib_install_v4(bgp: &super::peer::BgpTop, prefix: Ipv4Net, selected: &[BgpRib]) {
    let transport = bgp
        .vrf_transport_v4
        .and_then(|m| m.get(&prefix))
        .map(|v| v.as_slice());
    let best = table_map_apply(
        &bgp.local_rib.table_map,
        *bgp.router_id,
        IpNet::V4(prefix),
        selected.first(),
    );
    let best = best.as_deref();
    let entry = best.and_then(|b| select_fib_entry_v4(b, transport));
    match entry {
        Some(mut rib_entry) => {
            // Colour-aware steering — plain-path only; a VPN tunnel
            // entry already carries its full label stack. An SR Policy
            // match (RFC 9256 §8) takes precedence over a Flex-Algo
            // binding; Flex-Algo is the fallback.
            if let Some(best) = best
                && !is_vpn_fib_winner(best, transport)
                && let Some(BgpNexthop::Ipv4(nh)) = best.attr.nexthop.as_ref()
                && let rib::Nexthop::Uni(ref mut uni) = rib_entry.nexthop
            {
                if let Some(stack) = sr_policy_steer_mpls(bgp, &best.attr, IpAddr::V4(*nh)) {
                    for label in stack {
                        uni.mpls.push(rib::Label::Explicit(label));
                    }
                } else if let Some(label) = resolve_flex_algo_label(bgp, &best.attr, *nh) {
                    uni.mpls.push(rib::Label::Explicit(label));
                }
            }
            let _ = bgp.rib_client.send(rib::Message::Ipv4Add {
                prefix,
                rib: rib_entry,
            });
        }
        None => {
            // Either selected is empty or the best path lacks a
            // usable v4 next-hop. Either way, the prefix should not
            // be in the FIB. The RIB layer ignores a Del for an
            // entry it never installed, so this is safe to fire
            // unconditionally.
            let mut stub = rib::entry::RibEntry::new(rib::RibType::Bgp);
            stub.valid = false;
            let _ = bgp
                .rib_client
                .send(rib::Message::Ipv4Del { prefix, rib: stub });
        }
    }
}

/// IPv6 counterpart of [`make_bgp_rib_entry_v4`]. Reads the IPv6
/// next-hop from `attr.nexthop` (`BgpNexthop::Ipv6`); there's no
/// RFC 8950 ENHE case for native v6 unicast. Returns `None` when the
/// best path lacks a usable v6 next-hop.
fn make_bgp_rib_entry_v6(best: &BgpRib) -> Option<rib::entry::RibEntry> {
    let distance = match best.typ {
        BgpRibType::EBGP => 20,
        BgpRibType::IBGP | BgpRibType::Originated => 200,
    };
    let metric = best.attr.med.as_ref().map(|m| m.med).unwrap_or(0);

    let nh = match best.attr.nexthop.as_ref()? {
        BgpNexthop::Ipv6(addr) => *addr,
        // VPNv6 / VPNv4 / EVPN nexthops install via their own paths;
        // the plain v6 Loc-RIB shouldn't carry them.
        _ => return None,
    };
    if nh.is_unspecified() {
        return None;
    }
    let nexthop = rib::Nexthop::Uni(rib::NexthopUni {
        addr: IpAddr::V6(nh),
        metric,
        weight: 1,
        valid: true,
        ..Default::default()
    });

    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = distance;
    entry.metric = metric;
    entry.valid = true;
    entry.nexthop = nexthop;
    Some(entry)
}

/// SRv6 ingress for a *received* plain IPv6 unicast route carrying an
/// SRv6 L3 service SID (RFC 9252 / RFC 8669). The SRv6 counterpart of
/// [`make_bgp_rib_entry_v6`]: same BGP next-hop + distance/metric, but the
/// next-hop gets `segs = [sid]` + an H.Encaps seg6 encap, so matched
/// traffic is SRv6-encapsulated (outer IPv6 DA = the SID) toward the
/// egress PE that owns the SID. The BGP next-hop is the underlay egress —
/// exactly the next-hop a plain entry installs `via`, only with the seg6
/// encap attached (the kernel forwards the encapped packet on toward the
/// SID's locator). Returns `None` when the best path lacks a usable v6
/// next-hop. Self-originated routes never reach here (they carry
/// `nexthop = None` and install nothing).
fn make_bgp_srv6_encap_entry_v6(
    best: &BgpRib,
    sid: std::net::Ipv6Addr,
) -> Option<rib::entry::RibEntry> {
    let distance = match best.typ {
        BgpRibType::EBGP => 20,
        BgpRibType::IBGP | BgpRibType::Originated => 200,
    };
    let metric = best.attr.med.as_ref().map(|m| m.med).unwrap_or(0);

    let nh = match best.attr.nexthop.as_ref()? {
        BgpNexthop::Ipv6(addr) => *addr,
        _ => return None,
    };
    if nh.is_unspecified() {
        return None;
    }

    let mut uni = rib::NexthopUni::new(IpAddr::V6(nh), 0, Vec::new());
    uni.segs = vec![sid];
    uni.encap_type = Some(isis_packet::srv6::EncapType::HEncap);
    uni.metric = metric;
    uni.weight = 1;
    uni.valid = true;

    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = distance;
    entry.metric = metric;
    entry.valid = true;
    entry.nexthop = rib::Nexthop::Uni(uni);
    Some(entry)
}

/// IPv6 counterpart of [`select_fib_entry_v4`].
fn select_fib_entry_v6(
    best: &BgpRib,
    transport: Option<&[rib::nht::ResolvedNexthop]>,
) -> Option<rib::entry::RibEntry> {
    // SRv6 L3VPN (VPNv6 over an SRv6 underlay) — see `select_fib_entry_v4`.
    if best.typ == BgpRibType::Originated
        && let Some((sid, _behavior)) = best.attr.srv6_l3_sid()
    {
        return transport
            .filter(|t| !t.is_empty())
            .and_then(|t| build_srv6_vpn_fib_entry(sid, t));
    }
    if is_vpn_fib_winner(best, transport) {
        build_vpn_fib_entry(best.label.map(|l| l.label).unwrap_or(0), transport.unwrap())
    } else if let Some((sid, _behavior)) = best.attr.srv6_l3_sid() {
        // A *received* plain IPv6 unicast route carrying an SRv6 L3
        // service SID installs an H.Encaps entry toward the SID instead
        // of a plain next-hop entry, so matched traffic is SRv6-
        // encapsulated to the egress PE. (The `Originated` + SID case is
        // VPNv6-over-SRv6, handled above; this is the global-table,
        // non-VPN ingress.)
        make_bgp_srv6_encap_entry_v6(best, sid)
    } else {
        make_bgp_rib_entry_v6(best)
    }
}

/// IPv6 counterpart of [`fib_install_v4`]: the single install path for
/// `rd == None` v6 winners in a VRF (imported VPNv6 labelled entry vs
/// CE plain entry), and plain v6 unicast install on the global instance.
pub(super) fn fib_install_v6(bgp: &super::peer::BgpTop, prefix: Ipv6Net, selected: &[BgpRib]) {
    let transport = bgp
        .vrf_transport_v6
        .and_then(|m| m.get(&prefix))
        .map(|v| v.as_slice());
    let best = table_map_apply(
        &bgp.local_rib.table_map,
        *bgp.router_id,
        IpNet::V6(prefix),
        selected.first(),
    );
    match best
        .as_deref()
        .and_then(|b| select_fib_entry_v6(b, transport))
    {
        Some(rib_entry) => {
            let _ = bgp.rib_client.send(rib::Message::Ipv6Add {
                prefix,
                rib: rib_entry,
            });
        }
        None => {
            let mut stub = rib::entry::RibEntry::new(rib::RibType::Bgp);
            stub.valid = false;
            let _ = bgp
                .rib_client
                .send(rib::Message::Ipv6Del { prefix, rib: stub });
        }
    }
}

/// Choose the FIB entry for a Labeled-Unicast (SAFI 4) best-path winner.
/// A *received* labeled route forwards toward its BGP next-hop with the
/// received label pushed (plus any transport label stack from recursively
/// resolving that next-hop) — exactly [`build_vpn_fib_entry`], but the
/// transport comes from the global NHT `cache` rather than a per-VRF map.
/// Returns `None` (→ withdraw) when:
///   - the winner is *self-originated* (`network` / redistribute): we are
///     the egress FEC, so the underlying connected/static/IGP route owns
///     forwarding and BGP installs nothing; or
///   - the next-hop hasn't resolved yet (no transport).
fn select_fib_entry_label(
    cache: Option<&super::nht::NexthopCache>,
    best: &BgpRib,
) -> Option<rib::entry::RibEntry> {
    if best.typ == BgpRibType::Originated {
        return None;
    }
    // A received implicit-null (label 3) means the downstream is the egress
    // FEC and wants the label popped, not carried — forward with only the
    // transport stack (label 3 must never appear on the wire). This is the
    // Inter-AS Option C case: a PE originates its loopback into BGP-LU with
    // implicit-null, and the re-originating ASBR must swap to transport-only,
    // not transport+3. 0 already means "no service label".
    let service_label = best.label.map(|l| l.label).filter(|&l| l != 3).unwrap_or(0);
    let transport = match (cache, super::nht::bgp_nexthop_ip(&best.attr)) {
        (Some(c), Some(nh)) => c.transport_for(nh),
        _ => &[][..],
    };
    build_vpn_fib_entry(service_label, transport)
}

/// Program the BGP-LU transit swap ILM for `best` (a SAFI-4 best-path
/// winner). When `best` is a *received* route we allocated a local label
/// for, install `local → swap to [transport…, received]` toward the
/// resolved egress so traffic a peer sends us (with our advertised local
/// label) is forwarded down the LSP. Self-originated winners (we are the
/// egress) carry no local label. An unresolved next-hop removes the ILM.
/// AFI-agnostic — the ILM is keyed by the local MPLS label, not the IP
/// prefix.
pub(super) fn reconcile_swap_ilm(
    rib_client: &crate::rib::client::RibClient,
    cache: Option<&super::nht::NexthopCache>,
    best: Option<&BgpRib>,
) {
    let Some(best) = best else { return };
    let Some(local) = best.local_label else {
        return;
    };
    if best.typ == BgpRibType::Originated {
        return;
    }
    let transport = match (cache, super::nht::bgp_nexthop_ip(&best.attr)) {
        (Some(c), Some(nh)) => c.transport_for(nh),
        _ => &[][..],
    };
    if transport.is_empty() {
        ilm_swap_remove(rib_client, local);
        return;
    }
    // A received implicit-null (label 3) means the downstream is the egress
    // FEC and wants the label popped, not carried — forward with only the
    // transport stack (label 3 must never appear on the wire). This is the
    // Inter-AS Option C case: a PE originates its loopback into BGP-LU with
    // implicit-null, and the re-originating ASBR must swap to transport-only,
    // not transport+3. 0 already means "no service label".
    let service_label = best.label.map(|l| l.label).filter(|&l| l != 3).unwrap_or(0);
    ilm_swap_install(rib_client, local, service_label, transport);
}

/// Send `Message::IlmAdd` for a swap entry at `local_label`. The outgoing
/// label stack `[transport labels…, service_label]` rides `mpls_label`
/// (the ILM swap field, distinct from `mpls` used by IP-route installs);
/// the egress address/ifindex mirror [`build_vpn_fib_entry`].
fn ilm_swap_install(
    rib_client: &crate::rib::client::RibClient,
    local_label: u32,
    service_label: u32,
    transport: &[rib::nht::ResolvedNexthop],
) {
    let mk_uni = |egress: &rib::nht::ResolvedNexthop| {
        let mut uni = rib::NexthopUni::new(egress.addr, 0, Vec::new());
        let mut labels = egress.labels.clone();
        if service_label != 0 {
            labels.push(service_label);
        }
        uni.mpls_label = labels;
        if egress.ifindex != 0 {
            uni.ifindex_origin = Some(egress.ifindex);
        }
        uni.valid = true;
        uni
    };
    let nexthop = if transport.len() == 1 {
        rib::Nexthop::Uni(mk_uni(&transport[0]))
    } else {
        let mut multi = rib::NexthopMulti::default();
        for egress in transport {
            multi.nexthops.push(mk_uni(egress));
        }
        rib::Nexthop::Multi(multi)
    };
    let mut ilm = rib::inst::IlmEntry::new(rib::RibType::Bgp);
    ilm.ilm_type = rib::inst::IlmType::Swap;
    ilm.nexthop = nexthop;
    let _ = rib_client.send(rib::Message::IlmAdd {
        label: local_label,
        ilm,
    });
}

/// Tear down the swap ILM at `local_label` (route withdrawn / next-hop
/// unresolved). The RIB ignores a Del for a label it never installed.
fn ilm_swap_remove(rib_client: &crate::rib::client::RibClient, local_label: u32) {
    let ilm = rib::inst::IlmEntry::new(rib::RibType::Bgp);
    let _ = rib_client.send(rib::Message::IlmDel {
        label: local_label,
        ilm,
    });
}

/// Install / reconcile the kernel FIB for an IPv4 Labeled-Unicast prefix
/// (ingress LSR: push the label toward the BGP next-hop). Takes the RIB
/// client + NHT cache directly (not a `BgpTop`) so it is callable both
/// from the receive path and from the NHT re-eval in `inst.rs`.
pub(super) fn fib_install_labelv4(
    rib_client: &crate::rib::client::RibClient,
    cache: Option<&super::nht::NexthopCache>,
    prefix: Ipv4Net,
    selected: &[BgpRib],
) {
    match selected
        .first()
        .and_then(|b| select_fib_entry_label(cache, b))
    {
        Some(rib_entry) => {
            let _ = rib_client.send(rib::Message::Ipv4Add {
                prefix,
                rib: rib_entry,
            });
        }
        None => {
            let mut stub = rib::entry::RibEntry::new(rib::RibType::Bgp);
            stub.valid = false;
            let _ = rib_client.send(rib::Message::Ipv4Del { prefix, rib: stub });
        }
    }
    reconcile_swap_ilm(rib_client, cache, selected.first());
}

/// IPv6 counterpart of [`fib_install_labelv4`] (incl. 6PE — the resolved
/// transport carries the v4/v6 egress).
pub(super) fn fib_install_labelv6(
    rib_client: &crate::rib::client::RibClient,
    cache: Option<&super::nht::NexthopCache>,
    prefix: Ipv6Net,
    selected: &[BgpRib],
) {
    match selected
        .first()
        .and_then(|b| select_fib_entry_label(cache, b))
    {
        Some(rib_entry) => {
            let _ = rib_client.send(rib::Message::Ipv6Add {
                prefix,
                rib: rib_entry,
            });
        }
        None => {
            let mut stub = rib::entry::RibEntry::new(rib::RibType::Bgp);
            stub.valid = false;
            let _ = rib_client.send(rib::Message::Ipv6Del { prefix, rib: stub });
        }
    }
    reconcile_swap_ilm(rib_client, cache, selected.first());
}

/// Walk the route's Color extcomms (ascending color order), look each
/// up in `color_policy`, LPM the next-hop against the matching
/// per-algo shadow, return the first hit's outer label.
fn resolve_flex_algo_label(bgp: &super::peer::BgpTop, attr: &BgpAttr, nh: Ipv4Addr) -> Option<u32> {
    resolve_flex_algo_label_inner(bgp.color_policy?, bgp.flex_algo_routes?, attr, nh)
}

/// SR Policy automated steering (RFC 9256 §8) for a plain IPv4 unicast
/// service route: if one of the route's Color extended communities maps
/// to an active SR-MPLS policy for `<color, next-hop>` (honouring the
/// CO-bit endpoint fallback), return that policy's SID list to impose on
/// the packet. Colors are tried in ascending color order; the first SR
/// Policy match wins and takes precedence over any Flex-Algo binding.
fn sr_policy_steer_mpls(bgp: &super::peer::BgpTop, attr: &BgpAttr, nh: IpAddr) -> Option<Vec<u32>> {
    for color in attr.colors() {
        if let Some(stack) = bgp
            .local_rib
            .sr_policy
            .steer_mpls(color.color, nh, color.co_bits())
        {
            return Some(stack);
        }
    }
    None
}

/// Pure-function inner for `resolve_flex_algo_label` — testable
/// without a full `BgpTop`. Same algorithm: walk the Color extcomms
/// in ascending color order, return the first one bound to an algo
/// whose per-algo shadow has a covering route for `nh`.
fn resolve_flex_algo_label_inner(
    color_policy: &super::color_policy::ColorPolicy,
    flex_algo_routes: &std::collections::BTreeMap<
        u8,
        prefix_trie::PrefixMap<Ipv4Net, crate::rib::api::FlexAlgoNexthop>,
    >,
    attr: &BgpAttr,
    nh: Ipv4Addr,
) -> Option<u32> {
    let host = Ipv4Net::new(nh, 32).ok()?;
    for color in attr.colors() {
        let Some(algo) = color_policy.flex_algo_for(color.color) else {
            // Color unbound — try the next one rather than bailing,
            // so a route with both an "unbound colour" and a "bound
            // colour" still resolves on the bound one.
            continue;
        };
        if let Some(table) = flex_algo_routes.get(&algo)
            && let Some((_, entry)) = table.get_lpm(&host)
        {
            return Some(entry.label);
        }
    }
    None
}

/// VPN next-hop carried on a `BgpRib` for routes living in the
/// `v4vpn` / `v6vpn` Loc-RIB tables. A route belongs to exactly one
/// of those tables, so it has exactly one VPN next-hop — modelled as
/// a sum type rather than parallel `Option` slots. `None` on a
/// `BgpRib` means a plain unicast (or otherwise non-VPN) row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VpnNexthop {
    V4(Vpnv4Nexthop),
    V6(Vpnv6Nexthop),
}

#[derive(Debug, Clone)]
pub struct BgpRib {
    // AddPath ID from peer.
    pub remote_id: u32,
    // AddPath ID from peer.
    pub local_id: u32,
    // BGP Attribute.
    pub attr: Arc<BgpAttr>,
    // Peer ID.
    pub ident: usize,
    // Peer router id.
    pub router_id: Ipv4Addr,
    // Weight
    pub weight: u32,
    // Route type.
    pub typ: BgpRibType,
    // Whether this cand is currently the best path.
    pub best_path: bool,
    // Label.
    pub best_reason: Reason,
    // Label.
    pub label: Option<Label>,
    /// BGP-LU local label we allocated for this prefix (SAFI 4 only).
    /// When set and the route is re-advertised with next-hop-self, this
    /// label is sent in the NLRI (instead of `label`, the received one)
    /// and an ILM swaps it to `label` toward the resolved transport.
    /// `None` for unicast/VPN/EVPN rows and for next-hop-unchanged.
    pub local_label: Option<u32>,
    // VPN next-hop (v4vpn / v6vpn rows); `None` for unicast rows.
    pub nexthop: Option<VpnNexthop>,
    /// Next-Hop Tracking gate: `false` when this path's BGP next-hop is
    /// registered for resolution but not (yet) reachable in the RIB.
    /// Best-path treats a reachable path as strictly better than an
    /// unreachable one, and a prefix whose best path is unreachable is
    /// withdrawn. Defaults to `true` — locally-originated and
    /// not-yet-tracked paths are never gated; `route_*_update` lowers
    /// it from the `Bgp` nexthop cache for received routes.
    pub nexthop_reachable: bool,
    /// RFC 8950 IPv4-over-IPv6: when the route was received via
    /// MP_REACH(AFI=1) with an IPv6 next-hop, this is that next-hop
    /// (the peer's link-local) plus the local egress ifindex (the
    /// interface where we received the UPDATE — link-locals are
    /// meaningless without one). FIB install reads this and programs
    /// a v6-gateway nexthop (`via inet6 fe80::.. dev N`, RFC 5549
    /// style) instead of the v4 NEXT_HOP attribute, which RFC 8950 §4
    /// says the receiver MUST ignore. `None` for normal v4 routes.
    pub enhe_egress: Option<(Ipv6Addr, u32)>,
    // Stale.
    pub stale: bool,
    // EVPN ESI (Ethernet Segment Identifier) for multi-homing.
    pub esi: Option<[u8; 10]>,
    /// Inter-AS Option AB: a received VPNv4/VPNv6 route whose RT is
    /// imported by a local `inter-as-hybrid` VRF. Such a route is
    /// propagated only by that VRF's re-export (an `Originated` row with
    /// the VRF's RD + next-hop-self), never transparently relayed — so it
    /// must NOT be advertised to peers directly. Set once at receive
    /// (`route_ipv4_update` / `route_ipv6_update`); `route_update_ipv4` /
    /// `…ipv6` suppress the advertise. Default `false` (ordinary route).
    pub vrf_transit_only: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Reason {
    Default,
    NexthopUnreachable,
    Llgr,
    Weight,
    Originated,
    Origin,
    AsPath,
    LocalPref,
    Med,
    RouterId,
    NotSelected,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::Default => write!(f, "Default selection (no other candidate)"),
            Reason::NexthopUnreachable => write!(f, "next-hop unreachable"),
            Reason::Llgr => write!(f, "llgr-stale"),
            Reason::Weight => write!(f, "weight"),
            Reason::Originated => write!(f, "self originated route"),
            Reason::Origin => write!(f, "origin attribute"),
            Reason::AsPath => write!(f, "AS Path length"),
            Reason::LocalPref => write!(f, "Local preference"),
            Reason::Med => write!(f, "MED attribute"),
            Reason::RouterId => write!(f, "Router ID"),
            Reason::NotSelected => write!(f, "Not selected"),
        }
    }
}

impl BgpRib {
    pub fn new(
        ident: usize,
        router_id: Ipv4Addr,
        rib_type: BgpRibType,
        id: u32,
        weight: u32,
        attr: &BgpAttr,
        label: Option<Label>,
        nexthop: Option<VpnNexthop>,
        stale: bool,
    ) -> Self {
        Self::new_arc(
            ident,
            router_id,
            rib_type,
            id,
            weight,
            Arc::new(attr.clone()),
            label,
            nexthop,
            stale,
        )
    }

    /// As [`new`](Self::new) but takes the attribute as an owned `Arc`,
    /// skipping the deep clone when the caller already owns the
    /// attribute — the shard dispatcher receives it by value in a
    /// `ShardMsg`, so it can move it straight into the row instead of
    /// re-cloning (RIB sharding B.3; saves one `BgpAttr` clone per
    /// received update on the hot path).
    #[allow(clippy::too_many_arguments)]
    pub fn new_arc(
        ident: usize,
        router_id: Ipv4Addr,
        rib_type: BgpRibType,
        id: u32,
        weight: u32,
        attr: Arc<BgpAttr>,
        label: Option<Label>,
        nexthop: Option<VpnNexthop>,
        stale: bool,
    ) -> Self {
        BgpRib {
            remote_id: id,
            local_id: 0, // Will be assigned in LocalRibTable::update_route()
            ident,
            router_id,
            attr,
            weight,
            typ: rib_type,
            best_path: false,
            best_reason: Reason::NotSelected,
            label,
            local_label: None,
            nexthop,
            nexthop_reachable: true,
            enhe_egress: None,
            stale,
            esi: None,
            vrf_transit_only: false,
        }
    }

    pub fn is_originated(&self) -> bool {
        self.typ.is_originated()
    }
}

/// AFI-generic Loc-RIB table: candidate paths and the selected
/// best path per prefix, both keyed by the prefix type `P`
/// (`Ipv4Net` today; `Ipv6Net` once the v6 ingest path lands). The
/// best-path machinery below is NLRI-agnostic — it compares only
/// `BgpRib` fields — so the same engine serves every unicast AFI.
///
/// `Debug`/`Default` are hand-written rather than derived: `PrefixMap`
/// derives neither for an arbitrary `P` (its `Debug` needs
/// `P: Prefix + Debug`, and `derive` would instead demand the wrong
/// `P: Debug`/`P: Default` bounds on `LocalRibTable`).
pub struct LocalRibTable<P>(
    pub PrefixMap<P, Vec<BgpRib>>, // Cands.
    pub PrefixMap<P, BgpRib>,      // Selected.
);

impl<P> Default for LocalRibTable<P> {
    fn default() -> Self {
        LocalRibTable(PrefixMap::default(), PrefixMap::default())
    }
}

impl<P: Prefix> std::fmt::Debug for LocalRibTable<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LocalRibTable")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

impl<P: Prefix + Copy> LocalRibTable<P> {
    pub fn update(&mut self, prefix: P, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let cands = self.0.entry(prefix).or_default();

        // Find if we're replacing an existing route (same peer ident and path ID)
        let existing_local_id = cands
            .iter()
            .find(|r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .map(|r| r.local_id);

        // Extract routes being replaced
        let replaced: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .collect();

        // Allocate local_id for the new/updated rib
        let mut next_id = 1u32;
        let mut new_rib = rib.clone();
        if let Some(local_id) = existing_local_id {
            // Reuse the local_id from the replaced route
            new_rib.local_id = local_id;
        } else {
            // Allocate a new local_id - find smallest unused positive integer
            let used_ids: std::collections::HashSet<u32> =
                cands.iter().map(|r| r.local_id).collect();

            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        next_id = new_rib.local_id;

        cands.push(new_rib);

        let selected = self.select_best_path(prefix);

        (replaced, selected, next_id)
    }

    pub fn remove(&mut self, prefix: P, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.0.entry(prefix).or_default();
        let removed: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect();
        removed
    }

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: P) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.0.contains_key(&prefix) {
            self.1.remove(&prefix);
            return selected;
        }

        let is_empty = self
            .0
            .get(&prefix)
            .map(|cands| cands.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.0.remove(&prefix);
            self.1.remove(&prefix);
            return selected;
        }

        let best = {
            let cands = self.0.get_mut(&prefix).expect("prefix checked above");

            let mut best_index = 0usize;
            let mut best_reason = Reason::Default;
            for index in 1..cands.len() {
                let (better, reason) = Self::is_better(&cands[index], &cands[best_index]);
                if better {
                    best_index = index;
                }
                best_reason = reason;
            }

            for rib in cands.iter_mut() {
                rib.best_path = false;
                rib.best_reason = Reason::NotSelected;
            }
            cands[best_index].best_path = true;
            cands[best_index].best_reason = best_reason;
            cands[best_index].clone()
        };

        // NHT gate: if even the best candidate's next-hop is
        // unreachable, every candidate is (a reachable one would have
        // won) — the prefix has no usable path, so withdraw it.
        if !best.nexthop_reachable {
            self.1.remove(&prefix);
            return selected;
        }

        self.1.insert(prefix, best.clone());
        selected.push(best);

        selected
    }

    /// Set `nexthop_reachable` on every candidate at `prefix` whose BGP
    /// next-hop equals `nh`. Returns true if any candidate changed (the
    /// caller then re-runs `select_best_path`). Used by the NHT update
    /// path when a tracked next-hop's reachability flips.
    pub fn set_nexthop_reachable(
        &mut self,
        prefix: P,
        nh: std::net::IpAddr,
        reachable: bool,
    ) -> bool {
        let Some(cands) = self.0.get_mut(&prefix) else {
            return false;
        };
        let mut changed = false;
        for c in cands.iter_mut() {
            if super::nht::bgp_nexthop_ip(&c.attr) == Some(nh) && c.nexthop_reachable != reachable {
                c.nexthop_reachable = reachable;
                changed = true;
            }
        }
        changed
    }

    /// A representative candidate's attr for `prefix`. Used by the NHT
    /// re-eval to resolve the importing-VRF set for a VPN withdraw when
    /// the prefix has no winner left (the gate withdrew it), so the RT
    /// extcomms are still available.
    pub fn candidate_attr(&self, prefix: P) -> Option<Arc<BgpAttr>> {
        self.0
            .get(&prefix)
            .and_then(|c| c.first())
            .map(|r| r.attr.clone())
    }

    /// The surviving candidates for `prefix` (after a removal). Used by
    /// NHT untrack to tell whether another path still keeps a withdrawn
    /// path's next-hop alive.
    pub fn candidates(&self, prefix: P) -> &[BgpRib] {
        self.0.get(&prefix).map(|c| c.as_slice()).unwrap_or(&[])
    }

    fn is_better(cand: &BgpRib, incb: &BgpRib) -> (bool, Reason) {
        // NHT gate: a path whose next-hop resolves is strictly better
        // than one whose next-hop is unreachable, ahead of every other
        // attribute. (Both-unreachable falls through; `select_best_path`
        // withdraws the prefix if even the winner is unreachable.)
        if cand.nexthop_reachable != incb.nexthop_reachable {
            return (cand.nexthop_reachable, Reason::NexthopUnreachable);
        }
        if cand.stale != incb.stale {
            return (!cand.stale, Reason::Llgr);
        }

        if cand.weight != incb.weight {
            return (cand.weight > incb.weight, Reason::Weight);
        }

        let cand_lp = Self::effective_local_pref(cand);
        let incb_lp = Self::effective_local_pref(incb);
        if cand_lp != incb_lp {
            return (cand_lp > incb_lp, Reason::LocalPref);
        }

        // RFC 4456: Prefer path with shorter CLUSTER_LIST length (fewer route reflector hops)
        // let cand_cluster_len = cand
        //     .attr
        //     .cluster_list
        //     .as_ref()
        //     .map_or(0, |cl| cl.list.len());
        // let incb_cluster_len = incb
        //     .attr
        //     .cluster_list
        //     .as_ref()
        //     .map_or(0, |cl| cl.list.len());
        // if cand_cluster_len != incb_cluster_len {
        //     return cand_cluster_len < incb_cluster_len;
        // }

        let cand_local = matches!(cand.typ, BgpRibType::Originated);
        let incb_local = matches!(incb.typ, BgpRibType::Originated);
        if cand_local != incb_local {
            return (cand_local, Reason::Originated);
        }

        let cand_as_len = Self::as_path_len(cand);
        let incb_as_len = Self::as_path_len(incb);
        if cand_as_len != incb_as_len {
            return (cand_as_len < incb_as_len, Reason::AsPath);
        }

        let cand_origin_rank = Self::origin_rank(cand.attr.origin);
        let incb_origin_rank = Self::origin_rank(incb.attr.origin);
        if cand_origin_rank != incb_origin_rank {
            return (cand_origin_rank < incb_origin_rank, Reason::Origin);
        }

        // By default, MED is only compared between routes learned from the neighboring AS.
        // let cand_nei_as = cand.attr.aspath
        let cand_neigh_as = cand.attr.neighboring_as();
        let incb_neigh_as = incb.attr.neighboring_as();

        if cand_neigh_as == incb_neigh_as {
            let cand_med = cand.attr.med.clone().unwrap_or_default();
            let incb_med = incb.attr.med.clone().unwrap_or_default();
            if cand_med != incb_med {
                return (cand_med < incb_med, Reason::Med);
            }
        }

        let cand_type_rank = Self::route_type_rank(cand.typ);
        let incb_type_rank = Self::route_type_rank(incb.typ);
        if cand_type_rank != incb_type_rank {
            return (cand_type_rank < incb_type_rank, Reason::Origin);
        }

        if cand.ident != incb.ident {
            return (cand.ident < incb.ident, Reason::RouterId);
        }

        if cand.remote_id != incb.remote_id {
            return (cand.remote_id < incb.remote_id, Reason::RouterId);
        }

        (false, Reason::NotSelected)
    }

    fn effective_local_pref(rib: &BgpRib) -> u32 {
        if let Some(ref attr) = rib.attr.local_pref {
            attr.local_pref
        } else {
            LocalPref::DEFAULT
        }
    }

    fn as_path_len(rib: &BgpRib) -> u32 {
        rib.attr
            .aspath
            .as_ref()
            .map(|path| path.length)
            .unwrap_or(0)
    }

    fn origin_rank(origin: Option<Origin>) -> u8 {
        match origin.unwrap_or(Origin::Incomplete) {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }

    fn route_type_rank(typ: BgpRibType) -> u8 {
        match typ {
            BgpRibType::Originated => 0,
            BgpRibType::EBGP => 1,
            BgpRibType::IBGP => 2,
        }
    }
}

/// Per-RD Loc-RIB table for EVPN routes.
///
/// Mirrors `LocalRibTable` but uses an exact-match `BTreeMap<EvpnPrefix, _>`
/// rather than `prefix-trie`'s `PrefixMap`, since EVPN keys are not subject
/// to longest-prefix matching.
#[derive(Debug, Default)]
pub struct LocalRibEvpnTable {
    /// Candidate paths per prefix.
    pub cands: BTreeMap<EvpnPrefix, Vec<BgpRib>>,
    /// Selected best path per prefix.
    pub selected: BTreeMap<EvpnPrefix, BgpRib>,
}

impl LocalRibEvpnTable {
    pub fn update(&mut self, prefix: EvpnPrefix, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let cands = self.cands.entry(prefix.clone()).or_default();

        // Find if we're replacing an existing route (same peer ident and path ID)
        let existing_local_id = cands
            .iter()
            .find(|r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .map(|r| r.local_id);

        // Extract routes being replaced
        let replaced: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .collect();

        // Allocate local_id for the new/updated rib
        let mut next_id = 1u32;
        let mut new_rib = rib.clone();
        if let Some(local_id) = existing_local_id {
            new_rib.local_id = local_id;
        } else {
            let used_ids: std::collections::HashSet<u32> =
                cands.iter().map(|r| r.local_id).collect();
            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        next_id = new_rib.local_id;

        cands.push(new_rib);

        let selected = self.select_best_path(&prefix);

        (replaced, selected, next_id)
    }

    pub fn remove(&mut self, prefix: &EvpnPrefix, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.cands.entry(prefix.clone()).or_default();
        cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect()
    }

    pub fn select_best_path(&mut self, prefix: &EvpnPrefix) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.cands.contains_key(prefix) {
            self.selected.remove(prefix);
            return selected;
        }

        let is_empty = self
            .cands
            .get(prefix)
            .map(|cands| cands.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.cands.remove(prefix);
            self.selected.remove(prefix);
            return selected;
        }

        let best = {
            let cands = self.cands.get_mut(prefix).expect("prefix checked above");

            let mut best_index = 0usize;
            let mut best_reason = Reason::Default;
            for index in 1..cands.len() {
                // Reuse the best-path comparator — it operates only on
                // BgpRib fields and is NLRI-agnostic. The type parameter
                // is irrelevant (the fn ignores it); name a concrete one.
                let (better, reason) =
                    LocalRibTable::<Ipv4Net>::is_better(&cands[index], &cands[best_index]);
                if better {
                    best_index = index;
                }
                best_reason = reason;
            }

            for rib in cands.iter_mut() {
                rib.best_path = false;
                rib.best_reason = Reason::NotSelected;
            }
            cands[best_index].best_path = true;
            cands[best_index].best_reason = best_reason;
            cands[best_index].clone()
        };

        self.selected.insert(prefix.clone(), best.clone());
        selected.push(best);

        selected
    }
}

/// Loc-RIB table for Flow Specification routes — candidate paths and the
/// selected best path per `FlowspecNlri`, exact-match (overlapping flow
/// specs coexist, so no prefix trie). Mirrors `LocalRibEvpnTable`;
/// best-path reuses the NLRI-agnostic `BgpRib` comparator. Validity
/// (RFC 9117) gates re-advertise/install, not Loc-RIB membership, so the
/// selected best path is recorded here regardless of validation.
#[derive(Debug, Default)]
pub struct LocalRibFlowspecTable {
    pub cands: BTreeMap<FlowspecNlri, Vec<BgpRib>>,
    pub selected: BTreeMap<FlowspecNlri, BgpRib>,
}

impl LocalRibFlowspecTable {
    pub fn update(&mut self, nlri: FlowspecNlri, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let cands = self.cands.entry(nlri.clone()).or_default();

        let existing_local_id = cands
            .iter()
            .find(|r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .map(|r| r.local_id);

        let replaced: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .collect();

        let mut next_id = 1u32;
        let mut new_rib = rib.clone();
        if let Some(local_id) = existing_local_id {
            new_rib.local_id = local_id;
        } else {
            let used_ids: std::collections::HashSet<u32> =
                cands.iter().map(|r| r.local_id).collect();
            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        next_id = new_rib.local_id;

        cands.push(new_rib);

        let selected = self.select_best_path(&nlri);

        (replaced, selected, next_id)
    }

    pub fn remove(&mut self, nlri: &FlowspecNlri, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.cands.entry(nlri.clone()).or_default();
        cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect()
    }

    pub fn select_best_path(&mut self, nlri: &FlowspecNlri) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.cands.contains_key(nlri) {
            self.selected.remove(nlri);
            return selected;
        }

        let is_empty = self
            .cands
            .get(nlri)
            .map(|cands| cands.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.cands.remove(nlri);
            self.selected.remove(nlri);
            return selected;
        }

        let best = {
            let cands = self.cands.get_mut(nlri).expect("nlri checked above");

            let mut best_index = 0usize;
            let mut best_reason = Reason::Default;
            for index in 1..cands.len() {
                // NLRI-agnostic comparator (operates only on BgpRib
                // fields); the type parameter is irrelevant.
                let (better, reason) =
                    LocalRibTable::<Ipv4Net>::is_better(&cands[index], &cands[best_index]);
                if better {
                    best_index = index;
                }
                best_reason = reason;
            }

            for rib in cands.iter_mut() {
                rib.best_path = false;
                rib.best_reason = Reason::NotSelected;
            }
            cands[best_index].best_path = true;
            cands[best_index].best_reason = best_reason;
            cands[best_index].clone()
        };

        self.selected.insert(nlri.clone(), best.clone());
        selected.push(best);

        selected
    }
}

/// BGP Link-State Loc-RIB table (RFC 9552, AFI 16388 / SAFI 71), keyed on
/// `BgpLsNlri` (exact match — every Node/Link/Prefix object is a distinct
/// key, so no prefix trie). Mirrors `LocalRibFlowspecTable`; best-path reuses
/// the NLRI-agnostic `BgpRib` comparator to elect a single path per object.
/// BGP-LS has no AddPath, so candidates carry `remote_id == 0` and are
/// disambiguated purely by `ident` — one candidate per peer.
#[derive(Debug, Default)]
pub struct LocalRibBgpLsTable {
    pub cands: BTreeMap<BgpLsNlri, Vec<BgpRib>>,
    pub selected: BTreeMap<BgpLsNlri, BgpRib>,
}

impl LocalRibBgpLsTable {
    pub fn update(&mut self, nlri: BgpLsNlri, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let cands = self.cands.entry(nlri.clone()).or_default();

        let existing_local_id = cands
            .iter()
            .find(|r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .map(|r| r.local_id);

        let replaced: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .collect();

        let mut next_id = 1u32;
        let mut new_rib = rib.clone();
        if let Some(local_id) = existing_local_id {
            new_rib.local_id = local_id;
        } else {
            let used_ids: std::collections::HashSet<u32> =
                cands.iter().map(|r| r.local_id).collect();
            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        next_id = new_rib.local_id;

        cands.push(new_rib);

        let selected = self.select_best_path(&nlri);

        (replaced, selected, next_id)
    }

    pub fn remove(&mut self, nlri: &BgpLsNlri, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.cands.entry(nlri.clone()).or_default();
        cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect()
    }

    pub fn select_best_path(&mut self, nlri: &BgpLsNlri) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.cands.contains_key(nlri) {
            self.selected.remove(nlri);
            return selected;
        }

        let is_empty = self
            .cands
            .get(nlri)
            .map(|cands| cands.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.cands.remove(nlri);
            self.selected.remove(nlri);
            return selected;
        }

        let best = {
            let cands = self.cands.get_mut(nlri).expect("nlri checked above");

            let mut best_index = 0usize;
            let mut best_reason = Reason::Default;
            for index in 1..cands.len() {
                // NLRI-agnostic comparator (operates only on BgpRib
                // fields); the type parameter is irrelevant.
                let (better, reason) =
                    LocalRibTable::<Ipv4Net>::is_better(&cands[index], &cands[best_index]);
                if better {
                    best_index = index;
                }
                best_reason = reason;
            }

            for rib in cands.iter_mut() {
                rib.best_path = false;
                rib.best_reason = Reason::NotSelected;
            }
            cands[best_index].best_path = true;
            cands[best_index].best_reason = best_reason;
            cands[best_index].clone()
        };

        self.selected.insert(nlri.clone(), best.clone());
        selected.push(best);

        selected
    }
}

/// Per-AFI `table-map` binding (zebra-bgp-table-map.yang
/// `router bgp afi-safi <af> table-map <name>`): a policy applied to
/// best paths at BGP-to-RIB install time only. Deny keeps the route
/// out of the FIB; permit-side set clauses rewrite the installed
/// entry (MED -> metric, next-hop) without touching the Loc-RIB or
/// what peers are advertised.
#[derive(Debug, Default, Clone)]
pub struct BgpTableMap {
    /// Configured policy name (the `table-map` leaf value).
    pub name: Option<String>,
    /// Resolved snapshot, pushed by the policy actor via
    /// `PolicyRx::PolicyList` (`PolicyType::TableMap`). `None` while
    /// the name doesn't resolve — which denies every install for the
    /// family (FRR parity: a missing referenced route-map filters
    /// everything).
    pub policy: Option<PolicyList>,
}

/// Main-task-owned Loc-RIB tables. The prefix-hashable tables
/// (v4/v6 unicast, LU, VPNv4/v6) live in [`super::shard::BgpShard`]
/// instead — see the RIB sharding plan (B.1 / D3) for the partition.
#[derive(Debug, Default)]
pub struct LocalRib {
    /// Per-RD EVPN Loc-RIB tables.
    pub evpn: BTreeMap<RouteDistinguisher, LocalRibEvpnTable>,

    /// IPv4 / IPv6 Flow Specification Loc-RIB (SAFI 133).
    pub flowspec_v4: LocalRibFlowspecTable,
    pub flowspec_v6: LocalRibFlowspecTable,

    /// BGP SR Policy (SAFI 73) headend-consumer database, keyed by
    /// `<color, endpoint>` (the endpoint's family is the NLRI AFI, so a
    /// single table holds both IPv4 and IPv6 policies).
    pub sr_policy: super::sr_policy::SrPolicyDb,

    /// Locally-configured SR Policies to originate as SAFI 73
    /// (zebra-bgp-sr-policy.yang). Lives here so both the config
    /// callbacks (`&mut Bgp`) and the establish-time advertise
    /// (`BgpTop`) reach it without threading a new `BgpTop` field.
    pub sr_policy_local: super::sr_policy::LocalSrPolicies,

    /// BGP Link-State (AFI 16388, SAFI 71) Loc-RIB. A single exact-match
    /// table keyed by `BgpLsNlri`; the v4/v6 prefix distinction lives inside
    /// the NLRI, so one table holds Node, Link, and Prefix objects.
    pub bgp_ls: LocalRibBgpLsTable,

    /// Per-AFI `table-map` bindings (zebra-bgp-table-map.yang).
    /// Lives here — like `sr_policy_local` — so both the config
    /// callbacks (`&mut Bgp`) and `fib_install_v4`/`v6` (`BgpTop`)
    /// reach it without threading a new `BgpTop` field. Per-VRF
    /// tasks own a separate `LocalRib` whose map stays empty, so
    /// VRF installs are unaffected until table-map grows VRF config.
    pub table_map: BTreeMap<AfiSafi, BgpTableMap>,
}

impl LocalRib {
    // EVPN dispatch ----------------------------------------------------------

    pub fn update_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: EvpnPrefix,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.evpn.entry(rd).or_default().update(prefix, rib)
    }

    pub fn remove_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: &EvpnPrefix,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        self.evpn.entry(rd).or_default().remove(prefix, id, ident)
    }

    pub fn select_best_path_evpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: &EvpnPrefix,
    ) -> Vec<BgpRib> {
        self.evpn.entry(*rd).or_default().select_best_path(prefix)
    }

    // Flow Specification dispatch --------------------------------------------

    fn flowspec_table_mut(&mut self, afi: Afi) -> &mut LocalRibFlowspecTable {
        match afi {
            Afi::Ip6 => &mut self.flowspec_v6,
            _ => &mut self.flowspec_v4,
        }
    }

    pub fn update_flowspec(
        &mut self,
        afi: Afi,
        nlri: FlowspecNlri,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.flowspec_table_mut(afi).update(nlri, rib)
    }

    pub fn remove_flowspec(
        &mut self,
        afi: Afi,
        nlri: &FlowspecNlri,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        self.flowspec_table_mut(afi).remove(nlri, id, ident)
    }

    pub fn select_best_path_flowspec(&mut self, afi: Afi, nlri: &FlowspecNlri) -> Vec<BgpRib> {
        self.flowspec_table_mut(afi).select_best_path(nlri)
    }

    // BGP Link-State dispatch ------------------------------------------------

    pub fn update_bgpls(
        &mut self,
        nlri: BgpLsNlri,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.bgp_ls.update(nlri, rib)
    }

    pub fn remove_bgpls(&mut self, nlri: &BgpLsNlri, id: u32, ident: usize) -> Vec<BgpRib> {
        self.bgp_ls.remove(nlri, id, ident)
    }

    pub fn select_best_path_bgpls(&mut self, nlri: &BgpLsNlri) -> Vec<BgpRib> {
        self.bgp_ls.select_best_path(nlri)
    }
}

// RIB update from peer.
pub fn route_apply_policy_in(
    peer: &Peer,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    apply_policy_in_pure(
        peer.prefix_set.get(&InOut::Input),
        peer.policy_list.get(&InOut::Input),
        peer.router_id,
        nlri,
        bgp_attr,
        weight,
    )
}

/// Family- and direction-generic policy evaluation. The prefix arrives
/// as an `IpNet`, so the same per-direction prefix-set match + policy-list
/// walk + default-permit serves IPv4 and IPv6 in BOTH directions — the
/// caller picks the direction by passing the Input or Output config
/// snapshots. `PrefixSet::matches` and `policy_list_apply_net` are both
/// already dual-stack, so no per-family code is needed here.
///
/// Mutates nothing (takes config by reference, not `&mut Peer`), so the
/// batch ingest / advertise paths can run it in parallel across a
/// packet's prefixes (RIB sharding C.1 / C.2).
pub fn apply_policy_net(
    prefix_cfg: &super::PrefixSetValue,
    policy_cfg: &super::PolicyListValue,
    router_id: Ipv4Addr,
    prefix: IpNet,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    if prefix_cfg.name.is_some() {
        let Some(prefix_set) = &prefix_cfg.prefix_set else {
            return None;
        };
        if !prefix_set.matches(prefix) {
            return None;
        }
    }
    if policy_cfg.name.is_some() {
        let Some(policy_list) = &policy_cfg.policy_list else {
            return None;
        };
        return policy_list_apply_net(policy_list, prefix, bgp_attr, weight, router_id);
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

/// Inbound-policy evaluation for an IPv4 NLRI: the v4 projection of
/// [`apply_policy_net`].
pub fn apply_policy_in_pure(
    prefix_cfg: &super::PrefixSetValue,
    policy_cfg: &super::PolicyListValue,
    router_id: Ipv4Addr,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    apply_policy_net(
        prefix_cfg,
        policy_cfg,
        router_id,
        IpNet::V4(nlri.prefix),
        bgp_attr,
        weight,
    )
}

/// Inbound policy entry point for an EVPN route. Mirrors
/// `route_apply_policy_in` but skips the per-direction prefix-set
/// (no IPv4 prefix on EVPN NLRIs) and dispatches to
/// `policy_list_apply_evpn`. When no input policy-list is bound
/// to the peer the route passes through unmodified.
pub fn route_apply_policy_in_evpn(
    peer: &mut Peer,
    route: &EvpnRoute,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    let config = peer.policy_list.get(&InOut::Input);
    if config.name.is_some() {
        let Some(policy_list) = &config.policy_list else {
            return None;
        };
        return policy_list_apply_evpn(policy_list, route, bgp_attr, weight, peer.router_id);
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

/// Outbound policy entry point for an EVPN route. Mirrors
/// `route_apply_policy_out` but skips the per-direction prefix-set
/// (no IPv4 prefix on EVPN NLRIs) and dispatches to
/// `policy_list_apply_evpn`. Default-permit when no output
/// policy-list is bound, same as the IPv4 outbound path.
pub fn route_apply_policy_out_evpn(
    peer: &mut Peer,
    route: &EvpnRoute,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    let config = peer.policy_list.get(&InOut::Output);
    if config.name.is_some() {
        let Some(policy_list) = &config.policy_list else {
            return None;
        };
        return policy_list_apply_evpn(policy_list, route, bgp_attr, weight, peer.router_id);
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

/// Outbound-policy evaluation for an IPv4 NLRI: the v4 / Output
/// projection of [`apply_policy_net`]. `set next-hop self` anchors on
/// the session's local router-id (`peer.router_id`).
pub fn route_apply_policy_out(
    peer: &Peer,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    apply_policy_net(
        peer.prefix_set.get(&InOut::Output),
        peer.policy_list.get(&InOut::Output),
        peer.router_id,
        IpNet::V4(nlri.prefix),
        bgp_attr,
        weight,
    )
}

/// Inbound-policy evaluation for an IPv6 NLRI: the v6 / Input projection
/// of [`apply_policy_net`]. Before this, the v6 ingest applied no
/// per-neighbor inbound policy — v6 route-maps / prefix-lists were
/// silently ignored.
pub fn route_apply_policy_in_v6(
    peer: &Peer,
    nlri: &Ipv6Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    apply_policy_net(
        peer.prefix_set.get(&InOut::Input),
        peer.policy_list.get(&InOut::Input),
        peer.router_id,
        IpNet::V6(nlri.prefix),
        bgp_attr,
        weight,
    )
}

/// Outbound-policy evaluation for an IPv6 NLRI: the v6 / Output
/// projection of [`apply_policy_net`].
pub fn route_apply_policy_out_v6(
    peer: &Peer,
    nlri: &Ipv6Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    apply_policy_net(
        peer.prefix_set.get(&InOut::Output),
        peer.policy_list.get(&InOut::Output),
        peer.router_id,
        IpNet::V6(nlri.prefix),
        bgp_attr,
        weight,
    )
}

/// Next-Hop Tracking for a received route: register its BGP next-hop
/// with the RIB on first sight, record `dep` so a resolution change
/// re-evaluates this prefix, and lower `rib.nexthop_reachable` from the
/// cache (`false` while a fresh registration is pending — best-path
/// then holds the path until the first `NexthopUpdate`). No-op outside
/// the global instance, where `bgp.nexthop_cache` is `None`.
fn nht_track_received(bgp: &mut BgpTop, rib: &mut BgpRib, dep: super::nht::NhtDep) {
    let Some(cache) = bgp.nexthop_cache.as_deref_mut() else {
        return;
    };
    let Some(nh) = super::nht::bgp_nexthop_ip(&rib.attr) else {
        return;
    };
    let (needs_register, reachable) = cache.track(nh, dep);
    rib.nexthop_reachable = reachable;
    if needs_register {
        let _ = bgp.rib_client.send(rib::Message::NexthopRegister {
            proto: "bgp".to_string(),
            nh,
        });
    }
}

/// Main-side NHT for a route whose rib lives in the shard (RIB sharding
/// B.3 sync-dispatch): register the post-policy attr's next-hop (when
/// new) and return its reachability, to pass into the shard's `Update*`
/// message — the shard gates the row with it before best-path. The
/// gating half of [`nht_track_received`] without needing the rib.
/// Returns `true` when there is no NHT view or no next-hop (matching
/// `BgpRib::new`'s default).
fn nht_track_received_attr(bgp: &mut BgpTop, attr: &BgpAttr, dep: super::nht::NhtDep) -> bool {
    let Some(cache) = bgp.nexthop_cache.as_deref_mut() else {
        return true;
    };
    let Some(nh) = super::nht::bgp_nexthop_ip(attr) else {
        return true;
    };
    let (needs_register, reachable) = cache.track(nh, dep);
    if needs_register {
        let _ = bgp.rib_client.send(rib::Message::NexthopRegister {
            proto: "bgp".to_string(),
            nh,
        });
    }
    reachable
}

/// Symmetric to [`nht_track_received`]: on a withdrawal, drop `dep` from
/// each distinct next-hop the `removed` paths used, and unregister a
/// next-hop from the RIB once it has no deps left. `survivor_nhs` are
/// the next-hops still in use by surviving candidates for the same
/// prefix (a `NhtDep` is tracked under every path's next-hop, so a
/// partial withdrawal must not release a next-hop another path keeps).
/// No-op outside the global instance (`bgp.nexthop_cache` is `None`).
fn nht_untrack_withdrawn(
    bgp: &mut BgpTop,
    removed: &[BgpRib],
    survivor_nhs: &std::collections::BTreeSet<IpAddr>,
    dep: super::nht::NhtDep,
) {
    if bgp.nexthop_cache.is_none() {
        return;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut to_unregister = Vec::new();
    for r in removed {
        // ENHE rows were never tracked (see the guard at the
        // `nht_track_received` call) — their v4 NEXT_HOP attribute is
        // ignored per RFC 8950 §4, so releasing it here could steal a
        // registration a genuine v4 path holds on the same address.
        if r.enhe_egress.is_some() {
            continue;
        }
        let Some(nh) = super::nht::bgp_nexthop_ip(&r.attr) else {
            continue;
        };
        if survivor_nhs.contains(&nh) || !seen.insert(nh) {
            continue;
        }
        if let Some(cache) = bgp.nexthop_cache.as_deref_mut()
            && cache.untrack(nh, &dep)
        {
            to_unregister.push(nh);
        }
    }
    for nh in to_unregister {
        let _ = bgp.rib_client.send(rib::Message::NexthopUnregister {
            proto: "bgp".to_string(),
            nh,
        });
    }
}

/// The VPN service label + resolved transport for a winning VPNv4
/// route, for the per-VRF dataplane install. The service label rides
/// on `winner.label` (the received NLRI label); the transport egress(es)
/// come from the global NHT cache keyed by the remote-PE next-hop.
/// Returns `(0, &[])` outside the global instance (no `nexthop_cache`)
/// or when the PE next-hop hasn't resolved — yielding no FIB install.
fn vpn_import_transport<'a>(
    bgp: &'a BgpTop,
    winner: &BgpRib,
) -> (u32, &'a [rib::nht::ResolvedNexthop]) {
    let label = winner.label.map(|l| l.label).unwrap_or(0);
    let transport = match (
        bgp.nexthop_cache.as_deref(),
        super::nht::bgp_nexthop_ip(&winner.attr),
    ) {
        (Some(cache), Some(nh)) => cache.transport_for(nh),
        _ => &[][..],
    };
    (label, transport)
}

pub fn route_ipv4_update(
    ident: usize,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<VpnNexthop>,
    enhe_egress: Option<(Ipv6Addr, u32)>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let checks = {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        inbound_attr_checks(peer, attr, bgp.router_id)
    };
    let Some((peer_ident, peer_router_id, typ)) = checks else {
        return;
    };
    let stale = stale || attr_has_llgr_stale(attr);
    let decision = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        route_apply_policy_in(peer, nlri, attr.clone(), 0)
    };
    let jobs = route_ipv4_update_decided(
        peer_ident,
        peer_router_id,
        typ,
        nlri,
        rd,
        label,
        attr,
        nexthop,
        enhe_egress,
        decision,
        bgp,
        None,
        stale,
    );
    for job in jobs {
        apply_ipv4_advertise_job(job, peer_ident, BTreeMap::new(), bgp, peers);
    }
}

/// Per-attr inbound checks shared by every prefix in an UPDATE (AS-path
/// loop, enforce-first-as, route-reflection). Returns the peer identity
/// or `None` if the UPDATE is dropped; the batch path runs it once.
fn inbound_attr_checks(
    peer: &Peer,
    attr: &BgpAttr,
    local_router_id: &Ipv4Addr,
) -> Option<(usize, Ipv4Addr, BgpRibType)> {
    if let Some(ref aspath) = attr.aspath
        && aspath_own_as_loop(peer, aspath)
    {
        return None;
    }
    if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
        return None;
    }
    if let Some(ref originator_id) = attr.originator_id
        && originator_id.id == *local_router_id
    {
        return None;
    }
    if let Some(ref cluster_list) = attr.cluster_list
        && cluster_list.list.contains(local_router_id)
    {
        return None;
    }
    let typ = if peer.is_ibgp() {
        BgpRibType::IBGP
    } else {
        BgpRibType::EBGP
    };
    Some((peer.ident, peer.remote_id, typ))
}

/// Parallel ingest for a packet's plain IPv4-unicast NLRIs (RIB
/// sharding C.1). The prefixes share one attribute and inbound policy
/// is pure (read-only on the peer's policy snapshot), so the per-prefix
/// policy walk — the serial bottleneck under heavy policy — fans out
/// across cores with rayon. The Loc-RIB writes + advertise then run
/// serially in NLRI order off the decisions.
pub fn route_ipv4_update_batch(
    ident: usize,
    prefixes: &[Ipv4Nlri],
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
    stale: bool,
) {
    let checks = {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        inbound_attr_checks(peer, attr, bgp.router_id)
    };
    let Some((peer_ident, peer_router_id, typ)) = checks else {
        return;
    };
    let stale = stale || attr_has_llgr_stale(attr);

    // N>1 (RIB sharding Phase C + RouteBatch): inbound policy runs in the
    // shard (no main-side `par_iter`), and this UPDATE's prefixes are
    // split by hash and sent as ONE batch per shard — collapsing the
    // per-prefix dispatch (a futex wake + attr clone each) to one per
    // shard. Best-path + advertise happen asynchronously on the event
    // loop (`process_shard_result`). NHT registers per prefix in main
    // (a no-op when NHT is off); reachability is shared (same attr).
    if let Some(pool) = shards {
        let mut per_shard: Vec<Vec<Ipv4Nlri>> = vec![Vec::new(); pool.n()];
        let mut nexthop_reachable = true;
        for nlri in prefixes {
            nexthop_reachable =
                nht_track_received_attr(bgp, attr, super::nht::NhtDep::V4(nlri.prefix));
            let idx = pool.shard_of(std::net::IpAddr::V4(nlri.prefix.addr()));
            per_shard[idx].push(nlri.clone());
        }
        for (idx, nlris) in per_shard.into_iter().enumerate() {
            if nlris.is_empty() {
                continue;
            }
            pool.dispatch(
                idx,
                ShardMsg::RouteBatchV4(super::shard::msg::ShardRouteBatchV4 {
                    ident: peer_ident,
                    peer_router_id,
                    typ,
                    attr: attr.clone(),
                    nlris,
                    enhe_egress: None,
                    stale,
                    nexthop_reachable,
                    compute_policy: true,
                }),
            );
        }
        return;
    }

    // Phase A — N=1 (the synchronous shard): route inbound policy THROUGH
    // the shard (`compute_policy: true` — it holds the peer's policy via
    // `PolicyReplace`), so policy is applied in exactly one place at every
    // N and the main-side par_iter is gone. NHT registers on the raw attr
    // (as the N>1 path does; reachability is shared across the UPDATE's
    // prefixes — one attr). `reduce_bestpath_v4_nht_fib` runs the
    // NHT-untrack + FIB + advertise-job post-work, the same routine the
    // N>1 reduce uses; the out-policy advertise is deferred to Phase B/C.
    let mut jobs: Vec<Ipv4AdvertiseJob> = Vec::new();
    for nlri in prefixes {
        let nexthop_reachable =
            nht_track_received_attr(bgp, attr, super::nht::NhtDep::V4(nlri.prefix));
        let msg = ShardMsg::UpdateV4(ShardUpdateV4 {
            ident: peer_ident,
            rd: None,
            nlri: nlri.clone(),
            peer_router_id,
            typ,
            attr: attr.clone(),
            label: None,
            nexthop: None,
            enhe_egress: None,
            stale,
            nexthop_reachable,
            vrf_transit_only: false,
            decision: None,
            compute_policy: true,
        });
        let deltas = bgp
            .shard
            .handle(msg, bgp.central_label_alloc.as_deref_mut());
        for delta in deltas {
            if let Some((_src, job)) = reduce_bestpath_v4_nht_fib(bgp, delta) {
                jobs.push(job);
            }
        }
    }

    // Phase B (parallel, cost-gated): precompute each job's per-group
    // advertise outcome — the out-policy prefix-set walk, the convergence
    // hot spot under a large policy. Same gate as the reduce (Phase E.1):
    // fan out only when an out-policy is bound, else the empty memos make
    // the apply compute inline (identical result, no rayon overhead).
    let memos = if any_established_out_policy_v4(peers) {
        precompute_ipv4_advertise_outcomes(&jobs, bgp, peers)
    } else {
        vec![BTreeMap::new(); jobs.len()]
    };

    // Phase C (serial): apply each job's advertise off the precomputed
    // outcomes; cache / adj-out / send mutate shared state in NLRI order.
    for (job, memo) in jobs.into_iter().zip(memos) {
        apply_ipv4_advertise_job(job, peer_ident, memo, bgp, peers);
    }
}

/// Whether any Established plain IPv4-unicast peer has an outbound policy
/// (route-map or prefix-list) bound — the cost-gate for the advertise
/// out-policy precompute. With none, the precompute's prefix-set walk is a
/// no-op, so its rayon fan-out is pure overhead at the default N=1 and
/// steals cores from the shard threads at N>1; callers fall back to a
/// serial apply (identical result).
fn any_established_out_policy_v4(peers: &PeerMap) -> bool {
    peers
        .established_plain_idents(Afi::Ip, Safi::Unicast)
        .into_iter()
        .filter_map(|id| peers.get_by_idx(id))
        .any(|p| {
            p.policy_list.get(&InOut::Output).name.is_some()
                || p.prefix_set.get(&InOut::Output).name.is_some()
        })
}

/// Bounded worker pool for the egress (advertise-outcome) precompute —
/// Phase E.2. The out-policy prefix-set walk fans out here instead of on
/// rayon's cores-wide *global* pool, so at N ≈ cores it can't oversubscribe
/// the dedicated shard threads (the "no spare cores" effect the no-policy
/// N=12 bench showed). Sized from `ZEBRA_BGP_UPDATE_WORKERS`, defaulting to
/// `max(1, cores − ZEBRA_BGP_SHARDS)` so shards + egress workers fit the
/// core count. Built once, lazily; lives for the process.
fn egress_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let default = cores.saturating_sub(super::inst::shard_count()).max(1);
        let workers = std::env::var("ZEBRA_BGP_UPDATE_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .map(|n| n.clamp(1, 256))
            .unwrap_or(default);
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .thread_name(|i| format!("bgp-egress-{i}"))
            .build()
            .expect("build BGP egress worker pool")
    })
}

/// Parallel precompute of per-group advertise outcomes for a batch of
/// IPv4 advertise jobs (C.2). Returns one memo per job, in `jobs` order,
/// each mapping an update-group id to the outcome a clean (non-source,
/// non-LLGR) member of that group would produce. The serial apply
/// consumes these via the pre-seeded memo; per-peer split-horizon / LLGR
/// suppression and any no-group peers still resolve inline.
fn precompute_ipv4_advertise_outcomes(
    jobs: &[Ipv4AdvertiseJob],
    bgp: &BgpTop,
    peers: &PeerMap,
) -> Vec<BTreeMap<super::update_group::UpdateGroupId, AdvertiseOutcome<Ipv4Nlri>>> {
    use rayon::prelude::*;

    let (afi, safi) = (Afi::Ip, Safi::Unicast);
    let afi_safi = AfiSafi::new(afi, safi);

    // Established plain-unicast peers grouped by update-group id, built
    // once (the peer set is fixed for the batch). Each group records its
    // member idents and a representative `add_path` (uniform per group).
    let mut groups: BTreeMap<super::update_group::UpdateGroupId, (Vec<usize>, bool)> =
        BTreeMap::new();
    for ident in peers.established_plain_idents(afi, safi) {
        let Some(peer) = peers.get_by_idx(ident) else {
            continue;
        };
        let Some(gid) = peer.update_group_id.get(&afi_safi).cloned() else {
            continue; // no-group peer: resolved inline in the apply
        };
        let add_path = peer.opt.is_add_path_send(afi, safi);
        groups
            .entry(gid)
            .or_insert_with(|| (Vec::new(), add_path))
            .0
            .push(ident);
    }

    // Phase E.2: fan out on the bounded egress worker pool, not rayon's
    // cores-wide global pool, so the out-policy walk can't steal cores from
    // the dedicated shard threads at N ≈ cores.
    egress_pool().install(|| {
        jobs.par_iter()
            .map(|job| {
                let mut memo = BTreeMap::new();
                // VPNv4 (rd) keeps its inline path; a withdraw has no outcome.
                if job.rd.is_some() {
                    return memo;
                }
                let Some(best) = job.selected.last() else {
                    return memo;
                };
                for (gid, (members, add_path)) in groups.iter() {
                    // Canonical member: the first established, non-source,
                    // non-LLGR peer — the one the serial memo computes on.
                    let canonical = members.iter().copied().find(|&idx| {
                        peers.get_by_idx(idx).is_some_and(|p| {
                            best.ident != p.ident
                                && !llgr_blocks_advertisement(best.stale, &p.cap_recv, afi, safi)
                        })
                    });
                    if let Some(idx) = canonical {
                        let peer = peers.get_by_idx(idx).expect("peer exists");
                        let outcome =
                            compute_advertise_outcome(peer, &job.prefix, best, bgp, *add_path);
                        memo.insert(gid.clone(), outcome);
                    }
                }
                memo
            })
            .collect()
    })
}

/// One IPv4 advertise job produced by a Loc-RIB best-path delta: the
/// surviving paths to advertise (empty = withdraw) plus the AddPath
/// added/removed deltas. `route_ipv4_update_decided` returns these after
/// doing the NHT / VRF / FIB post-work it owns; the caller runs the
/// (out-policy) advertise, either inline or — for the batch — after a
/// parallel precompute of the per-group outcomes.
struct Ipv4AdvertiseJob {
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    selected: Vec<BgpRib>,
    added: Option<BgpRib>,
    replaced: Vec<BgpRib>,
}

/// The post-policy half of `route_ipv4_update`: with the inbound
/// decision already computed, resolve NHT + transit, hand the table op
/// to the shard, and run the FIB / VRF post-work off the delta. The
/// advertise is deferred to the returned [`Ipv4AdvertiseJob`]s so the
/// batch path can parallelize the out-policy. Shared by the
/// single-prefix and batch entry points.
#[allow(clippy::too_many_arguments)]
fn route_ipv4_update_decided(
    peer_ident: usize,
    peer_router_id: Ipv4Addr,
    typ: BgpRibType,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<VpnNexthop>,
    enhe_egress: Option<(Ipv6Addr, u32)>,
    decision: Option<PolicyDecision>,
    bgp: &mut BgpTop,
    shards: Option<&super::shard::pool::ShardPool>,
    stale: bool,
) -> Vec<Ipv4AdvertiseJob> {
    let dep = match rd {
        Some(rd) => super::nht::NhtDep::V4vpn(rd, nlri.prefix),
        None => super::nht::NhtDep::V4(nlri.prefix),
    };

    // N-shard (N>1): v4-unicast (rd == None) fans out to the worker pool
    // by prefix hash. Phase C runs inbound policy IN the shard, so main
    // only resolves NHT on the raw attr (policy rarely rewrites the
    // next-hop; exact NHT-in-shard is a follow-up) and ships the raw-attr
    // table op with `compute_policy`. The best-path delta returns
    // asynchronously on the event loop (`process_shard_result`) — no
    // inline advertise job. VPNv4 (rd == Some) stays on the synchronous
    // shard (its transit label needs main's central allocator, which
    // can't be borrowed across the thread boundary).
    if let Some(pool) = shards
        && rd.is_none()
    {
        let nexthop_reachable = if enhe_egress.is_none() {
            nht_track_received_attr(bgp, attr, dep.clone())
        } else {
            true
        };
        let msg = ShardMsg::UpdateV4(ShardUpdateV4 {
            ident: peer_ident,
            rd,
            nlri: nlri.clone(),
            peer_router_id,
            typ,
            attr: attr.clone(),
            label,
            nexthop,
            enhe_egress,
            stale,
            nexthop_reachable,
            vrf_transit_only: false,
            decision: None,
            compute_policy: true,
        });
        pool.dispatch(pool.shard_of(std::net::IpAddr::V4(nlri.prefix.addr())), msg);
        return Vec::new();
    }

    // N=1: main resolves NHT + the Inter-AS Option AB transit flag on the
    // (already-computed) decision, then the synchronous shard applies it.
    // `import_attr` feeds the VPNv4 import-withdraw dispatch.
    let (nexthop_reachable, vrf_transit_only, import_attr) = match &decision {
        Some(d) => {
            let reachable = if enhe_egress.is_none() {
                nht_track_received_attr(bgp, &d.attr, dep.clone())
            } else {
                true
            };
            let transit = rd.is_some()
                && peer_ident != ORIGINATED_PEER
                && bgp.vrf_import.is_some_and(|disp| {
                    super::inst::rt_imported_by_hybrid_vrf_v4(disp.rib_known_vrfs, &d.attr.ecom)
                });
            (reachable, transit, d.attr.clone())
        }
        None => (true, false, attr.clone()),
    };
    let msg = ShardMsg::UpdateV4(ShardUpdateV4 {
        ident: peer_ident,
        rd,
        nlri: nlri.clone(),
        peer_router_id,
        typ,
        attr: attr.clone(),
        label,
        nexthop,
        enhe_egress,
        stale,
        nexthop_reachable,
        vrf_transit_only,
        decision,
        compute_policy: false,
    });
    let deltas = bgp
        .shard
        .handle(msg, bgp.central_label_alloc.as_deref_mut());

    let mut jobs = Vec::new();
    for delta in deltas {
        let ShardOut::BestPathV4 {
            rd,
            prefix,
            selected,
            replaced,
            added,
            survivor_nexthops,
            ..
        } = delta
        else {
            continue;
        };
        // Release displaced next-hops (survivors computed by the shard).
        if bgp.nexthop_cache.is_some() && !replaced.is_empty() {
            nht_untrack_withdrawn(bgp, &replaced, &survivor_nexthops, dep.clone());
        }
        // Per-VRF VPNv4 export (rd == None, inside a VRF task).
        if rd.is_none()
            && let Some(exporter) = bgp.vrf_export
        {
            if let Some(winner) = selected.first() {
                super::vrf::vrf_emit_export(exporter, prefix.prefix, &winner.attr);
            } else {
                super::vrf::vrf_emit_withdraw(exporter, prefix.prefix);
            }
        }
        // Global v4vpn best-path → per-VRF import (rd == Some, global).
        if let Some(rd) = rd
            && let Some(dispatcher) = bgp.vrf_import
        {
            if let Some(winner) = selected.first() {
                let (label, transport) = vpn_import_transport(bgp, winner);
                super::vrf::dispatch_import_v4(
                    dispatcher,
                    rd,
                    prefix.prefix,
                    &winner.attr,
                    label,
                    transport,
                    None,
                );
            } else {
                super::vrf::dispatch_withdraw_import_v4(
                    dispatcher,
                    rd,
                    prefix.prefix,
                    &import_attr,
                    None,
                );
            }
        }
        // Kernel FIB (unicast) / swap-ILM reconcile (VPNv4).
        if rd.is_none() {
            fib_install_v4(bgp, prefix.prefix, &selected);
        } else {
            reconcile_swap_ilm(
                bgp.rib_client,
                bgp.nexthop_cache.as_deref(),
                selected.first(),
            );
        }
        // Defer the advertise (out-policy + AddPath) to the caller so the
        // batch path can precompute the per-group outcomes in parallel.
        jobs.push(Ipv4AdvertiseJob {
            rd,
            prefix: prefix.prefix,
            selected,
            added,
            replaced,
        });
    }
    jobs
}

/// Run one [`Ipv4AdvertiseJob`]'s advertise: the out-policy fan-out (an
/// empty `selected` withdraws) plus the AddPath added/removed deltas.
/// `memo` is the per-group outcome map — empty for the single-prefix
/// path (computed inline) or parallel-precomputed for the batch.
fn apply_ipv4_advertise_job(
    job: Ipv4AdvertiseJob,
    source_ident: usize,
    memo: BTreeMap<super::update_group::UpdateGroupId, AdvertiseOutcome<Ipv4Nlri>>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let Ipv4AdvertiseJob {
        rd,
        prefix,
        selected,
        added,
        replaced,
    } = job;
    route_advertise_batch::<V4Batch>(rd, prefix, &selected, source_ident, bgp, peers, memo);
    match &added {
        Some(added) => {
            route_advertise_to_addpath(rd, prefix, added, source_ident, bgp, peers);
        }
        None => {
            for removed in &replaced {
                route_withdraw_from_addpath(rd, prefix, removed, source_ident, bgp, peers);
            }
        }
    }
}

/// Reduce side of the shard pool for v4-unicast (RIB sharding N-shard
/// B.1 + Phase E.1): apply one worker's whole `ShardResult` of best-path
/// deltas. NHT untrack + FIB install run serially per delta (the NHT
/// cache and the FIB client are main-owned), then the advertise
/// out-policy + attribute transform are **precomputed in parallel across
/// the batch** (`precompute_ipv4_advertise_outcomes`, the C.2 routine),
/// then the bucketing / adj-out apply serially off the memos in delta
/// order. Restores the C.2 out-policy parallelism the N-shard reduce had
/// lost — `route_ipv4_update_decided`'s shard branch returns no inline
/// advertise job, so without this the reduce ran the out-policy serially.
/// Unicast only — the pool never carries VPNv4 (`rd == Some` stays on the
/// synchronous shard), so there is no VRF import/export or transit-label
/// work here.
pub(super) fn route_apply_bestpath_v4_batch(
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    outs: Vec<ShardOut>,
) {
    // N>1 read replica: ingest + best-path for v4-unicast ran on the
    // worker pool, so the main shard's `v4` table is empty. The
    // synchronous main-task read paths still read it (`route_sync_ipv4`
    // dumps `bgp.shard.v4` to a new peer; `show bgp ipv4` reads it). Keep
    // it in step by mirroring each delta before consuming it for the
    // advertise. This reduce only runs at N>1 (it is dispatched solely
    // from `process_shard_result`), so the N=1 path is untouched.
    for out in &outs {
        mirror_v4_delta(bgp, out);
    }

    // Cost-gate the parallel precompute. Its whole purpose is to fan out
    // the out-policy prefix-set walk; with no out-policy bound on any
    // advertised-to peer there is nothing expensive to amortize, and at
    // N ≈ cores there are no spare cores — rayon's pool would only
    // steal them from the (CPU-bound) shard threads doing best-path
    // (measured 3x slower on a no-policy full-table load). So parallelize
    // egress only when out-policy makes egress the bottleneck (the shards
    // are then mostly idle).
    let worth_parallel = any_established_out_policy_v4(peers);

    if !worth_parallel {
        // Serial, per delta — byte-identical to the pre-E.1 reduce (no
        // jobs / memos vectors): NHT untrack + FIB install + inline
        // advertise with an empty memo (computed on the first group member).
        for out in outs {
            if let Some((ident, job)) = reduce_bestpath_v4_nht_fib(bgp, out) {
                apply_ipv4_advertise_job(job, ident, BTreeMap::new(), bgp, peers);
            }
        }
        return;
    }

    // Parallel path: collect the advertise jobs (NHT + FIB serial per
    // delta), precompute each job's per-(prefix, group) out-policy walk +
    // attribute transform across the batch, then apply the bucketing
    // serially off the memos in delta order (per-prefix ordering preserved).
    let mut jobs: Vec<Ipv4AdvertiseJob> = Vec::with_capacity(outs.len());
    let mut idents: Vec<usize> = Vec::with_capacity(outs.len());
    for out in outs {
        if let Some((ident, job)) = reduce_bestpath_v4_nht_fib(bgp, out) {
            jobs.push(job);
            idents.push(ident);
        }
    }
    let memos = precompute_ipv4_advertise_outcomes(&jobs, bgp, peers);
    for ((job, memo), ident) in jobs.into_iter().zip(memos).zip(idents) {
        apply_ipv4_advertise_job(job, ident, memo, bgp, peers);
    }
}

/// Mirror one pool `BestPathV4` delta into the main shard's v4-unicast
/// Loc-RIB so the synchronous read paths see it at N>1 (read replica).
/// VPNv4 (`rd = Some`) is not pool-dispatched, so only `rd = None` is
/// mirrored; non-`BestPathV4` deltas are ignored.
fn mirror_v4_delta(bgp: &mut BgpTop, out: &ShardOut) {
    if let ShardOut::BestPathV4 {
        rd: None,
        prefix,
        selected,
        replaced,
        added,
        ..
    } = out
    {
        bgp.shard
            .mirror_v4(prefix.prefix, added.as_ref(), replaced, selected.first());
    }
}

/// NHT untrack + FIB install for one v4 best-path delta — the main-owned,
/// always-serial half of the reduce (the NHT cache and FIB client are
/// single-owner). Returns the advertise job + its source ident; `None` for
/// a non-`BestPathV4` out.
fn reduce_bestpath_v4_nht_fib(
    bgp: &mut BgpTop,
    out: ShardOut,
) -> Option<(usize, Ipv4AdvertiseJob)> {
    let ShardOut::BestPathV4 {
        ident,
        rd: _,
        prefix,
        selected,
        replaced,
        added,
        survivor_nexthops,
    } = out
    else {
        return None;
    };
    if bgp.nexthop_cache.is_some() && !replaced.is_empty() {
        nht_untrack_withdrawn(
            bgp,
            &replaced,
            &survivor_nexthops,
            super::nht::NhtDep::V4(prefix.prefix),
        );
    }
    fib_install_v4(bgp, prefix.prefix, &selected);
    Some((
        ident,
        Ipv4AdvertiseJob {
            rd: None,
            prefix: prefix.prefix,
            selected,
            added,
            replaced,
        },
    ))
}

fn rtc_match(rtc: &BTreeSet<ExtCommunityValue>, ecom: &Option<ExtCommunity>) -> bool {
    if let Some(ecom) = ecom {
        // Extended community value in RIB.
        for eval in ecom.0.iter() {
            // When the value matches one of RTC, return true;
            for rt in rtc.iter() {
                if eval == rt {
                    return true;
                }
            }
        }
    }
    false
}

/// Generic AddPath advertise for the delta-driven (one-rib) BatchAfi
/// families: advertise `rib` (carrying its path-id) to every AddPath-Send
/// peer. v4-unicast/VPNv4 (V4Batch) and VPNv6 (V6Batch) share this; the
/// v6-unicast AddPath is diff-based and keeps its own inline loop.
fn route_advertise_batch_addpath<A: BatchAfi>(
    rd: Option<RouteDistinguisher>,
    prefix: A::Prefix,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let (afi, safi) = A::afi_safi(rd);
    for ident in peers.established_addpath_idents(afi, safi) {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        // RFC 9494 §4.3: stale routes only go to LLGR peers.
        if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, afi, safi) {
            continue;
        }
        A::advertise_addpath(peer, rd, prefix, rib, bgp);
    }
}

/// Advertise one added/changed IPv4-unicast or VPNv4 AddPath path. Thin
/// wrapper over [`route_advertise_batch_addpath`].
fn route_advertise_to_addpath(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    rib: &BgpRib,
    _source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    route_advertise_batch_addpath::<V4Batch>(rd, prefix, rib, bgp, peers);
}

fn route_withdraw_from_addpath(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    removed: &BgpRib,
    _source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };
    let afi_safi = AfiSafi::new(afi, safi);

    let peer_idents: Vec<usize> = peers.established_addpath_idents(afi, safi);

    for ident in peer_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");

        if let Some(ref rd) = rd {
            peer.cache_remove_vpnv4(*rd, prefix, removed.local_id);
        } else {
            // Group cache cleanup. Idempotent across the peer
            // iteration: first peer in the group cleans the bucket;
            // subsequent peers find it gone.
            let group_id = peer.update_group_id.get(&afi_safi).cloned();
            if let Some(gid) = group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::cache_remove_ipv4(group, prefix, removed.local_id);
            }
        }
        withdraw_ipv4_deferrable(bgp.update_groups, peer, rd, prefix, removed.local_id);
        peer.adj_out.remove(rd, prefix, removed.local_id);
    }
}

/// Advertise route changes to all appropriate peers
/// Outcome of running the canonical-member transform + outbound
/// policy for a route. Identical for every member of an
/// `update-group` for a given (route, AFI/SAFI), modulo per-peer
/// split-horizon (handled before cache lookup) and per-peer RTC
/// (applied after).
#[derive(Clone)]
enum AdvertiseOutcome<N> {
    Advertise(N, BgpAttr),
    Withdraw,
}

/// Run `route_update_ipv4` + `route_apply_policy_out` for `peer`.
/// Caller has already verified split-horizon does NOT fire for this
/// peer (`best.ident != peer.ident`); other filters inside
/// `route_update_ipv4` (notably the iBGP-iBGP rule) depend only on
/// signature fields, so the result is identical for every other
/// non-source member of the same update-group.
fn compute_advertise_outcome(
    peer: &Peer,
    prefix: &Ipv4Net,
    best: &BgpRib,
    bgp: &BgpTop,
    add_path: bool,
) -> AdvertiseOutcome<Ipv4Nlri> {
    if let Some((nlri, attr)) = route_update_ipv4(peer, prefix, best, bgp, add_path) {
        if let Some(decision) = route_apply_policy_out(peer, &nlri, attr, best.weight) {
            bgp_adj_out_trace!(peer, prefix = %prefix, "advertise");
            AdvertiseOutcome::Advertise(nlri, decision.attr)
        } else {
            AdvertiseOutcome::Withdraw
        }
    } else {
        AdvertiseOutcome::Withdraw
    }
}

/// Bump per-group counters for one cache miss. `denied` is true when
/// the computed outcome was `Withdraw` because the outbound policy
/// returned None — distinguishes deny-by-policy from skip-by-no-best.
fn bump_group_counters_on_miss(
    bgp: &mut BgpTop,
    afi_safi: AfiSafi,
    id: &super::update_group::UpdateGroupId,
    denied: bool,
) {
    let Some(af) = bgp.update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };
    group.counters.policy_runs += 1;
    if denied {
        group.counters.policy_denials += 1;
    }
}

pub(super) fn route_advertise_to_peers(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    selected: &[BgpRib],
    source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    // Non-batch callers run the out-policy inline (empty pre-seeded memo).
    route_advertise_batch::<V4Batch>(
        rd,
        prefix,
        selected,
        source_peer,
        bgp,
        peers,
        BTreeMap::new(),
    );
}

/// Per-AF hooks for the generic update-group/memo advertise path
/// ([`route_advertise_batch`]). Phase 2 of the Adj-RIB-Out unification:
/// v4-unicast/VPNv4 (`V4Batch`) and v6-unicast/VPNv6 (`V6Batch`) share the
/// memo loop + group-counter logic; the AF impls own the prefix/NLRI type,
/// the build (`compute_outcome`), and the per-peer `advertise` / `withdraw`
/// (which dispatch unicast vs VPN on `rd`). `afi` is fixed per impl; `safi`
/// (Unicast vs MplsVpn) follows `rd`.
trait BatchAfi {
    type Prefix: Copy;
    type Nlri: Clone;
    fn afi_safi(rd: Option<RouteDistinguisher>) -> (Afi, Safi);
    fn compute_outcome(
        peer: &mut Peer,
        prefix: &Self::Prefix,
        best: &BgpRib,
        bgp: &mut BgpTop,
        add_path: bool,
    ) -> AdvertiseOutcome<Self::Nlri>;
    #[allow(clippy::too_many_arguments)]
    fn advertise(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Self::Prefix,
        nlri: Self::Nlri,
        attr: BgpAttr,
        new_best: Option<&BgpRib>,
        bgp: &mut BgpTop,
    );
    fn withdraw(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Self::Prefix,
        new_best: Option<&BgpRib>,
        bgp: &mut BgpTop,
    );
    /// Advertise one AddPath candidate `rib` (carrying its path-id) to a
    /// single AddPath-Send peer. The peer loop + LLGR gate live in
    /// [`route_advertise_batch_addpath`]; split-horizon is enforced by the
    /// per-AF `route_update_*`.
    fn advertise_addpath(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Self::Prefix,
        rib: &BgpRib,
        bgp: &mut BgpTop,
    );
}

struct V4Batch;
impl BatchAfi for V4Batch {
    type Prefix = Ipv4Net;
    type Nlri = Ipv4Nlri;

    fn afi_safi(rd: Option<RouteDistinguisher>) -> (Afi, Safi) {
        if rd.is_some() {
            (Afi::Ip, Safi::MplsVpn)
        } else {
            (Afi::Ip, Safi::Unicast)
        }
    }
    fn compute_outcome(
        peer: &mut Peer,
        prefix: &Ipv4Net,
        best: &BgpRib,
        bgp: &mut BgpTop,
        add_path: bool,
    ) -> AdvertiseOutcome<Ipv4Nlri> {
        compute_advertise_outcome(peer, prefix, best, bgp, add_path)
    }
    fn advertise(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        nlri: Ipv4Nlri,
        attr: BgpAttr,
        new_best: Option<&BgpRib>,
        bgp: &mut BgpTop,
    ) {
        let (afi, safi) = Self::afi_safi(rd);
        let afi_safi = AfiSafi::new(afi, safi);
        if rd.is_some() && !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
            // RTC: per-peer; skip without withdrawing.
            return;
        }
        let attr = bgp.attr_store.intern(attr);
        if let Some(best) = new_best {
            let mut rib = best.clone();
            rib.attr = attr.clone();
            peer.adj_out.add(rd, prefix, rib);
        }
        if let Some(rd) = rd {
            let vpnv4_nlri = Vpnv4Nlri {
                label: new_best
                    .map(|b| vpnv4_service_label(peer, b))
                    .unwrap_or_default(),
                rd,
                nlri,
            };
            peer.send_vpnv4(vpnv4_nlri, attr, true);
        } else {
            let source_ident = new_best.map(|b| b.ident).unwrap_or(peer.ident);
            let group_id = peer.update_group_id.get(&afi_safi).cloned();
            if let Some(gid) = group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::send_ipv4(group, nlri, attr, source_ident, bgp.tx, true);
            } else {
                tracing::warn!(
                    peer = %peer.address,
                    prefix = %prefix,
                    "IPv4 advertise: peer is Established but not in any update-group; advertise skipped"
                );
            }
        }
    }
    fn withdraw(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        new_best: Option<&BgpRib>,
        bgp: &mut BgpTop,
    ) {
        let (afi, safi) = Self::afi_safi(rd);
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(rd) = rd {
            peer.cache_remove_vpnv4(rd, prefix, 0);
        } else {
            // Per-peer Withdraws (split-horizon / LLGR gate) must not clobber
            // the group's pending entry, which other members may still want.
            let per_peer_suppress = new_best
                .map(|b| {
                    b.ident == peer.ident
                        || llgr_blocks_advertisement(b.stale, &peer.cap_recv, afi, safi)
                })
                .unwrap_or(false);
            if !per_peer_suppress
                && let Some(gid) = peer.update_group_id.get(&afi_safi).cloned()
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::cache_remove_ipv4(group, prefix, 0);
            }
        }
        if peer.adj_out.contains_key(rd, &prefix) {
            withdraw_ipv4_deferrable(bgp.update_groups, peer, rd, prefix, 0);
            peer.adj_out.remove(rd, prefix, 0);
        }
    }
    fn advertise_addpath(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        rib: &BgpRib,
        bgp: &mut BgpTop,
    ) {
        let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, rib, bgp, true) else {
            return;
        };
        let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
            return;
        };
        let attr = decision.attr;
        if rd.is_some() && !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
            return;
        }
        let attr = bgp.attr_store.intern(attr);
        let mut rib_clone = rib.clone();
        rib_clone.attr = attr.clone();
        peer.adj_out.add(rd, prefix, rib_clone);
        if let Some(rd) = rd {
            let vpnv4_nlri = Vpnv4Nlri {
                label: vpnv4_service_label(peer, rib),
                rd,
                nlri,
            };
            peer.send_vpnv4(vpnv4_nlri, attr, true);
        } else {
            let (afi, safi) = Self::afi_safi(rd);
            let afi_safi = AfiSafi::new(afi, safi);
            let group_id = peer.update_group_id.get(&afi_safi).cloned();
            if let Some(gid) = group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::send_ipv4(group, nlri, attr, rib.ident, bgp.tx, true);
            } else {
                tracing::warn!(
                    peer = %peer.address,
                    prefix = %prefix,
                    "IPv4 addpath advertise: peer Established but not in any update-group; advertise skipped"
                );
            }
        }
    }
}

/// IPv6 twin of [`compute_advertise_outcome`] (the build + out-policy that
/// `V6Batch::compute_outcome` runs). `&mut` because `route_update_ipv6`
/// takes it; the v6 path has no parallel batch precompute, so this only
/// ever runs inline on the advertise loop.
fn compute_advertise_outcome_v6(
    peer: &mut Peer,
    prefix: &Ipv6Net,
    best: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> AdvertiseOutcome<Ipv6Nlri> {
    if let Some((nlri, attr)) = route_update_ipv6(peer, prefix, best, bgp, add_path) {
        if let Some(decision) = route_apply_policy_out_v6(peer, &nlri, attr, best.weight) {
            AdvertiseOutcome::Advertise(nlri, decision.attr)
        } else {
            AdvertiseOutcome::Withdraw
        }
    } else {
        AdvertiseOutcome::Withdraw
    }
}

struct V6Batch;
impl BatchAfi for V6Batch {
    type Prefix = Ipv6Net;
    type Nlri = Ipv6Nlri;

    fn afi_safi(rd: Option<RouteDistinguisher>) -> (Afi, Safi) {
        if rd.is_some() {
            (Afi::Ip6, Safi::MplsVpn)
        } else {
            (Afi::Ip6, Safi::Unicast)
        }
    }
    fn compute_outcome(
        peer: &mut Peer,
        prefix: &Ipv6Net,
        best: &BgpRib,
        bgp: &mut BgpTop,
        add_path: bool,
    ) -> AdvertiseOutcome<Ipv6Nlri> {
        compute_advertise_outcome_v6(peer, prefix, best, bgp, add_path)
    }
    fn advertise(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Net,
        nlri: Ipv6Nlri,
        attr: BgpAttr,
        new_best: Option<&BgpRib>,
        bgp: &mut BgpTop,
    ) {
        let (afi, safi) = Self::afi_safi(rd);
        let afi_safi = AfiSafi::new(afi, safi);
        if rd.is_some() && !peer.rtcv6.is_empty() && !rtc_match(&peer.rtcv6, &attr.ecom) {
            // RTC: per-peer; skip without withdrawing.
            return;
        }
        let attr = bgp.attr_store.intern(attr);
        if let Some(rd) = rd {
            // VPNv6: store best.clone() under the RD; send via send_vpnv6.
            if let Some(best) = new_best {
                peer.adj_out
                    .v6vpn
                    .entry(rd)
                    .or_default()
                    .add(prefix, best.clone());
            }
            let vpnv6_nlri = Vpnv6Nlri {
                label: new_best
                    .map(|b| b.label.unwrap_or_default())
                    .unwrap_or_default(),
                rd,
                nlri,
            };
            peer.send_vpnv6(vpnv6_nlri, attr, true);
        } else {
            // v6-unicast: store the interned rib in `v6`; send via update-group.
            if let Some(best) = new_best {
                let mut rib = best.clone();
                rib.attr = attr.clone();
                peer.adj_out.v6.add(prefix, rib);
            }
            let source_ident = new_best.map(|b| b.ident).unwrap_or(peer.ident);
            let group_id = peer.update_group_id.get(&afi_safi).cloned();
            if let Some(gid) = group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::send_ipv6(group, nlri, attr, source_ident, bgp.tx, true);
            } else {
                tracing::warn!(
                    peer = %peer.address,
                    prefix = %prefix,
                    "IPv6 advertise: peer is Established but not in any update-group; advertise skipped"
                );
            }
        }
    }
    fn withdraw(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Net,
        _new_best: Option<&BgpRib>,
        bgp: &mut BgpTop,
    ) {
        let (afi, safi) = Self::afi_safi(rd);
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(rd) = rd {
            // VPNv6: withdraw only from PEs whose v6vpn Adj-RIB-Out holds it.
            if peer
                .adj_out
                .v6vpn
                .get(&rd)
                .is_some_and(|t| t.0.contains_key(&prefix))
            {
                peer.cache_remove_vpnv6(rd, prefix, 0);
                route_withdraw_vpnv6(peer, rd, prefix, 0);
                if let Some(t) = peer.adj_out.v6vpn.get_mut(&rd) {
                    t.remove(prefix, 0);
                }
            }
        } else {
            // v6-unicast: withdraw only from peers whose v6 Adj-RIB-Out holds it.
            if peer.adj_out.v6.0.contains_key(&prefix) {
                let group_id = peer.update_group_id.get(&afi_safi).cloned();
                if let Some(gid) = group_id
                    && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                    && let Some(group) = af.group_by_id_mut(&gid)
                {
                    super::update_group::cache_remove_ipv6(group, prefix, 0);
                }
                withdraw_ipv6_deferrable(bgp.update_groups, peer, prefix, 0);
                peer.adj_out.v6.remove(prefix, 0);
            }
        }
    }
    fn advertise_addpath(
        peer: &mut Peer,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Net,
        rib: &BgpRib,
        bgp: &mut BgpTop,
    ) {
        let Some((nlri, attr)) = route_update_ipv6(peer, &prefix, rib, bgp, true) else {
            return;
        };
        let attr = bgp.attr_store.intern(attr);
        if let Some(rd) = rd {
            // VPNv6 AddPath (current behavior: RTC only, no out-policy/adj_out).
            if !peer.rtcv6.is_empty() && !rtc_match(&peer.rtcv6, &attr.ecom) {
                return;
            }
            let vpnv6_nlri = Vpnv6Nlri {
                label: rib.label.unwrap_or_default(),
                rd,
                nlri,
            };
            peer.send_vpnv6(vpnv6_nlri, attr, true);
        } else {
            // v6-unicast AddPath (current behavior: no out-policy).
            let (afi, safi) = Self::afi_safi(rd);
            let afi_safi = AfiSafi::new(afi, safi);
            let group_id = peer.update_group_id.get(&afi_safi).cloned();
            if let Some(gid) = group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::send_ipv6(group, nlri, attr, rib.ident, bgp.tx, true);
                peer.adj_out.v6.add(prefix, rib.clone());
            } else {
                tracing::warn!(
                    peer = %peer.address,
                    prefix = %prefix,
                    "IPv6 AddPath advertise: peer Established but not in any update-group; advertise skipped"
                );
            }
        }
    }
}

/// Generic update-group advertise with the per-group outcome memo, shared
/// across address families via [`BatchAfi`]. The memo caches the
/// post-policy outcome per `update-group` (members share it, modulo
/// per-peer split-horizon / LLGR / RTC which are handled outside the
/// cache); the map may arrive pre-seeded from the IPv4 batch precompute.
fn route_advertise_batch<A: BatchAfi>(
    rd: Option<RouteDistinguisher>,
    prefix: A::Prefix,
    selected: &[BgpRib],
    _source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    mut memo: BTreeMap<super::update_group::UpdateGroupId, AdvertiseOutcome<A::Nlri>>,
) {
    let new_best = selected.last();
    let (afi, safi) = A::afi_safi(rd);
    let afi_safi = AfiSafi::new(afi, safi);
    let peer_idents: Vec<usize> = peers.established_plain_idents(afi, safi);
    let mut bumped: BTreeSet<super::update_group::UpdateGroupId> = BTreeSet::new();

    for ident in peer_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        let add_path = peer.opt.is_add_path_send(afi, safi);
        let group_id = peer.update_group_id.get(&afi_safi).cloned();

        let outcome = match new_best {
            None => AdvertiseOutcome::Withdraw,
            Some(best) if best.ident == peer.ident => AdvertiseOutcome::Withdraw,
            Some(best) if llgr_blocks_advertisement(best.stale, &peer.cap_recv, afi, safi) => {
                AdvertiseOutcome::Withdraw
            }
            Some(best) => match group_id.as_ref() {
                Some(gid) => {
                    let outcome = match memo.get(gid) {
                        Some(cached) => cached.clone(),
                        None => {
                            let outcome = A::compute_outcome(peer, &prefix, best, bgp, add_path);
                            memo.insert(gid.clone(), outcome.clone());
                            outcome
                        }
                    };
                    if bumped.insert(gid.clone()) {
                        let denied = matches!(outcome, AdvertiseOutcome::Withdraw);
                        bump_group_counters_on_miss(bgp, afi_safi, gid, denied);
                    }
                    outcome
                }
                None => A::compute_outcome(peer, &prefix, best, bgp, add_path),
            },
        };

        match outcome {
            AdvertiseOutcome::Advertise(nlri, attr) => {
                A::advertise(peer, rd, prefix, nlri, attr, new_best, bgp);
            }
            AdvertiseOutcome::Withdraw => {
                A::withdraw(peer, rd, prefix, new_best, bgp);
            }
        }
    }
}

/// Per-peer EVPN advertise builder. Mirrors `route_update_ipv4`:
/// applies split-horizon, the iBGP-iBGP / route-reflector filter,
/// and fixes up AS_PATH / NEXT_HOP / LOCAL_PREF for the outgoing
/// direction. Returns `(EvpnRoute, BgpAttr)` if the peer should
/// receive an advertisement, `None` otherwise.
///
/// VNI is sourced from the RT extended community on the inbound
/// attribute (per RFC 8365 §5.1.2.4). For locally-originated routes
/// `evpn_originate_macip` attaches the RT first, so the lookup
/// always succeeds; for re-advertised routes the upstream RT is
/// preserved.
pub fn route_update_evpn(
    peer: &mut Peer,
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> Option<(EvpnRoute, BgpAttr)> {
    if rib.ident == peer.ident {
        return None;
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    // RFC 1997 well-known communities: NO_ADVERTISE / NO_EXPORT.
    if community_suppresses_advertisement(&rib.attr, peer.peer_type) {
        return None;
    }

    let id = if add_path { rib.local_id } else { 0 };

    let route = match prefix {
        EvpnPrefix::MacIp { eth_tag, mac, .. } => {
            let vni = extract_vni_from_attr(&rib.attr).unwrap_or(0);
            EvpnRoute::Mac(EvpnMac {
                id,
                rd: *rd,
                esi: rib.esi.unwrap_or([0; 10]),
                ether_tag: *eth_tag,
                mac: *mac,
                vni,
            })
        }
        EvpnPrefix::InclusiveMulticast { eth_tag, orig } => EvpnRoute::Multicast(EvpnMulticast {
            id,
            rd: *rd,
            ether_tag: *eth_tag,
            addr: *orig,
        }),
        EvpnPrefix::IpPrefix { eth_tag, prefix } => {
            // Type-5: the MPLS service label rides on the BgpRib; the
            // gateway IP defaults to the prefix family's unspecified
            // address (interface-less model — forwarding recurses on the
            // BGP next-hop).
            let gw = match prefix.addr() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            EvpnRoute::Prefix(EvpnIpPrefix {
                id,
                rd: *rd,
                esi: rib.esi.unwrap_or([0; 10]),
                ether_tag: *eth_tag,
                prefix: *prefix,
                gw,
                label: rib.label.as_ref().map(|l| l.label).unwrap_or(0),
            })
        }
    };

    let mut attrs = (*rib.attr).clone();

    ebgp_egress_aspath(peer, &mut attrs);

    if peer.is_ebgp() || rib.is_originated() {
        let nexthop: IpAddr = if let Some(ref local_addr) = peer.param.local_addr {
            local_addr.ip()
        } else {
            IpAddr::V4(*bgp.router_id)
        };
        attrs.nexthop = Some(BgpNexthop::Evpn(nexthop));
    }

    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }

    Some((route, attrs))
}

/// Send a single EVPN withdraw to one peer. Mirrors
/// `route_withdraw_ipv4` — no caching, straight to the wire as a
/// one-NLRI MP_UNREACH UPDATE. The receiver removes the route from
/// its adj-RIB-in and re-runs best-path; an empty selection at the
/// peer triggers `route_evpn_export_selected` which sends
/// `Message::MacDel` / `MdbDel` and the kernel FDB row goes away.
fn route_withdraw_evpn(peer: &mut Peer, route: EvpnRoute) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Evpn(vec![route]));
    peer.send_packet(update.into());
}

/// Fan out a withdraw to every peer with `(L2vpn, Evpn)` Established.
/// Also drains any pending advertise from each peer's `cache_evpn` —
/// without this, a quick add/remove cycle would leave a stale
/// announce in the cache that fires after the withdraw wins on the
/// wire.
/// Withdraw one EVPN `(rd, prefix)` path identified by `id` from a
/// single `peer`: drop any queued advertise from its cache, drop the
/// Adj-RIB-Out entry, and emit the MP_UNREACH. `id == 0` is the
/// non-AddPath sentinel (no path-id on the wire, whole-prefix
/// Adj-RIB-Out clear); a non-zero `id` withdraws exactly that path.
fn evpn_withdraw_one(peer: &mut Peer, rd: &RouteDistinguisher, prefix: &EvpnPrefix, id: u32) {
    let route = evpn_route_from_prefix(rd, prefix, id);
    // Drop a queued advertise for the same route from the peer's cache
    // so flush_evpn doesn't ship a now-stale add after the withdraw.
    if let Some(attr) = peer.cache_evpn_rev.remove(&route)
        && let Some(set) = peer.cache_evpn.get_mut(&attr)
    {
        set.remove(&route);
        if set.is_empty() {
            peer.cache_evpn.remove(&attr);
        }
    }
    // Drop the Adj-RIB-Out entry so soft-out's baseline reflects
    // reality — without this a follow-up policy change would think the
    // route is still advertised and emit a redundant withdraw.
    peer.adj_out.remove_evpn(*rd, prefix, id);
    route_withdraw_evpn(peer, route);
}

pub fn route_withdraw_evpn_to_peers(
    rd: RouteDistinguisher,
    prefix: EvpnPrefix,
    peers: &mut PeerMap,
) {
    // Non-AddPath members: a single id-less MP_UNREACH clears the prefix.
    for ident in peers.established_plain_idents(Afi::L2vpn, Safi::Evpn) {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        evpn_withdraw_one(peer, &rd, &prefix, 0);
    }

    // AddPath members: withdraw every path-id we advertised for this
    // prefix (read from the Adj-RIB-Out, the record of what was sent).
    for ident in peers.established_addpath_idents(Afi::L2vpn, Safi::Evpn) {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        let ids: Vec<u32> = peer
            .adj_out
            .evpn
            .get(&rd)
            .and_then(|t| t.0.get(&prefix))
            .map(|cands| cands.iter().map(|r| r.local_id).collect())
            .unwrap_or_default();
        for id in ids {
            evpn_withdraw_one(peer, &rd, &prefix, id);
        }
    }
}

/// Build an `EvpnRoute` (Mac/Multicast) from an `(rd, prefix)` pair
/// — needed both at advertise time (in `route_update_evpn` via the
/// inbound BgpRib's attr) and at withdraw time, where there's no
/// inbound attr to consult and the VNI is recovered from the RD's
/// trailing 2 bytes (Type-1 form). ESI defaults to zero, eth-tag
/// passes through.
fn evpn_route_from_prefix(rd: &RouteDistinguisher, prefix: &EvpnPrefix, id: u32) -> EvpnRoute {
    match prefix {
        EvpnPrefix::MacIp { eth_tag, mac, .. } => {
            // RD type 1 (IPv4 + 2-byte assigned-number) is the form
            // we emit at origination — the assigned-number bytes
            // [4..6] carry the low 16 bits of the VNI.
            let vni = u16::from_be_bytes([rd.val[4], rd.val[5]]) as u32;
            EvpnRoute::Mac(EvpnMac {
                id,
                rd: *rd,
                esi: [0; 10],
                ether_tag: *eth_tag,
                mac: *mac,
                vni,
            })
        }
        EvpnPrefix::InclusiveMulticast { eth_tag, orig } => EvpnRoute::Multicast(EvpnMulticast {
            id,
            rd: *rd,
            ether_tag: *eth_tag,
            addr: *orig,
        }),
        EvpnPrefix::IpPrefix { eth_tag, prefix } => {
            // Withdraw-side reconstruction: no inbound attr, so the label
            // is 0 (a Type-5 withdrawal is matched on the NLRI key, not
            // the label) and the gateway defaults to the family's
            // unspecified address.
            let gw = match prefix.addr() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            EvpnRoute::Prefix(EvpnIpPrefix {
                id,
                rd: *rd,
                esi: [0; 10],
                ether_tag: *eth_tag,
                prefix: *prefix,
                gw,
                label: 0,
            })
        }
    }
}

/// Advertise one EVPN candidate `rib` of `(rd, prefix)` to a single
/// `peer`: run the split-horizon / iBGP / community gate
/// (`route_update_evpn`, which stamps the path-id when `add_path`),
/// the outbound policy, record the Adj-RIB-Out entry, and queue the
/// send. Shared by the best-path (plain) and per-candidate (AddPath)
/// fan-outs and by the EVPN soft-out. No-op when any gate rejects.
fn evpn_advertise_one(
    peer: &mut Peer,
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> bool {
    // RFC 9494 §4.3: stale routes only go to LLGR peers.
    if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, Afi::L2vpn, Safi::Evpn) {
        return false;
    }
    let Some((route, attr)) = route_update_evpn(peer, rd, prefix, rib, bgp, add_path) else {
        return false;
    };
    let Some(decision) = route_apply_policy_out_evpn(peer, &route, attr, rib.weight) else {
        return false;
    };
    let attr = bgp.attr_store.intern(decision.attr);
    // Record what we advertised so a later policy change can diff the
    // Adj-RIB-Out against the Loc-RIB and withdraw what the new policy
    // now denies. Keyed by path-id, so AddPath candidates coexist.
    let mut adj = rib.clone();
    adj.attr = attr.clone();
    peer.adj_out.add_evpn(*rd, prefix.clone(), adj);
    peer.send_evpn(route, attr, true);
    true
}

/// Fan out an EVPN selection to every Established `(L2vpn, Evpn)` peer.
/// Plain members receive only the best path; AddPath members receive
/// every candidate in `selected`, each NLRI carrying its own path-id
/// (RFC 7911 §3). Split-horizon / iBGP rules are applied per candidate
/// inside `route_update_evpn`. Pairs with `route_withdraw_evpn_to_peers`.
pub fn route_advertise_evpn_to_peers(
    rd: RouteDistinguisher,
    prefix: EvpnPrefix,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let Some(new_best) = selected.last() else {
        return;
    };

    // Non-AddPath members: the best path only.
    for ident in peers.established_plain_idents(Afi::L2vpn, Safi::Evpn) {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        evpn_advertise_one(peer, &rd, &prefix, new_best, bgp, false);
    }

    // AddPath members: every candidate path, each with its path-id.
    for ident in peers.established_addpath_idents(Afi::L2vpn, Safi::Evpn) {
        for rib in selected {
            let peer = peers.get_mut_by_idx(ident).expect("peer exists");
            evpn_advertise_one(peer, &rd, &prefix, rib, bgp, true);
        }
    }
}

// Send BGP withdrawal for a prefix
pub(super) fn route_withdraw_ipv4(
    peer: &mut Peer,
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    id: u32,
) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());

    match rd {
        Some(rd) => {
            let vpnv4_nlri = Vpnv4Nlri {
                label: Label::default(),
                rd,
                nlri: Ipv4Nlri { id, prefix },
            };
            let mp_withdraw = MpUnreachAttr::Vpnv4(vec![vpnv4_nlri]);
            update.mp_withdraw = Some(mp_withdraw);
        }
        None => {
            let nlri = Ipv4Nlri { id, prefix };
            update.ipv4_withdraw.push(nlri);
        }
    }

    peer.send_packet(update.into());
}

/// Send — or, while the peer's update-group has a flush job in
/// flight, defer — a per-peer IPv4 withdraw (sharding plan A.2).
///
/// The flush worker may still be writing the in-flight job's announce
/// bytes onto the members' writer channels; a withdraw enqueued from
/// the main task now could be overtaken by an in-flight announce of
/// the same prefix, leaving the peer holding a stale route — and
/// unlike announce/announce inversions, nothing later corrects it.
/// Parked withdraws are replayed by `flush_done_ipv4` after every job
/// byte is enqueued. VPN withdraws (`rd = Some`) never ride the group
/// cache and always send immediately.
pub(super) fn withdraw_ipv4_deferrable(
    update_groups: &mut super::update_group::UpdateGroupMap,
    peer: &mut Peer,
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    id: u32,
) {
    if rd.is_none() {
        let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
        if let Some(gid) = peer.update_group_id.get(&afi_safi)
            && let Some(af) = update_groups.get_mut(&afi_safi)
            && let Some(group) = af.group_by_id_mut(gid)
            && group.flush_inflight_ipv4
        {
            group
                .deferred_withdraw_ipv4
                .push((peer.ident, Ipv4Nlri { id, prefix }));
            return;
        }
    }
    route_withdraw_ipv4(peer, rd, prefix, id);
}

// Soft-reconfiguration outbound: walk Loc-RIB for the AFI/SAFIs the
// peer has negotiated, run each prefix through the per-peer advertise
// builder + outbound policy, and either re-send the UPDATE or withdraw
// (when a previously-advertised prefix newly fails policy or filtering).
// Caller is responsible for ensuring the peer is established.
//
// Covers IPv4 unicast, IPv4 MPLS-VPN, and EVPN. Soft-in (replay of
// stored Adj-RIB-In through the new inbound policy) remains a
// separate path — see `route_soft_in_peer`.
pub fn route_soft_out_peer(peer_idx: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let (do_v4, vpn_rds, evpn_rds) = {
        let Some(peer) = peers.get_by_idx(peer_idx) else {
            return;
        };
        if !peer.state.is_established() {
            return;
        }
        let do_v4 = peer.is_afi_safi(Afi::Ip, Safi::Unicast);
        let do_vpn = peer.is_afi_safi(Afi::Ip, Safi::MplsVpn);
        let do_evpn = peer.is_afi_safi(Afi::L2vpn, Safi::Evpn);
        let v4vpn_rds: Vec<RouteDistinguisher> = if do_vpn {
            bgp.shard.v4vpn.keys().copied().collect()
        } else {
            Vec::new()
        };
        // Union the Loc-RIB RD set with the peer's Adj-RIB-Out RD
        // set so a policy change that purges every Loc-RIB entry
        // under an RD still drives a withdraw for whatever the peer
        // currently has under that RD.
        let evpn_rds: Vec<RouteDistinguisher> = if do_evpn {
            let mut s: BTreeSet<RouteDistinguisher> = bgp.local_rib.evpn.keys().copied().collect();
            s.extend(peer.adj_out.evpn.keys().copied());
            s.into_iter().collect()
        } else {
            Vec::new()
        };
        (do_v4, v4vpn_rds, evpn_rds)
    };

    if do_v4 {
        route_soft_out_peer_table(peer_idx, None, bgp, peers);
    }
    for rd in vpn_rds {
        route_soft_out_peer_table(peer_idx, Some(rd), bgp, peers);
    }
    for rd in evpn_rds {
        route_soft_out_peer_table_evpn(peer_idx, rd, bgp, peers);
    }
}

fn route_soft_out_peer_table(
    peer_idx: usize,
    rd: Option<RouteDistinguisher>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };

    // Snapshot Loc-RIB selected so the iteration outlives later
    // mutable borrows of `bgp` (attr_store.intern, send paths).
    let selected: Vec<(Ipv4Net, BgpRib)> = match rd {
        Some(rd) => bgp
            .shard
            .v4vpn
            .get(&rd)
            .map(|t| t.1.iter().map(|(p, r)| (p, r.clone())).collect())
            .unwrap_or_default(),
        None => bgp.shard.v4.1.iter().map(|(p, r)| (p, r.clone())).collect(),
    };

    // Snapshot what's currently in this peer's Adj-RIB-Out so we can
    // detect which previously-advertised prefixes need a withdraw.
    let was_advertised: BTreeSet<Ipv4Net> = {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        match rd {
            Some(rd) => peer
                .adj_out
                .v4vpn
                .get(&rd)
                .map(|t| t.0.keys().copied().collect())
                .unwrap_or_default(),
            None => peer.adj_out.v4.0.keys().copied().collect(),
        }
    };

    let mut newly_advertised: BTreeSet<Ipv4Net> = BTreeSet::new();
    // Soft-out targets a single peer; the per-group cache would
    // fan out to every member. Accumulate IPv4 unicast entries
    // and emit via `send_ipv4_direct` at the end so encoding
    // stays per-attr-batched without touching the group cache.
    let mut ipv4_entries: Vec<(Arc<BgpAttr>, Ipv4Nlri)> = Vec::new();

    for (prefix, rib) in &selected {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        let add_path = peer.opt.is_add_path_send(afi, safi);

        // RFC 9494 §4.3: stale routes only go to LLGR peers. A
        // previously-advertised route that went stale falls out of
        // `newly_advertised` here and is withdrawn by the diff below.
        if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, afi, safi) {
            continue;
        }
        let Some((nlri, attr)) = route_update_ipv4(peer, prefix, rib, bgp, add_path) else {
            continue;
        };
        let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
            continue;
        };
        let attr = decision.attr;
        if rd.is_some() && !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
            continue;
        }

        let attr = bgp.attr_store.intern(attr);
        let mut adj = rib.clone();
        adj.attr = attr.clone();
        peer.adj_out.add(rd, nlri.prefix, adj);

        if let Some(rd_val) = rd {
            let vpnv4_nlri = Vpnv4Nlri {
                label: vpnv4_service_label(peer, rib),
                rd: rd_val,
                nlri,
            };
            peer.send_vpnv4(vpnv4_nlri, attr, true);
        } else {
            ipv4_entries.push((attr, nlri));
        }

        newly_advertised.insert(*prefix);
    }

    // Direct-emit IPv4 unicast batch (no group fan-out). When the
    // peer negotiated RFC 8950 ENHE for IPv4 unicast, pass the
    // per-interface next-hop so the encoder emits MP_REACH instead
    // of the legacy inline-NLRI form. `compose_enhe_next_hop`
    // selects 32-octet dual when the egress interface also has a
    // global v6, else 16-octet link-local-only.
    if rd.is_none()
        && let Some(peer) = peers.get_by_idx(peer_idx)
    {
        let enhe_v6 = peer
            .is_enhe_v4_negotiated()
            .then(|| super::update_group::compose_enhe_next_hop(peer, bgp.interface_addrs))
            .flatten();
        super::update_group::send_ipv4_direct(peer, ipv4_entries, enhe_v6);
    }

    let to_withdraw: Vec<Ipv4Net> = was_advertised
        .difference(&newly_advertised)
        .copied()
        .collect();
    for prefix in to_withdraw {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        if let Some(rd) = rd {
            peer.cache_remove_vpnv4(rd, prefix, 0);
        }
        // No IPv4 cache to remove from — direct-encode means there
        // was never a pending bucket to drop. adj_out + the on-wire
        // withdraw still happen.
        peer.adj_out.remove(rd, prefix, 0);
        withdraw_ipv4_deferrable(bgp.update_groups, peer, rd, prefix, 0);
    }
}

/// Soft-reconfiguration outbound for one EVPN Route Distinguisher.
/// Mirrors `route_soft_out_peer_table` for IPv4/VPN: walk the
/// per-RD Loc-RIB EVPN table through `route_update_evpn` +
/// `route_apply_policy_out_evpn`, re-emit anything the (possibly
/// new) policy still permits, and withdraw entries that the peer
/// previously had in its Adj-RIB-Out but that now fall out.
///
/// Without this path, a `match evpn …` policy change only affects
/// *new* routes — previously-advertised routes remain in the peer's
/// table until the peer drops the session or the originating
/// speaker withdraws the route. Operator-triggered soft-out (or a
/// peer-initiated Route Refresh) flows through here.
fn route_soft_out_peer_table_evpn(
    peer_idx: usize,
    rd: RouteDistinguisher,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    // AddPath member: re-evaluate every candidate path and diff the
    // Adj-RIB-Out at (prefix, path-id) granularity. A plain member
    // keeps the best-path-per-prefix shape, with the sentinel path-id 0.
    let add_path = peers
        .get_by_idx(peer_idx)
        .map(|p| p.opt.is_add_path_send(Afi::L2vpn, Safi::Evpn))
        .unwrap_or(false);

    // Snapshot the (prefix, rib) set to (re)advertise so iteration
    // outlives later mutable borrows of `bgp` (attr_store.intern, send
    // paths): every candidate for AddPath, best-path-per-prefix
    // otherwise.
    let candidates: Vec<(EvpnPrefix, BgpRib)> = bgp
        .local_rib
        .evpn
        .get(&rd)
        .map(|t| {
            if add_path {
                t.cands
                    .iter()
                    .flat_map(|(p, v)| v.iter().map(move |r| (p.clone(), r.clone())))
                    .collect()
            } else {
                t.selected
                    .iter()
                    .map(|(p, r)| (p.clone(), r.clone()))
                    .collect()
            }
        })
        .unwrap_or_default();

    // What's currently in this peer's Adj-RIB-Out for the RD, keyed by
    // (prefix, path-id) — anything here but missing from the post-policy
    // newly-advertised set needs a withdraw. Plain members use the
    // sentinel id 0 (whole-prefix); AddPath members use each advertised
    // candidate's local_id.
    let was_advertised: BTreeSet<(EvpnPrefix, u32)> = {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        peer.adj_out
            .evpn
            .get(&rd)
            .map(|t| {
                if add_path {
                    t.0.iter()
                        .flat_map(|(p, v)| v.iter().map(move |r| (p.clone(), r.local_id)))
                        .collect()
                } else {
                    t.0.keys().map(|p| (p.clone(), 0)).collect()
                }
            })
            .unwrap_or_default()
    };

    let mut newly_advertised: BTreeSet<(EvpnPrefix, u32)> = BTreeSet::new();

    for (prefix, rib) in &candidates {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        let id = if add_path { rib.local_id } else { 0 };
        if evpn_advertise_one(peer, &rd, prefix, rib, bgp, add_path) {
            newly_advertised.insert((prefix.clone(), id));
        }
    }

    let to_withdraw: Vec<(EvpnPrefix, u32)> = was_advertised
        .difference(&newly_advertised)
        .cloned()
        .collect();
    for (prefix, id) in to_withdraw {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        evpn_withdraw_one(peer, &rd, &prefix, id);
    }
}

// Soft-reconfiguration inbound (stored mode): replay the peer's
// pre-policy Adj-RIB-In through the current inbound policy and
// reconcile Loc-RIB. The caller must have already verified
// `peer.config.soft_reconfig_in` and that the peer is established.
//
// For each stored entry: re-apply inbound policy. If accepted, refresh
// the Loc-RIB candidate with the (possibly new) post-policy attrs and
// fan out best-path changes via the normal advertise paths. If denied,
// withdraw from Loc-RIB only — the Adj-RIB-In entry stays so the next
// replay (e.g., after another policy edit) still has it.
//
// Covers IPv4 unicast and IPv4 MPLS-VPN. EVPN soft-in is left
// for a follow-up, mirroring the EVPN soft-out gap.
pub fn route_soft_in_peer(
    peer_idx: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    let (do_v4, vpn_rds) = {
        let Some(peer) = peers.get_by_idx(peer_idx) else {
            return;
        };
        if !peer.state.is_established() {
            return;
        }
        let do_v4 = peer.is_afi_safi(Afi::Ip, Safi::Unicast);
        let do_vpn = peer.is_afi_safi(Afi::Ip, Safi::MplsVpn);
        let rds: Vec<RouteDistinguisher> = if do_vpn {
            bgp.shard
                .adj_in(peer.ident)
                .map(|a| a.v4vpn.keys().copied().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        (do_v4, rds)
    };

    if do_v4 {
        route_soft_in_peer_table(peer_idx, None, bgp, peers, shards);
    }
    for rd in vpn_rds {
        route_soft_in_peer_table(peer_idx, Some(rd), bgp, peers, shards);
    }
}

fn route_soft_in_peer_table(
    peer_idx: usize,
    rd: Option<RouteDistinguisher>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    // RIB sharding (N>1): v4-unicast Adj-RIB-In lives on the pool shards,
    // so dispatch a SoftInV4 to each (the peer's prefixes hash across all)
    // to replay locally against the replicated policy snapshot; the async
    // reduce drives FIB + advertise. `process_policy_msg` sends the
    // matching `PolicyReplace` first, so the replay sees the new policy.
    // VPNv4 (`rd = Some`) is not pooled and replays synchronously below.
    if rd.is_none()
        && let Some(pool) = shards
    {
        let Some(ident) = peers.get_by_idx(peer_idx).map(|p| p.ident) else {
            return;
        };
        for idx in 0..pool.n() {
            pool.dispatch(idx, ShardMsg::SoftInV4 { ident });
        }
        return;
    }

    // Snapshot stored Adj-RIB-In entries so subsequent mutable borrows
    // of `peers` / `bgp` (policy apply, Loc-RIB update, advertise
    // fan-out) don't conflict with the iteration.
    let entries: Vec<(Ipv4Net, Vec<BgpRib>)> = {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        let Some(adj_in) = bgp.shard.adj_in(peer.ident) else {
            return;
        };
        match rd {
            Some(rd) => adj_in
                .v4vpn
                .get(&rd)
                .map(|t| t.0.iter().map(|(p, ribs)| (*p, ribs.clone())).collect())
                .unwrap_or_default(),
            None => adj_in
                .v4
                .0
                .iter()
                .map(|(p, ribs)| (*p, ribs.clone()))
                .collect(),
        }
    };

    for (prefix, ribs) in entries {
        for stored in ribs {
            let nlri = Ipv4Nlri {
                id: stored.remote_id,
                prefix,
            };

            // Re-run inbound policy against the stored pre-policy
            // attributes. The Adj-RIB-In keeps the original attr; only
            // the Loc-RIB candidate gets the post-policy version.
            let pre_attr: BgpAttr = (*stored.attr).clone();
            let pre_weight = stored.weight;
            let post_attr_opt = {
                let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
                route_apply_policy_in(peer, &nlri, pre_attr, pre_weight)
            };

            match post_attr_opt {
                None => {
                    // Policy denies this route under the new rules.
                    // rib_in=false leaves the Adj-RIB-In entry in
                    // place so subsequent replays still see it.
                    route_ipv4_withdraw(peer_idx, &nlri, rd, None, bgp, peers, None, false);
                }
                Some(decision) => {
                    let mut new_rib = stored.clone();
                    new_rib.attr = bgp.shard.intern(decision.attr);
                    new_rib.weight = decision.weight;
                    let (_, selected, next_id) = bgp.shard.update(rd, prefix, new_rib.clone());

                    // Policy-in change may have shifted the best path
                    // for this prefix; reconcile the FIB so the kernel
                    // tracks whatever Loc-RIB now considers best.
                    if rd.is_none() {
                        fib_install_v4(bgp, prefix, &selected);
                    }

                    if !selected.is_empty() {
                        route_advertise_to_peers(rd, prefix, &selected, peer_idx, bgp, peers);
                    }
                    new_rib.local_id = next_id;
                    route_advertise_to_addpath(rd, prefix, &new_rib, peer_idx, bgp, peers);
                }
            }
        }
    }
}

pub fn route_ipv4_withdraw(
    ident: usize,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    _label: Option<Label>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
    rib_in: bool,
) {
    // RIB sharding (N>1): v4-unicast lives on the pool, so dispatch the
    // withdraw to the owning shard and let the async reduce
    // (`process_shard_result` → `route_apply_bestpath_v4_batch`) drive the
    // Adj-RIB-In drop (in the shard, via `rib_in`), NHT untrack, FIB
    // reconcile and re-advertise — the same path the update ingest takes.
    // VPNv4 (`rd = Some`) is not pooled; it stays on the synchronous shard.
    if rd.is_none()
        && let Some(pool) = shards
    {
        let idx = pool.shard_of(std::net::IpAddr::V4(nlri.prefix.addr()));
        pool.dispatch(
            idx,
            ShardMsg::WithdrawV4 {
                ident,
                rd: None,
                nlri: nlri.clone(),
                rib_in,
            },
        );
        return;
    }

    {
        if rib_in {
            let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
            bgp.shard
                .adj_in_mut(peer.ident)
                .remove(rd, nlri.prefix, nlri.id);
        }
    }

    // BGP Path selection - this may select a new best path
    let mut removed = bgp.shard.remove(rd, nlri.prefix, nlri.id, ident);

    // NHT untrack: release the withdrawn path's next-hop(s) unless a
    // surviving candidate still uses them.
    if bgp.nexthop_cache.is_some() {
        let survivor_nhs = bgp.shard.candidate_nexthops_v4(rd, nlri.prefix);
        let dep = match rd {
            Some(rd) => super::nht::NhtDep::V4vpn(rd, nlri.prefix),
            None => super::nht::NhtDep::V4(nlri.prefix),
        };
        nht_untrack_withdrawn(bgp, &removed, &survivor_nhs, dep);
    }

    // Re-run best path selection and advertise changes
    let selected = if let Some(ref rd) = rd {
        bgp.shard.select_best_path_vpn(rd, nlri.prefix)
    } else {
        bgp.shard.select_best_path(nlri.prefix)
    };
    // Reconcile FIB after the withdraw: empty `selected` means the
    // last candidate just disappeared and we should withdraw from
    // the kernel; non-empty means a replacement path is now best
    // and a fresh Ipv4Add carries the new attrs.
    if let Some(rd) = rd {
        // VPNv4 transit (Option B): the prefix is fully gone → release
        // its local label and tear down the swap ILM; a surviving winner
        // keeps the same per-(RD,prefix) label, whose ILM is reconciled
        // for the (possibly new) winner's received label / transport.
        if selected.is_empty() {
            if let Some(local) = bgp.shard.labels.free_vpn_v4(rd, nlri.prefix) {
                ilm_swap_remove(bgp.rib_client, local);
            }
        } else {
            reconcile_swap_ilm(
                bgp.rib_client,
                bgp.nexthop_cache.as_deref(),
                selected.first(),
            );
        }
    } else {
        fib_install_v4(bgp, nlri.prefix, &selected);
    }

    // VRF export — symmetric with `route_update_ipv4`. After a
    // withdraw, either a replacement winner exists (emit a fresh
    // Export so the global v4vpn row carries the new attrs) or
    // `selected` is empty (emit WithdrawExport to drop the row).
    if rd.is_none()
        && let Some(exporter) = bgp.vrf_export
    {
        if let Some(winner) = selected.first() {
            super::vrf::vrf_emit_export(exporter, nlri.prefix, &winner.attr);
        } else {
            super::vrf::vrf_emit_withdraw(exporter, nlri.prefix);
        }
    }

    // Global v4vpn withdraw → per-VRF import dispatch. If a
    // replacement winner survives best-path, that VPNv4 row now
    // carries a different attr; re-import with the new attr. If
    // `selected` is empty, the route truly went away — flood a
    // WithdrawImport using the *removed* row's attr to resolve the
    // matching-VRF set (we no longer have the new attr).
    if let Some(rd) = rd
        && let Some(dispatcher) = bgp.vrf_import
    {
        if let Some(winner) = selected.first() {
            let (label, transport) = vpn_import_transport(bgp, winner);
            super::vrf::dispatch_import_v4(
                dispatcher,
                rd,
                nlri.prefix,
                &winner.attr,
                label,
                transport,
                None,
            );
        } else if let Some(gone) = removed.first() {
            super::vrf::dispatch_withdraw_import_v4(dispatcher, rd, nlri.prefix, &gone.attr, None);
        }
    }
    if !selected.is_empty() || !removed.is_empty() {
        route_advertise_to_peers(rd, nlri.prefix, &selected, ident, bgp, peers);
    }
    if let Some(removed) = removed.pop() {
        route_withdraw_from_addpath(rd, nlri.prefix, &removed, ident, bgp, peers);
    }
}

/// IPv6 unicast receive path — the v6 counterpart of
/// [`route_ipv4_update`]. The MP_REACH next-hop is carried in
/// `attr.nexthop` as `BgpNexthop::Ipv6` (stamped by the dispatch
/// site), drives the FIB install, and the route lands in
/// `shard.v6`.
///
/// Scope (layer 2b-i): receive → Adj-RIB-In → Loc-RIB → FIB. Inbound
/// policy is **not** applied yet (the policy engine is IPv4-typed),
/// peer re-advertisement is layer 2b-ii, and the per-VRF export/import
/// hooks are layer 3. None of those are wired here.
pub fn route_ipv6_update(
    ident: usize,
    nlri: &Ipv6Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<VpnNexthop>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        // RFC 4271 / 4456 loop detection — identical to the v4 path.
        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        // encapsulation-type srv6 (accept side): a plain IPv6 unicast
        // route from an SRv6-only peer must carry an SRv6 service SID;
        // drop a SID-less route before it reaches the Adj-RIB-In /
        // Loc-RIB. VPNv6 rows (rd = Some) are unaffected — they carry
        // their own service SID and have a separate filter contract.
        if rd.is_none() && peer.ipv6_srv6_strict() && attr.srv6_l3_sid().is_none() {
            tracing::debug!(
                peer = %peer.address,
                prefix = %nlri.prefix,
                "bgp: drop SID-less IPv6 route from encapsulation-type srv6 peer",
            );
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };
        (peer.ident, peer.remote_id, typ)
    };

    let stale = stale || attr_has_llgr_stale(attr);

    // Inbound policy: per-peer v6 route-map / prefix-list. The decision
    // carries the post-policy attribute; `None` means the route was
    // denied, so the shard withdraws any prior Loc-RIB row. (Reaches
    // parity with the v4 ingest — v6 previously applied no per-neighbor
    // inbound policy.)
    let decision = {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        route_apply_policy_in_v6(peer, nlri, attr.clone(), 0)
    };

    let dep = match rd {
        Some(rd) => super::nht::NhtDep::V6vpn(rd, nlri.prefix),
        None => super::nht::NhtDep::V6(nlri.prefix),
    };
    // Main owns NHT (the shard has no `nexthop_cache`): resolve
    // reachability on the POST-policy next-hop (policy may rewrite it),
    // and compute the Inter-AS Option AB (VPNv6) transit flag against the
    // post-policy communities; a denied route resolves nothing.
    // `import_attr` feeds the VPNv6 import-withdraw dispatch below.
    let (nexthop_reachable, vrf_transit_only, import_attr) = match &decision {
        Some(d) => {
            let reachable = nht_track_received_attr(bgp, &d.attr, dep.clone());
            let transit = rd.is_some()
                && peer_ident != ORIGINATED_PEER
                && bgp.vrf_import.is_some_and(|disp| {
                    super::inst::rt_imported_by_hybrid_vrf_v6(disp.rib_known_vrfs, &d.attr.ecom)
                });
            (reachable, transit, d.attr.clone())
        }
        None => (true, false, attr.clone()),
    };

    // Hand the table op (Adj-RIB-In + policy decision → intern + Loc-RIB
    // + best-path) to the shard; act on the returned best-path delta.
    let deltas = bgp.shard.handle(
        ShardMsg::UpdateV6(ShardUpdateV6 {
            ident: peer_ident,
            rd,
            nlri: nlri.clone(),
            peer_router_id,
            typ,
            attr: attr.clone(),
            label,
            nexthop,
            stale,
            nexthop_reachable,
            vrf_transit_only,
            decision,
        }),
        None,
    );

    for delta in deltas {
        let ShardOut::BestPathV6 {
            rd,
            prefix,
            selected,
            replaced,
            added,
            survivor_nexthops,
            ..
        } = delta
        else {
            continue;
        };
        // Release displaced next-hops (survivors computed by the shard).
        if bgp.nexthop_cache.is_some() && !replaced.is_empty() {
            nht_untrack_withdrawn(bgp, &replaced, &survivor_nexthops, dep.clone());
        }
        match rd {
            // Plain v6 unicast → kernel FIB + peer advertisement.
            None => {
                fib_install_v6(bgp, prefix.prefix, &selected);
                if let Some(exporter) = bgp.vrf_export {
                    if let Some(winner) = selected.first() {
                        super::vrf::vrf_emit_export_v6(exporter, prefix.prefix, &winner.attr);
                    } else {
                        super::vrf::vrf_emit_withdraw_v6(exporter, prefix.prefix);
                    }
                }
                if !selected.is_empty() {
                    route_advertise_to_peers_v6(prefix.prefix, &selected, bgp, peers);
                }
            }
            // VPNv6 → per-VRF import + PE-peer advertisement (no kernel FIB).
            Some(rd) => {
                if let Some(dispatcher) = bgp.vrf_import {
                    if let Some(winner) = selected.first() {
                        let (label, transport) = vpn_import_transport(bgp, winner);
                        super::vrf::dispatch_import_v6(
                            dispatcher,
                            rd,
                            prefix.prefix,
                            &winner.attr,
                            label,
                            transport,
                            None,
                        );
                    } else {
                        super::vrf::dispatch_withdraw_import_v6(
                            dispatcher,
                            rd,
                            prefix.prefix,
                            &import_attr,
                            None,
                        );
                    }
                }
                if !selected.is_empty() {
                    route_advertise_to_peers_vpnv6(rd, prefix.prefix, &selected, bgp, peers);
                }
                // VPNv6 AddPath: advertise the just-updated candidate path
                // itself (with its shard-allocated local_id), independent of
                // whether it won best-path.
                if let Some(rib_ap) = added {
                    route_advertise_to_peers_vpnv6_addpath(rd, prefix.prefix, &rib_ap, bgp, peers);
                }
            }
        }
    }
}

/// IPv6 withdraw — the v6 counterpart of [`route_ipv4_withdraw`].
/// `rd == Some` targets the VPNv6 Loc-RIB; `None` is plain unicast
/// (FIB reconcile + peer re-advertisement). VPNv6 peer
/// advertise/withdraw is layer 2c-ii.
pub fn route_ipv6_withdraw(
    ident: usize,
    nlri: &Ipv6Nlri,
    rd: Option<RouteDistinguisher>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    rib_in: bool,
) {
    if rib_in {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        match rd {
            Some(rd) => bgp
                .shard
                .adj_in_mut(peer.ident)
                .remove_v6vpn(rd, nlri.prefix, nlri.id),
            None => bgp
                .shard
                .adj_in_mut(peer.ident)
                .remove_v6(nlri.prefix, nlri.id),
        };
    }

    match rd {
        Some(rd) => {
            let removed = bgp.shard.remove_v6vpn(rd, nlri.prefix, nlri.id, ident);
            if bgp.nexthop_cache.is_some() {
                let survivor_nhs = bgp.shard.candidate_nexthops_v6(Some(rd), nlri.prefix);
                nht_untrack_withdrawn(
                    bgp,
                    &removed,
                    &survivor_nhs,
                    super::nht::NhtDep::V6vpn(rd, nlri.prefix),
                );
            }
            // No no-op guard — `route_advertise_to_peers_vpnv6` now prunes
            // via its Adj-RIB-Out (`adj_out.v6vpn`), like the v4 VPN path.
            let selected = bgp.shard.select_best_path_vpn_v6(&rd, nlri.prefix);

            // Remote VPNv6 withdraw → per-VRF import update/withdraw
            // (global task only). A surviving winner re-imports with
            // the new attr; otherwise flood a withdraw resolved from
            // the removed row's RTs.
            if let Some(dispatcher) = bgp.vrf_import {
                if let Some(winner) = selected.first() {
                    let (label, transport) = vpn_import_transport(bgp, winner);
                    super::vrf::dispatch_import_v6(
                        dispatcher,
                        rd,
                        nlri.prefix,
                        &winner.attr,
                        label,
                        transport,
                        None,
                    );
                } else if let Some(gone) = removed.first() {
                    super::vrf::dispatch_withdraw_import_v6(
                        dispatcher,
                        rd,
                        nlri.prefix,
                        &gone.attr,
                        None,
                    );
                }
            }

            // Empty `selected` → MP_UNREACH to PE peers; a replacement
            // winner → re-advertise. Both handled by the helper.
            route_advertise_to_peers_vpnv6(rd, nlri.prefix, &selected, bgp, peers);
            // AddPath members: withdraw exactly the path that left (by
            // its local_id); any remaining candidates stay advertised.
            if let Some(gone) = removed.first() {
                route_withdraw_vpnv6_addpath(rd, nlri.prefix, gone, peers);
            }
        }
        None => {
            let removed = bgp.shard.remove_v6(nlri.prefix, nlri.id, ident);
            if bgp.nexthop_cache.is_some() {
                let survivor_nhs = bgp.shard.candidate_nexthops_v6(None, nlri.prefix);
                nht_untrack_withdrawn(
                    bgp,
                    &removed,
                    &survivor_nhs,
                    super::nht::NhtDep::V6(nlri.prefix),
                );
            }
            // No no-op guard here: `route_advertise_to_peers_v6` now keeps
            // a per-peer Adj-RIB-Out (`adj_out.v6`) and withdraws only to
            // peers that were actually advertised the prefix, so an
            // empty-selected withdraw no longer floods or ping-pongs.
            let selected = bgp.shard.select_best_path_v6(nlri.prefix);
            fib_install_v6(bgp, nlri.prefix, &selected);

            // VRF export, symmetric with route_ipv6_update: a
            // replacement winner re-exports; an empty result withdraws.
            if let Some(exporter) = bgp.vrf_export {
                if let Some(winner) = selected.first() {
                    super::vrf::vrf_emit_export_v6(exporter, nlri.prefix, &winner.attr);
                } else {
                    super::vrf::vrf_emit_withdraw_v6(exporter, nlri.prefix);
                }
            }

            // Empty `selected` → withdraw to peers; a replacement
            // winner → re-advertise. Both handled by the helper.
            route_advertise_to_peers_v6(nlri.prefix, &selected, bgp, peers);
        }
    }
}

/// Ingest a received IPv4 Labeled-Unicast (SAFI 4) route into the
/// `v4lu` Loc-RIB. Control-plane only: the per-prefix label is stored on
/// the `BgpRib`, the MP_REACH next-hop is stamped into the attr so
/// best-path / show read it, and best-path runs. NHT gating, FIB
/// install (label-push) and peer re-advertisement land in later phases,
/// so this mirrors the v6-unicast ingest minus those steps.
pub fn route_labelv4_update(
    ident: usize,
    lu: &Labelv4Nlri,
    nhop: IpAddr,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        // RFC 4271 / 4456 loop detection — identical to the unicast path.
        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };
        (peer.ident, peer.remote_id, typ)
    };

    // Stamp the MP_REACH next-hop so best-path / show read the LU
    // next-hop rather than the (often absent) NEXT_HOP attribute.
    let mut attr = attr.clone();
    attr.nexthop = Some(match nhop {
        IpAddr::V4(v4) => BgpNexthop::Ipv4(v4),
        IpAddr::V6(v6) => BgpNexthop::Ipv6(v6),
    });

    let stale = stale || attr_has_llgr_stale(&attr);

    // Inbound policy: per-peer route-map / prefix-list. The decision
    // carries the post-policy attr; `None` drops the route (any prior
    // Loc-RIB row from this peer is withdrawn). Reaches parity with the
    // unicast ingest — LU previously applied no per-neighbor policy.
    let decision = {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        route_apply_policy_in(peer, &lu.nlri, attr.clone(), 0)
    };

    // Adj-RIB-In keeps the pre-policy attribute (soft-reconfig replay).
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        lu.nlri.id,
        0,
        &attr,
        Some(lu.label),
        None,
        stale,
    );
    bgp.shard
        .adj_in_mut(peer_ident)
        .add_v4lu(lu.nlri.prefix, rib.clone());

    // Next-Hop Tracking gate / per-prefix local label resolve only on the
    // permit path; a denied route removes this peer's row and re-selects.
    let dep = super::nht::NhtDep::V4lu(lu.nlri.prefix);
    let (replaced, selected) = match decision {
        None => {
            let replaced = bgp
                .shard
                .remove_v4lu(lu.nlri.prefix, lu.nlri.id, peer_ident);
            let selected = bgp.shard.select_best_path_v4lu(lu.nlri.prefix);
            (replaced, selected)
        }
        Some(decision) => {
            rib.attr = bgp.shard.intern(decision.attr);
            rib.weight = decision.weight;
            nht_track_received(bgp, &mut rib, dep.clone());
            // Allocate a per-prefix local label so re-advertising with
            // next-hop-self forwards via a swap ILM (Phase 5b). `None`
            // when no dynamic block is granted yet — advertise the
            // received label until then.
            rib.local_label = bgp
                .shard
                .labels
                .label_lu_v4(bgp.central_label_alloc.as_deref_mut(), lu.nlri.prefix);
            let (replaced, selected, _next_id) = bgp.shard.update_v4lu(lu.nlri.prefix, rib);
            (replaced, selected)
        }
    };
    if bgp.nexthop_cache.is_some() && !replaced.is_empty() {
        let survivor_nhs = bgp.shard.candidate_nexthops_v4lu(lu.nlri.prefix);
        nht_untrack_withdrawn(bgp, &replaced, &survivor_nhs, dep);
    }
    // Ingress LSR: install the received label toward the resolved
    // next-hop (no-op/withdraw for self-originated or unresolved).
    fib_install_labelv4(
        bgp.rib_client,
        bgp.nexthop_cache.as_deref(),
        lu.nlri.prefix,
        &selected,
    );
    if !selected.is_empty() {
        route_advertise_to_peers_labelv4(lu.nlri.prefix, &selected, bgp, peers);
    }
}

/// Ingest a received IPv6 Labeled-Unicast (SAFI 4) route — including
/// 6PE — into the `v6lu` Loc-RIB. See [`route_labelv4_update`].
pub fn route_labelv6_update(
    ident: usize,
    lu: &Labelv6Nlri,
    nhop: IpAddr,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };
        (peer.ident, peer.remote_id, typ)
    };

    let mut attr = attr.clone();
    attr.nexthop = Some(match nhop {
        IpAddr::V4(v4) => BgpNexthop::Ipv4(v4),
        IpAddr::V6(v6) => BgpNexthop::Ipv6(v6),
    });

    let stale = stale || attr_has_llgr_stale(&attr);

    // Inbound policy: per-peer route-map / prefix-list (see
    // `route_labelv4_update`). `None` drops the route.
    let decision = {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        route_apply_policy_in_v6(peer, &lu.nlri, attr.clone(), 0)
    };

    // Adj-RIB-In keeps the pre-policy attribute (soft-reconfig replay).
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        lu.nlri.id,
        0,
        &attr,
        Some(lu.label),
        None,
        stale,
    );
    bgp.shard
        .adj_in_mut(peer_ident)
        .add_v6lu(lu.nlri.prefix, rib.clone());

    let dep = super::nht::NhtDep::V6lu(lu.nlri.prefix);
    let (replaced, selected) = match decision {
        None => {
            let replaced = bgp
                .shard
                .remove_v6lu(lu.nlri.prefix, lu.nlri.id, peer_ident);
            let selected = bgp.shard.select_best_path_v6lu(lu.nlri.prefix);
            (replaced, selected)
        }
        Some(decision) => {
            rib.attr = bgp.shard.intern(decision.attr);
            rib.weight = decision.weight;
            nht_track_received(bgp, &mut rib, dep.clone());
            rib.local_label = bgp
                .shard
                .labels
                .label_lu_v6(bgp.central_label_alloc.as_deref_mut(), lu.nlri.prefix);
            let (replaced, selected, _next_id) = bgp.shard.update_v6lu(lu.nlri.prefix, rib);
            (replaced, selected)
        }
    };
    if bgp.nexthop_cache.is_some() && !replaced.is_empty() {
        let survivor_nhs = bgp.shard.candidate_nexthops_v6lu(lu.nlri.prefix);
        nht_untrack_withdrawn(bgp, &replaced, &survivor_nhs, dep);
    }
    fib_install_labelv6(
        bgp.rib_client,
        bgp.nexthop_cache.as_deref(),
        lu.nlri.prefix,
        &selected,
    );
    if !selected.is_empty() {
        route_advertise_to_peers_labelv6(lu.nlri.prefix, &selected, bgp, peers);
    }
}

/// Withdraw a received IPv4 Labeled-Unicast route (MP_UNREACH or
/// session teardown). Identity is (prefix, path-id); the on-wire label
/// is not part of it. Removes from Adj-RIB-In and the `v4lu` Loc-RIB and
/// recomputes best-path so `show` stays consistent.
pub fn route_labelv4_withdraw(
    ident: usize,
    nlri: &Ipv4Nlri,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    rib_in: bool,
) {
    if rib_in {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        bgp.shard
            .adj_in_mut(peer.ident)
            .remove_v4lu(nlri.prefix, nlri.id);
    }
    let removed = bgp.shard.remove_v4lu(nlri.prefix, nlri.id, ident);
    if bgp.nexthop_cache.is_some() {
        let survivor_nhs = bgp.shard.candidate_nexthops_v4lu(nlri.prefix);
        nht_untrack_withdrawn(
            bgp,
            &removed,
            &survivor_nhs,
            super::nht::NhtDep::V4lu(nlri.prefix),
        );
    }
    // No no-op guard: `route_advertise_to_peers_labelv4` now keeps a
    // per-peer Adj-RIB-Out (`adj_out.v4lu`) and withdraws only to peers
    // that were actually advertised the prefix, so an empty-selected
    // withdraw no longer floods or ping-pongs.
    let selected = bgp.shard.select_best_path_v4lu(nlri.prefix);
    // Prefix fully gone: release its local label and tear down the swap
    // ILM. (A surviving winner keeps the same per-prefix label, whose ILM
    // `fib_install_labelv4` reconciles below.)
    if selected.is_empty()
        && let Some(local) = bgp.shard.labels.free_lu_v4(nlri.prefix)
    {
        ilm_swap_remove(bgp.rib_client, local);
    }
    fib_install_labelv4(
        bgp.rib_client,
        bgp.nexthop_cache.as_deref(),
        nlri.prefix,
        &selected,
    );
    // Empty `selected` → MP_UNREACH to LU peers; a replacement winner →
    // re-advertise. Both handled by the advertise helper.
    route_advertise_to_peers_labelv4(nlri.prefix, &selected, bgp, peers);
}

/// Withdraw a received IPv6 Labeled-Unicast route. See
/// [`route_labelv4_withdraw`].
pub fn route_labelv6_withdraw(
    ident: usize,
    nlri: &Ipv6Nlri,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    rib_in: bool,
) {
    if rib_in {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        bgp.shard
            .adj_in_mut(peer.ident)
            .remove_v6lu(nlri.prefix, nlri.id);
    }
    let removed = bgp.shard.remove_v6lu(nlri.prefix, nlri.id, ident);
    if bgp.nexthop_cache.is_some() {
        let survivor_nhs = bgp.shard.candidate_nexthops_v6lu(nlri.prefix);
        nht_untrack_withdrawn(
            bgp,
            &removed,
            &survivor_nhs,
            super::nht::NhtDep::V6lu(nlri.prefix),
        );
    }
    // No no-op guard — `route_advertise_to_peers_labelv6` prunes via its
    // Adj-RIB-Out (`adj_out.v6lu`); see `route_labelv4_withdraw`.
    let selected = bgp.shard.select_best_path_v6lu(nlri.prefix);
    if selected.is_empty()
        && let Some(local) = bgp.shard.labels.free_lu_v6(nlri.prefix)
    {
        ilm_swap_remove(bgp.rib_client, local);
    }
    fib_install_labelv6(
        bgp.rib_client,
        bgp.nexthop_cache.as_deref(),
        nlri.prefix,
        &selected,
    );
    route_advertise_to_peers_labelv6(nlri.prefix, &selected, bgp, peers);
}

pub fn route_ipv4_rtc_update(peer_id: usize, rtcv4: &Rtcv4, peers: &mut PeerMap) {
    let Some(peer) = peers.get_mut_by_idx(peer_id) else {
        return;
    };
    peer.rtcv4.insert(rtcv4.rt.clone());
}

pub fn route_ipv6_rtc_update(peer_id: usize, rtcv6: &Rtcv6, peers: &mut PeerMap) {
    let Some(peer) = peers.get_mut_by_idx(peer_id) else {
        return;
    };
    peer.rtcv6.insert(rtcv6.rt.clone());
}

pub fn route_rtcv4_sync(peer_id: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let Some(peer) = peers.get_mut_by_idx(peer_id) else {
        return;
    };
    let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
    if peer.eor.contains_key(&key) {
        route_sync_vpnv4(peer, bgp);
    }
    peer.eor.clear();
}

/// Extract VNI from Route Distinguisher
/// For EVPN routes, VNI is typically encoded in the lower 3 bytes of the RD value.
/// RFC 7432 uses RD Type 0 (ASN) with format: [2 bytes ASN][3 bytes VNI][1 byte index]
///
/// Extract VNI from Route Target (RT) extended community
///
/// RFC 8365 Section 5.1: "Each VXLAN EVPN instance is associated with a VXLAN VNI.
/// The VNI is encoded in the Route Target extended community."
///
/// RFC 4360: Route Target Type 0x0002 (transitive)
/// Value format: [2 bytes ASN][4 bytes value]
/// VNI = lower 3 bytes of value (24-bit, bytes [2:5])
///
/// Example: RT 65501:550
///   - ASN: 65501 (0xFF8D)
///   - Value: 550 (0x000226)
///   - Bytes [2:5]: [0x02, 0x26, 0x00] → VNI 550
fn extract_vni_from_attr(attr: &BgpAttr) -> Option<u32> {
    if let Some(ecom) = &attr.ecom {
        for ec in &ecom.0 {
            // RFC 4360 Two-Octet AS Specific Route Target: high 0x00,
            // low 0x02. Wire layout of the 6-byte value:
            //   val[0..2] = Global Administrator (2-byte ASN)
            //   val[2..6] = Local Administrator (4 bytes)
            // RFC 8365 §5.1.2.4 places the VNI in the *lower 3 bytes*
            // of the 4-byte Local Administrator — i.e. val[3..6]. The
            // earlier code read val[2..5] which is offset by one byte
            // and grabbed the high (always-zero for ≤24-bit VNIs)
            // byte, producing values 256× too small. For RT 65501:550
            // the buggy read returned 2; for any 24-bit VNI < 0x100
            // it returned 0 and skipped the route entirely.
            if ec.high_type == 0x00 && ec.low_type == 0x02 {
                let vni =
                    ((ec.val[3] as u32) << 16) | ((ec.val[4] as u32) << 8) | (ec.val[5] as u32);

                if vni > 0 && vni < 0x1000000 {
                    if fib_l2_fdb() {
                        tracing::info!("extract_vni_from_attr: RT yields VNI {}", vni);
                    }
                    return Some(vni);
                }
            }
        }
    }
    None
}

/// Map a parsed `EvpnRoute` to the policy-side `EvpnRouteType`
/// discriminator. Type-2 (MAC-IP), Type-3 (Inclusive Multicast) and
/// Type-5 (IP Prefix) parse into `EvpnRoute`; Type-1/4 NLRIs are
/// dropped at parse, so they are not represented here.
fn evpn_route_type_of(route: &EvpnRoute) -> crate::policy::EvpnRouteType {
    use crate::policy::EvpnRouteType;
    match route {
        EvpnRoute::Mac(_) => EvpnRouteType::MacIp,
        EvpnRoute::Multicast(_) => EvpnRouteType::Multicast,
        EvpnRoute::Prefix(_) => EvpnRouteType::Prefix,
    }
}

/// Derive the VNI carried by an EVPN route. For Type-2 (MAC-IP)
/// the VNI lives directly in the NLRI's MPLS-label1 field
/// (`EvpnMac.vni`). For Type-3 (Inclusive Multicast) the NLRI
/// carries no VNI, so we fall back to the Route Target extended
/// community per RFC 8365 §5.1.2.4 via `extract_vni_from_attr`.
/// Returns `None` when neither source yields a non-zero VNI.
fn evpn_vni_of(route: &EvpnRoute, attr: &BgpAttr) -> Option<u32> {
    match route {
        EvpnRoute::Mac(m) => (m.vni != 0).then_some(m.vni),
        EvpnRoute::Multicast(_) => extract_vni_from_attr(attr),
        // Type-5 (IP Prefix) is an L3VPN-style route: forwarding rides
        // the per-route MPLS label / SRv6 SID, not a bridge VNI. No VNI.
        EvpnRoute::Prefix(_) => None,
    }
}

/// Extract flags (sticky, gateway, router) from extended communities
fn extract_flags_from_attr(attr: &BgpAttr) -> u8 {
    let mut flags = 0u8;

    if let Some(ecom) = &attr.ecom {
        for ec in &ecom.0 {
            // Check for Sticky MAC (Type 0x09, Sub-type 0x00)
            if ec.high_type == 0x09 && ec.low_type == 0x00 {
                // Sticky MAC flag
                flags |= 0x01;
            }
            // Check for Gateway MAC (Type 0x09, Sub-type 0x01)
            if ec.high_type == 0x09 && ec.low_type == 0x01 {
                // Gateway MAC flag
                flags |= 0x02;
            }
            // Check for Router flag (Type 0x09, Sub-type 0x03)
            if ec.high_type == 0x09 && ec.low_type == 0x03 {
                // Router flag
                flags |= 0x04;
            }
        }
    }

    flags
}

/// Extract MAC mobility sequence number from extended communities
fn extract_mac_mobility_seq(attr: &BgpAttr) -> u32 {
    if let Some(ecom) = &attr.ecom {
        for ec in &ecom.0 {
            // Check for MAC Mobility (Type 0x06, Sub-type 0x00)
            if ec.high_type == 0x06 && ec.low_type == 0x00 {
                // Sequence number is in bytes 4-5
                return u32::from_be_bytes([ec.val[2], ec.val[3], ec.val[4], ec.val[5]]);
            }
        }
    }
    0
}

/// Extract the remote VTEP IP for a received EVPN route. The VTEP
/// is the BGP nexthop, but EVPN routes carry it in
/// `BgpAttr::nexthop` as `BgpNexthop::Evpn(IpAddr)` — populated from
/// the MP_REACH_NLRI nexthop field on receive (`bgp/route.rs:960`).
///
/// `BgpRib::nexthop` is the VPNv4-specific `Vpnv4Nexthop` slot and
/// is always None for EVPN; the previous code read that field and
/// produced `tunnel_endpoint = None` for every received Type-2,
/// which made `mac_add` build an FDB row with no NDA_DST and the
/// kernel rejected the install with EINVAL.
fn extract_tunnel_endpoint(rib: &BgpRib) -> Option<IpAddr> {
    match rib.attr.nexthop.as_ref()? {
        BgpNexthop::Evpn(addr) => Some(*addr),
        _ => None,
    }
}

/// Export selected EVPN MAC entry to RIB for kernel installation
/// Called after best path selection to send MACs to the RIB layer.
///
/// `withdrawn` carries the path that was just removed from the
/// candidate set (when called from the withdraw flow). It exists
/// because the VNI lives in the path's RT extended community per
/// RFC 8365 §5.1.2.4 — and once `selected` is empty (no remaining
/// path on this prefix), there's no candidate to read the RT from.
/// Reading it from the withdrawn path's attr is the only correct
/// source. On the announce flow `withdrawn` is `None`; the empty-
/// selected case is unreachable there.
fn route_evpn_export_selected(
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    selected: &[BgpRib],
    withdrawn: Option<&BgpRib>,
    bgp: &mut BgpTop,
) {
    // If no selected path exists, send delete using the withdrawn
    // path's attr as the RT/VNI source.
    if selected.is_empty() {
        let Some(wd) = withdrawn else {
            // Withdraw of a non-existent path — nothing was removed,
            // nothing to delete in kernel state. Silent no-op.
            return;
        };
        match prefix {
            EvpnPrefix::MacIp { mac, .. } => {
                // Match the announce-side filter: never installed
                // multicast MAC entries → nothing to delete.
                let mac_addr = MacAddr::from(*mac);
                if mac_addr.is_multicast() {
                    return;
                }
                if let Some(vni) = extract_vni_from_attr(&wd.attr) {
                    let msg = rib::Message::MacDel { vni, mac: mac_addr };
                    let _ = bgp.rib_client.send(msg);
                } else {
                    eprintln!(
                        "[ERROR] EVPN Type 2 withdraw: removed path has no Route Target. \
                         RD: {:?}",
                        rd
                    );
                }
            }
            EvpnPrefix::InclusiveMulticast { orig, .. } => {
                if let Some(vni) = extract_vni_from_attr(&wd.attr) {
                    let msg = rib::Message::MdbDel {
                        vni,
                        group: *orig,
                        source: None,
                        ifindex: 0,
                    };
                    let _ = bgp.rib_client.send(msg);
                } else {
                    eprintln!(
                        "[ERROR] EVPN Type 3 withdraw: removed path has no Route Target. \
                         RD: {:?}",
                        rd
                    );
                }
            }
            EvpnPrefix::IpPrefix { prefix, .. } => {
                // Type-5 withdrawal un-imports the IP prefix from matching
                // VRFs, reusing the VPNv4/v6 withdraw dispatch.
                if let Some(dispatcher) = bgp.vrf_import {
                    match prefix {
                        IpNet::V4(p) => super::vrf::dispatch_withdraw_import_v4(
                            dispatcher, *rd, *p, &wd.attr, None,
                        ),
                        IpNet::V6(p) => super::vrf::dispatch_withdraw_import_v6(
                            dispatcher, *rd, *p, &wd.attr, None,
                        ),
                    }
                }
            }
        }
        return;
    }

    // Extract best path (last entry in selected vector)
    let best = &selected[selected.len() - 1];

    match prefix {
        EvpnPrefix::MacIp { mac, .. } => {
            // Defensive: the local FDB->BGP origination path skips
            // multicast MACs in `fdb_entry_from_neighbor`, but a peer
            // running different software may still have advertised
            // one. Don't try to install — there is no remote host
            // behind a multicast MAC and the kernel FDB rows for
            // these are local-reception filters owned by the OS.
            let mac_addr = MacAddr::from(*mac);
            if mac_addr.is_multicast() {
                return;
            }
            // RFC 8365: VNI must come from Route Target extended community
            if let Some(vni) = extract_vni_from_attr(&best.attr) {
                let msg = rib::Message::MacAdd {
                    vni,
                    mac: mac_addr,
                    tunnel_endpoint: extract_tunnel_endpoint(best),
                    flags: extract_flags_from_attr(&best.attr),
                    seq: extract_mac_mobility_seq(&best.attr),
                    esi: best.esi, // Extracted from EVPN route.
                };
                let _ = bgp.rib_client.send(msg);
            } else {
                eprintln!(
                    "[ERROR] EVPN Type 2 route missing Route Target (RFC 8365). \
                     VNI required from RT extended community. RD: {:?}",
                    rd
                );
            }
        }
        EvpnPrefix::InclusiveMulticast { orig, .. } => {
            // Type 3 Inclusive Multicast route installation.
            // This route indicates that a multicast group (*,G) should be replicated to
            // all VTEPs that have advertised this route.
            // RFC 8365: VNI must come from Route Target extended community.
            if let Some(vni) = extract_vni_from_attr(&best.attr) {
                let msg = rib::Message::MdbAdd {
                    vni,
                    group: *orig,
                    source: None,
                    ifindex: 0,
                    seq: extract_mac_mobility_seq(&best.attr),
                };
                let _ = bgp.rib_client.send(msg);
            } else {
                eprintln!(
                    "[ERROR] EVPN Type 3 route missing Route Target (RFC 8365). \
                     VNI required from RT extended community. RD: {:?}",
                    rd
                );
            }
        }
        EvpnPrefix::IpPrefix { prefix, .. } => {
            // A received Type-5 best-path imports into matching VRFs
            // exactly like a VPNv4/v6 route — reuse the same dispatch +
            // transport + FIB machinery. Our own originated Type-5
            // (typ Originated) is left to the VRF Export local-leak path.
            if best.typ != BgpRibType::Originated
                && let Some(dispatcher) = bgp.vrf_import
            {
                let (label, transport) = vpn_import_transport(bgp, best);
                match prefix {
                    IpNet::V4(p) => super::vrf::dispatch_import_v4(
                        dispatcher, *rd, *p, &best.attr, label, transport, None,
                    ),
                    IpNet::V6(p) => super::vrf::dispatch_import_v6(
                        dispatcher, *rd, *p, &best.attr, label, transport, None,
                    ),
                }
            }
        }
    }
}

/// Install one EVPN route received in an MP_REACH_NLRI into Adj-RIB-In and
/// the Loc-RIB. Mirrors `route_ipv4_update` but takes the parsed
/// `EvpnRoute` directly.
///
/// The `_nhop` parameter (the per-MpReach EVPN nexthop) is currently
/// unused: `BgpRib::new` only carries a `Vpnv4Nexthop`, which is IPv4-only
/// and RD-bound. The EVPN nexthop is recoverable from `peer.address` for
/// display purposes; threading it through `BgpRib` is a follow-up tied to
/// the show command.
pub fn route_evpn_update(
    ident: usize,
    route: &EvpnRoute,
    _nhop: IpAddr,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (rd, prefix) = EvpnPrefix::from_route(route);
    let id = match route {
        EvpnRoute::Mac(m) => m.id,
        EvpnRoute::Multicast(m) => m.id,
        EvpnRoute::Prefix(p) => p.id,
    };

    // Loop detection mirrors route_ipv4_update — drop the route silently
    // (no eprintln) on local-AS / ORIGINATOR_ID / CLUSTER_LIST hits.
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };

        (peer.ident, peer.remote_id, typ)
    };

    let stale = stale || attr_has_llgr_stale(attr);
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        id,
        0, // weight
        attr,
        None, // label (not applicable to EVPN at this layer)
        None, // nexthop — see function doc
        stale,
    );

    // Extract ESI from EVPN Type 2 route for multi-homing support.
    if let EvpnRoute::Mac(m) = route {
        rib.esi = Some(m.esi);
    }
    // Type-5 (IP Prefix) carries an MPLS service label in its NLRI;
    // preserve it on the BgpRib so the VRF import (which reuses the
    // VPNv4/v6 path) can build the label-push FIB entry. SRv6 Type-5
    // carries label 0 + the SID in the Prefix-SID attribute.
    if let EvpnRoute::Prefix(p) = route
        && p.label != 0
    {
        rib.label = Some(bgp_packet::Label {
            label: p.label,
            exp: 0,
            bos: true,
        });
    }

    // Apply input policy *after* the route is registered in
    // Adj-RIB-In (raw, pre-policy view) but *before* it enters
    // Loc-RIB / best-path. On deny, treat the receive as an
    // implicit withdrawal so any stale path is also pulled.
    let decision = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add_evpn(rd, prefix.clone(), rib.clone());
        route_apply_policy_in_evpn(peer, route, attr.clone(), rib.weight)
    };
    let Some(decision) = decision else {
        route_evpn_withdraw(ident, route, bgp, peers);
        return;
    };
    rib.attr = bgp.attr_store.intern(decision.attr);
    rib.weight = decision.weight;

    // Type-5: register the PE next-hop with NHT so the underlay
    // resolves (transport is empty at receive — resolution is async)
    // and a later reroute re-triggers the VRF import. Type-2/3 are
    // VXLAN (VTEP next-hop, no transport) and are not tracked.
    if let EvpnRoute::Prefix(_) = route {
        let dep = super::nht::NhtDep::Evpn(rd, prefix.clone());
        nht_track_received(bgp, &mut rib, dep);
    }

    let _ = bgp.local_rib.update_evpn(rd, prefix.clone(), rib);

    // After updating Loc-RIB, re-run best path selection and export to RIB.
    // No `withdrawn` source on the announce path — selected is non-empty by
    // construction (we just inserted the path).
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);
    route_evpn_export_selected(&rd, &prefix, &selected, None, bgp);
    if !selected.is_empty() {
        route_advertise_evpn_to_peers(rd, prefix, &selected, bgp, peers);
    }
}

/// Withdraw one EVPN route advertised in an MP_UNREACH_NLRI from Adj-RIB-In
/// and the Loc-RIB, then re-run best-path selection.
pub fn route_evpn_withdraw(ident: usize, route: &EvpnRoute, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let (rd, prefix) = EvpnPrefix::from_route(route);
    let id = match route {
        EvpnRoute::Mac(m) => m.id,
        EvpnRoute::Multicast(m) => m.id,
        EvpnRoute::Prefix(p) => p.id,
    };

    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.remove_evpn(rd, &prefix, id);
    }

    // Capture the removed path so the export below can read its
    // RT-derived VNI when the prefix has no remaining selected path.
    // `remove_evpn` returns every candidate that matched
    // `(ident, remote_id)`; in normal operation that's a single path,
    // and `.first()` is fine. If the prefix wasn't in the RIB the
    // vec is empty and the export becomes a no-op.
    let removed = bgp.local_rib.remove_evpn(rd, &prefix, id, ident);
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);

    route_evpn_export_selected(&rd, &prefix, &selected, removed.first(), bgp);
}

/// Store one received Flow Specification NLRI in the peer's Adj-RIB-In.
///
/// Phase 1 (receive/reflect) is control-plane only: the flow spec is
/// kept in Adj-RIB-In so it can be shown, but it is not validated
/// (RFC 9117 — Phase 2), not selected into a Loc-RIB or re-advertised
/// (Phase 3), and not installed (Phase 4). Loop detection mirrors
/// `route_evpn_update` so a route carrying our own AS / ORIGINATOR_ID /
/// CLUSTER_LIST is dropped silently.
pub fn route_flowspec_update(
    ident: usize,
    nlri: &FlowspecNlri,
    afi: Afi,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let id = nlri.id;

    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };

        (peer.ident, peer.remote_id, typ)
    };

    let stale = stale || attr_has_llgr_stale(attr);
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        id,
        0,    // weight
        attr, // interned just below
        None, // label
        None, // nexthop — flow specs carry actions, not a next-hop
        stale,
    );
    rib.attr = bgp.attr_store.intern(attr.clone());

    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add_flowspec(afi, nlri.clone(), rib.clone());
    }

    // Phase 3: run best-path selection into the Loc-RIB. Validity
    // (Phase 2 / RFC 9117) gates re-advertise and install, not Loc-RIB
    // membership, so the selected best path is recorded regardless of
    // the validation verdict.
    let (_, selected, _) = bgp.local_rib.update_flowspec(afi, nlri.clone(), rib);

    // Phase 3b: re-advertise (or withdraw) the new best path to flowspec
    // peers, gated on RFC 9117 validity.
    route_flowspec_propagate(afi, nlri, &selected, bgp, peers);
}

/// Withdraw one Flow Specification NLRI from the peer's Adj-RIB-In and
/// the Loc-RIB, re-run best-path selection, then propagate the result
/// (re-advertise a surviving path, or withdraw from peers).
pub fn route_flowspec_withdraw(
    ident: usize,
    nlri: &FlowspecNlri,
    afi: Afi,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.remove_flowspec(afi, nlri, nlri.id);
    }
    bgp.local_rib.remove_flowspec(afi, nlri, nlri.id, ident);
    let selected = bgp.local_rib.select_best_path_flowspec(afi, nlri);
    route_flowspec_propagate(afi, nlri, &selected, bgp, peers);
}

/// Consume one received SR Policy NLRI (RFC 9830, SAFI 73) into the
/// headend SR Policy database.
///
/// Control-plane only: the candidate path is decoded from the Tunnel
/// Encapsulation attribute (Tunnel-Type 15), selected per RFC 9256 §2.9,
/// and exposed via `show`; nothing is installed or steered yet. The
/// endpoint's address family (carried in the NLRI) keys the policy, so
/// IPv4 and IPv6 share one path. Loop detection mirrors
/// `route_flowspec_update`.
pub fn route_srpolicy_update(
    ident: usize,
    nlri: &SrPolicyNlri,
    attr: &BgpAttr,
    nhop: IpAddr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    use super::sr_policy::{self, Usability};

    // RFC 9830 §4.2.1: an update carrying neither NO_ADVERTISE nor an
    // IPv4-address Route Target is malformed — drop it entirely.
    let usability = sr_policy::usability(attr, bgp.router_id);
    if usability == Usability::Malformed {
        return;
    }

    // RFC 4456 loop prevention — drop a looped update before reflecting
    // or consuming it.
    {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }
    }

    // Route-reflector pass-through: a valid update (usable or not) is
    // reflected to other SAFI-73 peers per RR rules (unless NO_ADVERTISE).
    srpolicy_reflect(ident, nlri, attr, nhop, bgp, peers);

    // Consume into the local headend DB only when usable here (RFC 9830
    // §4.2.2: an RT must match our BGP Identifier).
    if usability != Usability::Usable {
        return;
    }

    // RFC 9256 §2.4 originator = <ASN, node-address>: the ORIGINATOR_ID
    // when route-reflected, else the advertising peer's router-id.
    let originator = {
        let peer = peers.get_by_idx(ident).expect("peer must exist");
        let node = attr
            .originator_id
            .as_ref()
            .map(|o| IpAddr::V4(o.id))
            .unwrap_or(IpAddr::V4(peer.remote_id));
        (peer.remote_as, node)
    };

    let tlvs = attr
        .tunnel_encap
        .as_ref()
        .and_then(sr_policy_tlvs)
        .and_then(|res| res.ok())
        .unwrap_or_default();

    let cp = sr_policy::candidate_path(&tlvs, originator, nlri.distinguisher, ident);
    let key = sr_policy::SrPolicyKey {
        color: nlri.color,
        endpoint: nlri.endpoint,
    };
    let delta = bgp.local_rib.sr_policy.insert(key, cp);
    apply_srpolicy_fib(delta, bgp);
    sr_policy_mpls_sync(bgp, nlri.color, nlri.endpoint);
}

/// Withdraw one SR Policy NLRI from the headend database, reflect the
/// withdrawal to other SAFI-73 peers, and apply the dataplane delta.
pub fn route_srpolicy_withdraw(
    ident: usize,
    nlri: &SrPolicyNlri,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    srpolicy_reflect_withdraw(ident, nlri, peers);
    let delta =
        bgp.local_rib
            .sr_policy
            .withdraw(nlri.color, nlri.endpoint, nlri.distinguisher, ident);
    apply_srpolicy_fib(delta, bgp);
    sr_policy_mpls_sync(bgp, nlri.color, nlri.endpoint);
}

/// Reflect a received SR Policy update to every other established
/// SAFI-73 peer the RR rules permit (RFC 4456 / RFC 9830 §4). The
/// received next-hop is preserved (an RR does not change it).
fn srpolicy_reflect(
    source_ident: usize,
    nlri: &SrPolicyNlri,
    attr: &BgpAttr,
    nhop: IpAddr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let our_rid = *bgp.router_id;
    let afi = nlri.afi();
    let Some(src) = peers.get_by_idx(source_ident) else {
        return;
    };
    let (source_ibgp, source_rid) = (src.is_ibgp(), src.remote_id);

    let mut dests: Vec<usize> = peers.established_idents(afi, Safi::SrTePolicy);
    dests.retain(|&ident| ident != source_ident);
    for ident in dests {
        let Some(peer) = peers.get_mut_by_idx(ident) else {
            continue;
        };
        let Some(out_attr) = super::sr_policy::reflect_attr(
            attr,
            source_ibgp,
            source_rid,
            peer.is_ibgp(),
            peer.is_reflector_client(),
            our_rid,
        ) else {
            continue;
        };
        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.mp_update = Some(MpReachAttr::SrPolicy {
            afi,
            snpa: 0,
            nhop,
            updates: vec![nlri.clone()],
        });
        update.bgp_attr = Some(out_attr);
        if let Some(bytes) = update.pop_srpolicy()
            && let Some(ref tx) = peer.packet_tx
        {
            let _ = tx.send(bytes);
        }
    }
}

/// Reflect a received SR Policy withdrawal to the RR-eligible peers.
fn srpolicy_reflect_withdraw(source_ident: usize, nlri: &SrPolicyNlri, peers: &mut PeerMap) {
    let afi = nlri.afi();
    let Some(src) = peers.get_by_idx(source_ident) else {
        return;
    };
    let source_ibgp = src.is_ibgp();
    let mut dests: Vec<usize> = peers.established_idents(afi, Safi::SrTePolicy);
    dests.retain(|&ident| ident != source_ident);
    for ident in dests {
        let Some(peer) = peers.get_mut_by_idx(ident) else {
            continue;
        };
        if !super::sr_policy::reflect_withdraw_to(
            source_ibgp,
            peer.is_ibgp(),
            peer.is_reflector_client(),
        ) {
            continue;
        }
        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.mp_withdraw = Some(MpUnreachAttr::SrPolicy {
            afi,
            withdraws: vec![nlri.clone()],
        });
        if let Some(bytes) = update.pop_srpolicy_withdraw()
            && let Some(ref tx) = peer.packet_tx
        {
            let _ = tx.send(bytes);
        }
    }
}

/// Consume one received BGP Link-State NLRI (RFC 9552, AFI 16388 / SAFI 71)
/// into the BGP-LS Loc-RIB.
///
/// Receive + best-path only: the NLRI is stored in the peer's Adj-RIB-In and
/// selected into the Loc-RIB exact-match table (a single best path per NLRI,
/// reusing the NLRI-agnostic `BgpRib` comparator). Re-advertisement /
/// reflection, install, and `show` are later phases — the selected best path
/// is recorded but not propagated. The companion BGP-LS Attribute (path
/// attribute type 29) is already captured in `attr.bgp_ls`. Loop detection
/// mirrors `route_flowspec_update`: a route carrying our own AS /
/// ORIGINATOR_ID / CLUSTER_LIST is dropped silently. BGP-LS has no AddPath,
/// so the path-id is always 0.
pub fn route_bgpls_update(
    ident: usize,
    nlri: &BgpLsNlri,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        if let Some(ref aspath) = attr.aspath
            && aspath_own_as_loop(peer, aspath)
        {
            return;
        }
        // FRR enforce-first-as: drop an inbound eBGP UPDATE whose AS_PATH
        // does not begin with this neighbor's own AS (eBGP only).
        if aspath_enforce_first_as_violation(peer, attr.aspath.as_ref()) {
            return;
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };

        (peer.ident, peer.remote_id, typ)
    };

    let stale = stale || attr_has_llgr_stale(attr);
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        0,    // remote_id — BGP-LS has no AddPath
        0,    // weight
        attr, // interned just below
        None, // label
        None, // nexthop — re-advertise next-hop is a later phase
        stale,
    );
    rib.attr = bgp.attr_store.intern(attr.clone());

    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add_bgpls(nlri.clone(), rib.clone());
    }

    // Select the single best path into the Loc-RIB. Reflection / install are
    // later phases, so the result is recorded but not propagated.
    let _ = bgp.local_rib.update_bgpls(nlri.clone(), rib);
}

/// Withdraw one BGP Link-State NLRI from the peer's Adj-RIB-In and the
/// Loc-RIB, then re-run best-path selection for that object. Propagation is
/// a later phase, so the re-selected result is recorded but not advertised.
pub fn route_bgpls_withdraw(ident: usize, nlri: &BgpLsNlri, bgp: &mut BgpTop, peers: &mut PeerMap) {
    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.remove_bgpls(nlri, 0);
    }
    bgp.local_rib.remove_bgpls(nlri, 0, ident);
    let _ = bgp.local_rib.select_best_path_bgpls(nlri);
}

/// Originate one locally-produced BGP Link-State NLRI (RFC 9552) into the
/// `bgp_ls` Loc-RIB as a self-originated route. Used by the IS-IS producer
/// bridge: IS-IS translates its LSDB to `BgpLsNlri`s and pushes them here.
///
/// Unlike `route_bgpls_update` (the receive path, which looks up a real
/// peer), this has no neighbor — it builds an `Originated` `BgpRib` keyed by
/// `ORIGINATED_PEER` and inserts straight into the Loc-RIB, mirroring
/// `evpn_originate_macip`. `ls_attr` is the producer-built BGP-LS Attribute
/// (path attribute type 29 — link/prefix metrics, admin-group, …); it is
/// stored on the route so `show bgp link-state` can render it and a future
/// advertise phase can re-emit it. An empty `ls_attr` leaves `bgp_ls` unset.
/// Re-advertisement to peers is deferred.
pub fn route_bgpls_originate(
    nlri: BgpLsNlri,
    ls_attr: BgpLsAttr,
    local_rib: &mut LocalRib,
    attr_store: &mut super::store::BgpAttrStore,
) {
    let mut attr = BgpAttr::new();
    if !ls_attr.is_empty() {
        attr.bgp_ls = Some(ls_attr);
    }
    let mut rib = BgpRib::new(
        ORIGINATED_PEER,
        Ipv4Addr::UNSPECIFIED,
        BgpRibType::Originated,
        0,     // remote_id — BGP-LS has no AddPath
        32768, // weight — default for locally-originated
        &attr,
        None, // label
        None, // nexthop
        false,
    );
    rib.attr = attr_store.intern(attr);
    let _ = local_rib.update_bgpls(nlri, rib);
}

/// Withdraw a previously-originated BGP-LS NLRI from the `bgp_ls` Loc-RIB
/// (the IS-IS producer no longer advertises it). Removes the
/// `ORIGINATED_PEER` candidate and re-runs best-path selection.
pub fn route_bgpls_withdraw_originated(nlri: &BgpLsNlri, local_rib: &mut LocalRib) {
    local_rib.remove_bgpls(nlri, 0, ORIGINATED_PEER);
    let _ = local_rib.select_best_path_bgpls(nlri);
}

/// Realize an SR Policy active-path change in the dataplane: remove the
/// previous SRv6 Binding SID and/or install the new one as an
/// End.B6.Encaps local SID (RFC 8986 §4.14) pushing the policy's
/// segment list, plus tear down an SR-MPLS Binding-SID ILM when a whole
/// policy is withdrawn. (The live SR-MPLS install/update is driven by
/// `sr_policy_mpls_sync` / `sr_policy_reconcile_mpls`, gated on NHT.)
fn apply_srpolicy_fib(delta: super::sr_policy::SrPolicyFibDelta, bgp: &mut BgpTop) {
    if let Some(addr) = delta.remove {
        let _ = bgp.rib_client.send(rib::Message::SidDel { addr });
    }
    if let Some(install) = delta.install {
        let sid = rib::Sid {
            addr: install.bsid,
            behavior: rib::SidBehavior::EndB6Encap,
            context: rib::SidContext::None,
            owner: rib::SidOwner::new("bgp", 0),
            locator: String::new(),
            allocation_type: rib::SidAllocationType::Dynamic,
            ifindex: 0,
            nh6: None,
            structure: None,
            table_id: 0,
            segs: install.segments,
        };
        let _ = bgp.rib_client.send(rib::Message::SidAdd { sid });
    }
    if let Some(label) = delta.mpls_remove {
        srpolicy_ilm_remove(bgp.rib_client, label);
    }
}

// =======================================================================
// Originator: advertise locally-configured SR Policies as SAFI 73.
// =======================================================================

/// Re-evaluate a locally-configured SR Policy after a config edit and
/// (re)advertise it to SAFI-73 peers, or withdraw it if it is no longer
/// complete. Called from the `sr-policy` config callbacks.
pub(super) fn srpolicy_origin_sync(bgp: &mut Bgp, name: &str) {
    let router_id = bgp.router_id;
    // Resolve to an owned action first so the `local_rib` borrow is
    // released before we touch `peers`.
    let action: Option<Result<(SrPolicyNlri, BgpAttr), SrPolicyNlri>> = bgp
        .local_rib
        .sr_policy_local
        .policies
        .get(name)
        .map(|p| match p.advert(router_id) {
            Some(pair) => Ok(pair),
            None => Err(p.nlri(router_id)),
        })
        .map(|r| match r {
            Ok(pair) => Ok(pair),
            // Incomplete: withdraw if an NLRI can still be formed.
            Err(Some(nlri)) => Err(nlri),
            Err(None) => Err(SrPolicyNlri {
                id: 0,
                distinguisher: 0,
                color: 0,
                endpoint: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            }),
        });
    match action {
        Some(Ok((nlri, attr))) => srpolicy_origin_reach(bgp, nlri, attr),
        // A synthetic all-zero NLRI means "nothing was ever advertisable"
        // — color/endpoint unset — so there is nothing to withdraw.
        Some(Err(nlri)) if nlri.color != 0 => srpolicy_origin_withdraw(bgp, nlri),
        _ => {}
    }
}

/// Idents of established peers that negotiated SAFI 73 for `afi`.
fn srpolicy_peer_idents(bgp: &Bgp, afi: Afi) -> Vec<usize> {
    bgp.peers.established_idents(afi, Safi::SrTePolicy)
}

/// Advertise one local SR Policy NLRI + attribute to every established
/// SAFI-73 peer of the endpoint's family (direct emit, no Adj-RIB-Out).
pub(super) fn srpolicy_origin_reach(bgp: &mut Bgp, nlri: SrPolicyNlri, attr: BgpAttr) {
    let afi = nlri.afi();
    let nhop = IpAddr::V4(bgp.router_id);
    for ident in srpolicy_peer_idents(bgp, afi) {
        let Some(peer) = bgp.peers.get_mut_by_idx(ident) else {
            continue;
        };
        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.mp_update = Some(MpReachAttr::SrPolicy {
            afi,
            snpa: 0,
            nhop,
            updates: vec![nlri.clone()],
        });
        update.bgp_attr = Some(attr.clone());
        if let Some(bytes) = update.pop_srpolicy()
            && let Some(ref tx) = peer.packet_tx
        {
            let _ = tx.send(bytes);
        }
    }
}

/// Withdraw one local SR Policy NLRI from every established SAFI-73 peer.
pub(super) fn srpolicy_origin_withdraw(bgp: &mut Bgp, nlri: SrPolicyNlri) {
    let afi = nlri.afi();
    for ident in srpolicy_peer_idents(bgp, afi) {
        let Some(peer) = bgp.peers.get_mut_by_idx(ident) else {
            continue;
        };
        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.mp_withdraw = Some(MpUnreachAttr::SrPolicy {
            afi,
            withdraws: vec![nlri.clone()],
        });
        if let Some(bytes) = update.pop_srpolicy_withdraw()
            && let Some(ref tx) = peer.packet_tx
        {
            let _ = tx.send(bytes);
        }
    }
}

/// On peer establishment, advertise every complete local SR Policy to
/// the new peer (the SAFI-73 analogue of `route_sync_evpn`).
pub fn route_sync_srpolicy(peer: &mut Peer, bgp: &BgpTop) {
    let router_id = *bgp.router_id;
    let max = peer.max_packet_size();
    let adverts: Vec<(Afi, SrPolicyNlri, BgpAttr)> = bgp
        .local_rib
        .sr_policy_local
        .policies
        .values()
        .filter_map(|p| {
            p.advert(router_id)
                .map(|(nlri, attr)| (nlri.afi(), nlri, attr))
        })
        .collect();
    for (afi, nlri, attr) in adverts {
        if !peer.is_afi_safi(afi, Safi::SrTePolicy) {
            continue;
        }
        let mut update = UpdatePacket::with_max_packet_size(max);
        update.mp_update = Some(MpReachAttr::SrPolicy {
            afi,
            snpa: 0,
            nhop: IpAddr::V4(router_id),
            updates: vec![nlri],
        });
        update.bgp_attr = Some(attr);
        if let Some(bytes) = update.pop_srpolicy()
            && let Some(ref tx) = peer.packet_tx
        {
            let _ = tx.send(bytes);
        }
    }
}

/// Track/untrack the policy endpoint with NHT and reconcile its SR-MPLS
/// Binding-SID ILM. The ILM forwards toward the endpoint's resolved
/// next-hop (an exact first hop for single-segment / endpoint-rooted
/// policies; an approximation when a multi-segment list's first waypoint
/// differs from the endpoint). Global instance only; a null endpoint
/// (color-only policy) has nothing to resolve.
fn sr_policy_mpls_sync(bgp: &mut BgpTop, color: u32, endpoint: IpAddr) {
    if bgp.nexthop_cache.is_none() || endpoint.is_unspecified() {
        return;
    }
    let dep = super::nht::NhtDep::SrPolicy { color, endpoint };
    let wants = bgp.local_rib.sr_policy.wants_mpls(color, endpoint);

    if wants && let Some(cache) = bgp.nexthop_cache.as_deref_mut() {
        let (needs_register, _reachable) = cache.track(endpoint, dep.clone());
        if needs_register {
            let _ = bgp.rib_client.send(rib::Message::NexthopRegister {
                proto: "bgp".to_string(),
                nh: endpoint,
            });
        }
    }

    if let Some(cache) = bgp.nexthop_cache.as_deref() {
        sr_policy_reconcile_mpls(
            bgp.rib_client,
            cache,
            &mut bgp.local_rib.sr_policy,
            color,
            endpoint,
        );
    }

    if !wants
        && let Some(cache) = bgp.nexthop_cache.as_deref_mut()
        && cache.untrack(endpoint, &dep)
    {
        let _ = bgp.rib_client.send(rib::Message::NexthopUnregister {
            proto: "bgp".to_string(),
            nh: endpoint,
        });
    }
}

/// Reconcile the SR-MPLS Binding-SID ILM for `<color, endpoint>` against
/// the active path and the endpoint's NHT resolution. Callable from the
/// receive path and from the NHT re-eval in `inst.rs`, so it takes the
/// RIB client + cache directly rather than a `BgpTop`.
pub(super) fn sr_policy_reconcile_mpls(
    rib_client: &crate::rib::client::RibClient,
    cache: &super::nht::NexthopCache,
    db: &mut super::sr_policy::SrPolicyDb,
    color: u32,
    endpoint: IpAddr,
) {
    let reachable = !cache.transport_for(endpoint).is_empty();
    let action = db.mpls_reconcile(color, endpoint, reachable);
    if let Some(label) = action.remove {
        srpolicy_ilm_remove(rib_client, label);
    }
    if let Some(install) = action.install {
        srpolicy_ilm_install(
            rib_client,
            install.bsid,
            &install.segments,
            cache.transport_for(endpoint),
        );
    }
}

/// Install the SR-MPLS Binding-SID ILM: incoming `bsid` label → push the
/// policy's `stack` (the explicit segment list) toward the resolved
/// `transport` egress(es). The transport's own labels are ignored — the
/// SR Policy stack is the explicit path; only the L2 next-hop is reused.
fn srpolicy_ilm_install(
    rib_client: &crate::rib::client::RibClient,
    bsid: u32,
    stack: &[u32],
    transport: &[rib::nht::ResolvedNexthop],
) {
    if transport.is_empty() {
        return;
    }
    let mk = |egress: &rib::nht::ResolvedNexthop| {
        let mut uni = rib::NexthopUni::new(egress.addr, 0, Vec::new());
        uni.mpls_label = stack.to_vec();
        if egress.ifindex != 0 {
            uni.ifindex_origin = Some(egress.ifindex);
        }
        uni.valid = true;
        uni
    };
    let nexthop = if transport.len() == 1 {
        rib::Nexthop::Uni(mk(&transport[0]))
    } else {
        let mut multi = rib::NexthopMulti::default();
        for egress in transport {
            multi.nexthops.push(mk(egress));
        }
        rib::Nexthop::Multi(multi)
    };
    let mut ilm = rib::inst::IlmEntry::new(rib::RibType::Bgp);
    ilm.ilm_type = rib::inst::IlmType::Swap;
    ilm.nexthop = nexthop;
    let _ = rib_client.send(rib::Message::IlmAdd { label: bsid, ilm });
}

/// Tear down the SR-MPLS Binding-SID ILM at `bsid`.
fn srpolicy_ilm_remove(rib_client: &crate::rib::client::RibClient, bsid: u32) {
    let ilm = rib::inst::IlmEntry::new(rib::RibType::Bgp);
    let _ = rib_client.send(rib::Message::IlmDel { label: bsid, ilm });
}

/// Propagate a flow spec's selected best path to peers: re-advertise it
/// when a valid (RFC 9117) best path exists, otherwise withdraw any
/// prior advertisement. Invalid best paths are kept in the Loc-RIB (and
/// shown) but never propagated.
fn route_flowspec_propagate(
    afi: Afi,
    nlri: &FlowspecNlri,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let Some(best) = selected.last() else {
        route_withdraw_flowspec_to_peers(afi, nlri, peers);
        return;
    };
    // RFC 9117 validity, honouring the source neighbor's per-neighbor
    // validation toggle. Invalid (or otherwise-suppressed) flow specs
    // are withdrawn from peers rather than advertised.
    let validation_enabled = peers
        .get_by_idx(best.ident)
        .map(|p| p.config.flowspec_validation)
        .unwrap_or(true);
    let valid =
        super::flowspec::flowspec_validate_with_mode(bgp.shard, nlri, best, validation_enabled)
            .is_valid();
    if valid {
        route_advertise_flowspec_to_peers(afi, nlri, best, bgp, peers);
    } else {
        route_withdraw_flowspec_to_peers(afi, nlri, peers);
    }
}

/// Build the per-peer flow spec NLRI + path attributes for a re-advertise.
/// Returns `None` to suppress the advertisement: split horizon (never
/// reflect back to the path's source) and iBGP-to-iBGP without route
/// reflection. eBGP prepends the local AS; iBGP supplies a default
/// LOCAL_PREF. Flow specs carry no next-hop (RFC 8955 §4.2.2), so the
/// NEXT_HOP attribute is cleared.
pub fn route_update_flowspec(
    peer: &mut Peer,
    nlri: &FlowspecNlri,
    rib: &BgpRib,
    add_path: bool,
) -> Option<(FlowspecNlri, BgpAttr)> {
    if rib.ident == peer.ident {
        return None;
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    let mut out = nlri.clone();
    out.id = if add_path { rib.local_id } else { 0 };

    let mut attrs = (*rib.attr).clone();
    ebgp_egress_aspath(peer, &mut attrs);
    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }
    // Flow specs have no next-hop in MP_REACH; don't emit a NEXT_HOP.
    attrs.nexthop = None;

    Some((out, attrs))
}

fn send_flowspec_one(peer: &mut Peer, afi: Afi, nlri: FlowspecNlri, attr: Arc<BgpAttr>) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_update = Some(MpReachAttr::Flowspec {
        afi,
        updates: vec![nlri],
    });
    update.bgp_attr = Some((*attr).clone());
    peer.send_packet(update.into());
}

/// Advertise a flow spec's best path to every Established peer that has
/// negotiated the matching `(afi, Flowspec)` family. Records the
/// advertisement in each peer's Adj-RIB-Out so a later change can
/// withdraw it.
pub fn route_advertise_flowspec_to_peers(
    afi: Afi,
    nlri: &FlowspecNlri,
    best: &BgpRib,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let peer_idents: Vec<usize> = peers.established_idents(afi, Safi::Flowspec);

    for ident in peer_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        let add_path = peer.opt.is_add_path_send(afi, Safi::Flowspec);

        let Some((out_nlri, attr)) = route_update_flowspec(peer, nlri, best, add_path) else {
            continue;
        };

        let attr = bgp.attr_store.intern(attr);
        let mut adj = best.clone();
        adj.attr = attr.clone();
        peer.adj_out.add_flowspec(afi, out_nlri.clone(), adj);
        send_flowspec_one(peer, afi, out_nlri, attr);
    }
}

/// Withdraw a flow spec from every peer to which it was advertised
/// (tracked via Adj-RIB-Out), sending one MP_UNREACH UPDATE each.
pub fn route_withdraw_flowspec_to_peers(afi: Afi, nlri: &FlowspecNlri, peers: &mut PeerMap) {
    let peer_idents: Vec<usize> = peers.established_idents(afi, Safi::Flowspec);

    for ident in peer_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        // Only withdraw what we actually advertised (skips the source
        // peer and any peer the announce-side policy suppressed).
        let advertised = {
            let table = if afi == Afi::Ip6 {
                &peer.adj_out.flowspec_v6
            } else {
                &peer.adj_out.flowspec_v4
            };
            table.0.contains_key(nlri)
        };
        if !advertised {
            continue;
        }
        peer.adj_out.remove_flowspec(afi, nlri, 0);

        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.mp_withdraw = Some(MpUnreachAttr::Flowspec {
            afi,
            withdraws: vec![nlri.clone()],
        });
        peer.send_packet(update.into());
    }
}

/// Withdraw every reachable NLRI carried in an MP_REACH attribute — the
/// RFC 7606 / RFC 9252 §7 treat-as-withdraw action taken when the
/// UPDATE's BGP Prefix-SID attribute is malformed. Mirrors the install
/// match in [`route_from_peer`], routing each AFI/SAFI through its
/// `*_withdraw` path so any previously-installed copy from this peer is
/// removed. RTC and any other family that cannot carry a Prefix-SID
/// attribute fall through the catch-all as a no-op.
fn withdraw_mp_reach(
    peer_id: usize,
    mp: MpReachAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    match mp {
        MpReachAttr::Vpnv4(nlri) => {
            for update in nlri.updates.iter() {
                route_ipv4_withdraw(
                    peer_id,
                    &update.nlri,
                    Some(update.rd),
                    Some(update.label),
                    bgp,
                    peers,
                    None,
                    true,
                );
            }
        }
        MpReachAttr::Vpnv6(nlri) => {
            for update in nlri.updates.iter() {
                route_ipv6_withdraw(peer_id, &update.nlri, Some(update.rd), bgp, peers, true);
            }
        }
        MpReachAttr::Evpn { updates, .. } => {
            for route in updates.iter() {
                route_evpn_withdraw(peer_id, route, bgp, peers);
            }
        }
        MpReachAttr::Ipv4 { updates, .. } => {
            for update in updates.iter() {
                route_ipv4_withdraw(peer_id, update, None, None, bgp, peers, shards, true);
            }
        }
        MpReachAttr::Ipv6 { updates, .. } => {
            for update in updates.iter() {
                route_ipv6_withdraw(peer_id, update, None, bgp, peers, true);
            }
        }
        MpReachAttr::Labelv4 { updates, .. } => {
            for lu in updates.iter() {
                route_labelv4_withdraw(peer_id, &lu.nlri, bgp, peers, true);
            }
        }
        MpReachAttr::Labelv6 { updates, .. } => {
            for lu in updates.iter() {
                route_labelv6_withdraw(peer_id, &lu.nlri, bgp, peers, true);
            }
        }
        MpReachAttr::Flowspec { afi, updates } => {
            for nlri in updates.iter() {
                route_flowspec_withdraw(peer_id, nlri, afi, bgp, peers);
            }
        }
        MpReachAttr::SrPolicy { updates, .. } => {
            for nlri in updates.iter() {
                route_srpolicy_withdraw(peer_id, nlri, bgp, peers);
            }
        }
        MpReachAttr::LinkState { updates, .. } => {
            for nlri in updates.iter() {
                route_bgpls_withdraw(peer_id, nlri, bgp, peers);
            }
        }
        _ => {
            // Rtcv4 / Rtcv6 and any other family that cannot carry a
            // Prefix-SID attribute — nothing to withdraw.
        }
    }
}

pub fn route_from_peer(
    peer_id: usize,
    mut packet: UpdatePacket,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    if let Some(peer) = peers.get_by_idx(peer_id) {
        bgp_adj_in_trace!(
            peer,
            updates = packet.ipv4_update.len(),
            withdraws = packet.ipv4_withdraw.len(),
            "recv UPDATE NLRI"
        );
    }
    // `local-as` ingress prepend (FRR does this at the attribute-parse
    // stage, bgp_attr.c): routes received from an eBGP neighbor with an
    // active substitute AS get the substitute prepended once, so the
    // rest of the network sees the path as if it still transited the
    // old AS; `no-prepend` turns it off. Done here — once per UPDATE,
    // before the per-family dispatch — because every family handler
    // below shares `packet.bgp_attr`. Adj-RIB-In stores the
    // post-prepend attrs, so soft-reconfig replays (which start from
    // `peer.adj_in`, not from here) never prepend twice.
    if let Some(peer) = peers.get_by_idx(peer_id)
        && peer.is_ebgp()
        && let Some(substitute) = peer.change_local_as()
        && !peer.config.local_as.is_some_and(|la| la.no_prepend)
        && let Some(attr) = packet.bgp_attr.as_mut()
        && let Some(aspath) = attr.aspath.as_mut()
    {
        aspath.prepend_mut(As4Path::from(vec![substitute]));
    }
    // Convert UpdatePacket to BgpAttr.
    // let attr = BgpAttr::from(&packet.attrs);

    // Convert UpdatePacket to BgpNlri.
    // let nlri = BgpNlriAttr::from(&packet);
    // RFC 7606 / RFC 9252 §7: when the UPDATE carried a malformed
    // Prefix-SID attribute, its reachable NLRI are treat-as-withdraw —
    // remove any installed copy from this peer instead of installing —
    // while the UPDATE's explicit withdrawals are still honoured and the
    // session stays up.
    let treat_as_withdraw = packet.treat_as_withdraw;

    if treat_as_withdraw {
        for update in packet.ipv4_update.iter() {
            route_ipv4_withdraw(peer_id, update, None, None, bgp, peers, shards, true);
        }
    } else if let Some(bgp_attr) = &packet.bgp_attr {
        // Plain IPv4-unicast ingest goes through the batch path, which
        // fans the per-prefix inbound-policy walk across cores (C.1).
        route_ipv4_update_batch(
            peer_id,
            &packet.ipv4_update,
            bgp_attr,
            bgp,
            peers,
            shards,
            false,
        );
    }

    for withdraw in packet.ipv4_withdraw.iter() {
        route_ipv4_withdraw(peer_id, withdraw, None, None, bgp, peers, shards, true);
    }
    if let Some(mp_updates) = packet.mp_update {
        if treat_as_withdraw {
            withdraw_mp_reach(peer_id, mp_updates, bgp, peers, shards);
        } else if let Some(bgp_attr) = &packet.bgp_attr {
            match mp_updates {
                MpReachAttr::Vpnv4(nlri) => {
                    for update in nlri.updates.iter() {
                        route_ipv4_update(
                            peer_id,
                            &update.nlri,
                            Some(update.rd),
                            Some(update.label),
                            bgp_attr,
                            Some(VpnNexthop::V4(nlri.nhop.clone())),
                            None,
                            bgp,
                            peers,
                            false,
                        )
                    }
                }
                MpReachAttr::Rtcv4(nlri) => {
                    for update in nlri.updates.iter() {
                        route_ipv4_rtc_update(peer_id, update, peers);
                    }
                }
                MpReachAttr::Rtcv6(nlri) => {
                    for update in nlri.updates.iter() {
                        route_ipv6_rtc_update(peer_id, update, peers);
                    }
                }
                MpReachAttr::Evpn {
                    snpa: _,
                    nhop,
                    updates,
                } => {
                    for route in updates.iter() {
                        route_evpn_update(peer_id, route, nhop, bgp_attr, bgp, peers, false);
                    }
                }
                MpReachAttr::Ipv4 {
                    snpa: _,
                    nhop,
                    updates,
                } => {
                    // RFC 8950 IPv4-over-IPv6: install the prefix into
                    // Loc-RIB and the FIB with the v6 next-hop from
                    // MP_REACH (the remote's link-local) as the gateway,
                    // pinned to the egress ifindex of the peer that
                    // delivered the UPDATE (a link-local needs its
                    // interface). ENHE on a non-interface peer or with a
                    // v4-shaped next-hop is unexpected — ENHE is currently
                    // only negotiated by unnumbered peers; log and drop in
                    // that case rather than fall back to a bogus install.
                    let egress_ifindex = peers.get_by_idx(peer_id).and_then(|p| p.scope_id);
                    if let (IpAddr::V6(nh6), Some(ifindex)) = (nhop, egress_ifindex) {
                        for update in updates.iter() {
                            route_ipv4_update(
                                peer_id,
                                update,
                                None,
                                None,
                                bgp_attr,
                                None,
                                Some((nh6, ifindex)),
                                bgp,
                                peers,
                                false,
                            );
                        }
                    } else {
                        tracing::warn!(
                            "RFC 8950: dropping IPv4 routes from peer {} via next-hop {} — need a v6 next-hop and an egress ifindex",
                            peer_id,
                            nhop,
                        );
                    }
                }
                MpReachAttr::Ipv6 {
                    snpa: _,
                    nhop,
                    updates,
                } => {
                    // Native IPv6 unicast: the MP_REACH next-hop replaces
                    // the (unused) v4 NEXT_HOP attribute. Stamp it into the
                    // attr so best-path / FIB read a v6 next-hop.
                    if let IpAddr::V6(nh6) = nhop {
                        let mut attr_v6 = bgp_attr.clone();
                        attr_v6.nexthop = Some(BgpNexthop::Ipv6(nh6));
                        for update in updates.iter() {
                            route_ipv6_update(
                                peer_id, update, None, None, &attr_v6, None, bgp, peers, false,
                            );
                        }
                    } else {
                        tracing::warn!(
                            "IPv6 unicast MP_REACH from peer {} carried a non-v6 next-hop {} — dropping",
                            peer_id,
                            nhop,
                        );
                    }
                }
                MpReachAttr::Vpnv6(nlri) => {
                    // VPNv6: store each route under its RD in the global
                    // v6vpn Loc-RIB, carrying the route's Vpnv6 next-hop.
                    for update in nlri.updates.iter() {
                        route_ipv6_update(
                            peer_id,
                            &update.nlri,
                            Some(update.rd),
                            Some(update.label),
                            bgp_attr,
                            Some(VpnNexthop::V6(nlri.nhop.clone())),
                            bgp,
                            peers,
                            false,
                        );
                    }
                }
                MpReachAttr::Flowspec { afi, updates } => {
                    for nlri in updates.iter() {
                        route_flowspec_update(peer_id, nlri, afi, bgp_attr, bgp, peers, false);
                    }
                }
                MpReachAttr::SrPolicy { nhop, updates, .. } => {
                    // SAFI 73: candidate-path content rides in the Tunnel
                    // Encapsulation attribute; the NLRI endpoint carries the
                    // AFI, so v4/v6 share one path.
                    for nlri in updates.iter() {
                        route_srpolicy_update(peer_id, nlri, bgp_attr, nhop, bgp, peers);
                    }
                }
                MpReachAttr::LinkState { updates, .. } => {
                    // AFI 16388 / SAFI 71: Node/Link/Prefix objects. The
                    // companion attributes ride in the BGP-LS Attribute
                    // (type 29), already captured in `bgp_attr.bgp_ls`. The
                    // MP_REACH next-hop is informational here; re-advertisement
                    // is a later phase. The v4/v6 split lives inside the NLRI,
                    // so a single Loc-RIB table holds every object.
                    for nlri in updates.iter() {
                        route_bgpls_update(peer_id, nlri, bgp_attr, bgp, peers, false);
                    }
                }
                MpReachAttr::Labelv4 {
                    snpa: _,
                    nhop,
                    updates,
                } => {
                    // IPv4 Labeled-Unicast (SAFI 4): store each route in the
                    // v4lu Loc-RIB with its per-prefix label. The MP_REACH
                    // next-hop is authoritative.
                    for update in updates.iter() {
                        route_labelv4_update(peer_id, update, nhop, bgp_attr, bgp, peers, false);
                    }
                }
                MpReachAttr::Labelv6 {
                    snpa: _,
                    nhop,
                    updates,
                } => {
                    // IPv6 Labeled-Unicast (SAFI 4), including 6PE.
                    for update in updates.iter() {
                        route_labelv6_update(peer_id, update, nhop, bgp_attr, bgp, peers, false);
                    }
                }
                _ => {
                    //
                }
            }
        }
    }
    if let Some(mp_withdrawals) = packet.mp_withdraw {
        match mp_withdrawals {
            MpUnreachAttr::Vpnv4(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_ipv4_withdraw(
                        peer_id,
                        &withdraw.nlri,
                        Some(withdraw.rd),
                        Some(withdraw.label),
                        bgp,
                        peers,
                        None,
                        true,
                    );
                }
            }
            MpUnreachAttr::Vpnv4Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip, Safi::MplsVpn);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            MpUnreachAttr::Rtcv4Eor => {
                // If peer's EoR is true.
                route_rtcv4_sync(peer_id, bgp, peers);
            }
            MpUnreachAttr::Rtcv6Eor => {
                // The peer's VPNv6 import-RT membership (collected in
                // `peer.rtcv6` from the preceding MP_REACH) now gates our
                // event-driven VPNv6 advertise. There is no VPNv6
                // sync-on-establish replay to trigger here (unlike the
                // VPNv4 path), so the EoR is purely informational.
            }
            MpUnreachAttr::Evpn(withdrawals) => {
                for route in withdrawals.iter() {
                    route_evpn_withdraw(peer_id, route, bgp, peers);
                }
            }
            MpUnreachAttr::EvpnEor => {
                let afi_safi = AfiSafi::new(Afi::L2vpn, Safi::Evpn);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            MpUnreachAttr::Ipv6Nlri(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_ipv6_withdraw(peer_id, withdraw, None, bgp, peers, true);
                }
            }
            MpUnreachAttr::Ipv6Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            MpUnreachAttr::Vpnv6(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_ipv6_withdraw(
                        peer_id,
                        &withdraw.nlri,
                        Some(withdraw.rd),
                        bgp,
                        peers,
                        true,
                    );
                }
            }
            MpUnreachAttr::Vpnv6Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip6, Safi::MplsVpn);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            MpUnreachAttr::Flowspec { afi, withdraws } => {
                for nlri in withdraws.iter() {
                    route_flowspec_withdraw(peer_id, nlri, afi, bgp, peers);
                }
                // An empty `withdraws` is End-of-RIB. Graceful-restart
                // stale handling for flow specs is deferred (no Loc-RIB
                // yet), so there is nothing to flush.
            }
            MpUnreachAttr::SrPolicy { withdraws, .. } => {
                for nlri in withdraws.iter() {
                    route_srpolicy_withdraw(peer_id, nlri, bgp, peers);
                }
                // An empty `withdraws` is End-of-RIB; nothing to flush.
            }
            MpUnreachAttr::LinkState { withdraws } => {
                for nlri in withdraws.iter() {
                    route_bgpls_withdraw(peer_id, nlri, bgp, peers);
                }
                // An empty `withdraws` is End-of-RIB; nothing to flush.
            }
            MpUnreachAttr::Labelv4(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_labelv4_withdraw(peer_id, &withdraw.nlri, bgp, peers, true);
                }
            }
            MpUnreachAttr::Labelv4Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip, Safi::MplsLabel);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            MpUnreachAttr::Labelv6(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_labelv6_withdraw(peer_id, &withdraw.nlri, bgp, peers, true);
                }
            }
            MpUnreachAttr::Labelv6Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip6, Safi::MplsLabel);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            _ => {
                //
            }
        }
    }
}

pub fn route_clean(
    peer_id: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    // IPv4 unicast. At N>1 the peer's v4-unicast routes live on the pool
    // shards, not `bgp.shard`; dispatch a PeerDown to each so it sweeps
    // its own slice (drops Adj-RIB-In + re-runs best-path), and the async
    // reduce withdraws or re-advertises. At N=1 sweep the in-process shard
    // inline, as before. (Only v4-unicast is pooled, so a pool shard's
    // PeerDown touches only that family; v6 / VPN / LU are swept below on
    // `bgp.shard` at every N.)
    if let Some(pool) = shards {
        for idx in 0..pool.n() {
            pool.dispatch(idx, ShardMsg::PeerDown { ident: peer_id });
        }
    } else {
        let withdrawn = {
            let mut withdrawn: Vec<Ipv4Nlri> = vec![];
            if let Some(adj_in) = bgp.shard.adj_in(peer_id) {
                for (prefix, ribs) in adj_in.v4.0.iter() {
                    for rib in ribs.iter() {
                        let withdraw = Ipv4Nlri {
                            id: rib.remote_id,
                            prefix: *prefix,
                        };
                        withdrawn.push(withdraw);
                    }
                }
            }
            withdrawn
        };
        for withdraw in withdrawn.iter() {
            route_ipv4_withdraw(peer_id, withdraw, None, None, bgp, peers, None, true);
        }
        bgp.shard.adj_in_mut(peer_id).v4.0.clear();
    }
    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.v4.0.clear();

    peer.cache_vpnv4.clear();
    peer.cache_vpnv6.clear();

    // IPv6 unicast. Same shape as the IPv4 block above — withdraw
    // every prefix the peer gave us from the Loc-RIB (which fans out
    // MP_UNREACH to other peers and removes any main-RIB install),
    // then drop the Adj-RIB tables. Was missing entirely: a session
    // leaving Established kept its v6 routes selected forever.
    let withdrawn_v6 = {
        let mut withdrawn: Vec<Ipv6Nlri> = vec![];
        if let Some(adj_in) = bgp.shard.adj_in(peer_id) {
            for (prefix, ribs) in adj_in.v6.0.iter() {
                for rib in ribs.iter() {
                    withdrawn.push(Ipv6Nlri {
                        id: rib.remote_id,
                        prefix: *prefix,
                    });
                }
            }
        }
        withdrawn
    };
    for withdraw in withdrawn_v6.iter() {
        route_ipv6_withdraw(peer_id, withdraw, None, bgp, peers, true);
    }
    bgp.shard.adj_in_mut(peer_id).v6.0.clear();
    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.v6.0.clear();

    // IPv4 VPN.
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::MplsVpn);
    if let Some(_) = peer.cap_send.llgr.get(&afi_safi)
        && let Some(llgr) = peer.cap_recv.llgr.get(&afi_safi)
    {
        // Start stale timer.
        peer.timer.stale_timer.insert(
            afi_safi,
            start_stale_timer(peer, afi_safi, llgr.stale_time()),
        );

        // RFC 9494 §4.2: routes the peer marked NO_LLGR "MUST NOT be
        // retained" by the long-lived procedures — remove and withdraw
        // them per normal RFC 4271 operation; only the rest go stale.
        let no_llgr: Vec<Vpnv4Nlri> = {
            let mut out = Vec::new();
            for (rd, table) in bgp.shard.adj_in_mut(peer_id).v4vpn.iter_mut() {
                for (prefix, ribs) in table.0.iter_mut() {
                    ribs.retain(|rib| {
                        let refuse = attr_refuses_llgr(&rib.attr);
                        if refuse {
                            out.push(Vpnv4Nlri {
                                label: rib.label.unwrap_or_default(),
                                rd: *rd,
                                nlri: Ipv4Nlri {
                                    id: rib.remote_id,
                                    prefix: *prefix,
                                },
                            });
                        }
                        !refuse
                    });
                }
            }
            out
        };
        for withdraw in no_llgr.iter() {
            route_ipv4_withdraw(
                peer_id,
                &withdraw.nlri,
                Some(withdraw.rd),
                Some(withdraw.label),
                bgp,
                peers,
                None,
                true,
            );
        }
        {
            // Disjoint borrows of two `BgpShard` fields: the adj-in
            // slice we mutate in place and the shard attr store we
            // re-intern into. (`adj_in_mut(..)` would borrow all of
            // `shard`, conflicting with `shard.intern`.)
            let super::shard::BgpShard {
                adj_in, attr_store, ..
            } = &mut *bgp.shard;
            if let Some(slice) = adj_in.get_mut(&peer_id) {
                for (_rd, table) in slice.v4vpn.iter_mut() {
                    for (_prefix, ribs) in table.0.iter_mut() {
                        for rib in ribs.iter_mut() {
                            rib.stale = true;
                            let mut new_attr = (*rib.attr).clone();
                            match &mut new_attr.com {
                                Some(com) => {
                                    com.insert(CommunityValue::LLGR_STALE.value());
                                }
                                None => {
                                    let mut com = Community::new();
                                    com.insert(CommunityValue::LLGR_STALE.value());
                                    new_attr.com = Some(com);
                                }
                            }
                            rib.attr = attr_store.intern(new_attr);
                        }
                    }
                }
            }
        }

        // Collect stale routes to update in LocalRib.
        let stale_updates: Vec<(
            RouteDistinguisher,
            Ipv4Nlri,
            Option<Label>,
            BgpAttr,
            Option<VpnNexthop>,
        )> = {
            let mut updates = Vec::new();
            for (rd, table) in bgp.shard.adj_in_mut(peer_id).v4vpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        let nlri = Ipv4Nlri {
                            id: rib.remote_id,
                            prefix: *prefix,
                        };
                        updates.push((
                            *rd,
                            nlri,
                            rib.label,
                            (*rib.attr).clone(),
                            rib.nexthop.clone(),
                        ));
                    }
                }
            }
            updates
        };

        // Update LocalRib with stale routes.
        for (rd, nlri, label, attr, nexthop) in stale_updates {
            route_ipv4_update(
                peer_id,
                &nlri,
                Some(rd),
                label,
                &attr,
                nexthop,
                None,
                bgp,
                peers,
                true,
            );
        }
    } else {
        let withdrawn = {
            let mut withdrawn: Vec<Vpnv4Nlri> = vec![];
            for (rd, table) in bgp.shard.adj_in_mut(peer_id).v4vpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        let withdraw = Vpnv4Nlri {
                            label: rib.label.unwrap_or(Label::default()),
                            rd: *rd,
                            nlri: Ipv4Nlri {
                                id: rib.remote_id,
                                prefix: *prefix,
                            },
                        };
                        withdrawn.push(withdraw);
                    }
                }
            }
            withdrawn
        };
        for withdraw in withdrawn.iter() {
            route_ipv4_withdraw(
                peer_id,
                &withdraw.nlri,
                Some(withdraw.rd),
                Some(withdraw.label),
                bgp,
                peers,
                None,
                true,
            );
        }
        bgp.shard.adj_in_mut(peer_id).v4vpn.clear();
    }

    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.v4vpn.clear();

    // IPv6 VPN. Same two-branch shape as the VPNv4 block above:
    // LLGR-negotiated sessions retain the adj-in entries stale-marked
    // (LLGR_STALE community attached, stale timer armed); otherwise
    // withdraw everything. Was missing entirely alongside the v6
    // unicast block.
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::MplsVpn);
    if peer.cap_send.llgr.contains_key(&afi_safi)
        && let Some(llgr) = peer.cap_recv.llgr.get(&afi_safi)
    {
        peer.timer.stale_timer.insert(
            afi_safi,
            start_stale_timer(peer, afi_safi, llgr.stale_time()),
        );

        // RFC 9494 §4.2: NO_LLGR routes are not retained — remove and
        // withdraw them; only the rest go stale.
        let no_llgr: Vec<Vpnv6Nlri> = {
            let mut out = Vec::new();
            for (rd, table) in bgp.shard.adj_in_mut(peer_id).v6vpn.iter_mut() {
                for (prefix, ribs) in table.0.iter_mut() {
                    ribs.retain(|rib| {
                        let refuse = attr_refuses_llgr(&rib.attr);
                        if refuse {
                            out.push(Vpnv6Nlri {
                                label: rib.label.unwrap_or_default(),
                                rd: *rd,
                                nlri: Ipv6Nlri {
                                    id: rib.remote_id,
                                    prefix: *prefix,
                                },
                            });
                        }
                        !refuse
                    });
                }
            }
            out
        };
        for withdraw in no_llgr.iter() {
            route_ipv6_withdraw(peer_id, &withdraw.nlri, Some(withdraw.rd), bgp, peers, true);
        }
        {
            // Disjoint borrows of two `BgpShard` fields (see the v4
            // VPN block above for why `adj_in_mut` + `shard.intern`
            // would conflict).
            let super::shard::BgpShard {
                adj_in, attr_store, ..
            } = &mut *bgp.shard;
            if let Some(slice) = adj_in.get_mut(&peer_id) {
                for (_rd, table) in slice.v6vpn.iter_mut() {
                    for (_prefix, ribs) in table.0.iter_mut() {
                        for rib in ribs.iter_mut() {
                            rib.stale = true;
                            let mut new_attr = (*rib.attr).clone();
                            match &mut new_attr.com {
                                Some(com) => {
                                    com.insert(CommunityValue::LLGR_STALE.value());
                                }
                                None => {
                                    let mut com = Community::new();
                                    com.insert(CommunityValue::LLGR_STALE.value());
                                    new_attr.com = Some(com);
                                }
                            }
                            rib.attr = attr_store.intern(new_attr);
                        }
                    }
                }
            }
        }

        // Re-import the now-stale entries into the Loc-RIB so best
        // path selection still sees them (with the stale community).
        let stale_updates: Vec<(
            RouteDistinguisher,
            Ipv6Nlri,
            Option<Label>,
            BgpAttr,
            Option<VpnNexthop>,
        )> = {
            let mut updates = Vec::new();
            for (rd, table) in bgp.shard.adj_in_mut(peer_id).v6vpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        let nlri = Ipv6Nlri {
                            id: rib.remote_id,
                            prefix: *prefix,
                        };
                        updates.push((
                            *rd,
                            nlri,
                            rib.label,
                            (*rib.attr).clone(),
                            rib.nexthop.clone(),
                        ));
                    }
                }
            }
            updates
        };
        for (rd, nlri, label, attr, nexthop) in stale_updates {
            route_ipv6_update(
                peer_id,
                &nlri,
                Some(rd),
                label,
                &attr,
                nexthop,
                bgp,
                peers,
                true,
            );
        }
    } else {
        let withdrawn = {
            let mut withdrawn: Vec<Vpnv6Nlri> = vec![];
            for (rd, table) in bgp.shard.adj_in_mut(peer_id).v6vpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        withdrawn.push(Vpnv6Nlri {
                            label: rib.label.unwrap_or_default(),
                            rd: *rd,
                            nlri: Ipv6Nlri {
                                id: rib.remote_id,
                                prefix: *prefix,
                            },
                        });
                    }
                }
            }
            withdrawn
        };
        for withdraw in withdrawn.iter() {
            route_ipv6_withdraw(peer_id, &withdraw.nlri, Some(withdraw.rd), bgp, peers, true);
        }
        bgp.shard.adj_in_mut(peer_id).v6vpn.clear();
    }

    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.v6vpn.clear();

    // EVPN. Same shape as the VPNv4 block above:
    //   * If both ends advertised LLGR for L2VPN/EVPN, retain the
    //     adj-in entries marked stale (with the LLGR_STALE community
    //     attached) and re-import them into the local-RIB so best
    //     path selection still considers them; the stale timer
    //     evicts them later.
    //   * Otherwise, withdraw every route the peer had given us.
    //     `route_evpn_withdraw` removes from adj-in + local-RIB and
    //     fans out MP_UNREACH to other peers (covering any kernel
    //     install/withdraw via `route_evpn_export_selected`).
    let afi_safi_evpn = AfiSafi::new(Afi::L2vpn, Safi::Evpn);
    let llgr_evpn = peer.cap_send.llgr.contains_key(&afi_safi_evpn)
        && peer.cap_recv.llgr.contains_key(&afi_safi_evpn);
    if llgr_evpn {
        let stale_time = peer
            .cap_recv
            .llgr
            .get(&afi_safi_evpn)
            .expect("checked above")
            .stale_time();
        peer.timer.stale_timer.insert(
            afi_safi_evpn,
            start_stale_timer(peer, afi_safi_evpn, stale_time),
        );

        // RFC 9494 §4.2: NO_LLGR routes are not retained — remove and
        // withdraw them; only the rest are stale-marked below.
        let no_llgr: Vec<EvpnRoute> = {
            let mut out = Vec::new();
            for (rd, table) in peer.adj_in.evpn.iter_mut() {
                for (prefix, ribs) in table.0.iter_mut() {
                    ribs.retain(|rib| {
                        let refuse = attr_refuses_llgr(&rib.attr);
                        if refuse && let Some(route) = build_evpn_route(rd, prefix, rib) {
                            out.push(route);
                        }
                        !refuse
                    });
                }
            }
            out
        };
        for route in no_llgr.iter() {
            route_evpn_withdraw(peer_id, route, bgp, peers);
        }
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");

        for (_rd, table) in peer.adj_in.evpn.iter_mut() {
            for (_prefix, ribs) in table.0.iter_mut() {
                for rib in ribs.iter_mut() {
                    rib.stale = true;
                    let mut new_attr = (*rib.attr).clone();
                    match &mut new_attr.com {
                        Some(com) => {
                            com.insert(CommunityValue::LLGR_STALE.value());
                        }
                        None => {
                            let mut com = Community::new();
                            com.insert(CommunityValue::LLGR_STALE.value());
                            new_attr.com = Some(com);
                        }
                    }
                    rib.attr = bgp.attr_store.intern(new_attr);
                }
            }
        }

        // Re-import the now-stale entries into local-RIB so best-path
        // re-evaluation includes the stale attr+community.
        let stale_updates: Vec<(EvpnRoute, BgpAttr, IpAddr)> = {
            let mut updates = Vec::new();
            for (rd, table) in peer.adj_in.evpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        if let Some(route) = build_evpn_route(rd, prefix, rib) {
                            let nhop = match rib.attr.nexthop.as_ref() {
                                Some(BgpNexthop::Evpn(addr)) => *addr,
                                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            };
                            updates.push((route, (*rib.attr).clone(), nhop));
                        }
                    }
                }
            }
            updates
        };
        for (route, attr, nhop) in stale_updates {
            route_evpn_update(peer_id, &route, nhop, &attr, bgp, peers, true);
        }
    } else {
        let withdrawn: Vec<EvpnRoute> = {
            let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
            let mut out = Vec::new();
            for (rd, table) in peer.adj_in.evpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        if let Some(route) = build_evpn_route(rd, prefix, rib) {
                            out.push(route);
                        }
                    }
                }
            }
            out
        };
        for route in withdrawn.iter() {
            route_evpn_withdraw(peer_id, route, bgp, peers);
        }
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
        peer.adj_in.evpn.clear();
    }

    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.evpn.clear();
    peer.cache_evpn.clear();
    peer.cache_evpn_rev.clear();
    peer.cache_evpn_timer = None;

    // IPv4 / IPv6 Labeled-Unicast (SAFI 4). No LLGR handling yet —
    // withdraw every labeled route the peer gave us and clear the
    // Adj-RIB tables, mirroring the unicast block above.
    let withdrawn_v4lu = {
        let mut withdrawn: Vec<Ipv4Nlri> = vec![];
        for (prefix, ribs) in bgp.shard.adj_in_mut(peer_id).v4lu.0.iter() {
            for rib in ribs.iter() {
                withdrawn.push(Ipv4Nlri {
                    id: rib.remote_id,
                    prefix: *prefix,
                });
            }
        }
        withdrawn
    };
    for withdraw in withdrawn_v4lu.iter() {
        route_labelv4_withdraw(peer_id, withdraw, bgp, peers, true);
    }
    let withdrawn_v6lu = {
        let mut withdrawn: Vec<Ipv6Nlri> = vec![];
        for (prefix, ribs) in bgp.shard.adj_in_mut(peer_id).v6lu.0.iter() {
            for rib in ribs.iter() {
                withdrawn.push(Ipv6Nlri {
                    id: rib.remote_id,
                    prefix: *prefix,
                });
            }
        }
        withdrawn
    };
    for withdraw in withdrawn_v6lu.iter() {
        route_labelv6_withdraw(peer_id, withdraw, bgp, peers, true);
    }
    {
        let adj_in = bgp.shard.adj_in_mut(peer_id);
        adj_in.v4lu.0.clear();
        adj_in.v6lu.0.clear();
    }
    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.v4lu.0.clear();
    peer.adj_out.v6lu.0.clear();

    // Flowspec v4 / v6 (SAFI 133). Withdraw each rule the peer gave
    // us — `route_flowspec_withdraw` removes adj-in + Loc-RIB entry
    // and re-propagates — then drop the Adj-RIB tables.
    let withdrawn_fs: Vec<(Afi, FlowspecNlri)> = {
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
        let mut out = Vec::new();
        for nlri in peer.adj_in.flowspec_v4.0.keys() {
            out.push((Afi::Ip, nlri.clone()));
        }
        for nlri in peer.adj_in.flowspec_v6.0.keys() {
            out.push((Afi::Ip6, nlri.clone()));
        }
        out
    };
    for (afi, nlri) in withdrawn_fs.iter() {
        route_flowspec_withdraw(peer_id, nlri, *afi, bgp, peers);
    }
    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_in.flowspec_v4.0.clear();
    peer.adj_in.flowspec_v6.0.clear();
    peer.adj_out.flowspec_v4.0.clear();
    peer.adj_out.flowspec_v6.0.clear();

    // BGP Link-State (SAFI 71). Withdraw each NLRI the peer gave us
    // from the bgp_ls Loc-RIB, then drop the Adj-RIB tables.
    let withdrawn_ls: Vec<BgpLsNlri> = {
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
        peer.adj_in.bgp_ls.0.keys().cloned().collect()
    };
    for nlri in withdrawn_ls.iter() {
        route_bgpls_withdraw(peer_id, nlri, bgp, peers);
    }
    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_in.bgp_ls.0.clear();
    peer.adj_out.bgp_ls.0.clear();

    // SR Policy (SAFI 73). The candidate paths live in the headend
    // database keyed by <color, endpoint, discriminator> with the
    // contributing peer recorded per candidate — sweep this peer's
    // candidates out through `route_srpolicy_withdraw`, which also
    // tears down any installed Binding-SID / MPLS FIB state and
    // reflects the withdraw to other SAFI-73 peers.
    let withdrawn_srp: Vec<SrPolicyNlri> = {
        let mut out = Vec::new();
        for (key, policy) in bgp.local_rib.sr_policy.policies.iter() {
            for (cp_key, cp) in policy.candidates.iter() {
                if cp.peer == peer_id {
                    out.push(SrPolicyNlri {
                        id: 0,
                        distinguisher: cp_key.discriminator,
                        color: key.color,
                        endpoint: key.endpoint,
                    });
                }
            }
        }
        out
    };
    for nlri in withdrawn_srp.iter() {
        route_srpolicy_withdraw(peer_id, nlri, bgp, peers);
    }

    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.cap_map = CapAfiMap::new();
    peer.cap_recv = BgpCap::default();
    peer.opt.clear();

    // IPv4 / IPv6 RTC.
    peer.rtcv4.clear();
    peer.rtcv6.clear();
    peer.eor.clear();

    // Drop the peer's sharded-family Adj-RIB-In slice once every
    // table in it is empty. The VPNv4/v6 LLGR branches above retain
    // stale-marked entries, so the slice must survive those.
    if bgp
        .shard
        .adj_in(peer_id)
        .map(|a| {
            a.v4.0.is_empty()
                && a.v6.0.is_empty()
                && a.v4lu.0.is_empty()
                && a.v6lu.0.is_empty()
                && a.v4vpn.values().all(|t| t.0.is_empty())
                && a.v6vpn.values().all(|t| t.0.is_empty())
        })
        .unwrap_or(false)
    {
        bgp.shard.adj_in_drop(peer_id);
    }
}

/// Reconstruct the wire `EvpnRoute` from a Loc-RIB / Adj-RIB entry,
/// re-deriving the per-NLRI fields (path-id, ESI, VNI) from the
/// stored `BgpRib`. Used by the peer-down cleanup path to feed
/// `route_evpn_withdraw`.
fn build_evpn_route(
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    rib: &BgpRib,
) -> Option<EvpnRoute> {
    match prefix {
        EvpnPrefix::MacIp { eth_tag, mac, .. } => {
            let vni = extract_vni_from_attr(&rib.attr).unwrap_or(0);
            Some(EvpnRoute::Mac(EvpnMac {
                id: rib.remote_id,
                rd: *rd,
                esi: rib.esi.unwrap_or([0; 10]),
                ether_tag: *eth_tag,
                mac: *mac,
                vni,
            }))
        }
        EvpnPrefix::InclusiveMulticast { eth_tag, orig } => {
            Some(EvpnRoute::Multicast(EvpnMulticast {
                id: rib.remote_id,
                rd: *rd,
                ether_tag: *eth_tag,
                addr: *orig,
            }))
        }
        EvpnPrefix::IpPrefix { eth_tag, prefix } => {
            let gw = match prefix.addr() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            Some(EvpnRoute::Prefix(EvpnIpPrefix {
                id: rib.remote_id,
                rd: *rd,
                esi: rib.esi.unwrap_or([0; 10]),
                ether_tag: *eth_tag,
                prefix: *prefix,
                gw,
                label: rib.label.as_ref().map(|l| l.label).unwrap_or(0),
            }))
        }
    }
}

pub fn stale_route_withdraw(peer_id: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    // Fetch all of route which has stale flag.
    let withdrawn = {
        let mut withdrawn: Vec<Vpnv4Nlri> = vec![];
        let Some(adj_in) = bgp.shard.adj_in(peer_id) else {
            return;
        };
        for (rd, table) in adj_in.v4vpn.iter() {
            for (prefix, ribs) in table.0.iter() {
                for rib in ribs.iter() {
                    if rib.stale {
                        let withdraw = Vpnv4Nlri {
                            label: rib.label.unwrap_or(Label::default()),
                            rd: *rd,
                            nlri: Ipv4Nlri {
                                id: rib.remote_id,
                                prefix: *prefix,
                            },
                        };
                        withdrawn.push(withdraw);
                    }
                }
            }
        }
        withdrawn
    };

    // Withdraw routes.
    for withdraw in withdrawn.iter() {
        route_ipv4_withdraw(
            peer_id,
            &withdraw.nlri,
            Some(withdraw.rd),
            Some(withdraw.label),
            bgp,
            peers,
            None,
            true,
        );
    }
}

/// Service label to advertise for a VPNv4 NLRI. A transit ASBR that
/// rewrites the next-hop to self — eBGP, or iBGP with `next-hop-self`
/// (Inter-AS Option B) — advertises its own allocated local label, so a
/// peer's VPN traffic arrives on a label we hold a swap ILM for (`local →
/// received` + transport). Otherwise (next-hop preserved, or a
/// self-originated VRF FEC with no local label) the route's own label
/// passes through unchanged. Mirrors the Labeled-Unicast rule in
/// [`route_update_labelv4`].
fn vpnv4_service_label(peer: &Peer, rib: &BgpRib) -> Label {
    let rewrites_nh = peer.is_ebgp() || peer.next_hop_self(Afi::Ip, Safi::MplsVpn);
    match (rewrites_nh, rib.local_label) {
        (true, Some(l)) => Label::new(l, 0, true),
        _ => rib.label.unwrap_or_default(),
    }
}

/// RFC 1997 well-known community egress gate, shared by the IPv4 /
/// IPv6 / EVPN outbound builders. NO_ADVERTISE suppresses
/// advertisement to every peer; NO_EXPORT — and NO_EXPORT_SUBCONFED,
/// which is equivalent while BGP confederations are unimplemented —
/// suppresses advertisement to eBGP peers. SR Policy (SAFI 73) keeps
/// its own RFC 9830 handling in `sr_policy.rs`.
///
/// Runs BEFORE the outbound policy, so a community the policy itself
/// attaches toward a peer does not self-suppress (FRR behaves the
/// same); only communities already on the route — received, or set at
/// origination/ingress — suppress.
///
/// Depends only on the route's attr and the peer TYPE — `peer_type`
/// is part of `UpdateGroupSig`, so the result is identical for every
/// member of an update-group and safe under the per-group advertise
/// memo in `route_advertise_to_peers`. Do not add per-peer state here
/// without moving the check out of the memoized path.
fn community_suppresses_advertisement(attr: &BgpAttr, peer_type: PeerType) -> bool {
    let Some(com) = attr.com.as_ref() else {
        return false;
    };
    if com.contains(&CommunityValue::NO_ADVERTISE.value()) {
        return true;
    }
    peer_type == PeerType::EBGP
        && (com.contains(&CommunityValue::NO_EXPORT.value())
            || com.contains(&CommunityValue::NO_EXPORT_SUBCONFED.value()))
}

/// RFC 9494 §4.3/§4.4 ingest side: a route received with the
/// LLGR_STALE community is depreferenced exactly like a route we
/// stale-marked ourselves — the ingest paths OR this into the
/// `BgpRib.stale` flag, and `is_better` does the rest. The community
/// itself stays on the attr, so further advertisement keeps it
/// (§4.3: "MUST NOT be removed") and the per-peer LLGR egress gate
/// applies to it transitively.
pub(super) fn attr_has_llgr_stale(attr: &BgpAttr) -> bool {
    attr.com
        .as_ref()
        .is_some_and(|c| c.contains(&CommunityValue::LLGR_STALE.value()))
}

/// RFC 9494 §4.2: a route carrying NO_LLGR "MUST NOT be retained"
/// by the long-lived procedures — at stale-marking time it is removed
/// per normal RFC 4271 operation instead.
fn attr_refuses_llgr(attr: &BgpAttr) -> bool {
    attr.com
        .as_ref()
        .is_some_and(|c| c.contains(&CommunityValue::NO_LLGR.value()))
}

/// RFC 9494 §4.3: a stale route "SHOULD NOT be advertised to any
/// neighbor from which the Long-Lived Graceful Restart Capability has
/// not been received". `cap_recv` is the peer's received capability
/// set (`peer.cap_recv`) — per-PEER state, NOT part of
/// `UpdateGroupSig`, so callers must apply this OUTSIDE the per-group
/// advertise memo — alongside split-horizon, not inside the memoized
/// outcome. The §4.6 partial-deployment MAY (advertise to non-LLGR
/// iBGP peers with NO_EXPORT + LOCAL_PREF 0) is not implemented.
fn llgr_blocks_advertisement(
    rib_stale: bool,
    cap_recv: &bgp_packet::BgpCap,
    afi: Afi,
    safi: Safi,
) -> bool {
    rib_stale && !cap_recv.llgr.contains_key(&AfiSafi::new(afi, safi))
}

pub fn route_update_ipv4(
    peer: &Peer,
    prefix: &Ipv4Net,
    rib: &BgpRib,
    bgp: &BgpTop,
    add_path: bool,
) -> Option<(Ipv4Nlri, BgpAttr)> {
    // Split-horizon: Don't send route back to the peer that sent it
    if rib.ident == peer.ident {
        return None;
    }

    // Inter-AS Option AB: a received VPNv4 route an `inter-as-hybrid` VRF
    // imports is relayed only by that VRF's re-export (an Originated row,
    // built separately), never transparently — suppress the direct relay.
    if rib.vrf_transit_only {
        return None;
    }

    // iBGP to iBGP: Don't advertise iBGP-learned routes except the peer is
    // route reflector client.
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    // RFC 1997 well-known communities: NO_ADVERTISE / NO_EXPORT. A
    // suppressed route flows into `AdvertiseOutcome::Withdraw`, so a
    // previously-advertised route that gains one of these communities
    // is withdrawn from the affected peers (adj-out gated).
    if community_suppresses_advertisement(&rib.attr, peer.peer_type) {
        return None;
    }

    // Create NLRI with optional path ID
    let nlri = Ipv4Nlri {
        id: if add_path { rib.local_id } else { 0 },
        prefix: *prefix,
    };

    // Build attributes
    let mut attrs = (*rib.attr).clone();

    // 1. Origin.  Pass through

    // 2. AS_PATH
    ebgp_egress_aspath(peer, &mut attrs);

    // 3. NEXT_HOP
    //
    // eBGP and self-originated routes always get a v4 rewrite. ENHE-
    // sourced routes (`enhe_egress.is_some()`) join that set
    // unconditionally: the inbound NEXT_HOP for such a route is
    // 0.0.0.0 (RFC 8950 §4) — preserving it for iBGP-iBGP, the way
    // RFC 4271 normally prescribes, would forward a black-hole. The
    // rewrite is harmless for ENHE-aware peers (they ignore the v4
    // NEXT_HOP attribute and read the LL from MP_REACH per RFC 8950
    // §4) and necessary for non-ENHE peers (they're the ones who
    // can't decode an MP_REACH with a v6 next-hop in the first place).
    // VPN rows (`rib.nexthop.is_some()`) additionally honor a per-neighbor
    // `afi-safi vpnv4 next-hop-self` — an Inter-AS Option B ASBR sets it on
    // the iBGP session to its PE so a re-advertised eBGP-VPNv4 route carries
    // the ASBR (a resolvable next-hop) instead of the unreachable foreign
    // PE. eBGP and self-originated routes rewrite unconditionally as before.
    let needs_v4_rewrite = peer.is_ebgp()
        || rib.is_originated()
        || rib.enhe_egress.is_some()
        || (rib.nexthop.is_some() && peer.next_hop_self(Afi::Ip, Safi::MplsVpn));
    if needs_v4_rewrite {
        let nexthop = if let Some(ref local_addr) = peer.param.local_addr
            && let IpAddr::V4(local_addr) = local_addr.ip()
        {
            local_addr
        } else {
            *bgp.router_id
        };
        // VPNv4 rows carry the `Vpnv4Nexthop` slot (it holds the
        // route's RD); emit an MP_REACH-shaped next-hop so
        // `flush_vpnv4` picks it up — writing a bare `BgpNexthop::Ipv4`
        // here would be ignored at flush time and the MP_REACH would
        // ship with no next-hop. The address is the local end of this
        // peer's (i)BGP session (next-hop-self toward the remote PE,
        // identical to the v4-unicast rule), falling back to the
        // router-id when that local address isn't IPv4. Plain
        // v4-unicast rows (`rib.nexthop == None`) keep the bare IPv4
        // next-hop.
        attrs.nexthop = match rib.nexthop {
            Some(VpnNexthop::V4(ref v4nh)) => Some(BgpNexthop::Vpnv4(Vpnv4Nexthop {
                rd: v4nh.rd,
                // SRv6 L3VPN (RFC 9252): a VPNv4 route advertised with an
                // SRv6 L3 Service SID carries the PE's locator (an IPv6
                // address stored on the row) as its next-hop — keep it
                // rather than next-hop-self. MPLS-mode rows next-hop-self
                // with the local IPv4.
                nhop: if attrs.srv6_l3_sid().is_some() {
                    v4nh.nhop
                } else {
                    std::net::IpAddr::V4(nexthop)
                },
            })),
            // A V6 VPN next-hop never reaches the v4 advertise path
            // (v6vpn rows advertise via route_update_ipv6); plain
            // v4-unicast rows keep the bare IPv4 next-hop.
            _ => Some(BgpNexthop::Ipv4(nexthop)),
        };
    };

    // 4. MED - Pass through.

    // 5. Local Preference (for IBGP only)
    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }

    // 6. Originator ID (for IBGP route reflection)
    // RFC 4456: A route reflector SHOULD NOT create an ORIGINATOR_ID if one already
    // exists. ORIGINATOR_ID is set only once by the first route reflector and preserved
    // thereafter to identify the original route source within the AS.
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && attrs.originator_id.is_none()
    {
        // Set ORIGINATOR_ID to the router ID of the peer that originated this route
        attrs.originator_id = Some(OriginatorId::new(rib.router_id));
    }
    // If ORIGINATOR_ID already exists, preserve it (don't overwrite)

    // 7. Cluster List (for IBGP route reflection)
    // RFC 4456: When a route reflector reflects a route, it must prepend the local
    // CLUSTER_ID to the CLUSTER_LIST. By default, the CLUSTER_ID is the router ID.
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        if let Some(ref mut cluster_list) = attrs.cluster_list {
            // Prepend local router ID to existing cluster list
            cluster_list.list.insert(0, *bgp.router_id);
        } else {
            // Create new cluster list with local router ID
            let mut cluster_list = ClusterList::new();
            cluster_list.list.push(*bgp.router_id);
            attrs.cluster_list = Some(cluster_list);
        }
    }

    Some((nlri, attrs))
}

/// IPv6 unicast outbound builder — the v6 counterpart of
/// [`route_update_ipv4`]. Applies split-horizon and the iBGP-iBGP /
/// route-reflector filter, fixes up AS_PATH / next-hop / LOCAL_PREF /
/// ORIGINATOR_ID / CLUSTER_LIST, and returns `(Ipv6Nlri, BgpAttr)` for
/// the peer or `None` to suppress.
///
/// Outbound policy is not applied yet for v6 (the policy engine is
/// `Ipv4Nlri`-typed) — same deferred gap as the ingest path.
pub fn route_update_ipv6(
    peer: &mut Peer,
    prefix: &Ipv6Net,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> Option<(Ipv6Nlri, BgpAttr)> {
    // Split-horizon: never send a route back to its source peer.
    if rib.ident == peer.ident {
        return None;
    }
    // Inter-AS Option AB: a VPNv6 route a hybrid VRF imports is relayed
    // only via that VRF's re-export, never transparently (see the v4 path).
    if rib.vrf_transit_only {
        return None;
    }
    // RFC 1997 well-known communities: NO_ADVERTISE / NO_EXPORT. Unlike
    // the v4 path there is no Adj-RIB-Out for v6 yet, so this filters
    // steady-state advertisement only — a previously-advertised route
    // that GAINS one of these communities is not withdrawn until the
    // session resyncs (same pre-existing limitation as the deferred v6
    // outbound policy).
    if community_suppresses_advertisement(&rib.attr, peer.peer_type) {
        return None;
    }
    // iBGP→iBGP: don't re-advertise iBGP-learned routes to iBGP peers
    // unless this peer is a route-reflector client.
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    let nlri = Ipv6Nlri {
        id: if add_path { rib.local_id } else { 0 },
        prefix: *prefix,
    };

    let mut attrs = (*rib.attr).clone();

    // AS_PATH prepend for eBGP.
    ebgp_egress_aspath(peer, &mut attrs);

    // NEXT_HOP: next-hop-self for eBGP / locally-originated routes.
    // RFC 2545 §2 requires the MP_REACH next-hop be one of OUR IPv6
    // addresses regardless of the session's transport family:
    //   - v6-transport session: the session's local end.
    //   - v4-transport session: the session interface's global v6
    //     (looked up via the v4 local end's owning ifindex). The old
    //     code skipped next-hop-self entirely here, so an originated
    //     route (whose stored next-hop is empty) went on the wire as
    //     `::` — the peer kept it best-path-selected but could never
    //     resolve or install it.
    let needs_self = peer.is_ebgp() || rib.is_originated();
    if needs_self {
        let self_v6: Option<Ipv6Addr> = match peer.param.local_addr.as_ref().map(|a| a.ip()) {
            Some(IpAddr::V6(v6)) => Some(v6),
            Some(IpAddr::V4(v4)) => bgp
                .interface_addrs
                .ifindex_for_v4(v4)
                .and_then(|ifindex| bgp.interface_addrs.global_for(ifindex)),
            None => None,
        };
        if let Some(local_v6) = self_v6 {
            // VPNv6 rows carry a `VpnNexthop::V6` (the route's RD); emit a
            // VPNv6-shaped next-hop so `flush_vpnv6` picks it up. Plain
            // v6-unicast rows get a bare IPv6 next-hop.
            attrs.nexthop = match rib.nexthop {
                Some(VpnNexthop::V6(ref v6nh)) => Some(BgpNexthop::Vpnv6(Vpnv6Nexthop {
                    rd: v6nh.rd,
                    // SRv6 L3VPN: a VPNv6 route with an SRv6 L3 Service SID
                    // advertises the PE's locator (stored on the row) as the
                    // next-hop; MPLS-mode rows next-hop-self with local_v6.
                    nhop: if attrs.srv6_l3_sid().is_some() {
                        v6nh.nhop
                    } else {
                        local_v6
                    },
                })),
                _ => Some(BgpNexthop::Ipv6(local_v6)),
            };
        } else if !matches!(
            attrs.nexthop,
            Some(BgpNexthop::Ipv6(_)) | Some(BgpNexthop::Vpnv6(_))
        ) {
            // No v6 self next-hop available (v4-transport session whose
            // interface carries no global v6) and the route brings no
            // usable v6 next-hop of its own. Emitting `::` is worse
            // than not advertising — the peer would select a route it
            // can never resolve — so skip it.
            return None;
        }
    }

    // LOCAL_PREF for iBGP.
    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }

    // ORIGINATOR_ID / CLUSTER_LIST for route reflection (RFC 4456).
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && attrs.originator_id.is_none()
    {
        attrs.originator_id = Some(OriginatorId::new(rib.router_id));
    }
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        if let Some(ref mut cluster_list) = attrs.cluster_list {
            cluster_list.list.insert(0, *bgp.router_id);
        } else {
            let mut cluster_list = ClusterList::new();
            cluster_list.list.push(*bgp.router_id);
            attrs.cluster_list = Some(cluster_list);
        }
    }

    // The two SRv6 hooks below apply only to plain IPv6 unicast rows.
    // `route_update_ipv6` is shared with the VPNv6 advertise path, whose
    // rows carry `Some(VpnNexthop::V6)`; gating on `rib.nexthop.is_none()`
    // keeps the unicast `encapsulation-type` knob from touching VPNv6.
    let plain_unicast = rib.nexthop.is_none();

    // SRv6 (global IPv6 unicast origination): a locally-originated route
    // already carries its End.DT6 Prefix-SID from origination (it's in
    // `rib.attr`, so `show bgp ipv6` renders a "Local SID"). On the wire
    // it advertises the PE locator as its next-hop, so a remote PE
    // H.Encaps to us and our End.DT6 decaps into the main table — mirrors
    // the per-VRF SRv6 L3VPN export. Received SID-bearing routes keep
    // their wire next-hop (they are not `is_originated`).
    if plain_unicast
        && rib.is_originated()
        && attrs.srv6_l3_sid().is_some()
        && let Some(exp) = bgp.srv6_ipv6_export
    {
        attrs.nexthop = Some(BgpNexthop::Ipv6(exp.nexthop));
    }

    // encapsulation-type srv6 (advertise side): withhold a SID-less
    // plain IPv6 unicast route from an SRv6-only peer — it carries no
    // SRv6 service SID for the peer to forward on. `srv6-relax`/unset
    // peers are unaffected. Locally-originated routes get the instance
    // End.DT6 SID attached just above (when `segment-routing srv6
    // ipv6-unicast` is enabled), so they pass this gate.
    if plain_unicast && peer.ipv6_srv6_strict() && attrs.srv6_l3_sid().is_none() {
        return None;
    }

    Some((nlri, attrs))
}

/// Per-peer IPv6 unicast withdraw — emit an MP_UNREACH(AFI=2, SAFI=1)
/// for `prefix`. The v6 counterpart of [`route_withdraw_ipv4`]'s
/// unicast arm; v6 has no legacy withdraw field.
pub(super) fn route_withdraw_ipv6(peer: &mut Peer, prefix: Ipv6Net, id: u32) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Ipv6Nlri(vec![Ipv6Nlri { id, prefix }]));
    peer.send_packet(update.into());
}

/// v6 twin of [`withdraw_ipv4_deferrable`] — defer the per-peer
/// MP_UNREACH while the peer's group has a v6 flush job in flight.
fn withdraw_ipv6_deferrable(
    update_groups: &mut super::update_group::UpdateGroupMap,
    peer: &mut Peer,
    prefix: Ipv6Net,
    id: u32,
) {
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
    if let Some(gid) = peer.update_group_id.get(&afi_safi)
        && let Some(af) = update_groups.get_mut(&afi_safi)
        && let Some(group) = af.group_by_id_mut(gid)
        && group.flush_inflight_ipv6
    {
        group
            .deferred_withdraw_ipv6
            .push((peer.ident, Ipv6Nlri { id, prefix }));
        return;
    }
    route_withdraw_ipv6(peer, prefix, id);
}

/// IPv6 unicast advertise — the v6 counterpart of
/// [`route_advertise_to_peers`] (unicast only). Reach winners are
/// bucketed into the per-group `cache_ipv6` (debounce-flushed via
/// [`super::update_group::flush_ipv6`]); a `None` best-path emits an
/// immediate MP_UNREACH to each member.
///
/// The update-group post-policy memoization, Adj-RIB-Out tracking, and
/// outbound policy that the v4 path carries are deferred for v6 (the
/// policy engine is IPv4-typed). Without Adj-RIB-Out, an empty-selected
/// withdraw is flooded to every Established v6 peer, even ones that
/// never received the route. That is safe ONLY because the caller drops
/// a no-op withdraw first: `route_ipv6_withdraw` returns early when it
/// removed nothing, so a route-less peer cannot bounce the MP_UNREACH
/// back and start an infinite withdraw storm (peers do NOT ignore an
/// unknown-prefix withdraw — they re-evaluate and re-flood it). Never
/// call this with an empty `selected` for a prefix that was not in the
/// Loc-RIB.
pub(super) fn route_advertise_to_peers_v6(
    prefix: Ipv6Net,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    // Plain (non-AddPath) members go through the generic memo path shared
    // with v4/VPN (V6Batch). v6 unicast has no batch precompute → empty memo.
    route_advertise_batch::<V6Batch>(None, prefix, selected, 0, bgp, peers, BTreeMap::new());

    // AddPath members keep their own inline loop below (the generic covers
    // plain members only).
    let (afi, safi) = (Afi::Ip6, Safi::Unicast);
    let afi_safi = AfiSafi::new(afi, safi);

    // AddPath members: every candidate path, each NLRI carrying its
    // path-id, bucketed into the (AddPath-signature) update-group cache.
    // v6 unicast has no per-peer batch cache, so the per-peer v6
    // Adj-RIB-Out (`adj_out.v6`) is the record of what was sent — diff
    // it against the new candidate set to withdraw exactly the path-ids
    // that fell out (no candidates ⇒ withdraw them all).
    //
    // The candidate set is the FULL Loc-RIB entry, not the best-only
    // `selected` arg: `select_best_path` returns a single winner, so
    // iterating `selected` here would only ever advertise the best path
    // and silently drop every non-best AddPath candidate on the
    // event-driven path — they would reach an AddPath peer only via the
    // session-up `route_sync_ipv6` dump (which reads the full cands
    // table) and then get withdrawn on the very next update.
    let addpath_idents = peers.established_addpath_idents(afi, safi);
    // Only clone the candidate list when there is an AddPath audience —
    // the common best-path-only fan-out must not pay a per-route clone.
    let all_cands: Vec<BgpRib> = if addpath_idents.is_empty() {
        Vec::new()
    } else {
        bgp.shard.v6.0.get(&prefix).cloned().unwrap_or_default()
    };
    for ident in addpath_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        let group_id = peer.update_group_id.get(&afi_safi).cloned();
        let was: Vec<u32> = peer
            .adj_out
            .v6
            .0
            .get(&prefix)
            .map(|c| c.iter().map(|r| r.local_id).collect())
            .unwrap_or_default();
        let mut newly: BTreeSet<u32> = BTreeSet::new();
        for cand in &all_cands {
            if cand.ident == peer.ident {
                continue; // split-horizon
            }
            if llgr_blocks_advertisement(cand.stale, &peer.cap_recv, afi, safi) {
                continue;
            }
            let Some((nlri, attr)) = route_update_ipv6(peer, &prefix, cand, bgp, true) else {
                continue;
            };
            let attr = bgp.attr_store.intern(attr);
            if let Some(gid) = &group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(gid)
            {
                super::update_group::send_ipv6(group, nlri, attr, cand.ident, bgp.tx, true);
            } else {
                tracing::warn!(
                    peer = %peer.address,
                    prefix = %prefix,
                    "IPv6 AddPath advertise: peer Established but not in any update-group; advertise skipped"
                );
                continue;
            }
            peer.adj_out.v6.add(prefix, cand.clone());
            newly.insert(cand.local_id);
        }
        for id in was {
            if newly.contains(&id) {
                continue;
            }
            if let Some(gid) = &group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(gid)
            {
                super::update_group::cache_remove_ipv6(group, prefix, id);
            }
            withdraw_ipv6_deferrable(bgp.update_groups, peer, prefix, id);
            peer.adj_out.v6.remove(prefix, id);
        }
    }
}

/// Per-peer VPNv6 withdraw — emit an MP_UNREACH(AFI=2, SAFI=128) for
/// `(rd, prefix)`. The v6 counterpart of the VPNv4 withdraw arm of
/// [`route_withdraw_ipv4`].
fn route_withdraw_vpnv6(peer: &mut Peer, rd: RouteDistinguisher, prefix: Ipv6Net, id: u32) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    let vpnv6_nlri = Vpnv6Nlri {
        label: Label::default(),
        rd,
        nlri: Ipv6Nlri { id, prefix },
    };
    update.mp_withdraw = Some(MpUnreachAttr::Vpnv6(vec![vpnv6_nlri]));
    peer.send_packet(update.into());
}

/// VPNv6 advertise — the v6 counterpart of the `rd.is_some()` branch
/// of [`route_advertise_to_peers`]. Reach winners are batched into the
/// per-peer `cache_vpnv6` (flushed via the VPNv6 adv timer); a `None`
/// best-path emits an immediate MP_UNREACH. The next-hop-self rewrite
/// to `BgpNexthop::Vpnv6` happens in [`route_update_ipv6`].
///
/// Outbound policy and a per-peer Adj-RIB-Out (`adj_out.v6vpn`) now match
/// the v4 path; only the update-group memoization is still deferred.
pub(super) fn route_advertise_to_peers_vpnv6(
    rd: RouteDistinguisher,
    prefix: Ipv6Net,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    // VPNv6 plain members go through the generic memo path (V6Batch with
    // rd=Some); AddPath is handled by route_advertise_to_peers_vpnv6_addpath.
    route_advertise_batch::<V6Batch>(Some(rd), prefix, selected, 0, bgp, peers, BTreeMap::new());
}

/// VPNv6 AddPath twin of [`route_advertise_to_peers_vpnv6`] — the v6
/// counterpart of the `rd.is_some()` branch of
/// [`route_advertise_to_addpath`]. Called once per changed candidate
/// path with that path's `rib` (its `local_id` already stamped), it
/// advertises the path — not just the best — to every AddPath-Send
/// member, each NLRI carrying the path-id (RFC 7911 §3). Split-horizon
/// excludes the path's own source peer.
pub(super) fn route_advertise_to_peers_vpnv6_addpath(
    rd: RouteDistinguisher,
    prefix: Ipv6Net,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    route_advertise_batch_addpath::<V6Batch>(Some(rd), prefix, rib, bgp, peers);
}

/// VPNv6 AddPath withdraw twin — emit an MP_UNREACH carrying the
/// withdrawn path's `local_id` to every AddPath-Send member, and drop
/// the matching entry from each peer's pending cache. The other paths
/// for the prefix stay advertised (they carry different path-ids).
pub(super) fn route_withdraw_vpnv6_addpath(
    rd: RouteDistinguisher,
    prefix: Ipv6Net,
    removed: &BgpRib,
    peers: &mut PeerMap,
) {
    let (afi, safi) = (Afi::Ip6, Safi::MplsVpn);

    let peer_idents: Vec<usize> = peers.established_addpath_idents(afi, safi);

    for ident in peer_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        peer.cache_remove_vpnv6(rd, prefix, removed.local_id);
        route_withdraw_vpnv6(peer, rd, prefix, removed.local_id);
    }
}

/// Extract a plain `IpAddr` from a unicast/labeled `BgpNexthop`. Returns
/// `None` for VPN nexthops, which never appear on the LU rows.
fn bgp_nexthop_to_ipaddr(nh: &BgpNexthop) -> Option<IpAddr> {
    match nh {
        BgpNexthop::Ipv4(a) => Some(IpAddr::V4(*a)),
        BgpNexthop::Ipv6(a) => Some(IpAddr::V6(*a)),
        BgpNexthop::Evpn(a) => Some(*a),
        BgpNexthop::Vpnv4(_) | BgpNexthop::Vpnv6(_) => None,
    }
}

/// Build the (NLRI, attr, next-hop, label) for advertising an IPv4
/// Labeled-Unicast route to `peer`. Mirrors `route_update_ipv6`'s
/// attribute handling (split-horizon, iBGP-RR gating, AS_PATH prepend,
/// next-hop-self, LOCAL_PREF, ORIGINATOR_ID/CLUSTER_LIST) for SAFI 4.
///
/// The advertised label is the row's label — the received label when
/// propagating, implicit-null (3) for self-originated FECs. The real
/// per-prefix local label + ILM swap is Phase 5; Phase 4 installs
/// nothing in the dataplane, so this is control-plane only.
///
/// `attrs.nexthop` is cleared: an MP_REACH carries the next-hop itself,
/// and a `BgpNexthop::Ipv4` left on the attr would also emit a legacy
/// (type-3) NEXT_HOP attribute.
fn route_update_labelv4(
    peer: &mut Peer,
    prefix: &Ipv4Net,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> Option<(Ipv4Nlri, BgpAttr, IpAddr, Label)> {
    if rib.ident == peer.ident {
        return None;
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    let nlri = Ipv4Nlri {
        id: if add_path { rib.local_id } else { 0 },
        prefix: *prefix,
    };
    let mut attrs = (*rib.attr).clone();

    ebgp_egress_aspath(peer, &mut attrs);

    // Next-hop-self for eBGP / locally-originated, or when the neighbor
    // has `afi-safi label-v4 next-hop-self` (Inter-AS Option C ASBR → PE);
    // otherwise keep the received next-hop (next-hop-unchanged). Captured
    // before clearing `attrs.nexthop`.
    let needs_self =
        peer.is_ebgp() || rib.is_originated() || peer.next_hop_self(Afi::Ip, Safi::MplsLabel);
    let nhop: IpAddr = if needs_self {
        // v4, or v6 for an RFC 8950 v4-over-v6 session.
        peer.param.local_addr.as_ref().map(|a| a.ip())?
    } else {
        attrs.nexthop.as_ref().and_then(bgp_nexthop_to_ipaddr)?
    };

    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && attrs.originator_id.is_none()
    {
        attrs.originator_id = Some(OriginatorId::new(rib.router_id));
    }
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        if let Some(ref mut cluster_list) = attrs.cluster_list {
            cluster_list.list.insert(0, *bgp.router_id);
        } else {
            let mut cluster_list = ClusterList::new();
            cluster_list.list.push(*bgp.router_id);
            attrs.cluster_list = Some(cluster_list);
        }
    }

    attrs.nexthop = None;
    // Next-hop-self makes us the forwarding hop: advertise our per-prefix
    // local label (swap-programmed via an ILM) so a peer's labeled
    // traffic reaches us with a label we can swap to the received one.
    // No local label (self-originated egress, or no dynamic block yet) →
    // implicit-null / received-label fallback. Next-hop-unchanged passes
    // the received label through untouched.
    let label = match (needs_self, rib.local_label) {
        (true, Some(l)) => Label::new(l, 0, true),
        _ => rib.label.unwrap_or(Label::new(3, 0, true)),
    };
    Some((nlri, attrs, nhop, label))
}

/// IPv6 Labeled-Unicast counterpart of [`route_update_labelv4`]. For 6PE
/// (RFC 4798), a next-hop-self over an IPv4 transport session is encoded
/// as the IPv4-mapped IPv6 form of the local address.
fn route_update_labelv6(
    peer: &mut Peer,
    prefix: &Ipv6Net,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> Option<(Ipv6Nlri, BgpAttr, IpAddr, Label)> {
    if rib.ident == peer.ident {
        return None;
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    let nlri = Ipv6Nlri {
        id: if add_path { rib.local_id } else { 0 },
        prefix: *prefix,
    };
    let mut attrs = (*rib.attr).clone();

    ebgp_egress_aspath(peer, &mut attrs);

    let needs_self =
        peer.is_ebgp() || rib.is_originated() || peer.next_hop_self(Afi::Ip6, Safi::MplsLabel);
    let nhop: IpAddr = if needs_self {
        match peer.param.local_addr.as_ref().map(|a| a.ip()) {
            Some(IpAddr::V6(v6)) => IpAddr::V6(v6),
            // 6PE (RFC 4798): IPv4 transport → IPv4-mapped IPv6 next-hop.
            Some(IpAddr::V4(v4)) => IpAddr::V6(v4.to_ipv6_mapped()),
            None => return None,
        }
    } else {
        attrs.nexthop.as_ref().and_then(bgp_nexthop_to_ipaddr)?
    };

    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && attrs.originator_id.is_none()
    {
        attrs.originator_id = Some(OriginatorId::new(rib.router_id));
    }
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        if let Some(ref mut cluster_list) = attrs.cluster_list {
            cluster_list.list.insert(0, *bgp.router_id);
        } else {
            let mut cluster_list = ClusterList::new();
            cluster_list.list.push(*bgp.router_id);
            attrs.cluster_list = Some(cluster_list);
        }
    }

    attrs.nexthop = None;
    // Next-hop-self makes us the forwarding hop: advertise our per-prefix
    // local label (swap-programmed via an ILM) so a peer's labeled
    // traffic reaches us with a label we can swap to the received one.
    // No local label (self-originated egress, or no dynamic block yet) →
    // implicit-null / received-label fallback. Next-hop-unchanged passes
    // the received label through untouched.
    let label = match (needs_self, rib.local_label) {
        (true, Some(l)) => Label::new(l, 0, true),
        _ => rib.label.unwrap_or(Label::new(3, 0, true)),
    };
    Some((nlri, attrs, nhop, label))
}

/// Per-AF hooks that let one generic [`route_advertise_labeled`] cover the
/// SAFI-4 (labeled-unicast) v4 and v6 advertise paths. Phase 2 of the
/// Adj-RIB-Out unification: the two families differ only in prefix/NLRI
/// type, which `adj_out` table records reach, their update builder and
/// out-policy, and which `Mp{Reach,Unreach}Attr` variant they encode.
trait LabeledAfi {
    type Prefix: Copy + Ord;
    type Nlri;
    const AFI: Afi;

    fn adj_out_add(peer: &mut Peer, prefix: Self::Prefix, rib: BgpRib);
    fn adj_out_contains(peer: &Peer, prefix: &Self::Prefix) -> bool;
    fn adj_out_remove(peer: &mut Peer, prefix: Self::Prefix, id: u32);
    fn adj_out_ids(peer: &Peer, prefix: &Self::Prefix) -> Vec<u32>;
    /// The full Loc-RIB candidate list for `prefix` (every path, not just
    /// the best). AddPath advertises all of them, but `select_best_path`
    /// collapses to a single winner, so the advertise loop must read the
    /// candidates straight from the shard.
    fn all_cands(bgp: &BgpTop, prefix: &Self::Prefix) -> Vec<BgpRib>;

    fn update(
        peer: &mut Peer,
        prefix: &Self::Prefix,
        rib: &BgpRib,
        bgp: &mut BgpTop,
        add_path: bool,
    ) -> Option<(Self::Nlri, BgpAttr, IpAddr, Label)>;
    fn apply_policy_out(
        peer: &Peer,
        nlri: &Self::Nlri,
        attr: BgpAttr,
        weight: u32,
    ) -> Option<PolicyDecision>;
    fn reach(nhop: IpAddr, label: Label, nlri: Self::Nlri) -> MpReachAttr;
    fn unreach(prefix: Self::Prefix, id: u32) -> MpUnreachAttr;
}

struct LabeledV4;
impl LabeledAfi for LabeledV4 {
    type Prefix = Ipv4Net;
    type Nlri = Ipv4Nlri;
    const AFI: Afi = Afi::Ip;

    fn adj_out_add(peer: &mut Peer, prefix: Ipv4Net, rib: BgpRib) {
        peer.adj_out.v4lu.add(prefix, rib);
    }
    fn adj_out_contains(peer: &Peer, prefix: &Ipv4Net) -> bool {
        peer.adj_out.v4lu.0.contains_key(prefix)
    }
    fn adj_out_remove(peer: &mut Peer, prefix: Ipv4Net, id: u32) {
        peer.adj_out.v4lu.remove(prefix, id);
    }
    fn adj_out_ids(peer: &Peer, prefix: &Ipv4Net) -> Vec<u32> {
        peer.adj_out
            .v4lu
            .0
            .get(prefix)
            .map(|c| c.iter().map(|r| r.local_id).collect())
            .unwrap_or_default()
    }
    fn all_cands(bgp: &BgpTop, prefix: &Ipv4Net) -> Vec<BgpRib> {
        bgp.shard.v4lu.0.get(prefix).cloned().unwrap_or_default()
    }
    fn update(
        peer: &mut Peer,
        prefix: &Ipv4Net,
        rib: &BgpRib,
        bgp: &mut BgpTop,
        add_path: bool,
    ) -> Option<(Ipv4Nlri, BgpAttr, IpAddr, Label)> {
        route_update_labelv4(peer, prefix, rib, bgp, add_path)
    }
    fn apply_policy_out(
        peer: &Peer,
        nlri: &Ipv4Nlri,
        attr: BgpAttr,
        weight: u32,
    ) -> Option<PolicyDecision> {
        route_apply_policy_out(peer, nlri, attr, weight)
    }
    fn reach(nhop: IpAddr, label: Label, nlri: Ipv4Nlri) -> MpReachAttr {
        MpReachAttr::Labelv4 {
            snpa: 0,
            nhop,
            updates: vec![Labelv4Nlri { label, nlri }],
        }
    }
    fn unreach(prefix: Ipv4Net, id: u32) -> MpUnreachAttr {
        MpUnreachAttr::Labelv4(vec![Labelv4Nlri {
            label: Label::default(),
            nlri: Ipv4Nlri { id, prefix },
        }])
    }
}

struct LabeledV6;
impl LabeledAfi for LabeledV6 {
    type Prefix = Ipv6Net;
    type Nlri = Ipv6Nlri;
    const AFI: Afi = Afi::Ip6;

    fn adj_out_add(peer: &mut Peer, prefix: Ipv6Net, rib: BgpRib) {
        peer.adj_out.v6lu.add(prefix, rib);
    }
    fn adj_out_contains(peer: &Peer, prefix: &Ipv6Net) -> bool {
        peer.adj_out.v6lu.0.contains_key(prefix)
    }
    fn adj_out_remove(peer: &mut Peer, prefix: Ipv6Net, id: u32) {
        peer.adj_out.v6lu.remove(prefix, id);
    }
    fn adj_out_ids(peer: &Peer, prefix: &Ipv6Net) -> Vec<u32> {
        peer.adj_out
            .v6lu
            .0
            .get(prefix)
            .map(|c| c.iter().map(|r| r.local_id).collect())
            .unwrap_or_default()
    }
    fn all_cands(bgp: &BgpTop, prefix: &Ipv6Net) -> Vec<BgpRib> {
        bgp.shard.v6lu.0.get(prefix).cloned().unwrap_or_default()
    }
    fn update(
        peer: &mut Peer,
        prefix: &Ipv6Net,
        rib: &BgpRib,
        bgp: &mut BgpTop,
        add_path: bool,
    ) -> Option<(Ipv6Nlri, BgpAttr, IpAddr, Label)> {
        route_update_labelv6(peer, prefix, rib, bgp, add_path)
    }
    fn apply_policy_out(
        peer: &Peer,
        nlri: &Ipv6Nlri,
        attr: BgpAttr,
        weight: u32,
    ) -> Option<PolicyDecision> {
        route_apply_policy_out_v6(peer, nlri, attr, weight)
    }
    fn reach(nhop: IpAddr, label: Label, nlri: Ipv6Nlri) -> MpReachAttr {
        MpReachAttr::Labelv6 {
            snpa: 0,
            nhop,
            updates: vec![Labelv6Nlri { label, nlri }],
        }
    }
    fn unreach(prefix: Ipv6Net, id: u32) -> MpUnreachAttr {
        MpUnreachAttr::Labelv6(vec![Labelv6Nlri {
            label: Label::default(),
            nlri: Ipv6Nlri { id, prefix },
        }])
    }
}

/// Generic labeled-unicast advertise (SAFI 4), shared by v4 and v6 via
/// [`LabeledAfi`]. Plain members get the best path (or a withdraw pruned
/// to actual recipients through the per-AF Adj-RIB-Out); AddPath members
/// get every candidate path-id, with the same diff-based withdraw of the
/// path-ids that fell out. Immediate per-peer send — no update-group cache.
fn route_advertise_labeled<A: LabeledAfi>(
    prefix: A::Prefix,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let new_best = selected.last();
    let (afi, safi) = (A::AFI, Safi::MplsLabel);

    // Non-AddPath members: best-path only.
    for ident in peers.established_plain_idents(afi, safi) {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");

        // Advertise the best path unless this peer is the source
        // (split-horizon), LLGR-blocked, suppressed, or out-policy-denied —
        // each falls through to the withdraw branch, which emits an
        // MP_UNREACH only to a peer the Adj-RIB-Out says received the route.
        let to_advertise: Option<(A::Nlri, BgpAttr, IpAddr, Label, BgpRib)> = match new_best {
            Some(best)
                if best.ident != peer.ident
                    && !llgr_blocks_advertisement(best.stale, &peer.cap_recv, afi, safi) =>
            {
                match A::update(peer, &prefix, best, bgp, false) {
                    Some((nlri, attr, nhop, label)) => {
                        A::apply_policy_out(peer, &nlri, attr, best.weight)
                            .map(|d| (nlri, d.attr, nhop, label, best.clone()))
                    }
                    None => None,
                }
            }
            _ => None,
        };

        match to_advertise {
            Some((nlri, attr, nhop, label, best)) => {
                A::adj_out_add(peer, prefix, best);
                let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
                update.bgp_attr = Some(attr);
                update.mp_update = Some(A::reach(nhop, label, nlri));
                peer.send_packet(update.into());
            }
            None => {
                if A::adj_out_contains(peer, &prefix) {
                    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
                    update.mp_withdraw = Some(A::unreach(prefix, 0));
                    peer.send_packet(update.into());
                    A::adj_out_remove(peer, prefix, 0);
                }
            }
        }
    }

    // AddPath members: every candidate, each NLRI carrying its path-id;
    // diff the prior path-ids (Adj-RIB-Out) against the new set to withdraw
    // exactly the ones that fell out (no candidates ⇒ withdraw them all).
    //
    // The candidate set is the FULL Loc-RIB entry, not the best-only
    // `selected` arg: `select_best_path` returns a single winner, so
    // iterating `selected` would only ever advertise the best path and
    // silently drop every non-best AddPath candidate on the event-driven
    // path (the v6-unicast advertise carried the same latent bug).
    let addpath_idents = peers.established_addpath_idents(afi, safi);
    let all_cands = if addpath_idents.is_empty() {
        Vec::new()
    } else {
        A::all_cands(bgp, &prefix)
    };
    for ident in addpath_idents {
        let peer = peers.get_mut_by_idx(ident).expect("peer exists");
        let was = A::adj_out_ids(peer, &prefix);
        let mut newly: BTreeSet<u32> = BTreeSet::new();
        for cand in &all_cands {
            if cand.ident == peer.ident {
                continue; // split-horizon
            }
            if llgr_blocks_advertisement(cand.stale, &peer.cap_recv, afi, safi) {
                continue;
            }
            let Some((nlri, attr, nhop, label)) = A::update(peer, &prefix, cand, bgp, true) else {
                continue;
            };
            let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
            update.bgp_attr = Some(attr);
            update.mp_update = Some(A::reach(nhop, label, nlri));
            peer.send_packet(update.into());
            A::adj_out_add(peer, prefix, cand.clone());
            newly.insert(cand.local_id);
        }
        for id in was {
            if newly.contains(&id) {
                continue;
            }
            let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
            update.mp_withdraw = Some(A::unreach(prefix, id));
            peer.send_packet(update.into());
            A::adj_out_remove(peer, prefix, id);
        }
    }
}

/// Advertise an IPv4 Labeled-Unicast best-path change (SAFI 4). Thin
/// wrapper over the generic [`route_advertise_labeled`].
pub(super) fn route_advertise_to_peers_labelv4(
    prefix: Ipv4Net,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    route_advertise_labeled::<LabeledV4>(prefix, selected, bgp, peers);
}

/// Advertise an IPv6 Labeled-Unicast (incl. 6PE) best-path change (SAFI 4).
/// Thin wrapper over the generic [`route_advertise_labeled`].
pub(super) fn route_advertise_to_peers_labelv6(
    prefix: Ipv6Net,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    route_advertise_labeled::<LabeledV6>(prefix, selected, bgp, peers);
}

impl Peer {
    pub fn send_packet(&self, bytes: BytesMut) {
        if let Some(ref packet_tx) = self.packet_tx
            && let Err(e) = packet_tx.send(bytes)
        {
            eprintln!("Failed to send BGP packet to {}: {}", self.address, e);
        }
    }

    pub fn send_vpnv4(&mut self, nlri: Vpnv4Nlri, attr: Arc<BgpAttr>, timer: bool) {
        self.cache_vpnv4
            .entry(attr.clone())
            .or_default()
            .insert(nlri.clone());
        self.cache_vpnv4_rev.insert(nlri, attr);
        if timer && self.cache_vpnv4_timer.is_none() {
            self.cache_vpnv4_timer = Some(start_adv_timer_vpnv4(self));
        }
    }

    pub fn cache_remove_vpnv4(&mut self, rd: RouteDistinguisher, prefix: Ipv4Net, id: u32) {
        let nlri = Vpnv4Nlri {
            label: Label::default(),
            rd,
            nlri: Ipv4Nlri { id, prefix },
        };
        if let Some(attr) = self.cache_vpnv4_rev.remove(&nlri)
            && let Some(set) = self.cache_vpnv4.get_mut(&attr)
        {
            set.remove(&nlri);
            if set.is_empty() {
                self.cache_vpnv4.remove(&attr);
            }
        }
    }

    /// Cache an EVPN route for advertisement, grouped by attribute.
    /// Mirrors `send_vpnv4`: same timer-debounce shape, same
    /// per-attribute batching so a single MP_REACH UPDATE can carry
    /// every route that shares an attribute set.
    pub fn send_evpn(&mut self, route: EvpnRoute, attr: Arc<BgpAttr>, timer: bool) {
        self.cache_evpn
            .entry(attr.clone())
            .or_default()
            .insert(route.clone());
        self.cache_evpn_rev.insert(route, attr);
        if timer && self.cache_evpn_timer.is_none() {
            self.cache_evpn_timer = Some(start_adv_timer_evpn(self));
        }
    }

    /// Drain `cache_evpn` and emit one BGP UPDATE per attribute
    /// group via `pop_evpn`. Pagination across multiple UPDATEs is a
    /// follow-up; the encoder currently emits all NLRIs from a
    /// single attr group in one packet.
    pub fn flush_evpn(&mut self) {
        let packet_tx = self.packet_tx.clone();
        let max_size = self.max_packet_size();
        for (attr, routes) in self.cache_evpn.drain() {
            let mut update = UpdatePacket::with_max_packet_size(max_size);

            // Nexthop comes from the cached attribute. EVPN allows
            // either an IPv4 or IPv6 nexthop; if neither was set on
            // the attr (shouldn't happen for locally-originated
            // routes), default to 0.0.0.0 — the receiver will
            // notice and drop, which is the right behavior.
            let nhop = match attr.nexthop.as_ref() {
                Some(BgpNexthop::Evpn(addr)) => *addr,
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            update.mp_update = Some(MpReachAttr::Evpn {
                snpa: 0,
                nhop,
                updates: routes.into_iter().collect(),
            });
            update.bgp_attr = Some((*attr).clone());

            if let Some(bytes) = update.pop_evpn()
                && let Some(ref tx) = packet_tx
            {
                let _ = tx.send(bytes);
            }
        }
        self.cache_evpn_rev.clear();
    }

    // Flush BGP update.
    pub fn flush_vpnv4(&mut self) {
        let packet_tx = self.packet_tx.clone();
        let max_size = self.max_packet_size();
        for (attr, nlris) in self.cache_vpnv4.drain() {
            let mut update = UpdatePacket::with_max_packet_size(max_size);

            if let Some(BgpNexthop::Vpnv4(nhop)) = attr.nexthop.as_ref() {
                let vpnv4reach = Vpnv4Reach {
                    snpa: 0,
                    nhop: nhop.clone(),
                    updates: nlris.into_iter().collect(),
                };
                update.mp_update = Some(MpReachAttr::Vpnv4(vpnv4reach));
            }
            update.bgp_attr = Some((*attr).clone());

            while let Some(bytes) = update.pop_vpnv4() {
                if let Some(ref tx) = packet_tx {
                    let _ = tx.send(bytes);
                }
            }
        }
        self.cache_vpnv4_rev.clear();
    }

    // VPNv6 advertise cache — mirror of the VPNv4 trio above.

    pub fn send_vpnv6(&mut self, nlri: Vpnv6Nlri, attr: Arc<BgpAttr>, timer: bool) {
        self.cache_vpnv6
            .entry(attr.clone())
            .or_default()
            .insert(nlri.clone());
        self.cache_vpnv6_rev.insert(nlri, attr);
        if timer && self.cache_vpnv6_timer.is_none() {
            self.cache_vpnv6_timer = Some(start_adv_timer_vpnv6(self));
        }
    }

    pub fn cache_remove_vpnv6(&mut self, rd: RouteDistinguisher, prefix: Ipv6Net, id: u32) {
        let nlri = Vpnv6Nlri {
            label: Label::default(),
            rd,
            nlri: Ipv6Nlri { id, prefix },
        };
        if let Some(attr) = self.cache_vpnv6_rev.remove(&nlri)
            && let Some(set) = self.cache_vpnv6.get_mut(&attr)
        {
            set.remove(&nlri);
            if set.is_empty() {
                self.cache_vpnv6.remove(&attr);
            }
        }
    }

    pub fn flush_vpnv6(&mut self) {
        let packet_tx = self.packet_tx.clone();
        let max_size = self.max_packet_size();
        for (attr, nlris) in self.cache_vpnv6.drain() {
            let mut update = UpdatePacket::with_max_packet_size(max_size);

            if let Some(BgpNexthop::Vpnv6(nhop)) = attr.nexthop.as_ref() {
                let vpnv6reach = Vpnv6Reach {
                    snpa: 0,
                    nhop: nhop.clone(),
                    updates: nlris.into_iter().collect(),
                };
                update.mp_update = Some(MpReachAttr::Vpnv6(vpnv6reach));
            }
            update.bgp_attr = Some((*attr).clone());

            while let Some(bytes) = update.pop_vpnv6() {
                if let Some(ref tx) = packet_tx {
                    let _ = tx.send(bytes);
                }
            }
        }
        self.cache_vpnv6_rev.clear();
    }
}

/// Apply a policy to a route. Walks entries in numeric-key order;
/// on each match consults the entry's terminal action:
///
/// - **`permit`**: apply any `set` clauses, return the modified
///   attribute (the route is accepted).
/// - **`next`**: apply any `set` clauses, then continue to the
///   next entry. Lets one entry decorate a route while another
///   later entry decides the verdict.
/// - **`deny`**: do NOT apply any `set` clauses; return `None`
///   (the route is dropped).
///
/// Default-deny when no entry matches (or all matching entries
/// fall through with `next` and the policy ends): returns `None`.
/// Operators express "default permit" by appending an
/// unconditional final entry with `action: permit`.
/// Outcome of applying a policy-list to a route. `attr` is the
/// (possibly modified) BGP attribute set; `weight` is the local
/// per-router BGP weight. `weight` is not on the wire — it lives
/// on `BgpRib::weight` and is used in best-path tie-breaking.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub attr: BgpAttr,
    pub weight: u32,
}

/// IPv4-unicast convenience wrapper over [`policy_list_apply_net`].
/// Currently exercised only by unit tests — the production ingest paths
/// call [`policy_list_apply_net`] (or the per-family helpers) directly.
#[allow(dead_code)]
pub fn policy_list_apply(
    policy_list: &PolicyList,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
    local_addr: Ipv4Addr,
) -> Option<PolicyDecision> {
    policy_list_apply_net(
        policy_list,
        IpNet::V4(nlri.prefix),
        bgp_attr,
        weight,
        local_addr,
    )
}

/// Family-generic core of [`policy_list_apply`]: the prefix arrives
/// as an `IpNet` so the same entry walk serves IPv4 and IPv6 routes
/// (`PrefixSet::matches` is already dual-stack). The v6 table-map is
/// the first v6 consumer; per-peer v6 policy can join later.
pub fn policy_list_apply_net(
    policy_list: &PolicyList,
    prefix: IpNet,
    bgp_attr: BgpAttr,
    weight: u32,
    local_addr: Ipv4Addr,
) -> Option<PolicyDecision> {
    use crate::policy::{PolicyAction, SetNextHop};
    let mut decision = PolicyDecision {
        attr: bgp_attr,
        weight,
    };
    for (_, entry) in policy_list.entry.iter() {
        if !entry_matches(entry, prefix, &decision.attr, decision.weight) {
            continue;
        }
        match entry.action {
            PolicyAction::Deny => {
                // Drop the route without applying any set clauses.
                return None;
            }
            PolicyAction::Permit | PolicyAction::Next => {
                // Apply the entry's set clauses to the working
                // attribute, then either return (Permit) or fall
                // through to the next entry (Next).
                if let Some(action) = &entry.local_pref {
                    let current = decision
                        .attr
                        .local_pref
                        .as_ref()
                        .map(|l| l.local_pref)
                        .unwrap_or(0);
                    decision.attr.local_pref = Some(LocalPref::new(action.apply(current)));
                }
                if let Some(action) = &entry.med {
                    let current = decision.attr.med.as_ref().map(|m| m.med).unwrap_or(0);
                    decision.attr.med = Some(Med {
                        med: action.apply(current),
                    });
                }
                if let Some(w) = entry.weight {
                    decision.weight = w;
                }
                if let Some(cfg) = &entry.set_community {
                    apply_set_community(&mut decision.attr, cfg);
                }
                if let Some(prepend) = &entry.set_as_path_prepend {
                    apply_set_as_path_prepend(&mut decision.attr, prepend);
                }
                if let Some(nh) = &entry.set_next_hop {
                    match nh {
                        SetNextHop::Address(IpAddr::V4(addr)) => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(*addr));
                        }
                        SetNextHop::Address(IpAddr::V6(_)) => {
                            // BgpNexthop is IPv4-only today; an
                            // IPv6 target parses but has no
                            // effect. Phase H follow-up wires
                            // BgpNexthop::Ipv6 + the emit path.
                        }
                        SetNextHop::SelfAddr => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(local_addr));
                        }
                    }
                }
                if let Some(origin) = entry.set_origin {
                    decision.attr.origin = Some(origin);
                }
                apply_color_and_prefix_sid(&mut decision.attr, entry);
                if entry.action == PolicyAction::Permit {
                    return Some(decision);
                }
                // Next: continue with the modified attribute.
            }
        }
    }
    // End of list reached without a permit verdict — default deny.
    None
}

fn entry_matches(
    entry: &crate::policy::PolicyEntry,
    prefix: IpNet,
    bgp_attr: &BgpAttr,
    weight: u32,
) -> bool {
    if let Some(prefix_set) = &entry.prefix_set
        && !prefix_set.matches(prefix)
    {
        return false;
    }
    if let Some(community_set) = &entry.community_set
        && !community_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.ext_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.large_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(as_path_set) = &entry.as_path_set
        && !as_path_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(want) = &entry.match_next_hop {
        // Exact equality. BgpAttr.nexthop is currently IPv4-only,
        // so an IPv6 entry never matches today; that's acceptable
        // until v6 nexthop is plumbed through.
        let std::net::IpAddr::V4(want_v4) = want else {
            return false;
        };
        let Some(BgpNexthop::Ipv4(have_v4)) = bgp_attr.nexthop.as_ref() else {
            return false;
        };
        if want_v4 != have_v4 {
            return false;
        }
    }
    if let Some(med_match) = &entry.match_med {
        let med = bgp_attr.med.as_ref().map(|m| m.med).unwrap_or(0);
        if !med_match.matches(med) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len {
        let len = bgp_attr.aspath.as_ref().map(|p| p.length()).unwrap_or(0);
        if !m.matches(len) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len_uniq {
        let uniq = bgp_attr
            .aspath
            .as_ref()
            .map(|p| p.unique_length())
            .unwrap_or(0);
        if !m.matches(uniq) {
            return false;
        }
    }
    if let Some(m) = &entry.match_local_pref {
        let lp = bgp_attr
            .local_pref
            .as_ref()
            .map(|l| l.local_pref)
            .unwrap_or(0);
        if !m.matches(lp) {
            return false;
        }
    }
    if let Some(m) = &entry.match_weight
        && !m.matches(weight)
    {
        return false;
    }
    if let Some(want) = entry.match_origin {
        let Some(have) = bgp_attr.origin else {
            return false;
        };
        if have != want {
            return false;
        }
    }
    if !matches_color(entry, bgp_attr) {
        return false;
    }
    true
}

/// Color (RFC 9012 §4.3) match shared between the IPv4 and EVPN
/// apply paths. Returns true when the entry has no `match color`
/// predicate, or when at least one Color extcomm on the route
/// matches the configured value. CO bits are not compared in v1.
fn matches_color(entry: &crate::policy::PolicyEntry, bgp_attr: &BgpAttr) -> bool {
    let Some(want) = entry.match_color else {
        return true;
    };
    let Some(ecom) = bgp_attr.ecom.as_ref() else {
        return false;
    };
    ecom.0
        .iter()
        .filter_map(|v| v.as_color())
        .any(|c| c.color == want)
}

/// Apply `set color N` and `set prefix-sid label-index N` to a
/// working route attribute. Shared between the IPv4 and EVPN apply
/// loops so a future `set color` semantic change lands once.
fn apply_color_and_prefix_sid(attr: &mut BgpAttr, entry: &crate::policy::PolicyEntry) {
    if let Some(color) = entry.set_color {
        let ecom = attr.ecom.get_or_insert_with(ExtCommunity::default);
        ecom.0.insert(ExtCommunityValue::from_color(0, color));
    }
    if let Some(idx) = entry.set_prefix_sid_label_index {
        attr.prefix_sid = Some(PrefixSid {
            tlvs: vec![PrefixSidTlv::LabelIndex {
                flags: 0,
                label_index: idx,
            }],
        });
    }
}

/// EVPN counterpart of `policy_list_apply`. Same Permit/Deny/Next
/// state machine and same `set` clauses; the matcher swaps to
/// `entry_matches_evpn`, which skips IPv4-prefix-only conditions
/// (`prefix_set`, `match_next_hop`) and adds the EVPN-specific
/// `match_evpn_route_type` and `match_evpn_vni` checks.
pub fn policy_list_apply_evpn(
    policy_list: &PolicyList,
    route: &EvpnRoute,
    bgp_attr: BgpAttr,
    weight: u32,
    local_addr: Ipv4Addr,
) -> Option<PolicyDecision> {
    use crate::policy::{PolicyAction, SetNextHop};
    let mut decision = PolicyDecision {
        attr: bgp_attr,
        weight,
    };
    for (_, entry) in policy_list.entry.iter() {
        if !entry_matches_evpn(entry, route, &decision.attr, decision.weight) {
            continue;
        }
        match entry.action {
            PolicyAction::Deny => return None,
            PolicyAction::Permit | PolicyAction::Next => {
                if let Some(action) = &entry.local_pref {
                    let current = decision
                        .attr
                        .local_pref
                        .as_ref()
                        .map(|l| l.local_pref)
                        .unwrap_or(0);
                    decision.attr.local_pref = Some(LocalPref::new(action.apply(current)));
                }
                if let Some(action) = &entry.med {
                    let current = decision.attr.med.as_ref().map(|m| m.med).unwrap_or(0);
                    decision.attr.med = Some(Med {
                        med: action.apply(current),
                    });
                }
                if let Some(w) = entry.weight {
                    decision.weight = w;
                }
                if let Some(cfg) = &entry.set_community {
                    apply_set_community(&mut decision.attr, cfg);
                }
                if let Some(prepend) = &entry.set_as_path_prepend {
                    apply_set_as_path_prepend(&mut decision.attr, prepend);
                }
                // `set next-hop` writes BgpAttr.nexthop (IPv4-only).
                // For EVPN the real nexthop travels in MP_REACH_NLRI,
                // so the mutation has no visible effect on the wire
                // today; we still honor it for parity with IPv4.
                if let Some(nh) = &entry.set_next_hop {
                    match nh {
                        SetNextHop::Address(IpAddr::V4(addr)) => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(*addr));
                        }
                        SetNextHop::Address(IpAddr::V6(_)) => {}
                        SetNextHop::SelfAddr => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(local_addr));
                        }
                    }
                }
                if let Some(origin) = entry.set_origin {
                    decision.attr.origin = Some(origin);
                }
                apply_color_and_prefix_sid(&mut decision.attr, entry);
                if entry.action == PolicyAction::Permit {
                    return Some(decision);
                }
            }
        }
    }
    None
}

/// EVPN match evaluator. Same shape as `entry_matches` minus the
/// IPv4-specific clauses: `prefix_set` (no IP prefix on EVPN
/// NLRIs) and `match_next_hop` (BgpAttr.nexthop is IPv4-only and
/// is not the EVPN nexthop). Common BGP attribute matches
/// (community/ext-community/large-community/as-path-set,
/// med/as-path-len/local-pref/weight/origin) carry over verbatim.
/// EVPN-specific clauses (`match_evpn_route_type`, `match_evpn_vni`)
/// pull from the route discriminator and the per-type VNI source.
fn entry_matches_evpn(
    entry: &crate::policy::PolicyEntry,
    route: &EvpnRoute,
    bgp_attr: &BgpAttr,
    weight: u32,
) -> bool {
    if let Some(community_set) = &entry.community_set
        && !community_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.ext_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.large_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(as_path_set) = &entry.as_path_set
        && !as_path_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(med_match) = &entry.match_med {
        let med = bgp_attr.med.as_ref().map(|m| m.med).unwrap_or(0);
        if !med_match.matches(med) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len {
        let len = bgp_attr.aspath.as_ref().map(|p| p.length()).unwrap_or(0);
        if !m.matches(len) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len_uniq {
        let uniq = bgp_attr
            .aspath
            .as_ref()
            .map(|p| p.unique_length())
            .unwrap_or(0);
        if !m.matches(uniq) {
            return false;
        }
    }
    if let Some(m) = &entry.match_local_pref {
        let lp = bgp_attr
            .local_pref
            .as_ref()
            .map(|l| l.local_pref)
            .unwrap_or(0);
        if !m.matches(lp) {
            return false;
        }
    }
    if let Some(m) = &entry.match_weight
        && !m.matches(weight)
    {
        return false;
    }
    if let Some(want) = entry.match_origin {
        let Some(have) = bgp_attr.origin else {
            return false;
        };
        if have != want {
            return false;
        }
    }
    if let Some(want) = entry.match_evpn_route_type
        && evpn_route_type_of(route) != want
    {
        return false;
    }
    if let Some(want) = entry.match_evpn_vni {
        let Some(have) = evpn_vni_of(route, bgp_attr) else {
            return false;
        };
        if have != want {
            return false;
        }
    }
    if !matches_color(entry, bgp_attr) {
        return false;
    }
    true
}

/// Apply a `set community <community-set> [additive]` action to `bgp_attr`.
///
/// Only `Standard::Exact` matchers contribute concrete values; regex and
/// extended-community matchers are skipped (extended communities live in
/// a separate BGP attribute, and regex patterns are not concrete values).
/// With `additive = false` the existing community list is replaced; with
/// `additive = true` the new values are merged in. The result is always
/// sorted and deduplicated.
fn apply_set_community(bgp_attr: &mut BgpAttr, cfg: &crate::policy::SetCommunityConfig) {
    // Unresolved name (community-set was deleted or never defined):
    // skip silently rather than touch the attribute. policy_entry_sync
    // re-resolves on changes.
    let Some(set) = cfg.resolved.as_ref() else {
        return;
    };
    let new_vals: Vec<u32> = set
        .vals
        .iter()
        .filter_map(|m| match m {
            CommunityMatcher::Standard(StandardMatcher::Exact(v)) => Some(v.0),
            _ => None,
        })
        .collect();

    use crate::policy::SetCommunityMode;
    match cfg.mode {
        SetCommunityMode::Replace => {
            if new_vals.is_empty() {
                bgp_attr.com = None;
                return;
            }
            bgp_attr.com = Some(new_vals.into_iter().collect());
        }
        SetCommunityMode::Additive => {
            let mut com = bgp_attr.com.clone().unwrap_or_default();
            for v in new_vals {
                com.insert(v);
            }
            bgp_attr.com = Some(com);
        }
        SetCommunityMode::Delete => {
            // Set difference: drop matching values from existing
            // community attribute. No-op if attribute absent.
            let Some(mut com) = bgp_attr.com.clone() else {
                return;
            };
            let drop: std::collections::HashSet<u32> = new_vals.into_iter().collect();
            com.0.retain(|v| !drop.contains(v));
            bgp_attr.com = if com.0.is_empty() { None } else { Some(com) };
        }
    }
}

/// Apply a `set as-path-prepend ASN repeat NUM` action by prepending
/// `cfg.asn` `cfg.repeat` times onto the existing AS-path (or
/// installing a new one if absent). `repeat` is bounded `1..=255` by
/// the YANG schema; a zero would be a no-op anyway.
fn apply_set_as_path_prepend(bgp_attr: &mut BgpAttr, cfg: &AsPathPrependConfig) {
    if cfg.repeat == 0 {
        return;
    }
    let prepend_path = As4Path::from(vec![cfg.asn; cfg.repeat as usize]);
    match bgp_attr.aspath.as_mut() {
        Some(existing) => existing.prepend_mut(prepend_path),
        None => bgp_attr.aspath = Some(prepend_path),
    }
}

pub fn route_sync_ipv4(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::Unicast);

    // Collect all routes first to avoid borrow checker issues
    let routes: Vec<(Ipv4Net, BgpRib)> = if add_path {
        bgp.shard
            .v4
            .0
            .iter()
            .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (prefix, rib.clone())))
            .collect()
    } else {
        bgp.shard
            .v4
            .1
            .iter()
            .map(|(prefix, rib)| (prefix, rib.clone()))
            .collect()
    };

    // Sync targets a single peer; the per-group cache would fan
    // out to every member, double-sending to peers that already
    // have these routes. Accumulate locally and emit via
    // `send_ipv4_direct`, which preserves the per-attr batching
    // (one MP_REACH UPDATE per shared attr-set).
    let mut entries: Vec<(Arc<BgpAttr>, Ipv4Nlri)> = Vec::new();
    for (prefix, mut rib) in routes {
        // RFC 9494 §4.3: stale routes only go to LLGR peers.
        if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, Afi::Ip, Safi::Unicast) {
            continue;
        }
        let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
            continue;
        };

        let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
            continue;
        };

        // Register to AdjOut.
        rib.attr = bgp.attr_store.intern(decision.attr);
        let arc_attr = rib.attr.clone();
        peer.adj_out.add(None, nlri.prefix, rib);

        entries.push((arc_attr, nlri));
    }

    let enhe_v6 = peer
        .is_enhe_v4_negotiated()
        .then(|| super::update_group::compose_enhe_next_hop(peer, bgp.interface_addrs))
        .flatten();
    super::update_group::send_ipv4_direct(peer, entries, enhe_v6);

    // Send End-of-RIB marker for IPv4 Unicast
    send_eor_ipv4_unicast(peer);
}

/// Dump the global IPv6-unicast Loc-RIB to a newly-established peer —
/// the v6 counterpart of [`route_sync_ipv4`]. Outbound policy is not
/// applied on the v6-unicast path yet (consistent with the event-driven
/// `route_advertise_to_peers_v6`); next-hop-self and eBGP AS_PATH
/// prepend happen inside `route_update_ipv6`.
pub fn route_sync_ipv6(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip6, Safi::Unicast);

    // Collect first to avoid borrowing `bgp.local_rib` across the loop.
    let routes: Vec<(Ipv6Net, BgpRib)> = if add_path {
        bgp.shard
            .v6
            .0
            .iter()
            .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (prefix, rib.clone())))
            .collect()
    } else {
        bgp.shard
            .v6
            .1
            .iter()
            .map(|(prefix, rib)| (prefix, rib.clone()))
            .collect()
    };

    // Single-peer dump (see `send_ipv6_direct`): accumulate per shared
    // attr-set and emit straight to this peer rather than through the
    // group cache. No Adj-RIB-Out registration — v6-unicast `adj_out`
    // tracking isn't wired (the event-driven `route_advertise_to_peers_v6`
    // skips it too); revisit when `show bgp neighbors <X> advertised-routes`
    // grows v6 support.
    let mut entries: Vec<(Arc<BgpAttr>, Ipv6Nlri)> = Vec::new();
    for (prefix, rib) in routes {
        // RFC 9494 §4.3: stale routes only go to LLGR peers.
        if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, Afi::Ip6, Safi::Unicast) {
            continue;
        }
        let Some((nlri, attr)) = route_update_ipv6(peer, &prefix, &rib, bgp, add_path) else {
            continue;
        };
        // Outbound policy: per-peer v6 route-map / prefix-list. The
        // session-establishment dump must filter the same way the
        // event-driven advertise does, mirroring the v4 sync path —
        // otherwise an out-policy-denied prefix leaks on the initial
        // sync and is only suppressed on a later update.
        let Some(decision) = route_apply_policy_out_v6(peer, &nlri, attr, rib.weight) else {
            continue;
        };
        let arc_attr = bgp.attr_store.intern(decision.attr);
        entries.push((arc_attr, nlri));
    }
    super::update_group::send_ipv6_direct(peer, entries);

    // End-of-RIB marker for IPv6 Unicast.
    send_eor_ipv6_unicast(peer);
}

pub fn route_sync_vpnv4(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::MplsVpn);

    // Collect all VPNv4 routes first to avoid borrow checker issues
    let all_routes: Vec<(RouteDistinguisher, Vec<(Ipv4Net, BgpRib)>)> = if add_path {
        bgp.shard
            .v4vpn
            .iter()
            .map(|(rd, table)| {
                let routes: Vec<(Ipv4Net, BgpRib)> = table
                    .0
                    .iter()
                    .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (prefix, rib.clone())))
                    .collect();
                (*rd, routes)
            })
            .collect()
    } else {
        bgp.shard
            .v4vpn
            .iter()
            .map(|(rd, table)| {
                let routes: Vec<(Ipv4Net, BgpRib)> = table
                    .1
                    .iter()
                    .map(|(prefix, rib)| (prefix, rib.clone()))
                    .collect();
                (*rd, routes)
            })
            .collect()
    };

    // Advertise all best paths to the peer
    for (rd, routes) in all_routes {
        for (prefix, mut rib) in routes {
            // RFC 9494 §4.3: stale routes only go to LLGR peers.
            if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, Afi::Ip, Safi::MplsVpn) {
                continue;
            }
            let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
                continue;
            };

            let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
                continue;
            };
            let attr = decision.attr;

            // RTC
            if !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
                continue;
            }

            // Register to AdjOut.
            rib.attr = bgp.attr_store.intern(attr);
            let arc_attr = rib.attr.clone();
            let label = vpnv4_service_label(peer, &rib);
            peer.adj_out.add(Some(rd), nlri.prefix, rib);

            let vpnv4_nlri = Vpnv4Nlri { label, rd, nlri };

            // Send the routes.
            peer.send_vpnv4(vpnv4_nlri, arc_attr, false);
        }
    }

    peer.flush_vpnv4();

    // Send End-of-RIB marker for IPv4 VPN
    send_eor_vpnv4_unicast(peer);
}

/// VPNv6 counterpart of [`route_sync_vpnv4`]: dump the VPNv6 Loc-RIB to a
/// peer when its session establishes. The global VPNv6 advertise is
/// event-driven, so a peer that comes up *after* a route was originated /
/// imported needs this catch-up (the v6 twin of the VPNv4 sync that was
/// previously missing).
pub fn route_sync_vpnv6(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip6, Safi::MplsVpn);

    let all_routes: Vec<(RouteDistinguisher, Vec<(Ipv6Net, BgpRib)>)> = if add_path {
        bgp.shard
            .v6vpn
            .iter()
            .map(|(rd, table)| {
                let routes: Vec<(Ipv6Net, BgpRib)> = table
                    .0
                    .iter()
                    .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (prefix, rib.clone())))
                    .collect();
                (*rd, routes)
            })
            .collect()
    } else {
        bgp.shard
            .v6vpn
            .iter()
            .map(|(rd, table)| {
                let routes: Vec<(Ipv6Net, BgpRib)> = table
                    .1
                    .iter()
                    .map(|(prefix, rib)| (prefix, rib.clone()))
                    .collect();
                (*rd, routes)
            })
            .collect()
    };

    for (rd, routes) in all_routes {
        for (prefix, mut rib) in routes {
            // RFC 9494 §4.3: stale routes only go to LLGR peers.
            if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, Afi::Ip6, Safi::MplsVpn) {
                continue;
            }
            let Some((nlri, attr)) = route_update_ipv6(peer, &prefix, &rib, bgp, add_path) else {
                continue;
            };
            let Some(decision) = route_apply_policy_out_v6(peer, &nlri, attr, rib.weight) else {
                continue;
            };
            let attr = decision.attr;
            // RTC: per-peer route-target constraint.
            if !peer.rtcv6.is_empty() && !rtc_match(&peer.rtcv6, &attr.ecom) {
                continue;
            }
            rib.attr = bgp.attr_store.intern(attr);
            let arc_attr = rib.attr.clone();
            let label = rib.label.unwrap_or_default();
            peer.adj_out.v6vpn.entry(rd).or_default().add(prefix, rib);
            let vpnv6_nlri = Vpnv6Nlri { label, rd, nlri };
            peer.send_vpnv6(vpnv6_nlri, arc_attr, false);
        }
    }

    peer.flush_vpnv6();
    send_eor_vpnv6_vpn(peer);
}

// Send End-of-RIB marker for IPv6 VPN.
fn send_eor_vpnv6_vpn(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Vpnv6Eor);
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for IPv4 Unicast.
fn send_eor_ipv4_unicast(peer: &mut Peer) {
    let update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for IPv6 Unicast: an empty MP_UNREACH(AFI=2,
// SAFI=1), per RFC 4724 §2 (only IPv4 unicast uses the bare empty UPDATE).
fn send_eor_ipv6_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Ipv6Eor);
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for VPNv4 Unicast.
fn send_eor_vpnv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Vpnv4Eor);
    peer.send_packet(update.into());
}

// Advertise our Route Target Constraint membership (RFC 4684): one
// NLRI per IPv4 import Route-Target across all local VRFs, so the peer
// only sends us the VPNv4 routes we actually import. With no local
// import RTs the membership is empty, which emits the zero-length
// "default" NLRI — the wildcard "send me everything" — preserving the
// behaviour of a router that has RTC enabled but no VRFs configured.
fn send_rtcv4_membership(peer: &mut Peer, bgp: &BgpTop) {
    let mut updates = Vec::new();
    if let Some(dispatcher) = bgp.vrf_import {
        // Union the per-VRF import-RT sets so a Route-Target shared by
        // several VRFs is advertised once.
        let mut rts: BTreeSet<RouteDistinguisher> = BTreeSet::new();
        for vrf in dispatcher.rib_known_vrfs.values() {
            rts.extend(vrf.import_rts_v4.iter().copied());
        }
        for rt in rts {
            // RTs are stored as RouteDistinguisher; the `From` impl sets
            // high_type per ASN-vs-IPv4 RD but leaves the sub-type 0, so
            // mark it as a Route Target (RFC 4360 §4, sub-type 0x02).
            let mut val: ExtCommunityValue = rt.into();
            val.low_type = 0x02;
            updates.push(Rtcv4 {
                id: 0,
                asn: peer.local_as,
                rt: val,
            });
        }
    }

    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    let mut attrs = BgpAttr::new();
    if peer.is_ibgp() {
        attrs.local_pref = Some(LocalPref::default());
    }
    update.bgp_attr = Some(attrs);
    update.mp_update = Some(MpReachAttr::Rtcv4(Rtcv4Reach {
        snpa: 0,
        nhop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        updates,
    }));
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for RTCv4.
fn send_eor_rtcv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Rtcv4Eor);
    peer.send_packet(update.into());
}

// IPv6 counterpart of `send_rtcv4_membership`: advertise our Route
// Target Constraint membership for the `(Ip6, Rtc)` family from the
// union of every local VRF's IPv6 import Route-Targets, so the peer
// only sends us the VPNv6 routes we import. Empty membership emits the
// zero-length "default" NLRI (the wildcard "send me everything").
fn send_rtcv6_membership(peer: &mut Peer, bgp: &BgpTop) {
    let mut updates = Vec::new();
    if let Some(dispatcher) = bgp.vrf_import {
        let mut rts: BTreeSet<RouteDistinguisher> = BTreeSet::new();
        for vrf in dispatcher.rib_known_vrfs.values() {
            rts.extend(vrf.import_rts_v6.iter().copied());
        }
        for rt in rts {
            let mut val: ExtCommunityValue = rt.into();
            val.low_type = 0x02;
            updates.push(Rtcv6 {
                id: 0,
                asn: peer.local_as,
                rt: val,
            });
        }
    }

    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    let mut attrs = BgpAttr::new();
    if peer.is_ibgp() {
        attrs.local_pref = Some(LocalPref::default());
    }
    update.bgp_attr = Some(attrs);
    update.mp_update = Some(MpReachAttr::Rtcv6(Rtcv6Reach {
        snpa: 0,
        nhop: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        updates,
    }));
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for RTCv6.
fn send_eor_rtcv6_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Rtcv6Eor);
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for L2VPN/EVPN. RFC 4724 §2 represents EoR
// as an empty UPDATE; the multiprotocol form (RFC 7606 §3) carries
// it as an MP_UNREACH with empty NLRI for the AFI/SAFI in question.
fn send_eor_evpn(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::EvpnEor);
    peer.send_packet(update.into());
}

/// Replay every selected EVPN route from the local-RIB to a peer
/// that just transitioned to Established. Mirrors `route_sync_ipv4`:
/// per-RD walk over `LocalRib::evpn[rd].selected`, push through
/// `route_update_evpn` (which handles split-horizon and iBGP gating),
/// batch into the per-peer EVPN cache, then flush a single batched
/// MP_REACH and finish with the EVPN EoR.
///
/// Called from `route_sync` only when the peer negotiated the
/// `(L2vpn, Evpn)` capability — without that gate the receiver would
/// reject the UPDATE.
pub fn route_sync_evpn(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::L2vpn, Safi::Evpn);

    // Snapshot first to dodge the borrow checker — `route_update_evpn`
    // takes `&mut Peer` and `&mut BgpTop`, both of which alias the
    // RIB we're walking.
    let snapshot: Vec<(RouteDistinguisher, EvpnPrefix, BgpRib)> = bgp
        .local_rib
        .evpn
        .iter()
        .flat_map(|(rd, table)| {
            table
                .selected
                .iter()
                .map(move |(prefix, rib)| (*rd, prefix.clone(), rib.clone()))
        })
        .collect();

    for (rd, prefix, rib) in snapshot {
        // RFC 9494 §4.3: stale routes only go to LLGR peers.
        if llgr_blocks_advertisement(rib.stale, &peer.cap_recv, Afi::L2vpn, Safi::Evpn) {
            continue;
        }
        let Some((route, attr)) = route_update_evpn(peer, &rd, &prefix, &rib, bgp, add_path) else {
            continue;
        };
        let Some(decision) = route_apply_policy_out_evpn(peer, &route, attr, rib.weight) else {
            continue;
        };
        let attr = bgp.attr_store.intern(decision.attr);
        // Record in Adj-RIB-Out so a subsequent soft-out can detect
        // which routes were synced and withdraw any that fail the
        // new policy.
        let mut adj = rib.clone();
        adj.attr = attr.clone();
        peer.adj_out.add_evpn(rd, prefix, adj);
        // `false`: don't arm the per-peer advertise timer — we flush
        // synchronously at end-of-sync so the new peer sees one
        // batched MP_REACH (or several, one per attribute group)
        // followed immediately by EoR, rather than waiting for the
        // debounce.
        peer.send_evpn(route, attr, false);
    }

    peer.flush_evpn();
    send_eor_evpn(peer);
}

// Called when peer has been established.
/// Dump the IPv4 Labeled-Unicast (SAFI 4) Loc-RIB to a peer that just
/// reached Established — the labeled-unicast counterpart of
/// [`route_sync_ipv4`]. Label-v4 is advertised event-driven and is NOT
/// update-group batched, so its only other advertise path
/// ([`route_advertise_to_peers_labelv4`]) fires solely on a route change.
/// Without this establish-time dump, a prefix originated or learned
/// *before* the peer came up is never sent — exactly the Inter-AS Option C
/// case, where each PE originates its loopback into BGP-LU before the ASBR
/// session is up, and each ASBR relays loopbacks it already holds. Dumps
/// the current Loc-RIB (originated + received), so it is robust to the
/// order sessions establish in. Best path per prefix (all paths under
/// add-path); `route_update_labelv4` applies split-horizon / next-hop /
/// label.
pub fn route_sync_labelv4(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::MplsLabel);
    let mut routes: Vec<(Ipv4Net, BgpRib)> = Vec::new();
    for (prefix, ribs) in bgp.shard.v4lu.0.iter() {
        if add_path {
            routes.extend(ribs.iter().map(|rib| (prefix, rib.clone())));
        } else if let Some(best) = ribs.last() {
            routes.push((prefix, best.clone()));
        }
    }
    for (prefix, best) in routes {
        // RFC 9494 §4.3: stale routes only go to LLGR peers.
        if llgr_blocks_advertisement(best.stale, &peer.cap_recv, Afi::Ip, Safi::MplsLabel) {
            continue;
        }
        let Some((nlri, attr, nhop, label)) =
            route_update_labelv4(peer, &prefix, &best, bgp, add_path)
        else {
            continue;
        };
        // Outbound policy on the establish-time dump (parity with the
        // event-driven advertise and the unicast sync paths).
        let Some(decision) = route_apply_policy_out(peer, &nlri, attr, best.weight) else {
            continue;
        };
        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.bgp_attr = Some(decision.attr);
        update.mp_update = Some(MpReachAttr::Labelv4 {
            snpa: 0,
            nhop,
            updates: vec![Labelv4Nlri { label, nlri }],
        });
        peer.send_packet(update.into());
    }
}

/// IPv6 Labeled-Unicast (incl. 6PE) establish-time Loc-RIB dump — the v6
/// counterpart of [`route_sync_labelv4`].
pub fn route_sync_labelv6(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip6, Safi::MplsLabel);
    let mut routes: Vec<(Ipv6Net, BgpRib)> = Vec::new();
    for (prefix, ribs) in bgp.shard.v6lu.0.iter() {
        if add_path {
            routes.extend(ribs.iter().map(|rib| (prefix, rib.clone())));
        } else if let Some(best) = ribs.last() {
            routes.push((prefix, best.clone()));
        }
    }
    for (prefix, best) in routes {
        // RFC 9494 §4.3: stale routes only go to LLGR peers.
        if llgr_blocks_advertisement(best.stale, &peer.cap_recv, Afi::Ip6, Safi::MplsLabel) {
            continue;
        }
        let Some((nlri, attr, nhop, label)) =
            route_update_labelv6(peer, &prefix, &best, bgp, add_path)
        else {
            continue;
        };
        // Outbound policy on the establish-time dump (see route_sync_labelv4).
        let Some(decision) = route_apply_policy_out_v6(peer, &nlri, attr, best.weight) else {
            continue;
        };
        let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
        update.bgp_attr = Some(decision.attr);
        update.mp_update = Some(MpReachAttr::Labelv6 {
            snpa: 0,
            nhop,
            updates: vec![Labelv6Nlri { label, nlri }],
        });
        peer.send_packet(update.into());
    }
}

pub fn route_sync(peer: &mut Peer, bgp: &mut BgpTop) {
    // RFC 4684: advertise our Route Target Constraint membership BEFORE
    // any other AFI/SAFI, so the peer can apply RTC filtering to every
    // route it sends us from the start of the session. The membership
    // carries our local VRFs' import RTs (or the wildcard when none are
    // configured); marking the RTC EoR in `peer.eor` defers our own
    // VPNv4 advertisement until the peer has sent us its membership.
    if peer.is_afi_safi(Afi::Ip, Safi::Rtc) {
        let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
        peer.eor.insert(key, true);
        send_rtcv4_membership(peer, bgp);
        send_eor_rtcv4_unicast(peer);
    }
    // IPv6 RTC: advertise our VPNv6 import-RT membership so the peer
    // constrains the VPNv6 routes it sends us. Unlike VPNv4 there is no
    // VPNv6 sync-on-establish to defer (VPNv6 is advertised event-driven
    // only), so the membership exchange stands alone — the peer's own
    // membership we learn here gates our event-driven VPNv6 advertise.
    if peer.is_afi_safi(Afi::Ip6, Safi::Rtc) {
        send_rtcv6_membership(peer, bgp);
        send_eor_rtcv6_unicast(peer);
    }
    // Advertize.
    if peer.is_afi_safi(Afi::Ip, Safi::Unicast) {
        route_sync_ipv4(peer, bgp);
    }
    if peer.is_afi_safi(Afi::Ip6, Safi::Unicast) {
        route_sync_ipv6(peer, bgp);
    }
    if peer.is_afi_safi(Afi::Ip, Safi::MplsVpn) {
        let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
        if !peer.eor.contains_key(&key) {
            route_sync_vpnv4(peer, bgp);
        }
    }
    if peer.is_afi_safi(Afi::Ip6, Safi::MplsVpn) {
        route_sync_vpnv6(peer, bgp);
    }
    if peer.is_afi_safi(Afi::L2vpn, Safi::Evpn) {
        route_sync_evpn(peer, bgp);
    }
    // SAFI 4 (RFC 3107 / 8277): dump the Labeled-Unicast Loc-RIBs. Needed
    // because label-v4/v6 are advertised event-driven only — a route that
    // existed before this peer came up would otherwise never be sent
    // (e.g. an Inter-AS Option C PE loopback originated at startup).
    if peer.is_afi_safi(Afi::Ip, Safi::MplsLabel) {
        route_sync_labelv4(peer, bgp);
    }
    if peer.is_afi_safi(Afi::Ip6, Safi::MplsLabel) {
        route_sync_labelv6(peer, bgp);
    }
    // SAFI 73: dump our locally-originated SR Policies to the new peer.
    if peer.is_afi_safi(Afi::Ip, Safi::SrTePolicy) || peer.is_afi_safi(Afi::Ip6, Safi::SrTePolicy) {
        route_sync_srpolicy(peer, bgp);
    }
}

impl Bgp {
    pub fn route_add(&mut self, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let attr = BgpAttr::new();
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update(None, prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        // An originated route lacks a v4 NEXT_HOP attribute, so when
        // it wins best by weight=32768 `fib_install_v4` will emit an
        // `Ipv4Del` for any BGP-typed FIB entry that a peer route
        // previously installed for the same prefix. That's correct:
        // the underlying source (Static / Connected / IGP) owns the
        // forwarding entry now, and BGP shouldn't shadow it.
        fib_install_v4(&bgp_ref, prefix, &selected);

        if !selected.is_empty() {
            route_advertise_to_peers(
                None,
                prefix,
                &selected,
                ident,
                &mut bgp_ref,
                &mut self.peers,
            );
        }
    }

    pub fn route_del(&mut self, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let id = 0;
        let removed = self.shard.remove(None, prefix, id, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path(prefix);
        // When the originated route disappears, a peer route may now
        // be the best (or no path may remain). Reconcile so the FIB
        // matches Loc-RIB.
        fib_install_v4(&bgp_ref, prefix, &selected);

        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers(
                None,
                prefix,
                &selected,
                ident,
                &mut bgp_ref,
                &mut self.peers,
            );
        }
    }

    /// Originate an IPv6 prefix into the global v6 unicast Loc-RIB from
    /// a `network` statement under `afi-safi ipv6`. The v6 counterpart
    /// of [`Self::route_add`]: weight 32768, no NEXT_HOP, so when it
    /// wins best `fib_install_v6` cedes the FIB entry to the underlying
    /// source (Connected / Static / IGP) rather than shadowing it.
    pub fn route_add_v6(&mut self, prefix: Ipv6Net) {
        // Remember the network so it can be re-originated (SID re-stamped)
        // when the SRv6 locator resolves after the `network` was added.
        self.networks_v6.insert(prefix);
        let mut attr = BgpAttr::new();
        // SRv6 global IPv6 unicast: stamp the End.DT6 Prefix-SID at
        // origination so it lands in the Loc-RIB (show "Local SID").
        if let Some(exp) = &self.srv6_ipv6_export {
            attr.prefix_sid = Some(exp.prefix_sid.clone());
        }
        let rib = BgpRib::new(
            ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, _next_id) = self.shard.update_v6(prefix, rib);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        fib_install_v6(&bgp_ref, prefix, &selected);

        if !selected.is_empty() {
            route_advertise_to_peers_v6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    pub fn route_del_v6(&mut self, prefix: Ipv6Net) {
        self.networks_v6.remove(&prefix);
        let ident = ORIGINATED_PEER;
        let removed = self.shard.remove_v6(prefix, 0, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path_v6(prefix);
        fib_install_v6(&bgp_ref, prefix, &selected);

        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers_v6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Originate an IPv4 prefix into the Labeled-Unicast (SAFI 4)
    /// Loc-RIB from a `network` statement under `afi-safi label-v4`. The
    /// advertised label is implicit-null (3): we are the egress for this
    /// FEC, so a labeled-unicast peer does penultimate-hop-pop and
    /// forwards as IP to us. The real per-prefix local label + ILM swap
    /// is Phase 5; no FIB install here (control-plane only).
    pub fn route_add_label_v4(&mut self, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let attr = BgpAttr::new();
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            Some(Label::new(3, 0, true)),
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update_v4lu(prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        // Reconcile the FIB: a self-originated winner withdraws any BGP
        // label entry (we are the egress; the source route forwards).
        fib_install_labelv4(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() {
            route_advertise_to_peers_labelv4(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    pub fn route_del_label_v4(&mut self, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let removed = self.shard.remove_v4lu(prefix, 0, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path_v4lu(prefix);
        // Reconcile the FIB: removing a self-originated route may reveal
        // a received label winner that now needs its label-push entry.
        fib_install_labelv4(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers_labelv4(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Originate an IPv6 prefix into the Labeled-Unicast (SAFI 4) Loc-RIB
    /// from a `network` statement under `afi-safi label-v6`. The v6
    /// counterpart of [`Bgp::route_add_label_v4`]; advertises
    /// implicit-null (we are the egress FEC). 6PE next-hop handling is in
    /// the advertise path. No FIB install (control-plane only).
    pub fn route_add_label_v6(&mut self, prefix: Ipv6Net) {
        let ident = ORIGINATED_PEER;
        let attr = BgpAttr::new();
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            Some(Label::new(3, 0, true)),
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update_v6lu(prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        fib_install_labelv6(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() {
            route_advertise_to_peers_labelv6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    pub fn route_del_label_v6(&mut self, prefix: Ipv6Net) {
        let ident = ORIGINATED_PEER;
        let removed = self.shard.remove_v6lu(prefix, 0, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path_v6lu(prefix);
        fib_install_labelv6(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers_labelv6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    // ---- redistribute injection -----------------------------------
    //
    // `route_redist_inject` / `route_redist_withdraw` are siblings of
    // `route_add` / `route_del`, but
    //   - carry a `metric` (lowered to MED on the originated route),
    //   - tag the originator with a per-rtype `remote_id` discriminator
    //     so a redistributed Connected route and a `network`
    //     statement for the same prefix do NOT collide in the
    //     LocalRibTable — both look like `ORIGINATED_PEER` to the
    //     update path, and same-prefix-same-(ident,remote_id) keys
    //     replace one another.
    //
    // IPv6 redistribution stays storage-only on `Bgp.redist_v6` until
    // a follow-up adds the LocalRib v6 path; today `LocalRib` only
    // holds v4 / VPNv4 / EVPN.

    /// Per-rtype remote_id discriminator, so distinct redistribute
    /// sources (and the `network` statement at id=0) coexist for the
    /// same prefix without overwriting one another. Values are local
    /// and never appear on the wire.
    pub(super) fn redist_remote_id(rtype: crate::rib::RibType) -> u32 {
        match rtype {
            crate::rib::RibType::Connected => 1,
            crate::rib::RibType::Static => 2,
            crate::rib::RibType::Ospf => 3,
            crate::rib::RibType::Isis => 4,
            crate::rib::RibType::Kernel => 5,
            crate::rib::RibType::Bgp => 0, // self-loop prevented upstream
            _ => 0,
        }
    }

    pub fn route_redist_inject(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: Ipv4Net,
        metric: u32,
    ) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let mut attr = BgpAttr::new();
        attr.med = Some(bgp_packet::Med::new(metric));
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            remote_id,
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update(None, prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        // Same logic as `route_add`: the redistributed BGP route has
        // no v4 NEXT_HOP, so winning best causes BGP to withdraw any
        // peer-installed FIB entry for this prefix and let the source
        // protocol's own RIB entry handle forwarding.
        fib_install_v4(&bgp_ref, prefix, &selected);

        if !selected.is_empty() {
            route_advertise_to_peers(
                None,
                prefix,
                &selected,
                ident,
                &mut bgp_ref,
                &mut self.peers,
            );
        }
    }

    pub fn route_redist_withdraw(&mut self, rtype: crate::rib::RibType, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let removed = self.shard.remove(None, prefix, remote_id, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path(prefix);
        // A peer route may now be best again (or nothing's left);
        // reconcile the FIB.
        fib_install_v4(&bgp_ref, prefix, &selected);

        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers(
                None,
                prefix,
                &selected,
                ident,
                &mut bgp_ref,
                &mut self.peers,
            );
        }
    }

    /// Redistribute an IPv6 route into the plain IPv6 unicast Loc-RIB.
    /// The v6-unicast sibling of [`Bgp::route_redist_inject`]: same
    /// `redist_remote_id` discriminator and MED-from-metric. When global
    /// SRv6 IPv6 origination is enabled (`segment-routing srv6
    /// ipv6-unicast` + a resolved locator) the route is stamped with the
    /// instance End.DT6 Prefix-SID at origination, so it shows as a
    /// "Local SID" and rides every advertisement; the locator next-hop is
    /// applied per-peer in [`route_update_ipv6`]. Like the v4 path an
    /// originated route has no usable next-hop, so the FIB install
    /// withdraws any BGP entry and the source protocol's RIB owns
    /// forwarding.
    pub fn route_redist_inject_v6(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: Ipv6Net,
        metric: u32,
    ) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let mut attr = BgpAttr::new();
        attr.med = Some(bgp_packet::Med::new(metric));
        if let Some(exp) = &self.srv6_ipv6_export {
            attr.prefix_sid = Some(exp.prefix_sid.clone());
        }
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            remote_id,
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update_v6(prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        fib_install_v6(&bgp_ref, prefix, &selected);

        if !selected.is_empty() {
            route_advertise_to_peers_v6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Withdraw a redistributed IPv6 unicast route (the v6 counterpart of
    /// [`Bgp::route_redist_withdraw`]). Like the v4 path and the labeled
    /// twins, the Loc-RIB row is keyed on `(ident, remote_id)` where
    /// `remote_id` is the per-source discriminator from
    /// [`Bgp::redist_remote_id`] — this used to pass a literal `0`, which
    /// matches no redistributed source (Connected=1, Static=2, …), so the
    /// withdraw was a silent no-op and a deleted route stayed originated
    /// and advertised until the daemon restarted.
    pub fn route_redist_withdraw_v6(&mut self, rtype: crate::rib::RibType, prefix: Ipv6Net) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let removed = self.shard.remove_v6(prefix, remote_id, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path_v6(prefix);
        fib_install_v6(&bgp_ref, prefix, &selected);

        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers_v6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Redistribute an IPv4 route into the label-v4 (SAFI 4) Loc-RIB.
    /// The label-v4 sibling of [`Bgp::route_redist_inject`]: same
    /// `redist_remote_id` discriminator and MED-from-metric, but
    /// originates into `v4lu` with implicit-null (we are the egress FEC)
    /// and advertises via the labelv4 path. No FIB install (control-plane
    /// only; the per-prefix local label + ILM is Phase 5).
    pub fn route_redist_inject_labelv4(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: Ipv4Net,
        metric: u32,
    ) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let mut attr = BgpAttr::new();
        attr.med = Some(bgp_packet::Med::new(metric));
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            remote_id,
            32768,
            &attr,
            Some(Label::new(3, 0, true)),
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update_v4lu(prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        // Reconcile the FIB: a self-originated winner withdraws any BGP
        // label entry (we are the egress; the source route forwards).
        fib_install_labelv4(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() {
            route_advertise_to_peers_labelv4(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    pub fn route_redist_withdraw_labelv4(&mut self, rtype: crate::rib::RibType, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let removed = self.shard.remove_v4lu(prefix, remote_id, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path_v4lu(prefix);
        // Reconcile the FIB: removing a self-originated route may reveal
        // a received label winner that now needs its label-push entry.
        fib_install_labelv4(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers_labelv4(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Redistribute an IPv6 route into the label-v6 (SAFI 4) Loc-RIB.
    /// The v6 counterpart of [`Bgp::route_redist_inject_labelv4`].
    pub fn route_redist_inject_labelv6(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: Ipv6Net,
        metric: u32,
    ) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let mut attr = BgpAttr::new();
        attr.med = Some(bgp_packet::Med::new(metric));
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            remote_id,
            32768,
            &attr,
            Some(Label::new(3, 0, true)),
            None,
            false,
        );
        let (_replaced, selected, next_id) = self.shard.update_v6lu(prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        fib_install_labelv6(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() {
            route_advertise_to_peers_labelv6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    pub fn route_redist_withdraw_labelv6(&mut self, rtype: crate::rib::RibType, prefix: Ipv6Net) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let removed = self.shard.remove_v6lu(prefix, remote_id, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        let selected = bgp_ref.shard.select_best_path_v6lu(prefix);
        fib_install_labelv6(
            bgp_ref.rib_client,
            Some(&self.nexthop_cache),
            prefix,
            &selected,
        );
        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers_labelv6(prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Originate an EVPN Type-2 (MAC/IP Advertisement) route from a
    /// kernel-learned bridge FDB entry.
    ///
    /// Inserts into `Bgp::local_rib.evpn` only — wire transmission
    /// (route_advertise_evpn_to_peers + send_evpn) lands in a follow-up.
    /// Verification target this PR: `show bgp l2vpn evpn` lists the
    /// route after a local FDB learn.
    ///
    /// Gates:
    ///   - `advertise_all_vni` must be true (FRR-style global enable).
    ///   - `NTF_EXT_LEARNED` must be clear in the FDB flags. Set bits
    ///     mark FDB rows that arrived via netlink from another speaker
    ///     (typically zebra-rs's own `mac_add` path installing a
    ///     remote VTEP MAC); re-advertising them would loop.
    ///
    /// Hardcodes (per RFC 8365 single-homed VLAN-Based service):
    ///   - ESI = 0 (no multi-homing)
    ///   - Ethernet Tag = 0 (one bridge per VNI)
    ///   - IP component absent (MAC-only Type-2; MAC+IP needs ARP/NDP
    ///     correlation, follow-up).
    ///   - RD = `<router-id>:<VNI>` (Type-1, IPv4 + 2-byte). VNIs
    ///     above 65535 are skipped — Type-0 ASN-format RD support
    ///     for big VNIs is a follow-up.
    pub fn evpn_originate_macip(&mut self, entry: &FdbEntry) {
        if !self.advertise_all_vni {
            return;
        }
        if entry.flags & NTF_EXT_LEARNED != 0 {
            return;
        }
        // Defer until router-id is set. The `local_fdb` cache holds
        // the entry; `set_router_id` replays the cache when the
        // router-id transitions from unspecified to a real value
        // (auto-derived from interface addrs or set by operator
        // config). Without this gate, a cold-boot race would emit
        // routes under RD `0.0.0.0:VNI`, peers would accept them,
        // and the subsequent router-id update would leave the
        // 0.0.0.0 RD orphaned (no path withdraws it).
        if self.router_id.is_unspecified() {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, entry.vni) else {
            tracing::warn!(
                "evpn_originate_macip: VNI {} > 65535, RD encoding not yet supported; \
                 dropping local origination for {}",
                entry.vni,
                entry.mac
            );
            return;
        };
        let prefix = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: entry.mac.octets(),
            ip: None,
        };

        // Build the BGP attributes for this origination. RFC 8365
        // §5.1.2.4 requires both:
        //   - RT (Route Target) carrying the VNI so receivers can
        //     install into the right L2VPN (auto-derived
        //     <local-AS>:<VNI>, two-octet ASN form for now).
        //   - Encapsulation extended community = VXLAN (8) so the
        //     receiver knows which data plane to use.
        // Nexthop = local VTEP source IP (RFC 8365 §5.1.3 — the
        // egress PE for VXLAN is the VTEP). RIB resolved this from
        // the VXLAN slave's `IFLA_VXLAN_LOCAL` / `LOCAL6` and stuck
        // it on the FdbEntry. Falling back to router-id keeps an
        // older configuration where the VXLAN was created without
        // an explicit `local` from emitting a 0.0.0.0 nexthop, but
        // operators with an actual VTEP IP set will get the right
        // family in the wire encoding (v4 → 4-byte nexthop, v6 →
        // 16-byte nexthop). Per-peer NEXT_HOP rewrite for eBGP
        // still happens inside `route_update_evpn`.
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity::from([
            evpn_route_target(self.asn, entry.vni),
            evpn_encap_vxlan(),
        ]));
        let nexthop = entry.vxlan_local.unwrap_or(IpAddr::V4(self.router_id));
        if entry.vxlan_local.is_none() {
            tracing::warn!(
                "evpn_originate_macip: VXLAN for VNI {} has no local IP; \
                 falling back to router-id {} as nexthop",
                entry.vni,
                self.router_id,
            );
        }
        attr.nexthop = Some(BgpNexthop::Evpn(nexthop));

        let mut rib = BgpRib::new(
            ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0, // remote_id — fixed at 0 for locally-originated; the
            // withdraw path matches against the same value.
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) =
            self.local_rib.update_evpn(rd, prefix.clone(), rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        if !selected.is_empty() {
            route_advertise_evpn_to_peers(rd, prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Inverse of `evpn_originate_macip`. No-op when
    /// `advertise_all_vni` is false (we never originated anything to
    /// withdraw) or when the entry's VNI exceeds the Type-1 RD
    /// encoding range.
    pub fn evpn_withdraw_macip(&mut self, entry: &FdbEntry) {
        if !self.advertise_all_vni {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, entry.vni) else {
            return;
        };
        let prefix = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: entry.mac.octets(),
            ip: None,
        };
        let _ = self.local_rib.remove_evpn(rd, &prefix, 0, ORIGINATED_PEER);
        // `remove_evpn` only edits `cands`; the per-prefix `selected`
        // map (the one `show bgp evpn` iterates) is updated
        // by `select_best_path_evpn`, which evicts the entry when no
        // candidate remains. Without this call the withdrawn route
        // stays visible in `show` and orphan RDs accumulate after
        // every router-id change. Don't route the result through
        // `route_evpn_export_selected` — that path triggers kernel
        // FDB del via `MacDel`, which is appropriate for received
        // EVPN routes but wrong for locally-originated ones (the
        // kernel row is the operator's local MAC, not something we
        // installed via mac_add).
        let _ = self.local_rib.select_best_path_evpn(&rd, &prefix);
        // Tell every EVPN peer the route is gone. No best-path
        // re-evaluation here — for a locally-originated route there
        // is no other path that would replace it; the peers can
        // figure it out when they see the MP_UNREACH.
        route_withdraw_evpn_to_peers(rd, prefix, &mut self.peers);
    }

    /// Originate (or refresh) an EVPN Type-5 (IP Prefix) route for a
    /// VRF route the global Export handler is re-emitting. The L3VPN
    /// service rides exactly as it does for VPNv4/VPNv6: an MPLS
    /// service `label` carried on the `BgpRib` (MPLS mode), or the
    /// SRv6 L3 Service TLV already attached to `attr` by
    /// `srv6_export_nexthop` (SRv6 mode, `label` 0). The route is
    /// inserted into `local_rib.evpn` and advertised to peers that
    /// negotiated the (L2vpn, Evpn) AFI/SAFI — so this composes with,
    /// rather than replaces, the VPNv4/VPNv6 advertisement of the same
    /// prefix.
    ///
    /// `attr` is the already export-RT-tagged attribute the Export
    /// handler interned for VPNv4/VPNv6; we set the EVPN next-hop
    /// (the PE router-id for MPLS, the locator for SRv6) and re-use it.
    pub fn evpn_originate_type5(
        &mut self,
        rd: RouteDistinguisher,
        net: IpNet,
        mut attr: BgpAttr,
        label: u32,
        srv6_nexthop: Option<std::net::Ipv6Addr>,
    ) {
        let prefix = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: net,
        };
        let nexthop = match srv6_nexthop {
            Some(v6) => IpAddr::V6(v6),
            None => IpAddr::V4(self.router_id),
        };
        attr.nexthop = Some(BgpNexthop::Evpn(nexthop));
        // MPLS: the service label rides on the BgpRib (mirrored by the
        // Type-5 NLRI emit in `route_update_evpn`). SRv6: label 0, the
        // SID is in `attr.prefix_sid`.
        let label_obj = if label != 0 && srv6_nexthop.is_none() {
            Some(bgp_packet::Label {
                label,
                exp: 0,
                bos: true,
            })
        } else {
            None
        };
        let mut rib = BgpRib::new(
            ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            label_obj,
            None,
            false,
        );
        let (_replaced, selected, next_id) =
            self.local_rib.update_evpn(rd, prefix.clone(), rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        if !selected.is_empty() {
            route_advertise_evpn_to_peers(rd, prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Inverse of `evpn_originate_type5`: withdraw the EVPN Type-5
    /// advertisement for `(rd, net)` from `local_rib.evpn` and every
    /// EVPN peer. Called from the VRF withdraw-export handlers.
    pub fn evpn_withdraw_type5(&mut self, rd: RouteDistinguisher, net: IpNet) {
        let prefix = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: net,
        };
        let _ = self.local_rib.remove_evpn(rd, &prefix, 0, ORIGINATED_PEER);
        let _ = self.local_rib.select_best_path_evpn(&rd, &prefix);
        route_withdraw_evpn_to_peers(rd, prefix, &mut self.peers);
    }

    /// Originate a Type-3 (Inclusive Multicast Ethernet Tag) route
    /// for one local VTEP×VNI pair (RFC 7432 §4.3, §11.3 + RFC 8365
    /// §5.1.3). One IMET per VNI tells remote PEs "send your BUM
    /// traffic for this VNI to me, encapsulated with VXLAN at this
    /// IP". Receivers install a zero-MAC FDB row whose `dst` = the
    /// nexthop, used for ingress-replication of broadcast / unknown
    /// unicast / multicast.
    ///
    /// Required attributes:
    ///   - RT (Two-Octet AS Specific) carrying VNI in low 3 bytes
    ///     of Local Admin (same as Type-2).
    ///   - Encapsulation extended community = VXLAN (8) per RFC 9012.
    ///   - PMSI Tunnel attribute (RFC 6514 §5) — Tunnel Type 6
    ///     (Ingress Replication), Label = VNI, Tunnel Identifier =
    ///     local VTEP IP. Without it, peers won't know which tunnel
    ///     mechanism to use and will reject the route.
    ///   - Nexthop = local VTEP IP. Same as Type-2 origination.
    ///
    /// Same gates as `evpn_originate_macip`: `advertise_all_vni` on
    /// AND a valid router-id. RD = `<router-id>:<VNI>`.
    pub fn evpn_originate_imet(&mut self, vni: u32, vtep_local: IpAddr) {
        if !self.advertise_all_vni {
            return;
        }
        if self.router_id.is_unspecified() {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, vni) else {
            tracing::warn!(
                "evpn_originate_imet: VNI {} > 65535, RD encoding not yet supported",
                vni
            );
            return;
        };
        let prefix = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: vtep_local,
        };
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity::from([
            evpn_route_target(self.asn, vni),
            evpn_encap_vxlan(),
        ]));
        attr.pmsi_tunnel = Some(PmsiTunnel {
            // Flags = 0 (no leaf info required, per RFC 6514 §5).
            flags: 0,
            // Tunnel Type 6 = Ingress Replication.
            tunnel_type: 6,
            vni,
            endpoint: vtep_local,
        });
        attr.nexthop = Some(BgpNexthop::Evpn(vtep_local));

        let mut rib = BgpRib::new(
            ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) =
            self.local_rib.update_evpn(rd, prefix.clone(), rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };

        if !selected.is_empty() {
            route_advertise_evpn_to_peers(rd, prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Inverse of `evpn_originate_imet`. Mirrors `evpn_withdraw_macip`:
    /// remove from candidate set, evict the per-prefix `selected`
    /// entry via `select_best_path_evpn`, fan out MP_UNREACH to peers.
    pub fn evpn_withdraw_imet(&mut self, vni: u32, vtep_local: IpAddr) {
        if !self.advertise_all_vni {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, vni) else {
            return;
        };
        let prefix = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: vtep_local,
        };
        let _ = self.local_rib.remove_evpn(rd, &prefix, 0, ORIGINATED_PEER);
        let _ = self.local_rib.select_best_path_evpn(&rd, &prefix);
        route_withdraw_evpn_to_peers(rd, prefix, &mut self.peers);
    }
}

/// `NTF_EXT_LEARNED` from `<linux/neighbour.h>` — bit 0x10. Set on
/// FDB entries learned from external sources (e.g. another EVPN
/// speaker that installed via netlink). Must be filtered out of
/// origination to avoid advertise loops.
const NTF_EXT_LEARNED: u8 = 0x10;

/// Build a Type-1 RD (4-byte IPv4 + 2-byte assigned number) from
/// the local router-id and VNI per RFC 8365 §5.1.2. Returns None
/// when the VNI exceeds 16 bits — Type-1 only has 2 bytes for the
/// assigned-number field; supporting VNIs above 65535 needs the
/// Type-0 (ASN) format and is a follow-up.
fn rd_from_router_id_vni(router_id: Ipv4Addr, vni: u32) -> Option<RouteDistinguisher> {
    let vni_short: u16 = vni.try_into().ok()?;
    let mut rd = RouteDistinguisher::new(RouteDistinguisherType::IP);
    rd.val[0..4].copy_from_slice(&router_id.octets());
    rd.val[4..6].copy_from_slice(&vni_short.to_be_bytes());
    Some(rd)
}

/// Build the auto-derived Route Target extended community for an EVPN
/// route per RFC 8365 §5.1.2.4: type 0x00 / sub 0x02 (Two-Octet AS
/// Specific Route Target) carrying `<local-AS>:<VNI>`. The 2-byte
/// ASN sits in the first two octets; the VNI fills the remaining
/// four (24-bit VNI naturally encoded big-endian into the low 3 of
/// 4 bytes; 32-bit values would clobber the high byte but VNIs are
/// 24-bit per RFC 7348).
fn evpn_route_target(asn: u32, vni: u32) -> ExtCommunityValue {
    let mut rt = ExtCommunityValue {
        high_type: 0x00,
        low_type: 0x02,
        val: [0; 6],
    };
    let asn16 = asn as u16;
    rt.val[0..2].copy_from_slice(&asn16.to_be_bytes());
    rt.val[2..6].copy_from_slice(&vni.to_be_bytes());
    rt
}

/// Build the Tunnel Encapsulation extended community for VXLAN per
/// RFC 9012 §6.1: type 0x03 (Transitive Opaque) / sub 0x0c
/// (Encapsulation), value = encapsulation type 8 (VXLAN) in the low
/// two octets. Without this community a Type-2 receiver that
/// understands EVPN but supports multiple data planes can't tell
/// which encap to install, so RFC 8365 §5.1.2.4 makes it mandatory.
fn evpn_encap_vxlan() -> ExtCommunityValue {
    let mut encap = ExtCommunityValue {
        high_type: 0x03,
        low_type: 0x0c,
        val: [0; 6],
    };
    // Encapsulation type 8 = VXLAN, occupies the trailing 2 octets.
    encap.val[5] = 8;
    encap
}

#[cfg(test)]
mod policy_apply_tests {
    use std::str::FromStr;

    use bgp_packet::{As4Path, BgpNexthop, Med, Origin};
    use ipnet::Ipv4Net;

    use super::*;
    use crate::policy::{AsPathMatcher, AsPathSet, NumericMatch, PolicyList};

    /// Test wrapper that preserves the legacy `Option<BgpAttr>`
    /// shape — weight defaults to 0, local_addr defaults to
    /// 0.0.0.0, and both are dropped from the result. Tests that
    /// need to assert on weight or `set next-hop self` call
    /// `super::policy_list_apply` directly with explicit
    /// arguments.
    fn policy_list_apply(list: &PolicyList, nlri: &Ipv4Nlri, attr: BgpAttr) -> Option<BgpAttr> {
        super::policy_list_apply(list, nlri, attr, 0, std::net::Ipv4Addr::UNSPECIFIED)
            .map(|d| d.attr)
    }

    fn nlri(prefix: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: Ipv4Net::from_str(prefix).unwrap(),
        }
    }

    fn attr_with(path: &str, med: Option<u32>, origin: Option<Origin>) -> BgpAttr {
        let mut attr = BgpAttr::new();
        attr.aspath = Some(As4Path::from_str(path).unwrap());
        attr.med = med.map(|m| Med { med: m });
        attr.origin = origin;
        attr
    }

    #[test]
    fn match_as_path_set() {
        let mut set = AsPathSet::default();
        set.vals
            .insert(AsPathMatcher::from_str("\\b65001\\b").unwrap());

        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.as_path_set = Some(set);

        let attr_match = attr_with("65001 65002 65003", None, None);
        let attr_miss = attr_with("65010 65020", None, None);

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());
    }

    #[test]
    fn match_med_ge() {
        let mut list = PolicyList::default();
        list.entry(10).match_med = Some(NumericMatch::Ge(100));

        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(150), None))
                .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(100), None))
                .is_some(),
            "ge accepts equality"
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(50), None)).is_none()
        );
    }

    #[test]
    fn match_med_le() {
        let mut list = PolicyList::default();
        list.entry(10).match_med = Some(NumericMatch::Le(200));

        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(150), None))
                .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(200), None))
                .is_some(),
            "le accepts equality"
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(250), None))
                .is_none()
        );
    }

    #[test]
    fn match_med_eq() {
        let mut list = PolicyList::default();
        list.entry(10).match_med = Some(NumericMatch::Eq(100));

        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(100), None))
                .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(101), None))
                .is_none()
        );
    }

    #[test]
    fn match_origin() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.match_origin = Some(Origin::Egp);

        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1", None, Some(Origin::Egp))
            )
            .is_some()
        );
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1", None, Some(Origin::Igp))
            )
            .is_none()
        );
    }

    #[test]
    fn match_next_hop_exact() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.match_next_hop = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1)));

        let mut attr_match = attr_with("1", None, None);
        attr_match.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(10, 1, 1, 1)));

        let mut attr_diff = attr_with("1", None, None);
        attr_diff.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(10, 1, 1, 2)));

        let attr_none = attr_with("1", None, None);

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_diff).is_none());
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_none).is_none(),
            "absent nexthop should not match"
        );
    }

    #[test]
    fn match_next_hop_v6_never_matches_v4_attr() {
        // BgpAttr.nexthop is IPv4-only today. An IPv6 next-hop in
        // the entry is accepted by YANG/parse but never matches
        // the route. Locks that contract.
        let mut list = PolicyList::default();
        list.entry(10).match_next_hop = Some(std::net::IpAddr::V6("2001:db8::1".parse().unwrap()));

        let mut attr = attr_with("1", None, None);
        attr.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(10, 1, 1, 1)));

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_none());
    }

    #[test]
    fn multiple_match_clauses_all_required() {
        let mut set = AsPathSet::default();
        set.vals
            .insert(AsPathMatcher::from_str("^65001\\b").unwrap());

        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.as_path_set = Some(set);
        entry.match_origin = Some(Origin::Igp);
        entry.match_med = Some(NumericMatch::Le(50));

        let pass = attr_with("65001 65002", Some(40), Some(Origin::Igp));
        let bad_origin = attr_with("65001 65002", Some(40), Some(Origin::Egp));
        let bad_med = attr_with("65001 65002", Some(60), Some(Origin::Igp));
        let bad_path = attr_with("65010 65002", Some(40), Some(Origin::Igp));

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), pass).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), bad_origin).is_none());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), bad_med).is_none());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), bad_path).is_none());
    }

    #[test]
    fn match_as_path_len() {
        // `1 2 3 4 5` -> length 5.
        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len = Some(NumericMatch::Eq(5));
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 3 4 5", None, None)
            )
            .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1 2 3 4", None, None))
                .is_none()
        );

        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len = Some(NumericMatch::Ge(3));
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1 2 3", None, None)).is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1 2", None, None)).is_none()
        );
    }

    #[test]
    fn match_as_path_len_uniq() {
        // `1 2 1 2 1` -> length 5, unique 2.
        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len_uniq = Some(NumericMatch::Eq(2));
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 1 2 1", None, None)
            )
            .is_some()
        );
        // `1 2 3 4 5` -> length 5, unique 5: `eq 2` should miss.
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 3 4 5", None, None)
            )
            .is_none()
        );

        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len_uniq = Some(NumericMatch::Le(3));
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 1 2 1", None, None)
            )
            .is_some()
        );
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 3 4 5", None, None)
            )
            .is_none()
        );
    }

    #[test]
    fn match_local_preference() {
        use bgp_packet::LocalPref;
        let mut list = PolicyList::default();
        list.entry(10).match_local_pref = Some(NumericMatch::Ge(100));

        let mut attr_hi = attr_with("1", None, None);
        attr_hi.local_pref = Some(LocalPref::new(150));
        let mut attr_eq = attr_with("1", None, None);
        attr_eq.local_pref = Some(LocalPref::new(100));
        let mut attr_lo = attr_with("1", None, None);
        attr_lo.local_pref = Some(LocalPref::new(50));

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_hi).is_some());
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_eq).is_some(),
            "ge accepts equality"
        );
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_lo).is_none());
    }

    #[test]
    fn match_weight_default_zero() {
        // The test wrapper passes weight=0; verify default-zero
        // semantics — `eq 0` matches, `ge 1` does not.
        let mut list = PolicyList::default();
        list.entry(10).match_weight = Some(NumericMatch::Eq(0));
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", None, None)).is_some()
        );

        let mut list = PolicyList::default();
        list.entry(10).match_weight = Some(NumericMatch::Ge(1));
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", None, None)).is_none()
        );
    }

    #[test]
    fn match_weight_with_incoming_weight() {
        // When the caller passes a non-zero weight, the matcher
        // must read that value, not 0.
        let mut list = PolicyList::default();
        list.entry(10).match_weight = Some(NumericMatch::Eq(500));
        let attr = attr_with("1", None, None);
        let local = std::net::Ipv4Addr::UNSPECIFIED;
        let d = super::policy_list_apply(&list, &nlri("10.0.0.0/8"), attr.clone(), 500, local);
        assert!(d.is_some(), "weight=500 should match Eq(500)");
        let d = super::policy_list_apply(&list, &nlri("10.0.0.0/8"), attr, 0, local);
        assert!(d.is_none(), "weight=0 should not match Eq(500)");
    }

    #[test]
    fn set_next_hop_self_uses_local_addr() {
        // `set next-hop self` resolves at apply time to the
        // `local_addr` argument passed to `policy_list_apply`.
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop = Some(crate::policy::SetNextHop::SelfAddr);

        let local = std::net::Ipv4Addr::new(192, 0, 2, 7);
        let attr = attr_with("1", None, None);
        let d =
            super::policy_list_apply(&list, &nlri("10.0.0.0/8"), attr, 0, local).expect("permit");
        match d.attr.nexthop.expect("nexthop set") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, local),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn set_next_hop_v4_address() {
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop = Some(crate::policy::SetNextHop::Address(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1)),
        ));
        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        match out.nexthop.expect("nexthop set") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, std::net::Ipv4Addr::new(10, 1, 1, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn set_next_hop_v6_is_inert_today() {
        // BgpNexthop is IPv4-only. An IPv6 target on the entry
        // parses cleanly but does not modify the route's nexthop
        // — locked in until BgpNexthop::Ipv6 is plumbed.
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop = Some(crate::policy::SetNextHop::Address(
            std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
        ));
        let mut attr = attr_with("1", None, None);
        attr.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        match out.nexthop.expect("untouched") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, std::net::Ipv4Addr::new(192, 0, 2, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn set_origin_overrides_incoming() {
        let mut list = PolicyList::default();
        list.entry(10).set_origin = Some(Origin::Egp);

        let attr = attr_with("1", None, Some(Origin::Igp));
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        assert_eq!(out.origin, Some(Origin::Egp));
    }

    #[test]
    fn set_origin_on_absent() {
        // Originating an ORIGIN attribute on a route that didn't
        // carry one previously.
        let mut list = PolicyList::default();
        list.entry(10).set_origin = Some(Origin::Incomplete);

        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        assert_eq!(out.origin, Some(Origin::Incomplete));
    }

    #[test]
    fn set_weight_overrides_incoming() {
        // `set weight 999` makes the decision carry that value
        // regardless of the incoming weight.
        let mut list = PolicyList::default();
        list.entry(10).weight = Some(999);
        let d = super::policy_list_apply(
            &list,
            &nlri("10.0.0.0/8"),
            attr_with("1", None, None),
            7,
            std::net::Ipv4Addr::UNSPECIFIED,
        )
        .expect("permit");
        assert_eq!(d.weight, 999);
    }

    #[test]
    fn match_color_present_in_ext_communities_permits() {
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(100);

        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity::from([ExtCommunityValue::from_color(0, 100)]));
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_some());
    }

    #[test]
    fn match_color_wrong_value_denies() {
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(100);

        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity::from([ExtCommunityValue::from_color(0, 200)]));
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_none());
    }

    #[test]
    fn match_color_absent_ext_communities_denies() {
        // Predicate is set but the route has no EXT_COMMUNITIES at
        // all — must not match.
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(100);
        let attr = attr_with("1", None, None);
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_none());
    }

    #[test]
    fn match_color_picks_one_from_many() {
        // Route carries two color extcomms (100 and 200); the
        // predicate for 200 must succeed.
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(200);
        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity::from([
            ExtCommunityValue::from_color(0, 100),
            ExtCommunityValue::from_color(0, 200),
        ]));
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_some());
    }

    #[test]
    fn set_color_appends_color_ext_community() {
        let mut list = PolicyList::default();
        list.entry(10).set_color = Some(128);

        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let ecom = out.ecom.expect("ecom appended");
        assert_eq!(ecom.0.len(), 1);
        let c = ecom.0.first().unwrap().as_color().expect("Color extcomm");
        assert_eq!(c.color, 128);
        assert_eq!(c.co_bits(), 0);
    }

    #[test]
    fn set_color_merges_with_existing_ext_communities() {
        let mut list = PolicyList::default();
        list.entry(10).set_color = Some(128);

        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity::from_str("rt:65001:100").unwrap());
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let ecom = out.ecom.expect("ecom retained");
        assert_eq!(ecom.0.len(), 2, "RT + Color");
        assert!(ecom.0.iter().any(|v| v.as_color().is_some()));
    }

    #[test]
    fn set_prefix_sid_label_index_installs_attr_40() {
        let mut list = PolicyList::default();
        list.entry(10).set_prefix_sid_label_index = Some(128);
        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let sid = out.prefix_sid.expect("prefix_sid set");
        assert_eq!(sid.tlvs.len(), 1);
        match &sid.tlvs[0] {
            bgp_packet::PrefixSidTlv::LabelIndex { flags, label_index } => {
                assert_eq!(*flags, 0);
                assert_eq!(*label_index, 128);
            }
            other => panic!("expected LabelIndex TLV, got {:?}", other),
        }
    }

    #[test]
    fn set_prefix_sid_label_index_overwrites_existing_attr() {
        // Operator-set label-index is authoritative — any existing
        // Originator-SRGB or SRv6 service TLVs are dropped to match
        // the documented "route-map is authoritative" semantics.
        let mut list = PolicyList::default();
        list.entry(10).set_prefix_sid_label_index = Some(42);
        let mut attr = attr_with("1", None, None);
        attr.prefix_sid = Some(bgp_packet::PrefixSid {
            tlvs: vec![bgp_packet::PrefixSidTlv::OriginatorSrgb {
                flags: 0,
                srgbs: vec![bgp_packet::SrgbRange {
                    base: 16000,
                    range: 8000,
                }],
            }],
        });
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let sid = out.prefix_sid.expect("prefix_sid set");
        assert_eq!(sid.tlvs.len(), 1, "SRGB dropped, only LabelIndex remains");
        assert!(matches!(
            sid.tlvs[0],
            bgp_packet::PrefixSidTlv::LabelIndex {
                label_index: 42,
                ..
            }
        ));
    }

    #[test]
    fn match_ext_community_exact() {
        use bgp_packet::ExtCommunity;
        use std::collections::BTreeSet;
        let mut set = crate::policy::ExtCommunitySet::default();
        set.vals.insert(
            crate::policy::ExtCommunityMatcher::from_str("rt:65001:100")
                .expect("parses rt:65001:100"),
        );
        let _: &BTreeSet<_> = &set.vals; // type sanity

        let mut list = PolicyList::default();
        list.entry(10).ext_community_set = Some(set);

        let mut attr_match = attr_with("1", None, None);
        attr_match.ecom = Some(ExtCommunity::from_str("rt:65001:100").unwrap());
        let mut attr_miss = attr_with("1", None, None);
        attr_miss.ecom = Some(ExtCommunity::from_str("rt:65001:200").unwrap());

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());
        // Absent ecom => no match
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", None, None)).is_none()
        );
    }

    #[test]
    fn match_ext_community_regex() {
        use bgp_packet::ExtCommunity;
        let mut set = crate::policy::ExtCommunitySet::default();
        set.vals
            .insert(crate::policy::ExtCommunityMatcher::from_str("rt:^65001:.*").unwrap());

        let mut list = PolicyList::default();
        list.entry(10).ext_community_set = Some(set);

        let mut attr_match = attr_with("1", None, None);
        attr_match.ecom = Some(ExtCommunity::from_str("rt:65001:100 rt:65002:200").unwrap());
        let mut attr_miss = attr_with("1", None, None);
        attr_miss.ecom = Some(ExtCommunity::from_str("rt:65003:100").unwrap());

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());
    }

    #[test]
    fn match_large_community_exact_and_regex() {
        use bgp_packet::LargeCommunity;
        let mut set = crate::policy::LargeCommunitySet::default();
        set.vals
            .insert(crate::policy::LargeCommunityMatcher::from_str("65001:100:200").unwrap());

        let mut list = PolicyList::default();
        list.entry(10).large_community_set = Some(set);

        let mut attr_match = attr_with("1", None, None);
        attr_match.lcom = Some(LargeCommunity::from_str("65001:100:200 65002:300:400").unwrap());
        let mut attr_miss = attr_with("1", None, None);
        attr_miss.lcom = Some(LargeCommunity::from_str("65001:100:201").unwrap());

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());

        // Regex variant
        let mut set = crate::policy::LargeCommunitySet::default();
        set.vals
            .insert(crate::policy::LargeCommunityMatcher::from_str("^65001:.*:.*$").unwrap());
        let mut list = PolicyList::default();
        list.entry(10).large_community_set = Some(set);

        let mut attr_regex = attr_with("1", None, None);
        attr_regex.lcom = Some(LargeCommunity::from_str("65001:9:9").unwrap());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_regex).is_some());
    }

    fn evpn_mac(vni: u32) -> EvpnRoute {
        EvpnRoute::Mac(EvpnMac {
            id: 0,
            rd: RouteDistinguisher::new(RouteDistinguisherType::IP),
            esi: [0; 10],
            ether_tag: 0,
            mac: [0x02, 0, 0, 0, 0, 1],
            vni,
        })
    }

    fn evpn_multicast() -> EvpnRoute {
        EvpnRoute::Multicast(EvpnMulticast {
            id: 0,
            rd: RouteDistinguisher::new(RouteDistinguisherType::IP),
            ether_tag: 0,
            addr: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        })
    }

    /// `attr_with(...)` augmented with a Route Target extended
    /// community carrying the supplied VNI. Mirrors how an EVPN
    /// Type-3 peer advertises VNI per RFC 8365 §5.1.2.4.
    fn attr_with_rt_vni(asn: u32, vni: u32) -> BgpAttr {
        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity::from([evpn_route_target(asn, vni)]));
        attr
    }

    fn evpn_apply(list: &PolicyList, route: &EvpnRoute, attr: BgpAttr) -> Option<BgpAttr> {
        super::policy_list_apply_evpn(list, route, attr, 0, Ipv4Addr::UNSPECIFIED).map(|d| d.attr)
    }

    #[test]
    fn match_evpn_route_type_macip_matches_mac() {
        use crate::policy::EvpnRouteType;
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_route_type = Some(EvpnRouteType::MacIp);

        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_some());
        assert!(evpn_apply(&list, &evpn_multicast(), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_route_type_multicast_matches_multicast() {
        use crate::policy::EvpnRouteType;
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_route_type = Some(EvpnRouteType::Multicast);

        assert!(evpn_apply(&list, &evpn_multicast(), attr_with("1", None, None)).is_some());
        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_route_type_unmatched_yields_default_deny() {
        use crate::policy::EvpnRouteType;
        // Looking for Ead — the parser never produces this variant
        // today, so no `EvpnRoute` will satisfy it. Default-deny
        // applies when the only entry fails to match.
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_route_type = Some(EvpnRouteType::Ead);

        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_none());
        assert!(evpn_apply(&list, &evpn_multicast(), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_vni_type2_uses_nlri_vni() {
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_vni = Some(100);

        // Type-2 carries VNI in the NLRI; the RT-EC is irrelevant.
        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_some());
        assert!(evpn_apply(&list, &evpn_mac(200), attr_with("1", None, None)).is_none());
        // VNI=0 means "absent" per evpn_vni_of — should not match.
        assert!(evpn_apply(&list, &evpn_mac(0), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_vni_type3_uses_rt_ec_vni() {
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_vni = Some(550);

        // Type-3 has no NLRI VNI; VNI comes from the RT extended
        // community per RFC 8365 §5.1.2.4.
        let attr_match = attr_with_rt_vni(65501, 550);
        let attr_miss = attr_with_rt_vni(65501, 551);
        let attr_no_rt = attr_with("1", None, None);

        assert!(evpn_apply(&list, &evpn_multicast(), attr_match).is_some());
        assert!(evpn_apply(&list, &evpn_multicast(), attr_miss).is_none());
        assert!(
            evpn_apply(&list, &evpn_multicast(), attr_no_rt).is_none(),
            "absent RT-EC yields no VNI, so the match fails"
        );
    }

    #[test]
    fn match_evpn_route_type_and_vni_compose() {
        use crate::policy::EvpnRouteType;
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.match_evpn_route_type = Some(EvpnRouteType::MacIp);
        entry.match_evpn_vni = Some(100);

        // Both conditions must hold (AND-semantics, same as the
        // rest of `entry_matches_evpn`).
        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_some());
        assert!(
            evpn_apply(&list, &evpn_mac(200), attr_with("1", None, None)).is_none(),
            "route-type matches but VNI differs"
        );
        assert!(
            evpn_apply(&list, &evpn_multicast(), attr_with_rt_vni(65501, 100)).is_none(),
            "VNI matches but route-type differs"
        );
    }
}

#[cfg(test)]
mod color_aware_nht_tests {
    use std::net::Ipv4Addr;

    use bgp_packet::{BgpAttr, ExtCommunity, ExtCommunityValue};
    use ipnet::Ipv4Net;
    use prefix_trie::PrefixMap;

    use super::resolve_flex_algo_label_inner;
    use crate::bgp::color_policy::ColorPolicy;
    use crate::rib::api::FlexAlgoNexthop;

    fn attr_with_colors(colors: &[u32]) -> BgpAttr {
        let entries: ExtCommunity = colors
            .iter()
            .map(|c| ExtCommunityValue::from_color(0, *c))
            .collect();
        BgpAttr {
            ecom: Some(entries),
            ..Default::default()
        }
    }

    fn shadow_with(
        algo: u8,
        prefix: &str,
        label: u32,
    ) -> std::collections::BTreeMap<u8, PrefixMap<Ipv4Net, FlexAlgoNexthop>> {
        let mut table = PrefixMap::new();
        table.insert(
            prefix.parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label,
            },
        );
        let mut map = std::collections::BTreeMap::new();
        map.insert(algo, table);
        map
    }

    #[test]
    fn no_color_returns_none() {
        let cp = ColorPolicy::new();
        let shadow = std::collections::BTreeMap::new();
        let attr = BgpAttr::default();
        assert!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn unbound_color_returns_none() {
        let cp = ColorPolicy::new();
        let shadow = std::collections::BTreeMap::new();
        let attr = attr_with_colors(&[100]);
        assert!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn bound_color_with_matching_route_returns_label() {
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let shadow = shadow_with(128, "10.0.0.0/24", 17128);
        let attr = attr_with_colors(&[100]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }

    #[test]
    fn bound_color_without_route_falls_through() {
        // Algo 128 is bound but the shadow has no covering route for
        // the next-hop. Should return None (strict, no fallback yet).
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let shadow = shadow_with(128, "192.0.2.0/24", 17128);
        let attr = attr_with_colors(&[100]);
        assert!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn unbound_color_then_bound_color_resolves_bound_one() {
        // Colors iterate in ascending order: 100 (unbound) is tried
        // first, 200 is bound and has a route — the bound one must
        // win, not abort on the unbound one.
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(200, 128);
        let shadow = shadow_with(128, "10.0.0.0/24", 17128);
        let attr = attr_with_colors(&[100, 200]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }

    #[test]
    fn first_bound_color_wins() {
        // Two bound colours, both with covering routes — ascending
        // color order decides (no preference/fallback semantics yet).
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        cp.bindings.insert(200, 129);
        let mut shadow = shadow_with(128, "10.0.0.0/24", 17128);
        let mut algo_129 = PrefixMap::new();
        algo_129.insert(
            "10.0.0.0/24".parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label: 17129,
            },
        );
        shadow.insert(129, algo_129);
        let attr = attr_with_colors(&[100, 200]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }

    #[test]
    fn lpm_picks_longest_covering_prefix() {
        // Both /24 and /16 cover 10.0.0.5; resolver picks /24's label.
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let mut table = PrefixMap::new();
        table.insert(
            "10.0.0.0/24".parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label: 17128,
            },
        );
        table.insert(
            "10.0.0.0/16".parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label: 99999,
            },
        );
        let mut shadow = std::collections::BTreeMap::new();
        shadow.insert(128, table);
        let attr = attr_with_colors(&[100]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }
}

/// `table-map` semantics at the BGP-to-RIB install seam
/// (zebra-bgp-table-map.yang): no binding passes through, an
/// unresolved binding denies everything (FRR parity), a policy deny
/// filters, permit-side set clauses rewrite only the install-time
/// copy — never the Loc-RIB original — and the v4/v6 bindings are
/// consulted strictly by the prefix's family.
#[cfg(test)]
mod table_map_tests {
    use std::borrow::Cow;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use bgp_packet::{Afi, AfiSafi, BgpAttr, BgpNexthop, Med, Safi};

    use super::*;
    use crate::policy::{NumericSet, PolicyAction, PolicyList, PrefixSet};

    fn binding(afi: Afi, policy: Option<PolicyList>) -> BTreeMap<AfiSafi, BgpTableMap> {
        let mut map = BTreeMap::new();
        map.insert(
            AfiSafi::new(afi, Safi::Unicast),
            BgpTableMap {
                name: Some("TM".into()),
                policy,
            },
        );
        map
    }

    fn rib_with_med(med: Option<u32>) -> BgpRib {
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        attr.med = med.map(|m| Med { med: m });
        BgpRib::new(
            1,
            Ipv4Addr::new(192, 0, 2, 1),
            BgpRibType::EBGP,
            0,
            0,
            &attr,
            None,
            None,
            false,
        )
    }

    fn rib_v6_with_med(med: Option<u32>) -> BgpRib {
        let mut attr = BgpAttr::new();
        attr.nexthop = Some(BgpNexthop::Ipv6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
        attr.med = med.map(|m| Med { med: m });
        BgpRib::new(
            1,
            Ipv4Addr::new(192, 0, 2, 1),
            BgpRibType::EBGP,
            0,
            0,
            &attr,
            None,
            None,
            false,
        )
    }

    fn p(s: &str) -> IpNet {
        IpNet::from_str(s).unwrap()
    }

    /// Deny-everything policy: a single deny entry plus nothing else,
    /// so any prefix that reaches it is filtered.
    fn deny_all_list() -> PolicyList {
        let mut list = PolicyList::default();
        list.entry(10).action = PolicyAction::Deny;
        list
    }

    #[test]
    fn no_binding_passes_through() {
        let map = BTreeMap::new();
        let best = rib_with_med(Some(7));
        let out = table_map_apply(&map, Ipv4Addr::UNSPECIFIED, p("10.0.0.0/8"), Some(&best))
            .expect("no binding must not filter");
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "pass-through must not clone the winner"
        );
        assert!(
            table_map_apply(&map, Ipv4Addr::UNSPECIFIED, p("10.0.0.0/8"), None).is_none(),
            "no winner stays no winner"
        );
    }

    #[test]
    fn unresolved_policy_denies_all() {
        for (afi, prefix) in [(Afi::Ip, p("10.0.0.0/8")), (Afi::Ip6, p("2001:db8::/32"))] {
            let map = binding(afi, None);
            let best = rib_with_med(None);
            assert!(
                table_map_apply(&map, Ipv4Addr::UNSPECIFIED, prefix, Some(&best)).is_none(),
                "a bound but unresolved table-map filters every install (FRR parity)"
            );
        }
    }

    #[test]
    fn policy_deny_filters_matching_prefix_only() {
        // seq 10: deny 10.0.0.0/8 (and longer); seq 20: permit any.
        let mut list = PolicyList::default();
        let mut pset = PrefixSet::default();
        pset.entry(p("10.0.0.0/8"));
        let entry = list.entry(10);
        entry.prefix_set = Some(pset);
        entry.action = PolicyAction::Deny;
        let _ = list.entry(20);
        let map = binding(Afi::Ip, Some(list));
        let best = rib_with_med(None);

        assert!(
            table_map_apply(&map, Ipv4Addr::UNSPECIFIED, p("10.1.0.0/16"), Some(&best)).is_none(),
            "denied prefix must not install"
        );
        assert!(
            table_map_apply(
                &map,
                Ipv4Addr::UNSPECIFIED,
                p("192.168.0.0/16"),
                Some(&best)
            )
            .is_some(),
            "non-matching prefix falls through to the permit entry"
        );
    }

    #[test]
    fn set_med_rewrites_install_copy_only() {
        let mut list = PolicyList::default();
        list.entry(10).med = Some(NumericSet::Set(50));
        let map = binding(Afi::Ip, Some(list));
        let best = rib_with_med(Some(7));

        let out = table_map_apply(&map, Ipv4Addr::UNSPECIFIED, p("10.0.0.0/8"), Some(&best))
            .expect("permit");
        assert_eq!(
            out.attr.med.as_ref().map(|m| m.med),
            Some(50),
            "install copy carries the rewritten MED"
        );
        assert_eq!(
            best.attr.med.as_ref().map(|m| m.med),
            Some(7),
            "Loc-RIB original is untouched"
        );
    }

    #[test]
    fn v6_policy_deny_filters_matching_prefix_only() {
        // seq 10: deny 2001:db8::/32 (and longer); seq 20: permit any.
        let mut list = PolicyList::default();
        let mut pset = PrefixSet::default();
        pset.entry(p("2001:db8::/32"));
        let entry = list.entry(10);
        entry.prefix_set = Some(pset);
        entry.action = PolicyAction::Deny;
        let _ = list.entry(20);
        let map = binding(Afi::Ip6, Some(list));
        let best = rib_v6_with_med(None);

        assert!(
            table_map_apply(
                &map,
                Ipv4Addr::UNSPECIFIED,
                p("2001:db8:1::/48"),
                Some(&best)
            )
            .is_none(),
            "denied v6 prefix must not install"
        );
        assert!(
            table_map_apply(
                &map,
                Ipv4Addr::UNSPECIFIED,
                p("2001:dead::/32"),
                Some(&best)
            )
            .is_some(),
            "non-matching v6 prefix falls through to the permit entry"
        );
    }

    #[test]
    fn v6_set_med_rewrites_install_copy_only() {
        let mut list = PolicyList::default();
        list.entry(10).med = Some(NumericSet::Set(50));
        let map = binding(Afi::Ip6, Some(list));
        let best = rib_v6_with_med(Some(7));

        let out = table_map_apply(&map, Ipv4Addr::UNSPECIFIED, p("2001:db8::/32"), Some(&best))
            .expect("permit");
        assert_eq!(
            out.attr.med.as_ref().map(|m| m.med),
            Some(50),
            "install copy carries the rewritten MED"
        );
        assert_eq!(
            best.attr.med.as_ref().map(|m| m.med),
            Some(7),
            "Loc-RIB original is untouched"
        );
    }

    #[test]
    fn bindings_are_per_family() {
        // A deny-all bound to v4-unicast must not touch v6 installs,
        // and vice versa.
        let v4_map = binding(Afi::Ip, Some(deny_all_list()));
        let v6_best = rib_v6_with_med(None);
        assert!(
            table_map_apply(
                &v4_map,
                Ipv4Addr::UNSPECIFIED,
                p("2001:db8::/32"),
                Some(&v6_best)
            )
            .is_some(),
            "a v4-only binding must pass v6 installs through"
        );

        let v6_map = binding(Afi::Ip6, Some(deny_all_list()));
        let v4_best = rib_with_med(None);
        assert!(
            table_map_apply(
                &v6_map,
                Ipv4Addr::UNSPECIFIED,
                p("10.0.0.0/8"),
                Some(&v4_best)
            )
            .is_some(),
            "a v6-only binding must pass v4 installs through"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use std::net::{IpAddr, Ipv4Addr};

    use bgp_packet::{
        As4Path, BgpAttr, BgpNexthop, Community, CommunityValue, Ipv4Nlri, LocalPref,
    };
    use ipnet::Ipv4Net;

    use crate::policy::prefix::set::PrefixSetEntry;
    use crate::policy::{
        AsPathPrependConfig, CommunityMatcher, CommunitySet, NumericSet, PolicyList, PrefixSet,
        SetCommunityConfig, SetCommunityMode, SetNextHop,
    };

    #[test]
    fn flowspec_locrib_select_then_remove() {
        use bgp_packet::{Afi, FlowspecComponent, FlowspecNlri, FlowspecPrefix};

        let nlri = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                "10.0.0.0/24".parse().unwrap(),
            ))],
        );
        let attr = BgpAttr::default();
        let mut table = super::LocalRibFlowspecTable::default();
        let rib = super::BgpRib::new(
            1,
            Ipv4Addr::new(1, 1, 1, 1),
            super::BgpRibType::EBGP,
            0,
            0,
            &attr,
            None,
            None,
            false,
        );

        let (_, selected, _) = table.update(nlri.clone(), rib);
        assert_eq!(selected.len(), 1);
        assert!(table.selected.contains_key(&nlri));

        // Remove the only path, then re-run selection — the selected
        // entry drops out of the Loc-RIB.
        table.remove(&nlri, 0, 1);
        assert!(table.select_best_path(&nlri).is_empty());
        assert!(!table.selected.contains_key(&nlri));
    }

    /// Test wrapper that preserves the legacy `Option<BgpAttr>`
    /// shape; weight defaults to 0, local_addr to 0.0.0.0.
    /// Weight-aware / next-hop-self tests call
    /// `super::policy_list_apply` directly.
    fn policy_list_apply(list: &PolicyList, nlri: &Ipv4Nlri, attr: BgpAttr) -> Option<BgpAttr> {
        super::policy_list_apply(list, nlri, attr, 0, std::net::Ipv4Addr::UNSPECIFIED)
            .map(|d| d.attr)
    }

    fn set_community_cfg(members: &[&str], mode: SetCommunityMode) -> SetCommunityConfig {
        SetCommunityConfig {
            name: "test".into(),
            mode,
            resolved: Some(community_set(members)),
        }
    }

    fn nlri(s: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: Ipv4Net::from_str(s).unwrap(),
        }
    }

    fn community_set(members: &[&str]) -> CommunitySet {
        let mut set = CommunitySet::default();
        for m in members {
            set.vals
                .insert(CommunityMatcher::from_str(m).unwrap_or_else(|_| panic!("parse {m}")));
        }
        set
    }

    fn com_val(s: &str) -> u32 {
        CommunityValue::from_readable_str(s)
            .unwrap_or_else(|| panic!("parse {s}"))
            .0
    }

    #[test]
    fn policy_list_apply_sets_local_pref() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(250));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default())
            .expect("entry with no match clause should apply");
        assert_eq!(out.local_pref.expect("local_pref applied").local_pref, 250);
    }

    #[test]
    fn policy_list_apply_sets_local_pref_and_med() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.local_pref = Some(NumericSet::Set(150));
        entry.med = Some(NumericSet::Set(42));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 150);
        assert_eq!(out.med.unwrap().med, 42);
    }

    #[test]
    fn policy_list_apply_local_pref_overrides_existing() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(200));

        let attr = BgpAttr {
            local_pref: Some(LocalPref::new(100)),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 200);
    }

    #[test]
    fn policy_list_apply_local_pref_add_to_existing() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Add(50));

        let attr = BgpAttr {
            local_pref: Some(LocalPref::new(100)),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 150);
    }

    #[test]
    fn policy_list_apply_local_pref_add_to_absent_treats_as_zero() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Add(75));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 75);
    }

    #[test]
    fn policy_list_apply_local_pref_sub_saturates_at_zero() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Sub(200));

        let attr = BgpAttr {
            local_pref: Some(LocalPref::new(100)),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(
            out.local_pref.unwrap().local_pref,
            0,
            "underflow saturates at 0"
        );
    }

    #[test]
    fn policy_list_apply_med_add_saturates_at_max() {
        let mut list = PolicyList::default();
        list.entry(10).med = Some(NumericSet::Add(10));

        let attr = BgpAttr {
            med: Some(bgp_packet::Med { med: u32::MAX - 5 }),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(
            out.med.unwrap().med,
            u32::MAX,
            "overflow saturates at u32::MAX"
        );
    }

    #[test]
    fn policy_list_apply_med_sub_clamps_to_zero() {
        let mut list = PolicyList::default();
        list.entry(10).med = Some(NumericSet::Sub(100));

        let attr = BgpAttr {
            med: Some(bgp_packet::Med { med: 30 }),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(out.med.unwrap().med, 0);
    }

    #[test]
    fn policy_list_apply_community_replace() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(
            &["100:200", "no-export"],
            SetCommunityMode::Replace,
        ));

        // Existing community 999:999 must be wiped on replace.
        let attr = BgpAttr {
            com: Some(Community::from([com_val("999:999")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute set");
        assert!(com.contains(&com_val("100:200")));
        assert!(com.contains(&CommunityValue::NO_EXPORT.value()));
        assert!(!com.contains(&com_val("999:999")));
        assert_eq!(com.0.len(), 2);
    }

    #[test]
    fn policy_list_apply_community_additive() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(&["100:200"], SetCommunityMode::Additive));

        let attr = BgpAttr {
            com: Some(Community::from([com_val("999:999")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute set");
        assert!(com.contains(&com_val("100:200")));
        assert!(com.contains(&com_val("999:999")));
        assert_eq!(com.0.len(), 2);
    }

    #[test]
    fn policy_list_apply_community_additive_dedups() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(&["100:200"], SetCommunityMode::Additive));

        // 100:200 already present — additive should not duplicate.
        let attr = BgpAttr {
            com: Some(Community::from([com_val("100:200")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute set");
        assert_eq!(com, Community::from([com_val("100:200")]));
    }

    #[test]
    fn policy_list_apply_community_replace_skips_regex() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        // Mix concrete + regex; only 100:200 is materializable.
        entry.set_community = Some(set_community_cfg(
            &["100:200", "^65000:.*"],
            SetCommunityMode::Replace,
        ));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        let com = out.com.expect("community attribute set");
        assert_eq!(com, Community::from([com_val("100:200")]));
    }

    #[test]
    fn policy_list_apply_community_delete_removes_matching() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(
            &["100:200", "no-export"],
            SetCommunityMode::Delete,
        ));

        // Existing has both targets and a non-target — only the
        // targets are removed; non-target survives.
        let attr = BgpAttr {
            com: Some(Community::from([
                com_val("100:200"),
                com_val("999:999"),
                CommunityValue::NO_EXPORT.value(),
            ])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute survives");
        assert_eq!(com, Community::from([com_val("999:999")]));
    }

    #[test]
    fn policy_list_apply_community_delete_drops_attr_when_empty() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(&["100:200"], SetCommunityMode::Delete));

        // Single value matches the deletion → attribute should be
        // None rather than an empty Community vec.
        let attr = BgpAttr {
            com: Some(Community::from([com_val("100:200")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert!(out.com.is_none());
    }

    #[test]
    fn policy_list_apply_as_path_prepend_onto_empty() {
        let mut list = PolicyList::default();
        list.entry(10).set_as_path_prepend = Some(AsPathPrependConfig {
            asn: 65001,
            repeat: 2,
        });

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        let path = out.aspath.expect("aspath set");
        assert_eq!(path.length(), 2);
        assert_eq!(path.as_path_display(), "65001 65001");
    }

    #[test]
    fn policy_list_apply_as_path_prepend_onto_existing() {
        let mut list = PolicyList::default();
        list.entry(10).set_as_path_prepend = Some(AsPathPrependConfig::new(65001));

        // Existing path: 100 200 (origin AS at the right).
        let attr = BgpAttr {
            aspath: Some(As4Path::from(vec![100, 200])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let path = out.aspath.expect("aspath set");
        assert_eq!(path.as_path_display(), "65001 100 200");
        assert_eq!(path.length(), 3);
    }

    #[test]
    fn policy_list_apply_as_path_prepend_repeat_three_onto_existing() {
        let mut list = PolicyList::default();
        list.entry(10).set_as_path_prepend = Some(AsPathPrependConfig {
            asn: 65001,
            repeat: 3,
        });

        let attr = BgpAttr {
            aspath: Some(As4Path::from(vec![100])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let path = out.aspath.expect("aspath set");
        assert_eq!(path.as_path_display(), "65001 65001 65001 100");
        assert_eq!(path.length(), 4);
    }

    #[test]
    fn policy_list_apply_sets_next_hop() {
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop =
            Some(SetNextHop::Address(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        match out.nexthop.expect("nexthop set") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, Ipv4Addr::new(10, 1, 1, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn policy_list_apply_next_hop_overrides_existing() {
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop =
            Some(SetNextHop::Address(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));

        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        match out.nexthop.unwrap() {
            BgpNexthop::Ipv4(a) => assert_eq!(a, Ipv4Addr::new(10, 1, 1, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    // ── Phase A: control-flow semantics for permit / next / deny ──

    #[test]
    fn policy_action_deny_drops_route_and_skips_set() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.local_pref = Some(NumericSet::Set(999));
        entry.action = crate::policy::PolicyAction::Deny;

        // Match clause empty → entry matches every route.
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(out.is_none(), "deny must drop the route");
    }

    #[test]
    fn policy_action_next_applies_set_and_falls_through() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(150));
        list.entry(10).action = crate::policy::PolicyAction::Next;
        // Entry 20 takes the verdict.
        list.entry(20).med = Some(NumericSet::Set(42));
        list.entry(20).action = crate::policy::PolicyAction::Permit;

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        // Both decorations applied: entry 10's local_pref AND
        // entry 20's med.
        assert_eq!(out.local_pref.unwrap().local_pref, 150);
        assert_eq!(out.med.unwrap().med, 42);
    }

    #[test]
    fn policy_action_default_deny_when_no_entry_matches() {
        let mut list = PolicyList::default();
        // Entry only matches a non-default prefix.
        let entry = list.entry(10);
        let mut pset = PrefixSet::default();
        pset.insert(
            Ipv4Net::from_str("192.168.0.0/16").unwrap().into(),
            PrefixSetEntry::default(),
        );
        entry.prefix_set = Some(pset);
        entry.action = crate::policy::PolicyAction::Permit;

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(out.is_none(), "no match → default deny");
    }

    #[test]
    fn policy_action_next_falling_through_to_end_of_list_is_default_deny() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(150));
        list.entry(10).action = crate::policy::PolicyAction::Next;
        // No further entries — fall-through past the end of the
        // policy is default-deny.

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(
            out.is_none(),
            "next falling through end of policy → default deny"
        );
    }

    #[test]
    fn policy_action_default_permit_via_unconditional_final_entry() {
        // The "default permit" idiom: a final entry with no match
        // clauses and action=permit accepts everything that fell
        // through.
        let mut list = PolicyList::default();
        let mut pset = PrefixSet::default();
        pset.insert(
            Ipv4Net::from_str("10.0.0.0/8").unwrap().into(),
            PrefixSetEntry::default(),
        );
        let entry = list.entry(10);
        entry.prefix_set = Some(pset);
        entry.action = crate::policy::PolicyAction::Deny;

        // Final unconditional permit — the "default permit" idiom.
        list.entry(20).action = crate::policy::PolicyAction::Permit;

        // 10.0.0.0/24 hits entry 10 (deny).
        let denied = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(denied.is_none());

        // 192.168.0.0/24 falls through to entry 20 (permit).
        let permitted = policy_list_apply(&list, &nlri("192.168.0.0/24"), BgpAttr::default());
        assert!(permitted.is_some());
    }

    // FIB install translation: `make_bgp_rib_entry_v4` produces an
    // installable RibEntry only when the BGP best-path has a usable
    // IPv4 next-hop. The four cases below cover the decision matrix.

    fn bgp_rib_with_nexthop(nh: Option<BgpNexthop>, typ: super::BgpRibType) -> super::BgpRib {
        let attr = BgpAttr {
            nexthop: nh,
            ..BgpAttr::default()
        };
        super::BgpRib::new(
            42, // ident
            Ipv4Addr::new(10, 0, 0, 1),
            typ,
            0,
            0,
            &attr,
            None,
            None,
            false,
        )
    }

    #[test]
    fn nht_gate_prefers_reachable_and_withdraws_when_all_unreachable() {
        use super::{BgpRib, BgpRibType, LocalRibTable};
        let attr = BgpAttr::default();
        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mk = |id: u32, weight: u32, reachable: bool| {
            let mut r = BgpRib::new(
                id as usize,
                Ipv4Addr::new(10, 0, 0, id as u8),
                BgpRibType::IBGP,
                0,
                weight,
                &attr,
                None,
                None,
                false,
            );
            r.remote_id = id;
            r.nexthop_reachable = reachable;
            r
        };

        let mut t: LocalRibTable<Ipv4Net> = LocalRibTable::default();
        // A: unreachable next-hop but higher weight (would win without
        // the gate). B: reachable, lower weight.
        t.update(prefix, mk(1, 100, false));
        let (_, selected, _) = t.update(prefix, mk(2, 10, true));
        assert_eq!(selected.len(), 1);
        assert!(selected[0].nexthop_reachable);
        assert_eq!(selected[0].remote_id, 2, "reachable path wins over weight");

        // Now B's next-hop also goes unreachable → no usable path →
        // the prefix is withdrawn.
        let (_, selected, _) = t.update(prefix, mk(2, 10, false));
        assert!(selected.is_empty(), "all-unreachable → withdraw");
    }

    #[test]
    fn fib_entry_built_for_v4_ebgp_route() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::EBGP,
        );
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        assert_eq!(entry.distance, 20);
        assert!(entry.valid);
        match entry.nexthop {
            crate::rib::Nexthop::Uni(ref uni) => {
                assert_eq!(uni.addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
            }
            _ => panic!("expected NexthopUni"),
        }
    }

    #[test]
    fn fib_entry_uses_ibgp_distance_for_ibgp() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::IBGP,
        );
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        assert_eq!(entry.distance, 200);
    }

    #[test]
    fn fib_entry_skipped_for_unspecified_nexthop() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::UNSPECIFIED)),
            super::BgpRibType::EBGP,
        );
        assert!(super::make_bgp_rib_entry_v4(&rib).is_none());
    }

    #[test]
    fn fib_entry_skipped_when_nexthop_missing() {
        let rib = bgp_rib_with_nexthop(None, super::BgpRibType::EBGP);
        assert!(super::make_bgp_rib_entry_v4(&rib).is_none());
    }

    // --- VRF FIB arbitration: select_fib_entry_v4 -----------------------

    #[test]
    fn select_fib_entry_v4_imported_with_transport_is_labelled() {
        use crate::rib::nht::ResolvedNexthop;
        // Imported (`Originated`) row: its `attr.nexthop` was rewritten
        // to the VRF router-id (ignored here), the service label rides
        // on `.label`, and the transport map supplies the real egress.
        let mut rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 255, 0, 1))),
            super::BgpRibType::Originated,
        );
        rib.label = Some(bgp_packet::Label {
            label: 24001,
            exp: 0,
            bos: true,
        });
        let transport = vec![ResolvedNexthop {
            addr: "172.16.0.2".parse().unwrap(),
            ifindex: 5,
            labels: vec![16800],
        }];
        let entry = super::select_fib_entry_v4(&rib, Some(&transport)).expect("labelled");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.addr, "172.16.0.2".parse::<IpAddr>().unwrap());
                assert_eq!(uni.ifindex(), Some(5));
                assert_eq!(uni.mpls_label, vec![16800, 24001]);
            }
            other => panic!("expected Uni, got {other:?}"),
        }
    }

    #[test]
    fn select_fib_entry_v4_ce_winner_is_plain_even_with_transport() {
        use crate::rib::nht::ResolvedNexthop;
        // A CE (EBGP) winner installs the plain next-hop entry even when
        // the prefix also has an imported transport — the arbitration
        // guarantee that CE routes are never mis-labelled.
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::EBGP,
        );
        let transport = vec![ResolvedNexthop {
            addr: "172.16.0.2".parse().unwrap(),
            ifindex: 5,
            labels: vec![16800],
        }];
        let entry = super::select_fib_entry_v4(&rib, Some(&transport)).expect("plain");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
                assert!(uni.mpls_label.is_empty(), "CE route carries no VPN labels");
            }
            other => panic!("expected Uni, got {other:?}"),
        }
    }

    #[test]
    fn select_fib_entry_v4_originated_without_transport_is_plain() {
        // `Originated` but absent from the transport map (a locally-
        // originated VRF route, not an import) → plain path, no self-loop.
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 9))),
            super::BgpRibType::Originated,
        );
        let entry = super::select_fib_entry_v4(&rib, None).expect("plain");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
                assert!(uni.mpls_label.is_empty());
            }
            other => panic!("expected Uni, got {other:?}"),
        }
    }

    // --- SRv6 L3VPN ingress (build_srv6_vpn_fib_entry) -------------------

    fn srv6_l3_attr(sid: std::net::Ipv6Addr) -> BgpAttr {
        BgpAttr {
            nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(10, 0, 0, 1))),
            prefix_sid: Some(bgp_packet::PrefixSid {
                tlvs: vec![bgp_packet::PrefixSidTlv::Srv6L3Service(
                    bgp_packet::Srv6ServiceTlv {
                        sids: vec![bgp_packet::Srv6SidInfo::new(
                            sid,
                            0,
                            bgp_packet::SRV6_BEHAVIOR_END_DT46,
                            None,
                        )],
                        ..Default::default()
                    },
                )],
            }),
            ..BgpAttr::default()
        }
    }

    #[test]
    fn srv6_vpn_fib_entry_carries_seg6_encap_over_resolved_underlay() {
        use crate::rib::nht::ResolvedNexthop;
        let sid: std::net::Ipv6Addr = "2001:db8:1:40::".parse().unwrap();
        // SRv6 underlay: the resolved transport has an on-link v6
        // next-hop + egress link and no MPLS labels.
        let transport = vec![ResolvedNexthop {
            addr: "fe80::1".parse().unwrap(),
            ifindex: 7,
            labels: vec![],
        }];
        let entry = super::build_srv6_vpn_fib_entry(sid, &transport).expect("srv6 entry");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                // `via fe80::1 dev 7 encap seg6 segs [sid]`.
                assert_eq!(uni.addr, "fe80::1".parse::<IpAddr>().unwrap());
                assert_eq!(uni.ifindex(), Some(7));
                assert_eq!(uni.segs, vec![sid]);
                assert_eq!(uni.encap_type, Some(isis_packet::srv6::EncapType::HEncap));
                assert!(uni.mpls_label.is_empty(), "no MPLS labels on an SRv6 entry");
            }
            other => panic!("expected Uni, got {other:?}"),
        }
    }

    #[test]
    fn srv6_vpn_fib_entry_none_without_resolved_underlay() {
        let sid: std::net::Ipv6Addr = "2001:db8:1:40::".parse().unwrap();
        assert!(super::build_srv6_vpn_fib_entry(sid, &[]).is_none());
    }

    #[test]
    fn select_fib_entry_v4_srv6_import_builds_seg6_encap() {
        use crate::rib::nht::ResolvedNexthop;
        // An imported (`Originated`) VPNv4 route carrying an SRv6 L3
        // Service SID installs an H.Encap entry toward the SID, not an
        // MPLS-labelled one — keyed on the Prefix-SID attr.
        let sid: std::net::Ipv6Addr = "2001:db8:1:40::".parse().unwrap();
        let attr = srv6_l3_attr(sid);
        let rib = super::BgpRib::new(
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            super::BgpRibType::Originated,
            0,
            0,
            &attr,
            None,
            None,
            false,
        );
        let transport = vec![ResolvedNexthop {
            addr: "fe80::1".parse().unwrap(),
            ifindex: 7,
            labels: vec![],
        }];
        let entry = super::select_fib_entry_v4(&rib, Some(&transport)).expect("srv6 entry");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.segs, vec![sid]);
                assert_eq!(uni.encap_type, Some(isis_packet::srv6::EncapType::HEncap));
            }
            other => panic!("expected Uni, got {other:?}"),
        }
    }

    // --- build_vpn_fib_entry (moved from bgp/vrf/inst.rs) ----------------

    #[test]
    fn vpn_fib_entry_pushes_service_label_below_transport() {
        use crate::rib::nht::ResolvedNexthop;
        let transport = vec![ResolvedNexthop {
            addr: "172.16.0.2".parse().unwrap(),
            ifindex: 5,
            labels: vec![16800],
        }];
        let entry = super::build_vpn_fib_entry(24001, &transport).expect("installable");
        assert_eq!(entry.distance, 200, "imported VPN routes arrive via iBGP");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.addr, "172.16.0.2".parse::<IpAddr>().unwrap());
                assert_eq!(uni.ifindex(), Some(5));
                // Top-of-stack first: transport (outer) then service (bottom).
                assert_eq!(uni.mpls_label, vec![16800, 24001]);
            }
            other => panic!("expected Uni nexthop, got {other:?}"),
        }
    }

    #[test]
    fn vpn_fib_entry_label_less_baseline_and_empty_transport() {
        use crate::rib::nht::ResolvedNexthop;
        let transport = vec![ResolvedNexthop {
            addr: "172.16.0.2".parse().unwrap(),
            ifindex: 5,
            labels: vec![],
        }];
        let entry = super::build_vpn_fib_entry(24001, &transport).expect("installable");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => assert_eq!(uni.mpls_label, vec![24001]),
            other => panic!("expected Uni nexthop, got {other:?}"),
        }
        assert!(super::build_vpn_fib_entry(24001, &[]).is_none());
    }

    #[test]
    fn vpn_fib_entry_ecmp_builds_multi() {
        use crate::rib::nht::ResolvedNexthop;
        let transport = vec![
            ResolvedNexthop {
                addr: "172.16.0.2".parse().unwrap(),
                ifindex: 5,
                labels: vec![16800],
            },
            ResolvedNexthop {
                addr: "172.16.1.2".parse().unwrap(),
                ifindex: 6,
                labels: vec![16801],
            },
        ];
        let entry = super::build_vpn_fib_entry(24001, &transport).expect("installable");
        match entry.nexthop {
            crate::rib::Nexthop::Multi(multi) => {
                assert_eq!(multi.nexthops.len(), 2);
                assert_eq!(multi.nexthops[0].mpls_label, vec![16800, 24001]);
                assert_eq!(multi.nexthops[1].mpls_label, vec![16801, 24001]);
            }
            other => panic!("expected Multi nexthop, got {other:?}"),
        }
    }

    #[test]
    fn vpn_fib_entry_v6_egress() {
        use crate::rib::nht::ResolvedNexthop;
        let transport = vec![ResolvedNexthop {
            addr: "2001:db8::2".parse().unwrap(),
            ifindex: 7,
            labels: vec![16900],
        }];
        let entry = super::build_vpn_fib_entry(24002, &transport).expect("installable");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.addr, "2001:db8::2".parse::<IpAddr>().unwrap());
                assert_eq!(uni.ifindex(), Some(7));
                assert_eq!(uni.mpls_label, vec![16900, 24002]);
            }
            other => panic!("expected Uni nexthop, got {other:?}"),
        }
    }

    #[test]
    fn candidate_nexthops_v4_collects_distinct_survivors() {
        use super::{BgpRib, BgpRibType};
        let mk = |ident: usize, nh: Ipv4Addr| {
            let attr = BgpAttr {
                nexthop: Some(BgpNexthop::Ipv4(nh)),
                ..BgpAttr::default()
            };
            BgpRib::new(
                ident,
                Ipv4Addr::new(10, 0, 0, 1),
                BgpRibType::EBGP,
                0,
                0,
                &attr,
                None,
                None,
                false,
            )
        };
        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut rib = super::super::shard::BgpShard::default();
        rib.update(None, prefix, mk(1, Ipv4Addr::new(192, 0, 2, 1)));
        rib.update(None, prefix, mk(2, Ipv4Addr::new(192, 0, 2, 2)));

        // Two peers, two next-hops → both survive.
        let nhs = rib.candidate_nexthops_v4(None, prefix);
        assert_eq!(nhs.len(), 2);
        assert!(nhs.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));

        // Withdraw peer 1's path → only peer 2's next-hop survives. This
        // is what stops a partial withdrawal / next-hop change from
        // releasing a next-hop another path still uses.
        rib.remove(None, prefix, 0, 1);
        assert_eq!(
            rib.candidate_nexthops_v4(None, prefix),
            std::collections::BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))])
        );
    }

    #[test]
    fn fib_entry_uses_v6_gateway_when_enhe_egress_set() {
        // RFC 8950 path: even with no v4 NEXT_HOP attribute, the
        // route is installable as `via inet6 <ll> dev <ifindex>`
        // because MP_REACH carried the v6 next-hop and the receiver
        // knows the egress interface.
        let ll: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let mut rib = bgp_rib_with_nexthop(None, super::BgpRibType::EBGP);
        rib.enhe_egress = Some((ll, 7));
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        assert_eq!(entry.distance, 20);
        match entry.nexthop {
            crate::rib::Nexthop::Uni(ref uni) => {
                assert_eq!(uni.addr, IpAddr::V6(ll));
                assert_eq!(uni.ifindex_origin, Some(7));
                assert!(uni.valid);
            }
            other => panic!("expected Nexthop::Uni, got {:?}", other),
        }
    }

    #[test]
    fn fib_entry_enhe_ignores_v4_nexthop_attribute() {
        // RFC 8950 §4: receiver MUST ignore the NEXT_HOP attribute
        // when MP_REACH carries an IPv6 next-hop. A stale 0.0.0.0
        // (or anything else) in the v4 NEXT_HOP must not perturb
        // the install — enhe_egress wins.
        let ll: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
        let mut rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::UNSPECIFIED)),
            super::BgpRibType::EBGP,
        );
        rib.enhe_egress = Some((ll, 11));
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(ref uni) => {
                assert_eq!(uni.addr, IpAddr::V6(ll));
                assert_eq!(uni.ifindex_origin, Some(11));
            }
            other => panic!("expected Nexthop::Uni, got {:?}", other),
        }
    }

    // IPv6 counterpart: `make_bgp_rib_entry_v6` installs only when the
    // best-path carries a usable `BgpNexthop::Ipv6`.

    #[test]
    fn fib_entry_v6_built_for_ebgp_route() {
        let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rib = bgp_rib_with_nexthop(Some(BgpNexthop::Ipv6(nh)), super::BgpRibType::EBGP);
        let entry = super::make_bgp_rib_entry_v6(&rib).expect("must build");
        assert_eq!(entry.distance, 20);
        assert!(entry.valid);
        match entry.nexthop {
            crate::rib::Nexthop::Uni(ref uni) => assert_eq!(uni.addr, IpAddr::V6(nh)),
            _ => panic!("expected NexthopUni"),
        }
    }

    #[test]
    fn fib_entry_v6_uses_ibgp_distance() {
        let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rib = bgp_rib_with_nexthop(Some(BgpNexthop::Ipv6(nh)), super::BgpRibType::IBGP);
        let entry = super::make_bgp_rib_entry_v6(&rib).expect("must build");
        assert_eq!(entry.distance, 200);
    }

    #[test]
    fn fib_entry_v6_skipped_for_unspecified() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv6(std::net::Ipv6Addr::UNSPECIFIED)),
            super::BgpRibType::EBGP,
        );
        assert!(super::make_bgp_rib_entry_v6(&rib).is_none());
    }

    #[test]
    fn fib_entry_v6_skipped_for_v4_nexthop() {
        // A v4 next-hop on a row reaching the v6 installer is a bug
        // upstream; the builder defensively declines rather than
        // install a mismatched entry.
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::EBGP,
        );
        assert!(super::make_bgp_rib_entry_v6(&rib).is_none());
    }

    #[test]
    fn fib_entry_v6_skipped_when_nexthop_missing() {
        let rib = bgp_rib_with_nexthop(None, super::BgpRibType::EBGP);
        assert!(super::make_bgp_rib_entry_v6(&rib).is_none());
    }

    /// The advertise/withdraw reconstruction maps an `EvpnPrefix::IpPrefix`
    /// key back to a Type-5 wire route: same RD/eth-tag/prefix, a
    /// family-matched unspecified gateway, label 0 (withdraw semantics),
    /// and a zero ESI.
    #[test]
    fn evpn_route_from_prefix_type5_v4() {
        use bgp_packet::{EvpnPrefix, EvpnRoute, RouteDistinguisher};
        let rd = RouteDistinguisher::from_str("65000:100").unwrap();
        let prefix = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "10.1.2.0/24".parse().unwrap(),
        };
        match super::evpn_route_from_prefix(&rd, &prefix, 0) {
            EvpnRoute::Prefix(p) => {
                assert_eq!(p.rd, rd);
                assert_eq!(p.ether_tag, 0);
                assert_eq!(p.prefix.to_string(), "10.1.2.0/24");
                assert_eq!(p.gw, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                assert_eq!(p.label, 0);
                assert_eq!(p.esi, [0u8; 10]);
            }
            _ => panic!("expected Type-5 Prefix route"),
        }
    }

    #[test]
    fn evpn_route_from_prefix_type5_v6() {
        use bgp_packet::{EvpnPrefix, EvpnRoute, RouteDistinguisher};
        let rd = RouteDistinguisher::from_str("65000:200").unwrap();
        let prefix = EvpnPrefix::IpPrefix {
            eth_tag: 0,
            prefix: "2001:db8::/32".parse().unwrap(),
        };
        match super::evpn_route_from_prefix(&rd, &prefix, 0) {
            EvpnRoute::Prefix(p) => {
                assert_eq!(p.prefix.to_string(), "2001:db8::/32");
                assert_eq!(p.gw, IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
            }
            _ => panic!("expected Type-5 Prefix route"),
        }
    }

    /// A Type-5 route imported over an SRv6 underlay installs an
    /// H.Encap next-hop toward the End.DT46 service SID (no MPLS label
    /// stack) — the shared `build_srv6_vpn_fib_entry` the EVPN import
    /// reuses, so an SRv6-mode Type-5 forwards with zero extra code.
    #[test]
    fn srv6_vpn_fib_entry_encaps_to_service_sid() {
        use crate::rib::nht::ResolvedNexthop;
        let sid: std::net::Ipv6Addr = "2001:db8:1::100".parse().unwrap();
        let transport = vec![ResolvedNexthop {
            addr: "fe80::1".parse().unwrap(),
            ifindex: 7,
            labels: vec![],
        }];
        let entry = super::build_srv6_vpn_fib_entry(sid, &transport).expect("installable");
        assert_eq!(entry.distance, 200, "imported VPN routes arrive via iBGP");
        match entry.nexthop {
            crate::rib::Nexthop::Uni(uni) => {
                assert_eq!(uni.segs, vec![sid]);
                assert_eq!(uni.encap_type, Some(isis_packet::srv6::EncapType::HEncap));
                assert_eq!(uni.ifindex_origin, Some(7));
            }
            other => panic!("expected Uni nexthop, got {other:?}"),
        }
        // Unresolved underlay → nothing to install.
        assert!(super::build_srv6_vpn_fib_entry(sid, &[]).is_none());
    }
}

#[cfg(test)]
mod allowas_in_tests {
    use std::str::FromStr;

    use bgp_packet::As4Path;

    use super::{AllowAsIn, aspath_local_as_loop};

    const LOCAL: u32 = 65001;

    fn loops(path: &str, allow: Option<AllowAsIn>) -> bool {
        let aspath = As4Path::from_str(path).unwrap();
        aspath_local_as_loop(&aspath, LOCAL, allow)
    }

    #[test]
    fn strict_check_drops_any_occurrence() {
        // No allowas-in: any appearance of the local AS is a loop.
        assert!(!loops("65002 65003", None), "no local AS ⇒ no loop");
        assert!(loops("65002 65001 65003", None), "transit local AS ⇒ loop");
        assert!(loops("65002 65001", None), "origin local AS ⇒ loop");
    }

    #[test]
    fn count_caps_occurrences() {
        // Default budget is 3: accept ≤3, drop the 4th.
        assert!(
            !loops("65001 65001 65001 65002", Some(AllowAsIn::Count(3))),
            "3 occurrences within budget 3"
        );
        assert!(
            loops("65001 65001 65001 65001", Some(AllowAsIn::Count(3))),
            "4 occurrences exceed budget 3"
        );
        // A tighter budget of 1.
        assert!(!loops("65001 65002", Some(AllowAsIn::Count(1))), "1 ≤ 1");
        assert!(
            loops("65001 65001 65002", Some(AllowAsIn::Count(1))),
            "2 > 1"
        );
        // Zero occurrences never loop, whatever the budget.
        assert!(!loops("65002 65003", Some(AllowAsIn::Count(1))));
    }

    #[test]
    fn origin_allows_only_at_origin() {
        // Local AS solely as the (right-most) origin ⇒ accept.
        assert!(!loops("65002 65003 65001", Some(AllowAsIn::Origin)));
        // Prepends at the origin are still origin-only ⇒ accept.
        assert!(!loops("65002 65001 65001", Some(AllowAsIn::Origin)));
        // Local AS as a transit hop ⇒ loop.
        assert!(loops("65001 65002 65003", Some(AllowAsIn::Origin)));
        // Local AS at origin AND transit ⇒ loop.
        assert!(loops("65001 65002 65001", Some(AllowAsIn::Origin)));
        // No local AS at all ⇒ no loop.
        assert!(!loops("65002 65003", Some(AllowAsIn::Origin)));
    }
}

/// `local-as` AS_PATH behavior (zebra-bgp-local-as.yang): the egress
/// prepend forms and the substitute-AS leg of the inbound loop check.
#[cfg(test)]
mod local_as_tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use bgp_packet::{As4Path, BgpAttr};
    use tokio::sync::mpsc;

    use super::super::peer::{LocalAs, Peer, PeerType};
    use super::{aspath_own_as_loop, ebgp_egress_aspath};

    const REAL_AS: u32 = 65100;
    const SUBSTITUTE: u32 = 64999;
    const PEER_AS: u32 = 65001;

    fn test_peer(local_as: Option<LocalAs>) -> Peer {
        let (tx, rx) = mpsc::channel(8);
        Box::leak(Box::new(rx));
        let mut peer = Peer::new(
            1,
            REAL_AS,
            Ipv4Addr::new(10, 255, 0, 1),
            PEER_AS,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.peer_type = PeerType::EBGP;
        peer.config.local_as = local_as;
        peer
    }

    fn local_as(no_prepend: bool, replace_as: bool) -> Option<LocalAs> {
        Some(LocalAs {
            as_number: SUBSTITUTE,
            no_prepend,
            replace_as,
            dual_as: false,
        })
    }

    /// Run the egress transform and flatten the resulting AS_PATH.
    fn egress(peer: &Peer, path: &str) -> String {
        let mut attrs = BgpAttr {
            aspath: Some(As4Path::from_str(path).unwrap()),
            ..Default::default()
        };
        ebgp_egress_aspath(peer, &mut attrs);
        attrs
            .aspath
            .unwrap()
            .segs
            .iter()
            .flat_map(|seg| seg.asn.iter())
            .map(|asn| asn.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn egress_without_local_as_prepends_real() {
        assert_eq!(egress(&test_peer(None), "65010"), "65100 65010");
    }

    #[test]
    fn egress_bare_prepends_substitute_over_real() {
        // The receiver sees `substitute, real, …` — both ASes visible.
        assert_eq!(
            egress(&test_peer(local_as(false, false)), "65010"),
            "64999 65100 65010"
        );
    }

    #[test]
    fn egress_replace_as_hides_real() {
        assert_eq!(
            egress(&test_peer(local_as(false, true)), "65010"),
            "64999 65010"
        );
    }

    #[test]
    fn egress_dual_as_fallback_degrades_to_real() {
        // While the dual-as fallback presents the global AS, the
        // substitute must vanish from the egress prepend too.
        let mut peer = test_peer(Some(LocalAs {
            as_number: SUBSTITUTE,
            no_prepend: false,
            replace_as: true,
            dual_as: true,
        }));
        peer.local_as_dual_fallback = true;
        assert_eq!(egress(&peer, "65010"), "65100 65010");
    }

    fn loops(peer: &Peer, path: &str) -> bool {
        aspath_own_as_loop(peer, &As4Path::from_str(path).unwrap())
    }

    #[test]
    fn loop_budget_allows_the_ingress_prepend() {
        let peer = test_peer(local_as(false, false));
        // One substitute occurrence is our own ingress prepend.
        assert!(!loops(&peer, "64999 65001 65010"));
        // Two means the route really looped through the old AS.
        assert!(loops(&peer, "64999 65001 64999"));
        // The real AS is still checked strictly.
        assert!(loops(&peer, "64999 65001 65100"));
    }

    #[test]
    fn loop_budget_zero_under_no_prepend() {
        // Without the ingress prepend any substitute occurrence came
        // from the network — strict.
        let peer = test_peer(local_as(true, false));
        assert!(loops(&peer, "64999 65001"));
        assert!(!loops(&peer, "65001 65010"));
    }
}

#[cfg(test)]
mod enforce_first_as_tests {
    use std::str::FromStr;

    use bgp_packet::As4Path;

    use super::aspath_first_as_mismatch;

    // The directly-connected eBGP peer's AS that must be left-most.
    const PEER_AS: u32 = 65001;

    fn mismatch(path: &str) -> bool {
        let aspath = As4Path::from_str(path).unwrap();
        aspath_first_as_mismatch(Some(&aspath), PEER_AS)
    }

    #[test]
    fn first_as_matches_peer_as() {
        // Left-most AS is the peer's AS ⇒ no violation.
        assert!(!mismatch("65001"));
        assert!(!mismatch("65001 65002 65003"));
        // The peer prepended its own AS several times ⇒ still left-most.
        assert!(!mismatch("65001 65001 65002"));
    }

    #[test]
    fn first_as_differs_from_peer_as() {
        // A foreign left-most AS ⇒ violation (the peer did not prepend
        // its own AS first).
        assert!(mismatch("65099 65001"));
        assert!(mismatch("65002 65001"));
        // The peer's AS is present but not left-most ⇒ still a violation.
        assert!(mismatch("65003 65001 65002"));
    }

    #[test]
    fn leading_non_sequence_segment_violates() {
        // A leading AS_SET (`{}`) is not an AS_SEQUENCE ⇒ violation even
        // though the set contains the peer's AS (mirrors FRR's
        // `aspath_firstas_check`, which requires AS_SEQUENCE).
        assert!(mismatch("{65001} 65002"));
        // A leading confederation sequence (`[]`) likewise violates.
        assert!(mismatch("[65001] 65002"));
    }

    #[test]
    fn absent_or_empty_aspath_violates() {
        // No AS_PATH at all ⇒ violation (an eBGP update must carry one).
        assert!(aspath_first_as_mismatch(None, PEER_AS));
        // A path whose left-most segment carries no AS ⇒ violation.
        let empty_seq = As4Path::from(vec![]);
        assert!(aspath_first_as_mismatch(Some(&empty_seq), PEER_AS));
    }
}

/// `community_suppresses_advertisement` truth table: NO_ADVERTISE
/// gates every peer type; NO_EXPORT and NO_EXPORT_SUBCONFED gate eBGP
/// only (no confederation support, so SUBCONFED ≡ NO_EXPORT).
#[cfg(test)]
mod community_suppress_tests {
    use bgp_packet::{BgpAttr, CommunityValue};

    use super::PeerType;
    use super::community_suppresses_advertisement;

    fn attr_with_coms(coms: &[u32]) -> BgpAttr {
        BgpAttr {
            com: Some(coms.iter().copied().collect()),
            ..Default::default()
        }
    }

    #[test]
    fn no_communities_never_suppresses() {
        let attr = BgpAttr::default();
        assert!(!community_suppresses_advertisement(&attr, PeerType::IBGP));
        assert!(!community_suppresses_advertisement(&attr, PeerType::EBGP));
    }

    #[test]
    fn ordinary_communities_never_suppress() {
        let attr = attr_with_coms(&[(100 << 16) | 1]);
        assert!(!community_suppresses_advertisement(&attr, PeerType::IBGP));
        assert!(!community_suppresses_advertisement(&attr, PeerType::EBGP));
    }

    #[test]
    fn no_advertise_suppresses_all_peer_types() {
        let attr = attr_with_coms(&[CommunityValue::NO_ADVERTISE.value()]);
        assert!(community_suppresses_advertisement(&attr, PeerType::IBGP));
        assert!(community_suppresses_advertisement(&attr, PeerType::EBGP));
    }

    #[test]
    fn no_export_suppresses_ebgp_only() {
        let attr = attr_with_coms(&[CommunityValue::NO_EXPORT.value()]);
        assert!(!community_suppresses_advertisement(&attr, PeerType::IBGP));
        assert!(community_suppresses_advertisement(&attr, PeerType::EBGP));
    }

    #[test]
    fn no_export_subconfed_suppresses_ebgp_only() {
        let attr = attr_with_coms(&[CommunityValue::NO_EXPORT_SUBCONFED.value()]);
        assert!(!community_suppresses_advertisement(&attr, PeerType::IBGP));
        assert!(community_suppresses_advertisement(&attr, PeerType::EBGP));
    }

    #[test]
    fn well_known_mixed_with_ordinary_still_suppresses() {
        let attr = attr_with_coms(&[(65000 << 16) | 7, CommunityValue::NO_EXPORT.value()]);
        assert!(community_suppresses_advertisement(&attr, PeerType::EBGP));
        assert!(!community_suppresses_advertisement(&attr, PeerType::IBGP));
    }
}

/// RFC 9494 helper truth tables: LLGR_STALE / NO_LLGR community
/// detection and the per-peer capability gate for stale routes.
#[cfg(test)]
mod llgr_tests {
    use bgp_packet::caps::LlgrValue;
    use bgp_packet::{Afi, AfiSafi, BgpAttr, BgpCap, CommunityValue, Safi};

    use super::{attr_has_llgr_stale, attr_refuses_llgr, llgr_blocks_advertisement};

    fn attr_with_coms(coms: &[u32]) -> BgpAttr {
        BgpAttr {
            com: Some(coms.iter().copied().collect()),
            ..Default::default()
        }
    }

    #[test]
    fn llgr_stale_community_detection() {
        assert!(!attr_has_llgr_stale(&BgpAttr::default()));
        assert!(!attr_has_llgr_stale(&attr_with_coms(&[(100 << 16) | 1])));
        assert!(attr_has_llgr_stale(&attr_with_coms(&[
            CommunityValue::LLGR_STALE.value()
        ])));
        // Mixed with ordinary communities still detects.
        assert!(attr_has_llgr_stale(&attr_with_coms(&[
            (65000 << 16) | 7,
            CommunityValue::LLGR_STALE.value(),
        ])));
        // NO_LLGR is not LLGR_STALE.
        assert!(!attr_has_llgr_stale(&attr_with_coms(&[
            CommunityValue::NO_LLGR.value()
        ])));
    }

    #[test]
    fn no_llgr_community_detection() {
        assert!(!attr_refuses_llgr(&BgpAttr::default()));
        assert!(attr_refuses_llgr(&attr_with_coms(&[
            CommunityValue::NO_LLGR.value()
        ])));
        assert!(!attr_refuses_llgr(&attr_with_coms(&[
            CommunityValue::LLGR_STALE.value()
        ])));
        assert!(attr_refuses_llgr(&attr_with_coms(&[
            (100 << 16) | 1,
            CommunityValue::NO_LLGR.value(),
        ])));
    }

    #[test]
    fn capability_gate_blocks_stale_to_non_llgr_peer() {
        let none = BgpCap::default();
        let mut with_v4u = BgpCap::default();
        with_v4u.llgr.insert(
            AfiSafi::new(Afi::Ip, Safi::Unicast),
            LlgrValue::new(Afi::Ip, Safi::Unicast, 120),
        );

        // Fresh routes are never blocked.
        assert!(!llgr_blocks_advertisement(
            false,
            &none,
            Afi::Ip,
            Safi::Unicast
        ));
        // Stale + no capability received → blocked.
        assert!(llgr_blocks_advertisement(
            true,
            &none,
            Afi::Ip,
            Safi::Unicast
        ));
        // Stale + capability received for the AFI/SAFI → allowed.
        assert!(!llgr_blocks_advertisement(
            true,
            &with_v4u,
            Afi::Ip,
            Safi::Unicast
        ));
        // Capability is per-AFI/SAFI: v4-unicast cap does not unlock VPNv4.
        assert!(llgr_blocks_advertisement(
            true,
            &with_v4u,
            Afi::Ip,
            Safi::MplsVpn
        ));
    }
}
