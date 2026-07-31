//! EVPN VPWS (RFC 8214): point-to-point E-Line services over SRv6 or VXLAN.
//!
//! A VPWS service binds one local attachment circuit to one remote PE's AC
//! with no MAC learning: the PE advertises an Ethernet A-D per-EVI route
//! (Type-1) whose Ethernet Tag is the *local* VPWS service instance id,
//! carrying this PE's service binding per the `afi-safi evpn encapsulation`
//! — an `End.DX2` L2-Service Prefix-SID (RFC 9252 §6.3) under SRv6, or the
//! VNI in the label field plus the VXLAN Encapsulation extended community
//! (RFC 8365 §6) under VXLAN. Importing the remote PE's Type-1 — matched by
//! Ethernet Tag == `remote_service_id` and the EVI Route Target — yields
//! the remote service endpoint *as the remote signalled it* (the two
//! directions of an E-Line are independent), and the AC is cross-connected
//! to it through the cradle tee (`rib::Message::XconnectAdd` → cradle
//! `AddXconnect`, which programs both the ingress XCONNECT map and the
//! local decap — the `End.DX2` LocalSid or the VNI→AC binding).
//!
//! A service whose AC sits on a multihomed Ethernet Segment picks it up from
//! that AC — an `ethernet-segment` whose `interface` is this service's
//! `interface` binds automatically ([`bind_es`]), with the
//! `ethernet-segment` leaf available to override. The segment's ESI replaces
//! the all-zero one in the Type-1, and Designated-Forwarder election over
//! the PEs advertising that segment's Type-4 — run per `<ESI, VPWS service
//! instance>` (RFC 8214 §5) — drives the P/B bits. Single-homed services
//! keep the all-zero ESI and advertise as primary.
//!
//! The Type-1 carries the RFC 8214 §3.1 Layer-2 Attributes extended
//! community (P/B plus the configured L2 MTU); a remote whose non-zero MTU
//! differs from our non-zero MTU is not bound (`mtu-mismatch`).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ethernet_segment::{EthernetSegment, VpwsRole};

/// The dataplane endpoint a remote PE's Type-1 advertises for a VPWS
/// service instance — what our AC's frames are encapsulated toward. Each
/// direction of an E-Line carries the encapsulation its *originator*
/// signalled, so a service can bind a VXLAN remote while advertising SRv6
/// itself (and vice versa) — which is what lets a fabric migrate one PE at
/// a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpwsEndpoint {
    /// The advertised `End.DX2` / `End.DX2V` L2-Service SID (RFC 9252
    /// §6.3).
    Srv6(Ipv6Addr),
    /// The advertised VTEP and VNI (RFC 8365 §6): the VNI rides the
    /// Type-1's label field, the VTEP is the route's next hop. IPv4 only —
    /// the cradle VXLAN underlay is IPv4.
    Vxlan { vtep: Ipv4Addr, vni: u32 },
}

/// One configured VPWS service (`router bgp afi-safi evpn vpws <name>`).
#[derive(Debug, Default, Clone)]
pub struct VpwsService {
    /// EVPN Instance — scopes the auto-derived RD (`router-id:evi`) and
    /// RT (`AS:evi`) both ends must share.
    pub evi: Option<u32>,
    /// Advertised as the Ethernet Tag of our Type-1 route.
    pub local_service_id: Option<u32>,
    /// Ethernet Tag expected on the remote PE's Type-1 route.
    pub remote_service_id: Option<u32>,
    /// The attachment circuit (CE-facing port) of the E-Line.
    pub interface: Option<String>,
    /// The `(evi, eth_tag, esi)` our Type-1 is currently originated under —
    /// what a withdraw must key on even after config fields change. The ESI
    /// rides here too: it is part of the Type-1 NLRI key, so re-pointing
    /// `ethernet-segment` must withdraw under the *old* segment's ESI.
    pub originated: Option<(u32, u32, [u8; 10])>,
    /// The remote endpoint currently cross-connected (set by the import
    /// side) — lets a config change re-program the xconnect without
    /// waiting for a route churn.
    pub remote: Option<VpwsEndpoint>,
    /// L2 MTU signalled in our Type-1's Layer-2 Attributes EC (RFC 8214
    /// §3.1) and checked against the remote's. `None`/0 = no MTU check.
    pub mtu: Option<u16>,
    /// 802.1Q VID scoping the AC (RFC 8214 VLAN-based E-Line): only tagged
    /// frames with this VID enter the cross-connect and the local SID
    /// becomes `End.DX2V` (VLAN table = the EVI). `None` = whole-port
    /// service (`End.DX2`).
    pub vlan: Option<u16>,
    /// The VNI advertised in our Type-1's label field under `encapsulation
    /// vxlan` (RFC 8365 §6). `None` = the EVI, which is the common
    /// fabric-wide-VNI deployment; set it when the VNI space is
    /// administered separately from the EVI space.
    pub vni: Option<u32>,
    /// The VNI our Type-1 actually went out with — the local decap
    /// identity the xconnect tee programs (VNI→AC), mirror of the
    /// `End.DX2` entry in `VpwsState::sids`. `None` when the service
    /// originated under SRv6 (or not at all).
    pub local_vni: Option<u32>,
    /// The remote's L2 MTU when a matching Type-1 was **rejected** for an
    /// MTU mismatch — the service shows `mtu-mismatch` instead of `up`.
    pub remote_mtu_mismatch: Option<u16>,
    /// The PE whose SID is currently bound, and whether it was chosen as the
    /// segment's backup rather than its primary. Display state: on a
    /// multihomed far end this is the difference between "converged" and
    /// "running on the standby".
    pub remote_pe: Option<IpAddr>,
    /// True when the bound remote advertised `B=1` rather than `P=1`.
    pub remote_is_backup: bool,
    /// How many usable remotes were advertised for this service instance —
    /// 2 or more means the far end is multihomed and one is standing by.
    pub remote_count: usize,
    /// Name configured on the `ethernet-segment` leaf, if any. Usually
    /// absent: every commercial implementation derives the segment from the
    /// attachment circuit, so this is the override for the cases inference
    /// cannot settle, not the normal way to bind one. The *effective*
    /// binding — configured or inferred — is [`VpwsService::es`].
    pub ethernet_segment: Option<String>,
    /// How this service ended up on a segment (or why it did not).
    pub es: EsBinding,
    /// The referenced segment's own `interface`, when it names one and it is
    /// **not** this service's AC. Display-only: the explicit leaf still
    /// wins, but a segment describing a different port than the AC it is
    /// bound to is a config error worth showing rather than swallowing.
    pub es_if_mismatch: Option<String>,
    /// The referenced segment's ESI, resolved from `Bgp::ethernet_segments`.
    /// Denormalized so the route paths — which see `LocalRib`, not the ES
    /// config map — can key the Type-1 without another borrow. Kept in step
    /// by `Bgp::vpws_resync_es` at every point either side can change.
    pub esi: Option<[u8; 10]>,
    /// The referenced segment's redundancy mode, denormalized alongside
    /// `esi`. Single-active gives exactly one primary per service instance;
    /// all-active advertises every PE as primary (RFC 8214 §5).
    pub single_active: bool,
    /// The primary/backup role last advertised on this service's Type-1,
    /// and the elected DF it was derived from — display state for `show`,
    /// and the comparison a DF re-election tests before re-originating.
    pub role: VpwsRole,
    /// The elected Designated Forwarder for `<esi, local_service_id>`, or
    /// `None` when the service is single-homed or no Type-4 is selected.
    pub df: Option<IpAddr>,
}

/// How a VPWS service is bound to an Ethernet Segment.
///
/// IOS-XR, Junos, Arista and FRR all configure the segment *on the access
/// interface*, so the attachment circuit is what identifies it and the two
/// can never contradict each other. zebra-rs keeps segments in a named list
/// under `router bgp` — which is what lets a service reference one by name —
/// so it recovers the same property by inference: the AC picks the segment,
/// and the `ethernet-segment` leaf is only needed when inference cannot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EsBinding {
    /// Single-homed: no `ethernet-segment` leaf and no segment claims the AC.
    #[default]
    None,
    /// Bound by the `ethernet-segment` leaf.
    Explicit(String),
    /// Inferred: exactly one segment names this service's AC as its
    /// `interface`.
    Derived(String),
    /// The AC is claimed by more than one segment, so inference cannot pick
    /// one. Treated as single-homed — guessing here would silently put the
    /// service on the wrong ESI. Naming one on the `ethernet-segment` leaf
    /// resolves it.
    Ambiguous(Vec<String>),
    /// The `ethernet-segment` leaf names a segment that does not exist.
    /// Distinct from `None` so a typo does not look like a deliberately
    /// single-homed service.
    Unresolved(String),
}

impl EsBinding {
    /// The effective segment name, or `None` when the service is not on one.
    pub fn name(&self) -> Option<&str> {
        match self {
            EsBinding::Explicit(name) | EsBinding::Derived(name) => Some(name),
            EsBinding::None | EsBinding::Ambiguous(_) | EsBinding::Unresolved(_) => None,
        }
    }
}

/// The all-zero ESI a single-homed service advertises.
pub const ZERO_ESI: [u8; 10] = [0; 10];

/// One remote endpoint advertised for a VPWS service instance — a per-EVI
/// Type-1 that matched this service's `remote-service-id` within its EVI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpwsRemote {
    /// The advertised dataplane endpoint — SRv6 service SID or VTEP+VNI.
    pub endpoint: VpwsEndpoint,
    /// L2 MTU from the route's Layer-2 Attributes EC; 0 = none signalled.
    pub mtu: u16,
    /// The route's ESI. All-zero means the far end is single-homed.
    pub esi: [u8; 10],
    /// The advertising PE (the route's BGP next-hop) — the tie-break, and
    /// what the per-ES A-D liveness check keys on.
    pub originator: IpAddr,
    /// RFC 8214 §3.1 P bit: this PE forwards for the service instance.
    pub primary: bool,
    /// RFC 8214 §3.1 B bit: this PE is the standby.
    pub backup: bool,
}

impl VpwsRemote {
    /// Preference rank, lower is better; `None` means the remote must not be
    /// used at all.
    ///
    /// A single-homed remote (all-zero ESI) is always usable regardless of
    /// the bits — an implementation that omits the Layer-2 Attributes EC
    /// entirely decodes as `P=0 B=0`, and refusing those would break every
    /// plain point-to-point peer. Only on a *multihomed* remote do the bits
    /// carry an election result: primary beats backup, and a PE that claims
    /// neither has lost the election and must not be forwarded to.
    fn rank(&self) -> Option<u8> {
        match (self.esi == ZERO_ESI, self.primary, self.backup) {
            (true, _, _) => Some(0),
            (false, true, _) => Some(0),
            (false, false, true) => Some(1),
            (false, false, false) => None,
        }
    }
}

/// The outcome of choosing among the remotes advertised for one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpwsSelection {
    /// Bind this remote's SID to the attachment circuit. `usable` counts
    /// every remote that survived filtering, so a caller can tell a
    /// multihomed far end (2+) from a plain one without re-scanning.
    Bound { remote: VpwsRemote, usable: usize },
    /// Remotes exist but every one clashes on L2 MTU (RFC 8214 §3.1), so
    /// none may be bound. Carries one clashing MTU for `show`.
    MtuMismatch(u16),
    /// Nothing usable: no matching route, or every candidate lost its
    /// election / was mass-withdrawn.
    None,
}

/// Choose which advertised remote a VPWS service binds.
///
/// MTU is filtered first, so a primary with a clashing MTU steps aside for a
/// compatible backup rather than wedging the service. Then the RFC 8214 §5
/// roles rank the survivors — primary over backup, non-designated dropped —
/// with the lowest originating address breaking a tie so both ends of a
/// segment make the same choice.
///
/// Under all-active every attached PE advertises `P=1`, so this picks the
/// lowest-addressed of them: correct, since any of them can deliver, but not
/// load-balanced. Spreading flows across several remote SIDs needs an
/// xconnect that can hold more than one, which is a data-plane change.
pub fn select_remote(candidates: Vec<VpwsRemote>, local_mtu: Option<u16>) -> VpwsSelection {
    if candidates.is_empty() {
        return VpwsSelection::None;
    }
    let mtu_ok = |remote_mtu: u16| match local_mtu {
        Some(local) if local != 0 && remote_mtu != 0 => local == remote_mtu,
        _ => true,
    };
    let clash = candidates.iter().find(|c| !mtu_ok(c.mtu)).map(|c| c.mtu);
    let mut usable: Vec<(u8, VpwsRemote)> = candidates
        .into_iter()
        .filter(|c| mtu_ok(c.mtu))
        .filter_map(|c| c.rank().map(|r| (r, c)))
        .collect();
    if usable.is_empty() {
        // Report the MTU clash only when that is what removed everything —
        // a lost election is not an MTU problem.
        return match clash {
            Some(mtu) => VpwsSelection::MtuMismatch(mtu),
            None => VpwsSelection::None,
        };
    }
    usable.sort_by(|(ra, a), (rb, b)| ra.cmp(rb).then_with(|| a.originator.cmp(&b.originator)));
    let count = usable.len();
    VpwsSelection::Bound {
        remote: usable.remove(0).1,
        usable: count,
    }
}

/// Resolve which Ethernet Segment a VPWS service sits on, from its
/// `ethernet-segment` leaf (`explicit`), its attachment circuit (`ac`) and
/// the configured segments.
///
/// An explicit name always wins — it is the operator overriding inference,
/// and ignoring it would be worse than any mismatch it creates (the mismatch
/// is surfaced separately). With no leaf, the AC picks the segment: exactly
/// one segment naming it as its `interface` binds. That is the property
/// IOS-XR / Junos / Arista / FRR get for free by configuring the segment on
/// the interface in the first place.
///
/// Two or more segments claiming one AC resolves to [`EsBinding::Ambiguous`]
/// rather than an arbitrary tie-break (first match, lowest name): the wrong
/// guess puts the service on the wrong ESI, which becomes a silent blackhole
/// once a remote starts choosing between P and B.
pub fn bind_es(
    explicit: Option<&String>,
    ac: Option<&String>,
    segments: &BTreeMap<String, EthernetSegment>,
) -> EsBinding {
    if let Some(name) = explicit {
        return if segments.contains_key(name) {
            EsBinding::Explicit(name.clone())
        } else {
            EsBinding::Unresolved(name.clone())
        };
    }
    let Some(ac) = ac else {
        return EsBinding::None;
    };
    let claims: Vec<String> = segments
        .iter()
        .filter(|(_, es)| es.interface.as_ref() == Some(ac))
        .map(|(name, _)| name.clone())
        .collect();
    match claims.len() {
        0 => EsBinding::None,
        1 => EsBinding::Derived(claims.into_iter().next().expect("len 1")),
        _ => EsBinding::Ambiguous(claims),
    }
}

impl VpwsService {
    /// All mandatory parameters, or `None` while the config is partial:
    /// `(evi, local_service_id, remote_service_id, interface)`.
    pub fn params(&self) -> Option<(u32, u32, u32, &str)> {
        Some((
            self.evi?,
            self.local_service_id?,
            self.remote_service_id?,
            self.interface.as_deref()?,
        ))
    }

    /// The cradle xconnect scoping pair `(802.1Q VID, End.DX2V VLAN-table
    /// id — the EVI)`; `(0, 0)` for a whole-port `End.DX2` service.
    pub fn vid_table(&self) -> (u16, u32) {
        match self.vlan {
            Some(vid) if vid != 0 => (vid, self.evi.unwrap_or(0)),
            _ => (0, 0),
        }
    }

    /// The VNI this service uses under `encapsulation vxlan`: the `vni`
    /// leaf, defaulting to the EVI. `None` while the EVI is unset too.
    pub fn vni_or_evi(&self) -> Option<u32> {
        self.vni.or(self.evi)
    }
}

/// All VPWS state. Lives on `LocalRib` — like `sr_policy_local` — so both
/// the config callbacks (`&mut Bgp`) and the Type-1 import arm (`BgpTop`)
/// reach it without threading a new `BgpTop` field.
#[derive(Debug, Default)]
pub struct VpwsState {
    /// Configured services, keyed by name.
    pub services: BTreeMap<String, VpwsService>,
    /// Allocated `End.DX2` SID `(addr, locator function)` per service name.
    pub sids: BTreeMap<String, (Ipv6Addr, u16)>,
    /// Services whose DF election may have changed because a Type-4 for
    /// their segment was installed or withdrawn. The receive path only sees
    /// `LocalRib`, but re-originating a Type-1 needs the full `Bgp` (SID
    /// pool, peers), so it marks here and `Bgp::vpws_df_drain` re-elects
    /// once the `BgpTop` borrow has ended.
    pub df_dirty: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A segment claiming access port `interface`.
    fn seg(interface: Option<&str>) -> EthernetSegment {
        EthernetSegment {
            esi: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]),
            interface: interface.map(str::to_string),
            ..Default::default()
        }
    }

    fn segments(entries: &[(&str, Option<&str>)]) -> BTreeMap<String, EthernetSegment> {
        entries
            .iter()
            .map(|(name, iface)| (name.to_string(), seg(*iface)))
            .collect()
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    const ES1: [u8; 10] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

    fn pe(last: u8) -> IpAddr {
        use std::net::Ipv4Addr;
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    fn sid(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfcbb, 0xbbbb, last, 0, 0, 0, 0, 0)
    }

    /// A remote on ES1 advertising the given role bits.
    fn mh(last: u8, primary: bool, backup: bool) -> VpwsRemote {
        VpwsRemote {
            endpoint: VpwsEndpoint::Srv6(sid(last as u16)),
            mtu: 0,
            esi: ES1,
            originator: pe(last),
            primary,
            backup,
        }
    }

    /// A single-homed remote — all-zero ESI, no role bits at all (the shape
    /// a peer that omits the Layer-2 Attributes EC produces).
    fn sh(last: u8) -> VpwsRemote {
        VpwsRemote {
            endpoint: VpwsEndpoint::Srv6(sid(last as u16)),
            mtu: 0,
            esi: ZERO_ESI,
            originator: pe(last),
            primary: false,
            backup: false,
        }
    }

    fn bound(sel: &VpwsSelection) -> &VpwsRemote {
        match sel {
            VpwsSelection::Bound { remote, .. } => remote,
            other => panic!("expected a bound remote, got {other:?}"),
        }
    }

    #[test]
    fn primary_beats_backup() {
        // z2 advertises P, z3 advertises B: the primary is bound even though
        // it is the higher address, so role beats the tie-break.
        let sel = select_remote(vec![mh(3, false, true), mh(2, true, false)], None);
        assert_eq!(bound(&sel).originator, pe(2));
        assert!(matches!(sel, VpwsSelection::Bound { usable: 2, .. }));
    }

    #[test]
    fn losing_the_primary_fails_over_to_the_backup() {
        // The primary's route is gone (mass withdraw, or its own withdraw):
        // what remains is the backup, and it binds rather than the service
        // going down. This is the whole point of remote selection.
        let sel = select_remote(vec![mh(3, false, true)], None);
        assert_eq!(bound(&sel).originator, pe(3));
        assert!(bound(&sel).backup);
    }

    #[test]
    fn non_designated_is_never_used() {
        // P=0 B=0 on a multihomed remote means that PE lost the election —
        // forwarding to it blackholes. With only such remotes there is no
        // usable endpoint at all.
        assert_eq!(
            select_remote(vec![mh(2, false, false), mh(3, false, false)], None),
            VpwsSelection::None
        );
        // ... and it is skipped in favour of a usable peer.
        let sel = select_remote(vec![mh(2, false, false), mh(3, false, true)], None);
        assert_eq!(bound(&sel).originator, pe(3));
        assert!(matches!(sel, VpwsSelection::Bound { usable: 1, .. }));
    }

    #[test]
    fn single_homed_remote_ignores_the_role_bits() {
        // A plain point-to-point peer may not send the Layer-2 Attributes EC
        // at all, which decodes as P=0 B=0. Excluding those would break every
        // pre-multihoming deployment, so an all-zero ESI is always usable.
        let sel = select_remote(vec![sh(2)], None);
        assert_eq!(bound(&sel).originator, pe(2));
        assert!(!bound(&sel).backup);
    }

    #[test]
    fn equal_rank_breaks_on_lowest_originator() {
        // All-active: every attached PE advertises P=1, so pick deterministically
        // — both ends of the segment must reach the same answer.
        let sel = select_remote(vec![mh(4, true, false), mh(2, true, false)], None);
        assert_eq!(bound(&sel).originator, pe(2));
        assert!(matches!(sel, VpwsSelection::Bound { usable: 2, .. }));
    }

    #[test]
    fn selection_is_encapsulation_agnostic() {
        // A multihomed pair where the primary advertises VXLAN and the
        // backup SRv6 (a fabric mid-migration): the ranking sees only the
        // role bits, so the VXLAN primary wins — and losing it fails over
        // to the SRv6 backup, endpoint flavor notwithstanding.
        let vxlan = VpwsEndpoint::Vxlan {
            vtep: Ipv4Addr::new(192, 0, 2, 2),
            vni: 100,
        };
        let mut primary = mh(2, true, false);
        primary.endpoint = vxlan;
        let backup = mh(3, false, true);
        let sel = select_remote(vec![backup.clone(), primary], None);
        assert_eq!(bound(&sel).endpoint, vxlan);
        let sel = select_remote(vec![backup], None);
        assert!(matches!(bound(&sel).endpoint, VpwsEndpoint::Srv6(_)));
    }

    #[test]
    fn mtu_is_filtered_before_the_role_ranking() {
        // The primary clashes on MTU but the backup agrees: bind the backup
        // rather than wedging the service on the unusable primary.
        let mut primary = mh(2, true, false);
        primary.mtu = 9000;
        let mut backup = mh(3, false, true);
        backup.mtu = 1500;
        let sel = select_remote(vec![primary, backup], Some(1500));
        assert_eq!(bound(&sel).originator, pe(3));
    }

    #[test]
    fn mtu_mismatch_only_when_that_is_what_removed_everything() {
        // Every candidate clashes -> mtu-mismatch, carrying the remote value.
        let mut clash = sh(2);
        clash.mtu = 9000;
        assert_eq!(
            select_remote(vec![clash], Some(1500)),
            VpwsSelection::MtuMismatch(9000)
        );
        // Removed by the election instead -> plain None, not an MTU story.
        assert_eq!(
            select_remote(vec![mh(2, false, false)], Some(1500)),
            VpwsSelection::None
        );
        // A zero MTU on either side disables the check (RFC 8214 §3.1).
        let mut zero = sh(2);
        zero.mtu = 0;
        assert!(matches!(
            select_remote(vec![zero], Some(1500)),
            VpwsSelection::Bound { .. }
        ));
    }

    #[test]
    fn no_candidates_is_none() {
        assert_eq!(select_remote(vec![], Some(1500)), VpwsSelection::None);
    }

    #[test]
    fn ac_infers_its_segment() {
        let segs = segments(&[("es1", Some("ce1")), ("es2", Some("ce2"))]);
        // The AC picks its own segment — no `ethernet-segment` leaf needed,
        // which is what every vendor gets by configuring the ES on the port.
        assert_eq!(
            bind_es(None, Some(&s("ce1")), &segs),
            EsBinding::Derived(s("es1"))
        );
        assert_eq!(
            bind_es(None, Some(&s("ce2")), &segs),
            EsBinding::Derived(s("es2"))
        );
    }

    #[test]
    fn unclaimed_ac_is_single_homed() {
        let segs = segments(&[("es1", Some("ce1"))]);
        // No segment names this port, and a segment with no interface at all
        // claims nothing — both leave the service single-homed.
        assert_eq!(bind_es(None, Some(&s("ce9")), &segs), EsBinding::None);
        assert_eq!(
            bind_es(None, Some(&s("ce1")), &segments(&[("es1", None)])),
            EsBinding::None
        );
        // No AC configured yet: nothing to infer from.
        assert_eq!(bind_es(None, None, &segs), EsBinding::None);
        // No segments configured at all.
        assert_eq!(
            bind_es(None, Some(&s("ce1")), &BTreeMap::new()),
            EsBinding::None
        );
    }

    #[test]
    fn two_segments_on_one_ac_is_ambiguous_not_a_guess() {
        let segs = segments(&[("es1", Some("ce1")), ("es2", Some("ce1")), ("es3", None)]);
        // Picking either one would silently put the service on the wrong ESI,
        // so refuse — and report both so the operator knows what to name.
        assert_eq!(
            bind_es(None, Some(&s("ce1")), &segs),
            EsBinding::Ambiguous(vec![s("es1"), s("es2")])
        );
        // Ambiguity is not a segment: the service stays single-homed.
        assert_eq!(bind_es(None, Some(&s("ce1")), &segs).name(), None);
        // Naming one explicitly is the documented way out.
        assert_eq!(
            bind_es(Some(&s("es2")), Some(&s("ce1")), &segs),
            EsBinding::Explicit(s("es2"))
        );
    }

    #[test]
    fn explicit_leaf_overrides_inference() {
        let segs = segments(&[("es1", Some("ce1")), ("es2", Some("ce2"))]);
        // The AC would infer es1; the leaf says es2 and wins. The caller
        // reports the interface discrepancy separately rather than silently
        // preferring one or the other.
        assert_eq!(
            bind_es(Some(&s("es2")), Some(&s("ce1")), &segs),
            EsBinding::Explicit(s("es2"))
        );
    }

    #[test]
    fn explicit_leaf_naming_nothing_is_distinct_from_single_homed() {
        let segs = segments(&[("es1", Some("ce1"))]);
        // A typo must not read as "deliberately single-homed" — and it must
        // not silently fall back to the segment the AC would have inferred,
        // which would hide the typo completely.
        assert_eq!(
            bind_es(Some(&s("nosuch")), Some(&s("ce1")), &segs),
            EsBinding::Unresolved(s("nosuch"))
        );
        assert_eq!(
            bind_es(Some(&s("nosuch")), Some(&s("ce1")), &segs).name(),
            None
        );
    }

    #[test]
    fn binding_name_is_the_effective_segment() {
        assert_eq!(EsBinding::Explicit(s("es1")).name(), Some("es1"));
        assert_eq!(EsBinding::Derived(s("es1")).name(), Some("es1"));
        assert_eq!(EsBinding::None.name(), None);
        // The default must stay single-homed: a service that has never been
        // resolved advertises the all-zero ESI.
        assert_eq!(EsBinding::default(), EsBinding::None);
    }
}
