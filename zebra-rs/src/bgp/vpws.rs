//! EVPN VPWS (RFC 8214): point-to-point E-Line services over SRv6.
//!
//! A VPWS service binds one local attachment circuit to one remote PE's AC
//! with no MAC learning: the PE advertises an Ethernet A-D per-EVI route
//! (Type-1) whose Ethernet Tag is the *local* VPWS service instance id,
//! carrying an `End.DX2` L2-Service Prefix-SID (RFC 9252 §6.3). Importing
//! the remote PE's Type-1 — matched by Ethernet Tag == `remote_service_id`
//! and the EVI Route Target — yields the remote service SID, and the AC is
//! cross-connected to it through the cradle tee (`rib::Message::XconnectAdd`
//! → cradle `AddXconnect`, which programs both the ingress XCONNECT map and
//! the local `End.DX2` decap).
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
use std::net::{IpAddr, Ipv6Addr};

use super::ethernet_segment::{EthernetSegment, VpwsRole};

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
    /// The remote `End.DX2` SID currently cross-connected (set by the
    /// import side) — lets a config change re-program the xconnect
    /// without waiting for a route churn.
    pub remote_sid: Option<Ipv6Addr>,
    /// L2 MTU signalled in our Type-1's Layer-2 Attributes EC (RFC 8214
    /// §3.1) and checked against the remote's. `None`/0 = no MTU check.
    pub mtu: Option<u16>,
    /// 802.1Q VID scoping the AC (RFC 8214 VLAN-based E-Line): only tagged
    /// frames with this VID enter the cross-connect and the local SID
    /// becomes `End.DX2V` (VLAN table = the EVI). `None` = whole-port
    /// service (`End.DX2`).
    pub vlan: Option<u16>,
    /// The remote's L2 MTU when a matching Type-1 was **rejected** for an
    /// MTU mismatch — the service shows `mtu-mismatch` instead of `up`.
    pub remote_mtu_mismatch: Option<u16>,
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

    /// RFC 8214 §3.1 MTU check: a remote is usable unless **both** ends
    /// signal a non-zero L2 MTU and they differ.
    pub fn mtu_compatible(&self, remote_mtu: u16) -> bool {
        match self.mtu {
            Some(local) if local != 0 && remote_mtu != 0 => local == remote_mtu,
            _ => true,
        }
    }

    /// The cradle xconnect scoping pair `(802.1Q VID, End.DX2V VLAN-table
    /// id — the EVI)`; `(0, 0)` for a whole-port `End.DX2` service.
    pub fn vid_table(&self) -> (u16, u32) {
        match self.vlan {
            Some(vid) if vid != 0 => (vid, self.evi.unwrap_or(0)),
            _ => (0, 0),
        }
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
