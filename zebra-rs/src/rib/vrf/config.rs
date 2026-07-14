/// Staged candidate-config for one VRF entry.
///
/// Mirrors `BridgeConfig` / `VxlanConfig` — a `delete` flag on top of
/// the per-VRF leaves so the commit step can tell adds apart from
/// deletes. The `name` itself is the list key and lives in the
/// containing `BTreeMap`'s key, not here.
///
/// The route-target sets are stored as `BTreeSet` because the YANG
/// leaf-lists carry no ordering and the BGP-side consumer
/// (`bgp::Bgp::rib_known_vrfs`) compares against incoming attribute
/// communities — set semantics, not list semantics. Both lists
/// reuse [`RouteDistinguisher`] for storage because RTs and RDs
/// share the on-wire 6-octet extended-community encoding; the
/// user-facing distinction is a YANG-layer label.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct VrfConfig {
    pub delete: bool,
    /// Per-VRF Router-ID override — `set vrf X router-id A.B.C.D`.
    /// `None` lets the RIB derive one from the VRF's member
    /// interfaces (falling back to the global effective value).
    pub router_id: Option<std::net::Ipv4Addr>,
    /// Per-VRF RFC 3443 MPLS TTL model — `set vrf X mpls ttl propagate
    /// {pipe|uniform}`. `None` = inherit the global `mpls ttl propagate`
    /// (the YANG `inherit` value and leaf-absent both map here).
    pub mpls_ttl_propagate: Option<crate::rib::inst::TtlModel>,
    /// IPv4-unicast RT import set —
    /// `set vrf X ipv4 route-target import …`.
    pub ipv4_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    /// IPv4-unicast RT export set —
    /// `set vrf X ipv4 route-target export …`.
    pub ipv4_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    /// IPv6-unicast RT import set —
    /// `set vrf X ipv6 route-target import …`.
    pub ipv6_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    /// IPv6-unicast RT export set —
    /// `set vrf X ipv6 route-target export …`.
    pub ipv6_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    /// MUP (mup / SAFI 85) RT import set —
    /// `set vrf X mup route-target import …`. Reserved for the
    /// MUP import dispatch follow-up; carried for framework parity.
    pub mup_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    /// MUP (mup / SAFI 85) RT export set —
    /// `set vrf X mup route-target export …`. Tags the
    /// Session-Transformed routes the MUP controller originates from this
    /// VRF.
    pub mup_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn default_has_no_rts_and_is_not_marked_for_deletion() {
        let cfg = VrfConfig::default();
        assert!(!cfg.delete);
        assert!(cfg.ipv4_import_rts.is_empty());
        assert!(cfg.ipv4_export_rts.is_empty());
        assert!(cfg.ipv6_import_rts.is_empty());
        assert!(cfg.ipv6_export_rts.is_empty());
    }

    #[test]
    fn rt_strings_parse_via_route_distinguisher_from_str() {
        // The two encodings the existing
        // `RouteDistinguisher::from_str` supports — 2-byte ASN and
        // IPv4 — both flow through to RT storage unchanged.
        // 4-byte ASN encoding is allowed by the YANG pattern but
        // not (yet) by the Rust parser; the YANG-side `commit`
        // will reject it.
        let a = bgp_packet::RouteDistinguisher::from_str("65000:100").unwrap();
        let b = bgp_packet::RouteDistinguisher::from_str("192.0.2.1:100").unwrap();
        let mut cfg = VrfConfig::default();
        cfg.ipv4_import_rts.insert(a);
        cfg.ipv4_import_rts.insert(b);
        assert_eq!(cfg.ipv4_import_rts.len(), 2);
    }

    #[test]
    fn import_and_export_sets_are_independent() {
        // A common config mistake is conflating import / export
        // — confirm the struct keeps them as distinct sets.
        let rt = bgp_packet::RouteDistinguisher::from_str("65000:1").unwrap();
        let mut cfg = VrfConfig::default();
        cfg.ipv4_import_rts.insert(rt);
        assert!(cfg.ipv4_import_rts.contains(&rt));
        assert!(!cfg.ipv4_export_rts.contains(&rt));
    }
}
