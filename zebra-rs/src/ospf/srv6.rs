//! OSPFv3 SRv6 (RFC 9513) — SRv6 Locator LSA origination. Phase 2 of
//! `docs/design/ospfv3-srv6-plan.md`: the locator configured under
//! `router ospfv3 segment-routing srv6 locator <name>` resolves
//! against the RIB locator registry and is advertised as an SRv6
//! Locator LSA carrying the End SID (= the locator base, behavior
//! End or uN by locator mode) plus its SID structure.

use std::net::Ipv4Addr;

use ospf_packet::{
    OSPFV3_SRV6_LOCATOR_LSA_TYPE, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader, Ospfv3Srv6EndSidSubTlv,
    Ospfv3Srv6LocatorLsa, Ospfv3Srv6LocatorLsaTlv, Ospfv3Srv6LocatorSubTlv, Ospfv3Srv6LocatorTlv,
    Ospfv3Srv6SidStructure,
};

use crate::rib::{Locator, LocatorBehavior};

/// Link-state ID of the (single) SRv6 Locator LSA. One locator per
/// instance today, mirroring IS-IS; multi-locator support would key
/// further instances off this base.
pub const SRV6_LOCATOR_LSID: u32 = 0;

/// Intra-Area route type in the SRv6 Locator TLV (RFC 9513 §7.1).
const SRV6_LOCATOR_ROUTE_TYPE_INTRA_AREA: u8 = 1;

/// Build the SRv6 Locator LSA for a resolved locator snapshot.
/// Returns `None` while the locator has no prefix (configured name
/// not committed globally yet) — callers flush instead.
///
/// The endpoint behavior is the raw IANA codepoint, mapped through
/// `isis_packet::Behavior` (the registry is protocol-neutral): plain
/// `End` for a classic locator, `End with NEXT-CSID` (uN) for a uSID
/// one. The SID structure is advertised for both, exactly like the
/// IS-IS LSP advertisement, so receivers can pack carriers.
pub fn srv6_locator_lsa_build(router_id: Ipv4Addr, locator: &Locator) -> Option<Ospfv3Lsa> {
    let prefix = locator.prefix?;
    let end_sid = locator.node_sid_addr()?;

    let behavior = match locator.behavior {
        Some(LocatorBehavior::Usid) => u16::from(isis_packet::Behavior::EndCSID),
        None => u16::from(isis_packet::Behavior::End),
    };
    let structure = locator.sid_structure().map(|s| Ospfv3Srv6SidStructure {
        lb_len: s.lb_bits,
        ln_len: s.ln_bits,
        fun_len: s.fun_bits,
        arg_len: s.arg_bits,
    });

    let mut end_subs = Vec::new();
    if let Some(st) = structure {
        end_subs.push(Ospfv3Srv6LocatorSubTlv::SidStructure(st));
    }
    let end = Ospfv3Srv6EndSidSubTlv {
        flags: 0,
        behavior,
        sid: end_sid,
        subs: end_subs,
    };
    let locator_tlv = Ospfv3Srv6LocatorTlv {
        route_type: SRV6_LOCATOR_ROUTE_TYPE_INTRA_AREA,
        algorithm: 0,
        locator_length: prefix.prefix_len(),
        prefix_options: 0,
        metric: 0,
        locator: prefix.network(),
        subs: vec![Ospfv3Srv6LocatorSubTlv::EndSid(end)],
    };
    let body = Ospfv3Srv6LocatorLsa {
        tlvs: vec![Ospfv3Srv6LocatorLsaTlv::Locator(locator_tlv)],
    };

    let mut lsa = Ospfv3Lsa {
        h: Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_SRV6_LOCATOR_LSA_TYPE,
            link_state_id: SRV6_LOCATOR_LSID,
            advertising_router: router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        },
        body: Ospfv3LsBody::Srv6Locator(body),
        raw: None,
    };
    lsa.update();
    Some(lsa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;

    fn locator(prefix: &str, usid: bool) -> Locator {
        Locator {
            prefix: Some(prefix.parse::<Ipv6Net>().unwrap()),
            behavior: usid.then_some(LocatorBehavior::Usid),
        }
    }

    #[test]
    fn usid_locator_advertises_un_behavior_and_structure() {
        let lsa = srv6_locator_lsa_build(
            "10.0.0.1".parse().unwrap(),
            &locator("fcbb:bbbb:5::/48", true),
        )
        .unwrap();
        assert_eq!(lsa.h.ls_type, OSPFV3_SRV6_LOCATOR_LSA_TYPE);
        let Ospfv3LsBody::Srv6Locator(body) = &lsa.body else {
            panic!("expected SRv6 Locator body");
        };
        let Ospfv3Srv6LocatorLsaTlv::Locator(loc) = &body.tlvs[0] else {
            panic!("expected Locator TLV");
        };
        assert_eq!(loc.locator_length, 48);
        assert_eq!(
            loc.locator,
            "fcbb:bbbb:5::".parse::<std::net::Ipv6Addr>().unwrap()
        );
        let Ospfv3Srv6LocatorSubTlv::EndSid(end) = &loc.subs[0] else {
            panic!("expected End SID sub-TLV");
        };
        // uN = End with NEXT-CSID, codepoint via the shared registry.
        assert_eq!(end.behavior, u16::from(isis_packet::Behavior::EndCSID));
        assert_eq!(
            end.sid,
            "fcbb:bbbb:5::".parse::<std::net::Ipv6Addr>().unwrap()
        );
        let Ospfv3Srv6LocatorSubTlv::SidStructure(st) = &end.subs[0] else {
            panic!("expected SID Structure");
        };
        // uSID geometry: LB capped at 32 → /48 splits 32/16, 16-bit fn.
        assert_eq!(
            (st.lb_len, st.ln_len, st.fun_len, st.arg_len),
            (32, 16, 16, 0)
        );
    }

    #[test]
    fn classic_locator_advertises_end_behavior() {
        let lsa = srv6_locator_lsa_build(
            "10.0.0.1".parse().unwrap(),
            &locator("2001:db8:f:1::/64", false),
        )
        .unwrap();
        let Ospfv3LsBody::Srv6Locator(body) = &lsa.body else {
            panic!("expected SRv6 Locator body");
        };
        let Ospfv3Srv6LocatorLsaTlv::Locator(loc) = &body.tlvs[0] else {
            panic!("expected Locator TLV");
        };
        let Ospfv3Srv6LocatorSubTlv::EndSid(end) = &loc.subs[0] else {
            panic!("expected End SID sub-TLV");
        };
        assert_eq!(end.behavior, u16::from(isis_packet::Behavior::End));
        let Ospfv3Srv6LocatorSubTlv::SidStructure(st) = &end.subs[0] else {
            panic!("expected SID Structure");
        };
        // Classic geometry: LB capped at 40 → /64 splits 40/24.
        assert_eq!((st.lb_len, st.ln_len), (40, 24));
    }

    #[test]
    fn unresolved_locator_builds_nothing() {
        let unresolved = Locator {
            prefix: None,
            behavior: None,
        };
        assert!(srv6_locator_lsa_build("10.0.0.1".parse().unwrap(), &unresolved).is_none());
    }
}
