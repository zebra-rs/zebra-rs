// IS-IS Mirror SID egress node/link protection — configuration and
// state (Phase 2).
//
// draft-ietf-rtgwg-srv6-egress-protection (SRv6 End.M) and RFC 8667 /
// RFC 8679 (SR-MPLS context label). A protector node (PEB) advertises a
// Mirror SID and the protected egress's locator(s); on egress failure a
// PLR redirects traffic to PEB, which processes the inner packet in the
// failed egress's mirrored context. This module only holds the operator
// config and the parsed state — origination (Phase 3), dataplane (Phase
// 4) and PLR repair (Phase 6) consume it later.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::{IpNet, Ipv6Net};
use isis_packet::{IsisMirrorSub2Tlv, IsisSysId, IsisTlv, prefix};

use crate::config::{Args, ConfigOp};

use super::lsdb::Lsdb;
use super::{Isis, Level, Message};

/// Which dataplane a Mirror SID egress-protection entry protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MirrorDataplane {
    /// SRv6 End.M, advertised as the SRv6 Mirror SID sub-TLV (type 8)
    /// inside the SRv6 Locator TLV (RFC 9352). The default.
    #[default]
    Srv6,
    /// SR-MPLS context label, advertised via the SID/Label Binding TLV
    /// (149) M-flag (RFC 8667). Wired in a later phase.
    Mpls,
}

impl FromStr for MirrorDataplane {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "srv6" => Ok(Self::Srv6),
            "mpls" => Ok(Self::Mpls),
            _ => Err(()),
        }
    }
}

/// One configured egress-protection relationship: this node (PEB)
/// protects the egress whose SRv6 locator is `protected_locator`,
/// advertising `mirror_sid` (End.M) and resolving the protected
/// service SIDs via `via_vrf`. Keyed in
/// [`super::config::IsisConfig::egress_protections`] by
/// `protected_locator`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorProtect {
    /// Prefix identifying the protected egress PE (PEA) — the map key.
    /// SRv6: PEA's SRv6 locator (IPv6). SR-MPLS: PEA's IGP loopback
    /// (IPv4, since the SR-MPLS dataplane has no IPv6 prefix-SID).
    pub protected_locator: IpNet,
    /// Mirror SID (End.M) to advertise. `None` ⇒ auto-allocate from
    /// the local SRv6 locator at origination time (Phase 3).
    pub mirror_sid: Option<Ipv6Addr>,
    /// Local VRF whose forwarding reaches the dual-homed CE. `None` ⇒
    /// no static context mapping yet (BGP-learned path, later phase).
    pub via_vrf: Option<String>,
    /// Dataplane this entry protects.
    pub dataplane: MirrorDataplane,
}

impl MirrorProtect {
    pub fn new(protected_locator: IpNet) -> Self {
        Self {
            protected_locator,
            mirror_sid: None,
            via_vrf: None,
            dataplane: MirrorDataplane::default(),
        }
    }
}

/// Map of configured egress-protection entries, keyed by protected
/// locator. Lives on `IsisConfig`.
pub type MirrorProtectMap = BTreeMap<IpNet, MirrorProtect>;

// ── Pure state operations (testable without an `Isis` instance) ───────

/// Get the entry for `key`, creating an empty one if absent.
fn ensure(map: &mut MirrorProtectMap, key: IpNet) -> &mut MirrorProtect {
    map.entry(key).or_insert_with(|| MirrorProtect::new(key))
}

/// The `(protected-locator, via-vrf)` pairs that should have a
/// mirror-context route installed, given the config and the resolved
/// local SRv6 locator. Gated identically to the End.M emit (SRv6
/// dataplane, explicit Mirror SID inside the local locator) plus a
/// configured `via-vrf` — so a context route exists exactly when its
/// End.M decap is active and there is a local VRF to resolve into.
pub(crate) fn desired_context_routes(
    entries: &MirrorProtectMap,
    local_prefix: Ipv6Net,
) -> Vec<(Ipv6Net, String)> {
    entries
        .values()
        .filter(|e| e.dataplane == MirrorDataplane::Srv6)
        .filter(|e| {
            e.mirror_sid
                .map(|s| local_prefix.contains(&s))
                .unwrap_or(false)
        })
        // SRv6 entries always key on an IPv6 locator.
        .filter_map(|e| match (e.protected_locator, e.via_vrf.clone()) {
            (IpNet::V6(loc), Some(vrf)) => Some((loc, vrf)),
            _ => None,
        })
        .collect()
}

/// The SR-MPLS Mirror Context ILM decaps to install, as
/// `(context_label, table_id, vrf_ifindex)`. One per `dataplane: mpls`
/// entry that has both an allocated context label (`labels`) and a
/// `via-vrf` resolved to its kernel `(table_id, vrf_ifindex)` in
/// `known_vrfs`. An entry missing either is skipped — it re-installs once
/// the label is allocated (SR-MPLS up) or the VRF appears (`VrfAdd`).
pub(crate) fn desired_context_labels(
    entries: &MirrorProtectMap,
    labels: &BTreeMap<IpNet, u32>,
    known_vrfs: &BTreeMap<String, (u32, u32)>,
) -> Vec<(u32, u32, u32)> {
    entries
        .values()
        .filter(|e| e.dataplane == MirrorDataplane::Mpls)
        .filter_map(|e| {
            let label = *labels.get(&e.protected_locator)?;
            let vrf = e.via_vrf.as_deref()?;
            let &(table_id, vrf_ifindex) = known_vrfs.get(vrf)?;
            Some((label, table_id, vrf_ifindex))
        })
        .collect()
}

// ── PLR-side reception (Phase 6a) ─────────────────────────────────────

/// A Mirror SID advertisement received from a peer — the PLR's view of
/// the network. The `protector` node advertises `mirror_sid` (End.M)
/// backing the egress whose locator is `protected_locator`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMirrorSid {
    pub protector: IsisSysId,
    pub mirror_sid: Ipv6Addr,
    pub protected_locator: Ipv6Net,
}

/// Extract the SRv6 Mirror SID advertisements carried in one node's LSP
/// TLVs: every Mirror SID sub-TLV inside an SRv6 Locator TLV, paired
/// with each of its Protected Locators sub-sub-TLVs.
fn mirror_sids_from_tlvs(protector: IsisSysId, tlvs: &[IsisTlv]) -> Vec<ReceivedMirrorSid> {
    let mut out = Vec::new();
    for tlv in tlvs {
        let IsisTlv::Srv6(srv6) = tlv else {
            continue;
        };
        for locator in &srv6.locators {
            for sub in &locator.subs {
                let prefix::IsisSubTlv::Srv6MirrorSid(m) = sub else {
                    continue;
                };
                for sub2 in &m.sub2s {
                    let IsisMirrorSub2Tlv::ProtectedLocators(pl) = sub2 else {
                        continue;
                    };
                    out.push(ReceivedMirrorSid {
                        protector,
                        mirror_sid: m.sid,
                        protected_locator: pl.locator,
                    });
                }
            }
        }
    }
    out
}

/// Scan a level's LSDB for received SRv6 Mirror SID advertisements.
/// Pseudonode LSPs never carry them and are skipped.
pub fn collect_received_mirror_sids(lsdb: &Lsdb) -> Vec<ReceivedMirrorSid> {
    let mut out = Vec::new();
    for (id, lsa) in lsdb.iter() {
        if id.is_pseudo() {
            continue;
        }
        out.extend(mirror_sids_from_tlvs(id.sys_id(), &lsa.lsp.tlvs));
    }
    out
}

/// An SR-MPLS Mirror Context binding received from a peer — the PLR's
/// view. The `protector` advertises `context_label` (RFC 8679) for the
/// mirroring context whose FEC is the protected egress's `protected_fec`
/// (its IGP loopback). The PLR pushes `context_label` to steer traffic to
/// the protector on egress failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMplsBinding {
    pub protector: IsisSysId,
    pub context_label: u32,
    pub protected_fec: IpNet,
}

/// Extract the SR-MPLS Mirror Context bindings carried in one node's LSP
/// TLVs: every SID/Label Binding TLV (149) with the M-flag set, paired
/// with the label from its SID/Label sub-TLV. The FEC is IPv4 (the
/// SR-MPLS transport) or IPv6.
fn mpls_bindings_from_tlvs(protector: IsisSysId, tlvs: &[IsisTlv]) -> Vec<ReceivedMplsBinding> {
    use isis_packet::{BindingPrefix, IsisBindingSubTlv, SidLabelValue};
    let mut out = Vec::new();
    for tlv in tlvs {
        let IsisTlv::SidLabelBinding(binding) = tlv else {
            continue;
        };
        if !binding.flags.m_flag() {
            continue;
        }
        let protected_fec = match binding.prefix {
            BindingPrefix::V4(p) => IpNet::V4(p),
            BindingPrefix::V6(p) => IpNet::V6(p),
        };
        for sub in &binding.subs {
            if let IsisBindingSubTlv::SidLabel(SidLabelValue::Label(label)) = sub {
                out.push(ReceivedMplsBinding {
                    protector,
                    context_label: *label,
                    protected_fec,
                });
            }
        }
    }
    out
}

/// Scan a level's LSDB for received SR-MPLS Mirror Context bindings.
/// Pseudonode LSPs never carry them and are skipped.
pub fn collect_received_mpls_bindings(lsdb: &Lsdb) -> Vec<ReceivedMplsBinding> {
    let mut out = Vec::new();
    for (id, lsa) in lsdb.iter() {
        if id.is_pseudo() {
            continue;
        }
        out.extend(mpls_bindings_from_tlvs(id.sys_id(), &lsa.lsp.tlvs));
    }
    out
}

/// The TE Router-ID (IPv4 loopback, TLV 134) a node advertises in its
/// LSP. Used to resolve a Mirror Context binding's protector — carried
/// only as a sys-id — to the loopback the SR-MPLS transport LSP reaches
/// it at, so the protected egress can build the redirect's transport
/// label stack.
pub fn node_te_router_id(lsdb: &Lsdb, sys_id: IsisSysId) -> Option<std::net::Ipv4Addr> {
    for (id, lsa) in lsdb.iter() {
        if id.is_pseudo() || id.sys_id() != sys_id {
            continue;
        }
        for tlv in &lsa.lsp.tlvs {
            if let IsisTlv::TeRouterId(te) = tlv {
                return Some(te.router_id);
            }
        }
    }
    None
}

// ── YANG callback wiring ──────────────────────────────────────────────
//
// Each shim parses the list key (`protected-locator`) and, for leaf
// callbacks, the leaf value, mutates the config map, then re-originates
// the self LSP so the Phase 3 emit picks the change up. Today nothing is
// emitted, so the re-origination is a harmless no-op; keeping it wired
// here means Phase 3 needs no callback changes.

/// `/router/isis/egress-protection/protect` — list-entry lifecycle.
/// Creates the entry on set, removes it on delete.
fn config_egress_protect(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let key = args.ipnet()?;
    if op.is_set() {
        ensure(&mut isis.config.egress_protections, key);
    } else {
        isis.config.egress_protections.remove(&key);
    }
    reoriginate(isis);
    Some(())
}

/// `/router/isis/egress-protection/protect/mirror-sid`.
fn config_egress_protect_mirror_sid(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let key = args.ipnet()?;
    if op.is_set() {
        let sid = args.v6addr()?;
        ensure(&mut isis.config.egress_protections, key).mirror_sid = Some(sid);
    } else if let Some(entry) = isis.config.egress_protections.get_mut(&key) {
        entry.mirror_sid = None;
    }
    reoriginate(isis);
    Some(())
}

/// `/router/isis/egress-protection/protect/via-vrf`.
fn config_egress_protect_via_vrf(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let key = args.ipnet()?;
    if op.is_set() {
        let vrf = args.string()?;
        ensure(&mut isis.config.egress_protections, key).via_vrf = Some(vrf);
    } else if let Some(entry) = isis.config.egress_protections.get_mut(&key) {
        entry.via_vrf = None;
    }
    reoriginate(isis);
    Some(())
}

/// `/router/isis/egress-protection/protect/dataplane`.
fn config_egress_protect_dataplane(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let key = args.ipnet()?;
    let dataplane = if op.is_set() {
        args.string()?.parse().ok()?
    } else {
        MirrorDataplane::default()
    };
    ensure(&mut isis.config.egress_protections, key).dataplane = dataplane;
    reoriginate(isis);
    Some(())
}

/// Reconcile the End.M dataplane install with the new config, then
/// re-originate both levels so the advertisement matches. Both are gated
/// identically (`update_mirror_sids` / `lsp::mirror_sid_subs`).
/// `process_lsp_originate` filters by `has_level` for single-level
/// instances, so sending both is safe.
fn reoriginate(isis: &mut Isis) {
    isis.update_mirror_sids();
    isis.update_mirror_context_routes();
    isis.update_mirror_labels();
    isis.update_mirror_context_labels();
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
}

pub fn callback_register(isis: &mut Isis) {
    isis.callback_add(
        "/router/isis/egress-protection/protect",
        config_egress_protect,
    );
    isis.callback_add(
        "/router/isis/egress-protection/protect/mirror-sid",
        config_egress_protect_mirror_sid,
    );
    isis.callback_add(
        "/router/isis/egress-protection/protect/via-vrf",
        config_egress_protect_via_vrf,
    );
    isis.callback_add(
        "/router/isis/egress-protection/protect/dataplane",
        config_egress_protect_dataplane,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }

    #[test]
    fn dataplane_parses_and_defaults() {
        assert_eq!("srv6".parse(), Ok(MirrorDataplane::Srv6));
        assert_eq!("mpls".parse(), Ok(MirrorDataplane::Mpls));
        assert_eq!("bogus".parse::<MirrorDataplane>(), Err(()));
        assert_eq!(MirrorDataplane::default(), MirrorDataplane::Srv6);
    }

    #[test]
    fn new_entry_defaults_to_srv6_and_empty_fields() {
        let e = MirrorProtect::new(net("2001:db8:a3:1::/64"));
        assert_eq!(e.protected_locator, net("2001:db8:a3:1::/64"));
        assert_eq!(e.mirror_sid, None);
        assert_eq!(e.via_vrf, None);
        assert_eq!(e.dataplane, MirrorDataplane::Srv6);
    }

    #[test]
    fn ensure_creates_once_then_returns_same_entry() {
        let mut map = MirrorProtectMap::new();
        let key = net("2001:db8:a3:1::/64");

        ensure(&mut map, key).mirror_sid = Some("2001:db8:a4:1::3".parse().unwrap());
        ensure(&mut map, key).via_vrf = Some("cust".to_string());
        assert_eq!(map.len(), 1, "second ensure must not add a new entry");

        let e = &map[&key];
        assert_eq!(e.mirror_sid, Some("2001:db8:a4:1::3".parse().unwrap()));
        assert_eq!(e.via_vrf, Some("cust".to_string()));
        assert_eq!(e.dataplane, MirrorDataplane::Srv6);
    }

    #[test]
    fn separate_locators_are_independent_entries() {
        let mut map = MirrorProtectMap::new();
        ensure(&mut map, net("2001:db8:a3:1::/64")).dataplane = MirrorDataplane::Mpls;
        ensure(&mut map, net("2001:db8:b3:1::/64"));
        assert_eq!(map.len(), 2);
        assert_eq!(
            map[&net("2001:db8:a3:1::/64")].dataplane,
            MirrorDataplane::Mpls
        );
        assert_eq!(
            map[&net("2001:db8:b3:1::/64")].dataplane,
            MirrorDataplane::Srv6
        );
    }

    #[test]
    fn desired_context_routes_requires_in_locator_sid_and_via_vrf() {
        let local = v6("2001:db8:a4:1::/64");
        let mut map = MirrorProtectMap::new();

        // Fully eligible: SRv6, in-locator Mirror SID, via-vrf set.
        let mut ok = MirrorProtect::new(net("2001:db8:a3:1::/64"));
        ok.mirror_sid = Some("2001:db8:a4:1::3".parse().unwrap());
        ok.via_vrf = Some("cust".to_string());
        map.insert(ok.protected_locator, ok);

        // In-locator SID but no via-vrf → no context route.
        let mut no_vrf = MirrorProtect::new(net("2001:db8:b3:1::/64"));
        no_vrf.mirror_sid = Some("2001:db8:a4:1::4".parse().unwrap());
        map.insert(no_vrf.protected_locator, no_vrf);

        // via-vrf set but Mirror SID outside the local locator → skipped.
        let mut outside = MirrorProtect::new(net("2001:db8:c3:1::/64"));
        outside.mirror_sid = Some("2001:db8:ffff::9".parse().unwrap());
        outside.via_vrf = Some("cust".to_string());
        map.insert(outside.protected_locator, outside);

        let routes = desired_context_routes(&map, local);
        assert_eq!(
            routes,
            vec![(v6("2001:db8:a3:1::/64"), "cust".to_string())],
            "only the fully-eligible entry yields a context route"
        );
    }

    #[test]
    fn desired_context_labels_requires_mpls_label_and_known_vrf() {
        let mut map = MirrorProtectMap::new();

        // MPLS entry with via-vrf, an allocated label, and a known VRF →
        // yields one ILM decap.
        let mut ok = MirrorProtect::new(net("2001:db8::3/128"));
        ok.dataplane = MirrorDataplane::Mpls;
        ok.via_vrf = Some("cust".to_string());
        map.insert(ok.protected_locator, ok);

        // MPLS entry without via-vrf → skipped.
        let mut no_vrf = MirrorProtect::new(net("2001:db8::4/128"));
        no_vrf.dataplane = MirrorDataplane::Mpls;
        map.insert(no_vrf.protected_locator, no_vrf);

        // SRv6 entry with via-vrf → skipped (MPLS ILM only).
        let mut srv6 = MirrorProtect::new(net("2001:db8::5/128"));
        srv6.via_vrf = Some("cust".to_string());
        map.insert(srv6.protected_locator, srv6);

        let mut labels = BTreeMap::new();
        labels.insert(net("2001:db8::3/128"), 16001u32);
        labels.insert(net("2001:db8::4/128"), 16002u32);
        let mut vrfs: BTreeMap<String, (u32, u32)> = BTreeMap::new();
        vrfs.insert("cust".to_string(), (10, 42));

        assert_eq!(
            desired_context_labels(&map, &labels, &vrfs),
            vec![(16001, 10, 42)],
            "only the MPLS entry with label + known via-vrf installs"
        );

        // VRF not yet known (VrfAdd will re-add) → nothing installs.
        assert!(desired_context_labels(&map, &labels, &BTreeMap::new()).is_empty());

        // No label allocated (SR-MPLS not up) → nothing installs.
        assert!(desired_context_labels(&map, &BTreeMap::new(), &vrfs).is_empty());
    }

    #[test]
    fn mirror_sids_from_tlvs_extracts_protector_and_protected_locator() {
        use isis_packet::{
            Algo, Behavior, IsisSub2ProtectedLocators, IsisSubSrv6MirrorSid, IsisTlvSrv6,
            Srv6Locator,
        };

        let protector = IsisSysId {
            id: [0, 0, 0, 0, 0, 4],
        };
        let mirror = IsisSubSrv6MirrorSid {
            flags: 0,
            behavior: Behavior::EndM,
            sid: "2001:db8:a4:1::3".parse().unwrap(),
            sub2s: vec![IsisMirrorSub2Tlv::ProtectedLocators(
                IsisSub2ProtectedLocators {
                    locator: "2001:db8:a3:1::/64".parse().unwrap(),
                },
            )],
        };
        let tlvs = vec![IsisTlv::Srv6(IsisTlvSrv6 {
            flags: 0u16.into(),
            locators: vec![Srv6Locator {
                metric: 0,
                flags: 0,
                algo: Algo::Spf,
                locator: "2001:db8:a4:1::/64".parse().unwrap(),
                subs: vec![prefix::IsisSubTlv::Srv6MirrorSid(mirror)],
            }],
        })];

        let got = mirror_sids_from_tlvs(protector, &tlvs);
        assert_eq!(
            got,
            vec![ReceivedMirrorSid {
                protector,
                mirror_sid: "2001:db8:a4:1::3".parse().unwrap(),
                protected_locator: "2001:db8:a3:1::/64".parse().unwrap(),
            }]
        );
    }

    #[test]
    fn mpls_bindings_from_tlvs_extracts_label_and_fec() {
        use isis_packet::{
            BindingFlags, BindingPrefix, IsisBindingSubTlv, IsisTlvSidLabelBinding, SidLabelValue,
        };

        let protector = IsisSysId {
            id: [0, 0, 0, 0, 0, 4],
        };
        // Mirror Context binding (M-flag) → extracted.
        let binding = IsisTlv::SidLabelBinding(IsisTlvSidLabelBinding {
            flags: BindingFlags::new().with_m_flag(true).with_f_flag(true),
            weight: 0,
            range: 1,
            prefix: BindingPrefix::V6("2001:db8::3/128".parse().unwrap()),
            subs: vec![IsisBindingSubTlv::SidLabel(SidLabelValue::Label(16003))],
        });
        // A plain (non-Mirror) Binding TLV without the M-flag → ignored.
        let mapping = IsisTlv::SidLabelBinding(IsisTlvSidLabelBinding {
            flags: BindingFlags::new().with_f_flag(true),
            weight: 0,
            range: 1,
            prefix: BindingPrefix::V6("2001:db8::5/128".parse().unwrap()),
            subs: vec![IsisBindingSubTlv::SidLabel(SidLabelValue::Label(99))],
        });

        let got = mpls_bindings_from_tlvs(protector, &[binding, mapping]);
        assert_eq!(
            got,
            vec![ReceivedMplsBinding {
                protector,
                context_label: 16003,
                protected_fec: "2001:db8::3/128".parse().unwrap(),
            }]
        );
    }
}
