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

use ipnet::Ipv6Net;

use crate::config::{Args, ConfigOp};

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
    /// SRv6 locator of the protected egress PE (PEA). The map key.
    pub protected_locator: Ipv6Net,
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
    pub fn new(protected_locator: Ipv6Net) -> Self {
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
pub type MirrorProtectMap = BTreeMap<Ipv6Net, MirrorProtect>;

// ── Pure state operations (testable without an `Isis` instance) ───────

/// Get the entry for `key`, creating an empty one if absent.
fn ensure(map: &mut MirrorProtectMap, key: Ipv6Net) -> &mut MirrorProtect {
    map.entry(key).or_insert_with(|| MirrorProtect::new(key))
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
    let key = args.v6net()?;
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
    let key = args.v6net()?;
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
    let key = args.v6net()?;
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
    let key = args.v6net()?;
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

    fn net(s: &str) -> Ipv6Net {
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
}
