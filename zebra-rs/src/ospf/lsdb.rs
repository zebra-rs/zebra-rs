use std::time::Duration;
use std::{collections::BTreeMap, net::Ipv4Addr};

use ospf_packet::*;
use tokio::sync::mpsc::UnboundedSender;

use crate::spf::label_block::{LabelBlock, LabelConfig, LabelMap};

use super::ReachMap;
use super::inst::Message;
use super::task::{Timer, TimerType};
use super::version::{OspfVersion, Ospfv2};

pub type OspfLabelMap = LabelMap<Ipv4Addr>;

pub const OSPF_MAX_AGE: u16 = 3600;
pub const OSPF_MAX_AGE_DIFF: u16 = 900; // 15 minutes (RFC 2328 Section 13.1)
pub const OSPF_LS_REFRESH_TIME: u64 = 1800;
pub const OSPF_MAX_LSA_SEQ: u32 = 0x7FFFFFFF;
pub const OSPF_MIN_LS_ARRIVAL: u64 = 1; // 1 second (RFC 2328)

/// Flat LSDB storage: a single BTreeMap keyed by the full
/// `(LS-Type, LS-ID, Advertising-Router)` triple. Replaces the
/// earlier per-LS-type bucket layout (`LsTypes<LsTable>`).
///
/// The flat shape is friendlier to the v3 generification arc — v3's
/// LSA types (RFC 5340 §A.4.2.1, 0x2001 / 0x2002 / 0x2003 / …)
/// don't map cleanly onto v2's named buckets (Router / Network /
/// Summary / SummaryAsbr / AsExternal / OpaqueAreaLocal /
/// Unknown). Iterating per-type now goes through
/// [`Lsdb::iter_by_type`].
pub type LsTable<V = Ospfv2> = BTreeMap<OspfLsaKey, Lsa<V>>;

/// LSDB key: `(LS-Type, LS-ID, Advertising-Router)`.
///
/// Widened from `(OspfLsType, Ipv4Addr, Ipv4Addr)` to a flat
/// `(u16, u32, Ipv4Addr)` shape so v3 LS-Types (16-bit per
/// RFC 5340 §A.4.2.1) and v3 Link State IDs (32-bit opaque
/// values, not always IPs) fit alongside v2's smaller types.
/// v2 callers convert their `OspfLsType` enum to `u16` via the
/// existing `u8::from(ls_type)` impl, and their `Ipv4Addr`
/// `ls_id` to `u32` via `u32::from`; the reverse conversions
/// (`OspfLsType::from(x as u8)`, `Ipv4Addr::from(x)`) are used
/// where the original v2-typed value is wanted back.
pub type OspfLsaKey = (u16, u32, Ipv4Addr);

/// Construct an `OspfLsaKey` from v2-typed components — `OspfLsType`
/// widens to `u16` (via the existing `u8::from(ls_type)` impl) and
/// `Ipv4Addr` widens to `u32`. Convenience for the v2-bound code
/// paths that already speak the v2 types and just need a key for
/// LSDB / channel use.
pub fn v2_lsa_key(ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) -> OspfLsaKey {
    (u8::from(ls_type) as u16, u32::from(ls_id), adv_router)
}

/// Destructure an `OspfLsaKey` back into v2-typed components.
/// Inverse of [`v2_lsa_key`]; `OspfLsType::from(u8)` round-trips
/// from u16, and `Ipv4Addr::from(u32)` from u32. The reverse
/// conversion is safe for v2-shaped keys; on v3-shaped keys the
/// `OspfLsType::from(... as u8)` truncates the upper byte and
/// returns the `Unknown` variant for codepoints that don't fit v2.
pub fn v2_lsa_key_unpack(key: OspfLsaKey) -> (OspfLsType, Ipv4Addr, Ipv4Addr) {
    (OspfLsType::from(key.0 as u8), Ipv4Addr::from(key.1), key.2)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LsdbEvent {
    RefreshTimerExpire,
    HoldTimerExpire,
    SelfOriginatedReceived,
}

/// Per-area (or AS-scope) Link State Database.
///
/// Parameterized over `V: OspfVersion`. The storage layout
/// (`tables: LsTable<V>`) is generic; the methods that
/// manipulate LSAs live in `impl Lsdb<Ospfv2>` for now because they
/// destructure v2-specific header / body types
/// (`OspfLsType` enum match, `OspfLsp::OpaqueAreaRouterInfo` body
/// shape). Those move into a generic impl when the `OspfVersion`
/// trait grows accessor methods (`fn ls_type(&Lsa) -> u16`,
/// `fn ls_id(&Lsa) -> Ipv4Addr`, etc.) — PR 7b.
pub struct Lsdb<V: OspfVersion = Ospfv2> {
    pub tables: LsTable<V>,
    pub label_map: OspfLabelMap,
    pub reach_map: ReachMap,
}

/// One LSDB entry — the parsed LSA plus the bookkeeping the LSDB
/// needs (origination flag, install/refresh timestamps, age and
/// refresh timer handles).
///
/// `data: V::Lsa` is the concrete wire-LSA type for the version
/// (e.g. `OspfLsa` for v2, `Ospfv3Lsa` for v3).
pub struct Lsa<V: OspfVersion = Ospfv2> {
    pub data: V::Lsa,
    pub originated: bool,
    pub birth_time: tokio::time::Instant,
    pub install_time: tokio::time::Instant,
    pub hold_timer: Option<Timer>,
    pub refresh_timer: Option<Timer>,
}

impl<V: OspfVersion> Lsa<V> {
    pub fn new(data: V::Lsa) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            data,
            originated: false,
            birth_time: now,
            install_time: now,
            hold_timer: None,
            refresh_timer: None,
        }
    }

    /// Borrow the LSA header. Convenience over `V::lsa_header(&lsa.data)`.
    pub fn header(&self) -> &V::LsaHeader {
        V::lsa_header(&self.data)
    }

    /// Compute the current LSA age: original ls_age plus elapsed
    /// time since install, capped at MaxAge.
    pub fn current_age(&self) -> u16 {
        let initial_age = V::ls_age(self.header());
        let elapsed = self.birth_time.elapsed().as_secs() as u16;
        let age = initial_age.saturating_add(elapsed);
        age.min(OSPF_MAX_AGE)
    }

    /// True when the LSA's `ls_age` field has reached MaxAge —
    /// the canonical signal that an LSA is being flushed.
    #[allow(dead_code)]
    pub fn is_max_age(&self) -> bool {
        V::ls_age(self.header()) == OSPF_MAX_AGE
    }

    // The remaining wrappers below delegate to the matching
    // OspfVersion trait accessors. They give consumers a uniform
    // `lsa.foo()` method-call surface instead of `V::foo(&lsa.data)`,
    // which is easier on the eye for show / display code that
    // needs several fields at once.

    /// LS Type as a 16-bit value. See [`OspfVersion::ls_type`].
    #[allow(dead_code)]
    pub fn ls_type(&self) -> u16 {
        V::ls_type(self.header())
    }

    /// Link State ID as a 32-bit value. See [`OspfVersion::ls_id`].
    #[allow(dead_code)]
    pub fn ls_id(&self) -> u32 {
        V::ls_id(self.header())
    }

    /// Advertising Router. See [`OspfVersion::adv_router`].
    pub fn adv_router(&self) -> Ipv4Addr {
        V::adv_router(self.header())
    }

    /// LS Sequence Number. See [`OspfVersion::ls_seq_number`].
    pub fn ls_seq_number(&self) -> u32 {
        V::ls_seq_number(self.header())
    }

    /// LSA checksum. See [`OspfVersion::ls_checksum`].
    pub fn ls_checksum(&self) -> u16 {
        V::ls_checksum(self.header())
    }

    /// LSA total length in octets. See [`OspfVersion::length`].
    pub fn length(&self) -> u16 {
        V::length(self.header())
    }
}

fn lsdb_timer<V: OspfVersion>(
    tx: &UnboundedSender<Message<V>>,
    area_id: Option<Ipv4Addr>,
    key: OspfLsaKey,
    secs: u64,
    ev: LsdbEvent,
) -> Timer {
    let tx = tx.clone();
    Timer::new(Duration::from_secs(secs), TimerType::Once, move || {
        let tx = tx.clone();
        let msg = Message::<V>::Lsdb(ev, area_id, key);
        async move {
            let _ = tx.send(msg);
        }
    })
}

fn hold_timer<V: OspfVersion>(
    tx: &UnboundedSender<Message<V>>,
    area_id: Option<Ipv4Addr>,
    key: OspfLsaKey,
    ls_age: u16,
) -> Timer {
    let remaining = (OSPF_MAX_AGE - ls_age).max(1) as u64;
    lsdb_timer(tx, area_id, key, remaining, LsdbEvent::HoldTimerExpire)
}

fn refresh_timer<V: OspfVersion>(
    tx: &UnboundedSender<Message<V>>,
    area_id: Option<Ipv4Addr>,
    key: OspfLsaKey,
) -> Timer {
    lsdb_timer(
        tx,
        area_id,
        key,
        OSPF_LS_REFRESH_TIME,
        LsdbEvent::RefreshTimerExpire,
    )
}

impl<V: OspfVersion> Lsdb<V> {
    pub fn new() -> Self {
        Self {
            tables: LsTable::<V>::default(),
            label_map: OspfLabelMap::default(),
            reach_map: ReachMap::default(),
        }
    }

    /// Iterate the LSAs of a particular LS-Type. Yields the
    /// historic `(ls_id, adv_router)` 2-tuple key shape so existing
    /// callsites that destructure `((ls_id, adv_router), lsa)`
    /// keep working unchanged after the storage flattening.
    pub fn iter_by_type(
        &self,
        ls_type: OspfLsType,
    ) -> impl Iterator<Item = ((Ipv4Addr, Ipv4Addr), &Lsa<V>)> {
        let want: u16 = u8::from(ls_type) as u16;
        self.tables
            .iter()
            .filter(move |((t, _, _), _)| *t == want)
            .map(|((_, id, adv), lsa)| ((Ipv4Addr::from(*id), *adv), lsa))
    }

    /// Iterate just the LSA values of a particular LS-Type. Convenience
    /// over `iter_by_type` for callers that don't need the key.
    pub fn values_by_type(&self, ls_type: OspfLsType) -> impl Iterator<Item = &Lsa<V>> {
        let want: u16 = u8::from(ls_type) as u16;
        self.tables
            .iter()
            .filter(move |((t, _, _), _)| *t == want)
            .map(|(_, lsa)| lsa)
    }

    /// Drop the LSA at the given key. Key-only operation — no
    /// header field access, so trivially generic.
    pub fn remove_lsa(&mut self, ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) {
        self.tables.remove(&v2_lsa_key(ls_type, ls_id, adv_router));
    }

    /// Flush an LSA by setting its age to MaxAge and returning a
    /// clone for re-flooding. The refresh timer is cancelled, and
    /// a new hold timer is set. Now generic — header mutation goes
    /// through `V::lsa_header_mut` + `V::set_ls_age`.
    pub fn flush_lsa(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        tx: &UnboundedSender<Message<V>>,
        area_id: Option<Ipv4Addr>,
    ) -> Option<V::Lsa> {
        let lsa_key: OspfLsaKey = v2_lsa_key(ls_type, ls_id, adv_router);
        if let Some(lsa) = self.tables.get_mut(&lsa_key) {
            V::set_ls_age(V::lsa_header_mut(&mut lsa.data), OSPF_MAX_AGE);
            lsa.birth_time = tokio::time::Instant::now();
            lsa.refresh_timer = None;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, OSPF_MAX_AGE));
            Some(lsa.data.clone())
        } else {
            None
        }
    }

    /// Look up an LSA's payload by key. Returns a reference into
    /// the LSDB. Now generic — no header field access.
    pub fn lookup_by_id(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&V::Lsa> {
        self.tables
            .get(&v2_lsa_key(ls_type, ls_id, adv_router))
            .map(|lsa| &lsa.data)
    }

    /// Look up an LSA by the flat 3-tuple key directly. Same as
    /// `lookup_by_id` but without the v2-typed `OspfLsType` arg —
    /// v3 carries `ls_type` as a raw `u16` per RFC 5340 §A.4.2.1
    /// (U / S2 / S1 / function-code packing), so it builds the
    /// key itself rather than going through `v2_lsa_key`.
    pub fn lookup_by_raw_key(&self, key: OspfLsaKey) -> Option<&V::Lsa> {
        self.tables.get(&key).map(|lsa| &lsa.data)
    }

    /// Flush an LSA by the flat 3-tuple key directly. Same as
    /// `flush_lsa` but accepts the raw key — used by v3 callers
    /// where `ls_type` is a `u16` that doesn't compress to
    /// `OspfLsType` (e.g. `OSPFV3_NETWORK_LSA_TYPE = 0x2002`).
    pub fn flush_lsa_by_raw_key(
        &mut self,
        key: OspfLsaKey,
        tx: &UnboundedSender<Message<V>>,
        area_id: Option<Ipv4Addr>,
    ) -> Option<V::Lsa> {
        if let Some(lsa) = self.tables.get_mut(&key) {
            V::set_ls_age(V::lsa_header_mut(&mut lsa.data), OSPF_MAX_AGE);
            lsa.birth_time = tokio::time::Instant::now();
            lsa.refresh_timer = None;
            lsa.hold_timer = Some(hold_timer(tx, area_id, key, OSPF_MAX_AGE));
            Some(lsa.data.clone())
        } else {
            None
        }
    }

    /// Look up the full LSDB entry (including bookkeeping) by key.
    /// Now generic.
    pub fn lookup_lsa(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&Lsa<V>> {
        self.tables.get(&v2_lsa_key(ls_type, ls_id, adv_router))
    }

    /// Install a parsed LSA into the LSDB and start its hold
    /// timer. The key is derived from the LSA header via the
    /// `OspfVersion` trait accessors; no version-specific body
    /// destructuring happens here. v2 callers that need to do
    /// extra processing (e.g. ingesting Opaque LSA TLVs into the
    /// label / reach maps) wrap this with their own pre-step.
    pub fn install_lsa(
        &mut self,
        lsa_data: V::Lsa,
        tx: &UnboundedSender<Message<V>>,
        area_id: Option<Ipv4Addr>,
    ) {
        let lsa_key: OspfLsaKey = {
            let h = V::lsa_header(&lsa_data);
            (V::ls_type(h), V::ls_id(h), V::adv_router(h))
        };
        let ls_age = V::ls_age(V::lsa_header(&lsa_data));
        let mut lsa = Lsa::<V>::new(lsa_data);
        lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, ls_age));
        self.tables.insert(lsa_key, lsa);
    }

    /// Install a self-originated LSA: same as [`install_lsa`] but
    /// also marks `originated = true` and starts the refresh
    /// timer. Caller is responsible for filtering (which LS Types
    /// are originatable) and for recomputing checksum / length
    /// via `V::update_lsa` before calling, since the body bytes
    /// are committed to the LSDB verbatim.
    pub fn install_originated(
        &mut self,
        lsa_data: V::Lsa,
        tx: &UnboundedSender<Message<V>>,
        area_id: Option<Ipv4Addr>,
    ) {
        let lsa_key: OspfLsaKey = {
            let h = V::lsa_header(&lsa_data);
            (V::ls_type(h), V::ls_id(h), V::adv_router(h))
        };
        let ls_age = V::ls_age(V::lsa_header(&lsa_data));
        let mut lsa = Lsa::<V>::new(lsa_data);
        lsa.originated = true;
        lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, ls_age));
        lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
        self.tables.insert(lsa_key, lsa);
    }

    /// Return the install timestamp of an LSA, if present. Now
    /// generic.
    pub fn lookup_install_time(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<tokio::time::Instant> {
        self.lookup_lsa(ls_type, ls_id, adv_router)
            .map(|lsa| lsa.install_time)
    }

    /// Re-originate an existing LSA with a bumped sequence number.
    /// Drops it back at age 0, runs the version-specific
    /// `update_lsa` to refresh length / checksum, and resets the
    /// hold / refresh timers. Now generic.
    pub fn refresh_lsa(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        tx: &UnboundedSender<Message<V>>,
        area_id: Option<Ipv4Addr>,
    ) {
        let lsa_key: OspfLsaKey = v2_lsa_key(ls_type, ls_id, adv_router);
        if let Some(old_lsa) = self.tables.get(&lsa_key) {
            let mut new_data = old_lsa.data.clone();
            let h = V::lsa_header_mut(&mut new_data);
            V::set_ls_seq_number(h, V::ls_seq_number(h) + 1);
            V::set_ls_age(h, 0);
            V::update_lsa(&mut new_data);
            let mut lsa = Lsa::<V>::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            self.tables.insert(lsa_key, lsa);
        }
    }

    /// Re-originate an existing LSA but only after raising the
    /// sequence number above `min_seq`. Used when we see a peer
    /// advertising our LSA with a higher sequence than what we
    /// have on file (RFC 2328 §13.4 self-originated catch-up).
    /// Now generic.
    pub fn refresh_lsa_with_seq(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        min_seq: u32,
        tx: &UnboundedSender<Message<V>>,
        area_id: Option<Ipv4Addr>,
    ) {
        let lsa_key: OspfLsaKey = v2_lsa_key(ls_type, ls_id, adv_router);
        if let Some(old_lsa) = self.tables.get(&lsa_key) {
            let mut new_data = old_lsa.data.clone();
            let h = V::lsa_header_mut(&mut new_data);
            let next_seq = V::ls_seq_number(h).max(min_seq) + 1;
            V::set_ls_seq_number(h, next_seq);
            V::set_ls_age(h, 0);
            V::update_lsa(&mut new_data);
            let mut lsa = Lsa::<V>::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            self.tables.insert(lsa_key, lsa);
        }
    }
}

impl<V: OspfVersion> Default for Lsdb<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl Lsdb<Ospfv2> {
    pub fn insert_self_originated(
        &mut self,
        mut ospf_lsa: OspfLsa,
        tx: &UnboundedSender<Message<Ospfv2>>,
        area_id: Option<Ipv4Addr>,
    ) {
        use OspfLsType::*;
        match ospf_lsa.h.ls_type {
            Router | Network | Summary | SummaryAsbr | AsExternal | NssaAsExternal
            | OpaqueAreaLocal => {
                // v2-specific Fletcher checksum + length recompute,
                // then dispatch through the generic install path.
                ospf_lsa.update();
                self.install_originated(ospf_lsa, tx, area_id);
            }
            _ => {}
        }
    }

    pub fn insert_received(
        &mut self,
        ospf_lsa: OspfLsa,
        tx: &UnboundedSender<Message<Ospfv2>>,
        area_id: Option<Ipv4Addr>,
    ) {
        // v2-specific SR-MPLS / Opaque ExtPrefix ingestion (label
        // map + reach map). Stays v2-only because OspfLsp variants
        // are v2 codec types with no v3 analogue.
        self.update_lsa(&ospf_lsa);
        // Generic key construction + hold timer + insertion.
        self.install_lsa(ospf_lsa, tx, area_id);
    }

    pub fn update_lsa(&mut self, lsa: &OspfLsa) {
        if let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.lsp {
            if lsa.h.ls_age == OSPF_MAX_AGE {
                self.label_map.remove(&lsa.h.adv_router);
                return;
            }
            let mut global = None;
            let mut local = None;
            for tlv in &ri.tlvs {
                match tlv {
                    RouterInfoTlv::SidLabelRnage(r) => {
                        if let SidLabelTlv::Label(start) = r.sid_label {
                            global = Some(LabelBlock::new(start, r.range));
                        }
                    }
                    RouterInfoTlv::LocalBlock(lb) => {
                        if let SidLabelTlv::Label(start) = lb.sid_label {
                            local = Some(LabelBlock::new(start, lb.range));
                        }
                    }
                    _ => {}
                }
            }
            if let Some(global) = global {
                let label_config = LabelConfig { global, local };
                self.label_map.insert(lsa.h.adv_router, label_config);
            }
        }
        if let OspfLsp::OpaqueAreaExtPrefix(ref lsp) = lsa.lsp {
            for tlv in lsp.tlvs.iter() {
                self.reach_map.insert(tlv.prefix, tlv.subs.clone());
            }
        }
    }
}
