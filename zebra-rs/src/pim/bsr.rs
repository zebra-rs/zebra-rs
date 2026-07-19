//! Bootstrap Router machinery (RFC 5059): candidate-BSR election,
//! hop-by-hop RPF-checked BSM flooding, Candidate-RP advertisement,
//! and the BSR-learned RP-set that `rp_lookup` falls back to when no
//! static mapping covers a group.
//!
//! Simplifications, documented: RP selection inside the learned set
//! is longest-prefix → lowest priority → highest address (the RFC
//! 2362 hash for same-priority load-splitting is not implemented),
//! and BSM fragments are treated as whole-set replacements per group
//! range.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pim_packet::{
    BsmGroup, BsmRp, EncodedGroup, EncodedUnicast, PimBootstrap, PimCandRpAdv, PimPacket,
    PimPayload,
};

use super::af::PimAf;
use super::inst::{Pim, PimSend};
use super::ipv4::Ipv4;
use crate::pim_trace;

/// BSM origination period at the elected BSR (RFC 5059 §5).
const BS_PERIOD: Duration = Duration::from_secs(60);

/// Bootstrap timeout at non-elected routers: 2 × period + 10.
const BS_TIMEOUT: Duration = Duration::from_secs(130);

/// C-RP advertisement period and advertised holdtime (2.5 × period).
const CRP_ADV_PERIOD: Duration = Duration::from_secs(60);
const CRP_HOLDTIME: u16 = 150;

const HASH_MASK_LEN: u8 = 10;

#[derive(Debug, Clone)]
pub struct BsrConfig<A: PimAf = Ipv4> {
    /// Candidate-BSR: (advertised address, priority).
    pub cbsr_addr: Option<A::Addr>,
    pub cbsr_priority: Option<u8>,
    pub cbsr_enabled: bool,
    /// Candidate-RP: advertised address + served range + priority.
    pub crp_addr: Option<A::Addr>,
    pub crp_group: Option<A::Prefix>,
    pub crp_priority: Option<u8>,
    pub crp_enabled: bool,
}

impl<A: PimAf> Default for BsrConfig<A> {
    fn default() -> Self {
        Self {
            cbsr_addr: None,
            cbsr_priority: None,
            cbsr_enabled: false,
            crp_addr: None,
            crp_group: None,
            crp_priority: None,
            crp_enabled: false,
        }
    }
}

impl<A: PimAf> BsrConfig<A> {
    fn cbsr(&self) -> Option<(A::Addr, u8)> {
        if !self.cbsr_enabled {
            return None;
        }
        Some((self.cbsr_addr?, self.cbsr_priority.unwrap_or(64)))
    }

    fn crp(&self) -> Option<(A::Addr, A::Prefix, u8)> {
        if !self.crp_enabled {
            return None;
        }
        Some((
            self.crp_addr?,
            self.crp_group.unwrap_or(A::DEFAULT_RP_RANGE),
            self.crp_priority.unwrap_or(192),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsrRole {
    /// Not a candidate; tracking whatever BSR the domain elects.
    None,
    /// Candidate waiting out the bootstrap timeout before claiming
    /// the role.
    Pending { until: Instant },
    /// Candidate that lost to a preferred BSR.
    Candidate,
    /// The elected BSR: originates BSMs, collects C-RP advs.
    Elected,
}

#[derive(Debug, Clone, Copy)]
pub struct BsrRpEntry {
    pub priority: u8,
    pub holdtime: u16,
    pub expires: Instant,
}

#[derive(Debug)]
pub struct BsrRun<A: PimAf = Ipv4> {
    pub role: Option<BsrRole>,
    /// The domain's current BSR: (priority, address).
    pub elected: Option<(u8, A::Addr)>,
    /// Non-elected: discard the BSR + learned set when this passes.
    pub bsm_expires: Option<Instant>,
    /// Elected only: next scheduled BSM.
    pub originate_next: Option<Instant>,
    /// Candidate-RP: next advertisement.
    pub crp_next: Option<Instant>,
    pub fragment_tag: u16,
    /// Learned candidate RPs: (group range, RP address) → entry.
    /// Fed by C-RP advs at the BSR and by BSMs everywhere else.
    pub rp_set: BTreeMap<(A::Prefix, A::Addr), BsrRpEntry>,
    /// RPF-tracked BSR address (released on BSR change/loss).
    pub rpf_target: Option<A::Addr>,
}

impl<A: PimAf> Default for BsrRun<A> {
    fn default() -> Self {
        Self {
            role: None,
            elected: None,
            bsm_expires: None,
            originate_next: None,
            crp_next: None,
            fragment_tag: 0,
            rp_set: BTreeMap::new(),
            rpf_target: None,
        }
    }
}

impl<A: PimAf> BsrRun<A> {
    fn role(&self) -> BsrRole {
        self.role.unwrap_or(BsrRole::None)
    }
}

/// Higher (priority, address) wins the BSR election (RFC 5059 §3.1).
fn preferred<T: Ord>(a: (u8, T), b: (u8, T)) -> bool {
    a > b
}

impl<A: PimAf> Pim<A> {
    /// The BSR-learned RP for `grp`: longest matching range, then
    /// lowest priority, then highest address; expired entries are
    /// skipped (swept by the tick).
    pub(crate) fn bsr_rp_lookup(&self, grp: A::Addr) -> Option<A::Addr> {
        let now = Instant::now();
        self.bsr
            .rp_set
            .iter()
            .filter(|((range, _), e)| A::prefix_contains(range, &grp) && e.expires > now)
            .max_by_key(|((range, rp), e)| {
                (A::prefix_len(range), std::cmp::Reverse(e.priority), *rp)
            })
            .map(|((_, rp), _)| *rp)
    }

    /// Config changed: (re)enter or leave the candidate roles.
    pub(crate) fn bsr_config_changed(&mut self) {
        let now = Instant::now();
        match (self.bsr_config.cbsr(), self.bsr.role()) {
            (Some((_, priority)), BsrRole::None) => {
                // Stagger by priority so the strongest candidate
                // claims first when several start together.
                let delay = Duration::from_millis(3000 + (255 - priority) as u64 * 20);
                self.bsr.role = Some(BsrRole::Pending { until: now + delay });
                pim_trace!(self.tracing, Bsr, "pim: candidate-BSR pending election");
            }
            (None, role) if role != BsrRole::None => {
                if role == BsrRole::Elected {
                    self.bsr.elected = None;
                    self.bsr.originate_next = None;
                    self.bsr_rp_set_flush();
                }
                self.bsr.role = Some(BsrRole::None);
                pim_trace!(self.tracing, Bsr, "pim: candidate-BSR disabled");
            }
            _ => {}
        }
        if self.bsr_config.crp().is_some() {
            // Advertise promptly once a BSR is known.
            self.bsr.crp_next = Some(now);
        } else {
            self.bsr.crp_next = None;
        }
    }

    fn bsr_rp_set_flush(&mut self) {
        if !self.bsr.rp_set.is_empty() {
            self.bsr.rp_set.clear();
            self.rp_reevaluate();
        }
    }

    /// Track the RPF toward the adopted BSR so the flooding check
    /// has a reverse path to compare against.
    fn bsr_track(&mut self, bsr: A::Addr) {
        if self.bsr.rpf_target == Some(bsr) {
            return;
        }
        if let Some(old) = self.bsr.rpf_target.take() {
            self.rpf_release(old);
        }
        self.rpf_acquire(bsr);
        self.bsr.rpf_target = Some(bsr);
    }

    /// BSM RX (RFC 5059 §3.1): adopt preferred BSRs, absorb the
    /// RP-set, re-flood hop-by-hop on the other PIM interfaces.
    pub(crate) fn bootstrap_recv(&mut self, ifindex: u32, src: A::Addr, bsm: &PimBootstrap) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled || link.is_my_addr(&src) {
            return;
        }
        let Some(bsr) = A::from_ip(bsm.bsr_addr.addr) else {
            return;
        };
        // Our own BSM flooded back: ignore.
        if self.links.values().any(|l| l.is_my_addr(&bsr)) {
            return;
        }
        let candidate = (bsm.bsr_priority, bsr);

        // RPF check: once we track this BSR, the BSM must arrive on
        // the reverse-path interface (loop guard for the re-flood).
        if self.bsr.rpf_target == Some(bsr)
            && let Some(expected) = self.rpf_state_ifindex(bsr)
            && expected != ifindex
        {
            tracing::debug!(
                "pim: BSM for {} on {} fails RPF (expect ifindex {})",
                bsr,
                self.ifname(ifindex),
                expected
            );
            return;
        }

        match self.bsr.elected {
            Some(current) if preferred(current, candidate) => {
                // Inferior BSM. An elected BSR answers with its own.
                if self.bsr.role() == BsrRole::Elected {
                    self.bsr_originate();
                }
                return;
            }
            _ => {}
        }

        // Preferred (or refreshing) BSR: adopt.
        let new_bsr = self.bsr.elected != Some(candidate);
        if new_bsr {
            pim_trace!(
                self.tracing,
                Bsr,
                "pim: elected BSR is {} (priority {})",
                bsr,
                bsm.bsr_priority
            );
            if self.bsr.role() == BsrRole::Elected
                || matches!(self.bsr.role(), BsrRole::Pending { .. })
            {
                self.bsr.role = Some(BsrRole::Candidate);
                self.bsr.originate_next = None;
            }
        }
        self.bsr.elected = Some(candidate);
        self.bsr.bsm_expires = Some(Instant::now() + BS_TIMEOUT);
        self.bsr_track(bsr);

        // Absorb the RP-set: whole-range replacement per fragment.
        let now = Instant::now();
        let mut changed = false;
        for group in &bsm.groups {
            let Some(range_addr) = A::from_ip(group.group.addr) else {
                continue;
            };
            let Some(range) = A::prefix_new(range_addr, group.group.masklen) else {
                continue;
            };
            self.bsr.rp_set.retain(|(r, _), _| *r != range);
            for rp in &group.rps {
                let Some(rp_addr) = A::from_ip(rp.addr.addr) else {
                    continue;
                };
                if rp.holdtime == 0 {
                    continue;
                }
                self.bsr.rp_set.insert(
                    (range, rp_addr),
                    BsrRpEntry {
                        priority: rp.priority,
                        holdtime: rp.holdtime,
                        expires: now + Duration::from_secs(rp.holdtime as u64),
                    },
                );
            }
            changed = true;
        }
        if changed {
            self.rp_reevaluate();
        }

        // Hop-by-hop re-flood to every other PIM interface.
        let out: Vec<u32> = self
            .links
            .values()
            .filter(|l| l.enabled && l.ifindex != ifindex)
            .map(|l| l.ifindex)
            .collect();
        let packet = PimPacket::new(PimPayload::Bootstrap(bsm.clone()));
        for oif in out {
            let _ = self.send_tx.send(PimSend {
                packet: packet.clone(),
                ifindex: oif,
                dst: A::ALL_PIM_ROUTERS,
                src: None,
            });
        }

        // A candidate RP hearing a new BSR advertises right away.
        if new_bsr && self.bsr_config.crp().is_some() {
            self.bsr.crp_next = Some(Instant::now());
        }
    }

    fn rpf_state_ifindex(&self, addr: A::Addr) -> Option<u32> {
        self.rpf.get(&addr).and_then(|e| e.state.ifindex())
    }

    /// C-RP advertisement RX — meaningful at the elected BSR only.
    pub(crate) fn cand_rp_adv_recv(&mut self, src: A::Addr, adv: &PimCandRpAdv) {
        if self.bsr.role() != BsrRole::Elected {
            return;
        }
        let Some(rp) = A::from_ip(adv.rp_addr.addr) else {
            return;
        };
        let now = Instant::now();
        let mut changed = false;
        for group in &adv.groups {
            let Some(range_addr) = A::from_ip(group.addr) else {
                continue;
            };
            let Some(range) = A::prefix_new(range_addr, group.masklen) else {
                continue;
            };
            if adv.holdtime == 0 {
                changed |= self.bsr.rp_set.remove(&(range, rp)).is_some();
                continue;
            }
            self.bsr.rp_set.insert(
                (range, rp),
                BsrRpEntry {
                    priority: adv.priority,
                    holdtime: adv.holdtime,
                    expires: now + Duration::from_secs(adv.holdtime as u64),
                },
            );
            changed = true;
        }
        if changed {
            pim_trace!(
                self.tracing,
                Bsr,
                "pim: C-RP {} registered by {} at the BSR",
                rp,
                src
            );
            self.rp_reevaluate();
            // Push the updated RP-set out promptly instead of waiting
            // for the periodic BSM.
            self.bsr.originate_next = Some(Instant::now());
        }
    }

    /// Originate a BSM (elected BSR): the whole RP-set to every PIM
    /// interface.
    fn bsr_originate(&mut self) {
        let Some((addr, priority)) = self.bsr_config.cbsr() else {
            return;
        };
        self.bsr.fragment_tag = self.bsr.fragment_tag.wrapping_add(1);
        let now = Instant::now();
        let mut by_range: BTreeMap<A::Prefix, Vec<BsmRp>> = BTreeMap::new();
        for ((range, rp), entry) in self.bsr.rp_set.iter() {
            if entry.expires <= now {
                continue;
            }
            by_range.entry(*range).or_default().push(BsmRp {
                addr: EncodedUnicast::new(A::to_ip(*rp)),
                holdtime: entry.holdtime,
                priority: entry.priority,
            });
        }
        let groups: Vec<BsmGroup> = by_range
            .into_iter()
            .map(|(range, rps)| BsmGroup {
                group: EncodedGroup {
                    bidir: false,
                    zone: false,
                    masklen: A::prefix_len(&range),
                    addr: A::to_ip(A::prefix_addr(&range)),
                },
                rp_count: rps.len() as u8,
                rps,
            })
            .collect();
        let bsm = PimBootstrap {
            fragment_tag: self.bsr.fragment_tag,
            hash_mask_len: HASH_MASK_LEN,
            bsr_priority: priority,
            bsr_addr: EncodedUnicast::new(A::to_ip(addr)),
            groups,
        };
        let packet = PimPacket::new(PimPayload::Bootstrap(bsm));
        let out: Vec<u32> = self
            .links
            .values()
            .filter(|l| l.enabled)
            .map(|l| l.ifindex)
            .collect();
        for oif in out {
            let _ = self.send_tx.send(PimSend {
                packet: packet.clone(),
                ifindex: oif,
                dst: A::ALL_PIM_ROUTERS,
                src: None,
            });
        }
    }

    /// Send our C-RP advertisement to the elected BSR (or absorb it
    /// locally when we are the BSR ourselves).
    fn crp_advertise(&mut self) {
        let Some((rp, range, priority)) = self.bsr_config.crp() else {
            return;
        };
        let Some((_, bsr)) = self.bsr.elected else {
            return;
        };
        if self.bsr.role() == BsrRole::Elected {
            let now = Instant::now();
            self.bsr.rp_set.insert(
                (range, rp),
                BsrRpEntry {
                    priority,
                    holdtime: CRP_HOLDTIME,
                    expires: now + Duration::from_secs(CRP_HOLDTIME as u64),
                },
            );
            self.rp_reevaluate();
            return;
        }
        let adv = PimCandRpAdv {
            priority,
            holdtime: CRP_HOLDTIME,
            rp_addr: EncodedUnicast::new(A::to_ip(rp)),
            groups: vec![EncodedGroup {
                bidir: false,
                zone: false,
                masklen: A::prefix_len(&range),
                addr: A::to_ip(A::prefix_addr(&range)),
            }],
        };
        let packet = PimPacket::new(PimPayload::CandRpAdv(adv));
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex: 0,
            dst: bsr,
            src: None,
        });
    }

    pub(crate) fn bsr_next_wakeup(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        if let Some(BsrRole::Pending { until }) = self.bsr.role {
            consider(until);
        }
        if let Some(t) = self.bsr.bsm_expires {
            consider(t);
        }
        if let Some(t) = self.bsr.originate_next {
            consider(t);
        }
        if let Some(t) = self.bsr.crp_next {
            consider(t);
        }
        for entry in self.bsr.rp_set.values() {
            consider(entry.expires);
        }
        earliest
    }

    pub(crate) fn bsr_tick(&mut self, now: Instant) {
        // Candidate claims the role when nothing preferred spoke up.
        if let Some(BsrRole::Pending { until }) = self.bsr.role
            && until <= now
            && let Some((addr, priority)) = self.bsr_config.cbsr()
        {
            self.bsr.role = Some(BsrRole::Elected);
            self.bsr.elected = Some((priority, addr));
            self.bsr.bsm_expires = None;
            pim_trace!(
                self.tracing,
                Bsr,
                "pim: elected BSR (self, {} priority {})",
                addr,
                priority
            );
            // Absorb our own candidate-RP first so the very first BSM
            // already carries it.
            if self.bsr_config.crp().is_some() {
                self.crp_advertise();
                self.bsr.crp_next = Some(now + CRP_ADV_PERIOD);
            }
            self.bsr_originate();
            self.bsr.originate_next = Some(now + BS_PERIOD);
        }

        if let Some(t) = self.bsr.originate_next
            && t <= now
        {
            self.bsr_originate();
            self.bsr.originate_next = Some(now + BS_PERIOD);
        }

        // BSR timed out at a non-elected router.
        if let Some(t) = self.bsr.bsm_expires
            && t <= now
        {
            pim_trace!(self.tracing, Bsr, "pim: elected BSR timed out");
            self.bsr.bsm_expires = None;
            self.bsr.elected = None;
            if let Some(old) = self.bsr.rpf_target.take() {
                self.rpf_release(old);
            }
            self.bsr_rp_set_flush();
            if self.bsr_config.cbsr().is_some() {
                self.bsr.role = None;
                self.bsr_config_changed();
            }
        }

        if let Some(t) = self.bsr.crp_next
            && t <= now
        {
            self.crp_advertise();
            self.bsr.crp_next = Some(now + CRP_ADV_PERIOD);
        }

        // Sweep expired learned RPs.
        let before = self.bsr.rp_set.len();
        self.bsr.rp_set.retain(|_, e| e.expires > now);
        if self.bsr.rp_set.len() != before {
            self.rp_reevaluate();
        }
    }
}
