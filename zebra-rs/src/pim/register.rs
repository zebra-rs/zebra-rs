//! PIM Register machinery (RFC 7761 §4.4): the DR-side register FSM
//! (encapsulate source traffic toward the RP until a Register-Stop,
//! then suppression with Null-Register probes) and the RP side
//! (Register RX creates (S,G) state, triggers the SPT join, answers
//! with Register-Stop once the source tree is being joined or nobody
//! is listening).
//!
//! Dataplane note: kernel decapsulation at the RP (register VIF as
//! MFC IIF) is not used — the brief pre-SPT data window is dropped,
//! matching the "switch to SPT immediately" policy. Native traffic
//! takes over as soon as the (S,G) join propagates.

use std::time::{Duration, Instant};

use pim_packet::{
    EncodedGroup, EncodedUnicast, PimPacket, PimPayload, PimRegister, PimRegisterStop,
};

use super::af::PimAf;
use super::inst::{Pim, PimSend};
use super::mroute::{PimForwardingPlane, Upcall};
use super::tib::{JoinState, KEEPALIVE_PERIOD, RegState, SgKey};

/// Register suppression: how long a Register-Stop silences the DR.
const REGISTER_SUPPRESS: Duration = Duration::from_secs(55);

/// Probe window: the Null-Register goes out this long before
/// suppression would lapse.
const REGISTER_PROBE: Duration = Duration::from_secs(5);

impl<A: PimAf> Pim<A> {
    /// First-hop-router check on NOCACHE: start registering when we
    /// are the DR on the directly-connected source's interface, the
    /// group is ASM with a known RP, and we are not the RP ourselves.
    pub(crate) fn register_check_fhr(&mut self, key: SgKey<A>, vif: u16) {
        let SgKey::Sg { src, grp } = key else {
            return;
        };
        if A::is_ssm(grp) || self.i_am_rp(grp) || self.rp_lookup(grp).is_none() {
            return;
        }
        let Some(ifindex) = self.fp.ifindex_of(vif) else {
            return;
        };
        let directly_connected = self
            .links
            .get(&ifindex)
            .map(|l| l.enabled && l.addrs.iter().any(|p| A::prefix_contains(p, &src)))
            .unwrap_or(false);
        if !directly_connected || !self.i_am_dr(ifindex) {
            return;
        }
        let entry = self.tib.get_mut(&key).unwrap();
        if entry.reg_state == RegState::NoInfo {
            entry.reg_state = RegState::Join;
            tracing::info!("pim: {} registering toward the RP (FHR)", key);
        }
    }

    /// WHOLEPKT upcall: the kernel punted a full packet through the
    /// register VIF — encapsulate and unicast it to RP(G).
    pub(crate) fn register_wholepkt(&mut self, upcall: Upcall<A>) {
        let key = SgKey::Sg {
            src: upcall.src,
            grp: upcall.grp,
        };
        let Some(entry) = self.tib.get_mut(&key) else {
            return;
        };
        if entry.reg_state != RegState::Join {
            return;
        }
        // Traffic is flowing: refresh the keepalive alongside.
        entry.stream_expires = Some(Instant::now() + KEEPALIVE_PERIOD);
        let Some(rp) = self.rp_lookup(upcall.grp) else {
            return;
        };
        self.register_send(rp, upcall.payload, false);
    }

    fn register_send(&self, rp: A::Addr, data: Vec<u8>, null: bool) {
        let packet = PimPacket::new(PimPayload::Register(PimRegister {
            border: false,
            null_register: null,
            data,
        }));
        // ifindex 0: egress selection by the kernel FIB toward the RP.
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex: 0,
            dst: rp,
            src: None,
        });
    }

    // ---- RP side ----

    /// Register RX at the RP: (re)create the (S,G), keep it alive,
    /// let `tib_update` fire the SPT join (KAT + inherited olist),
    /// and answer Register-Stop once the source tree is joined — or
    /// immediately when nobody is listening.
    pub(crate) fn register_recv(&mut self, outer_src: A::Addr, register: &PimRegister) {
        // The inner packet (or Null-Register dummy header) names (S,G).
        let Some((src, grp)) = A::register_inner_sg(&register.data) else {
            tracing::debug!("pim: malformed register from {}", outer_src);
            return;
        };
        if !A::is_multicast(grp) || A::is_ssm(grp) {
            return;
        }
        if !self.i_am_rp(grp) {
            tracing::debug!(
                "pim: register for {} from {} but we are not its RP",
                grp,
                outer_src
            );
            return;
        }
        let key = SgKey::Sg { src, grp };
        let entry = self.tib_get_or_create(key);
        entry.stream_expires = Some(Instant::now() + KEEPALIVE_PERIOD);
        self.tib_update(key);

        let Some(entry) = self.tib.get(&key) else {
            return;
        };
        let receivers = !super::macros::inherited_olist(&self.tib, key).is_empty();
        let spt_underway = entry.join_state == JoinState::Joined;
        if !receivers || spt_underway {
            self.register_stop_send(outer_src, src, grp);
        }
    }

    fn register_stop_send(&self, dr: A::Addr, src: A::Addr, grp: A::Addr) {
        let packet = PimPacket::new(PimPayload::RegisterStop(PimRegisterStop {
            group: EncodedGroup::new(A::to_ip(grp)),
            source: EncodedUnicast::new(A::to_ip(src)),
        }));
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex: 0,
            dst: dr,
            src: None,
        });
    }

    /// Register-Stop RX at the DR: suppress.
    pub(crate) fn register_stop_recv(&mut self, stop: &PimRegisterStop) {
        let (Some(grp), Some(src)) = (A::from_ip(stop.group.addr), A::from_ip(stop.source.addr))
        else {
            return;
        };
        let key = SgKey::Sg { src, grp };
        let Some(entry) = self.tib.get_mut(&key) else {
            return;
        };
        match entry.reg_state {
            RegState::Join | RegState::JoinPending { .. } => {
                entry.reg_state = RegState::Prune {
                    until: Instant::now() + REGISTER_SUPPRESS,
                };
                tracing::info!("pim: {} register suppressed (Register-Stop)", key);
                self.tib_update(key);
            }
            RegState::Prune { .. } => {
                entry.reg_state = RegState::Prune {
                    until: Instant::now() + REGISTER_SUPPRESS,
                };
            }
            RegState::NoInfo => {}
        }
    }

    /// Register FSM deadlines: suppression lapse → Null-Register
    /// probe; probe unanswered → resume registering.
    pub(crate) fn register_tick(&mut self, now: Instant) {
        let due: Vec<(SgKey<A>, RegState)> = self
            .tib
            .iter()
            .filter_map(|(key, e)| match e.reg_state {
                RegState::Prune { until } if until <= now => Some((*key, e.reg_state)),
                RegState::JoinPending { until } if until <= now => Some((*key, e.reg_state)),
                _ => None,
            })
            .collect();
        for (key, state) in due {
            let SgKey::Sg { src, grp } = key else {
                continue;
            };
            match state {
                RegState::Prune { .. } => {
                    // Probe: Null-Register; a live RP answers with
                    // another Stop before the window closes.
                    if let Some(rp) = self.rp_lookup(grp) {
                        self.register_send(rp, A::null_register_payload(src, grp), true);
                    }
                    if let Some(entry) = self.tib.get_mut(&key) {
                        entry.reg_state = RegState::JoinPending {
                            until: now + REGISTER_PROBE,
                        };
                    }
                }
                RegState::JoinPending { .. } => {
                    if let Some(entry) = self.tib.get_mut(&key) {
                        entry.reg_state = RegState::Join;
                        tracing::info!("pim: {} register probe unanswered — registering", key);
                    }
                    self.tib_update(key);
                }
                _ => {}
            }
        }
    }
}
