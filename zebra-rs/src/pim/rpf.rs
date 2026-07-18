//! RPF cache: per-source resolution backed by the RIB's next-hop
//! tracking (register-then-gate — state parks while unresolved).
//! Directly-connected sources resolve against the interface table
//! first; everything else follows the tracked RIB resolution.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::rib;
use crate::rib::nht::NexthopResolution;

use super::af::PimAf;
use super::inst::Pim;
use super::ipv4::Ipv4;
use super::tib::SgKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpfState<A: PimAf = Ipv4> {
    Unresolved,
    /// The source is on-link: no upstream neighbor, no Join to send.
    Connected {
        ifindex: u32,
    },
    /// Remote source: Joins go to `nexthop` out `ifindex` — if that
    /// address is a live PIM neighbor there.
    Gateway {
        ifindex: u32,
        nexthop: A::Addr,
    },
}

impl<A: PimAf> RpfState<A> {
    pub fn ifindex(&self) -> Option<u32> {
        match self {
            RpfState::Unresolved => None,
            RpfState::Connected { ifindex } | RpfState::Gateway { ifindex, .. } => Some(*ifindex),
        }
    }
}

pub struct RpfEntry<A: PimAf = Ipv4> {
    pub state: RpfState<A>,
    refs: usize,
    resolution: Option<NexthopResolution>,
}

impl<A: PimAf> Pim<A> {
    /// Take a reference on the RPF state for `src`, registering NHT
    /// interest on first use. The immediate `NexthopUpdate` echo from
    /// RIB refines the state asynchronously.
    pub(crate) fn rpf_acquire(&mut self, src: A::Addr) -> RpfState<A> {
        if let Some(entry) = self.rpf.get_mut(&src) {
            entry.refs += 1;
            return entry.state;
        }
        let state = compute_rpf(&self.links, src, None);
        let _ = self.ctx.rib.send(rib::Message::NexthopRegister {
            proto: self.proto_label.clone(),
            nh: A::to_ip(src),
            vrf_id: self.ctx.vrf_id(),
        });
        self.rpf.insert(
            src,
            RpfEntry {
                state,
                refs: 1,
                resolution: None,
            },
        );
        state
    }

    pub(crate) fn rpf_release(&mut self, src: A::Addr) {
        let Some(entry) = self.rpf.get_mut(&src) else {
            return;
        };
        entry.refs -= 1;
        if entry.refs == 0 {
            self.rpf.remove(&src);
            let _ = self.ctx.rib.send(rib::Message::NexthopUnregister {
                proto: self.proto_label.clone(),
                nh: A::to_ip(src),
                vrf_id: self.ctx.vrf_id(),
            });
        }
    }

    /// RIB pushed a new resolution for a tracked address.
    pub(crate) fn rpf_nexthop_update(&mut self, nh: IpAddr, resolution: NexthopResolution) {
        let Some(src) = A::from_ip(nh) else {
            return;
        };
        let Some(entry) = self.rpf.get_mut(&src) else {
            return;
        };
        entry.resolution = Some(resolution);
        let state = compute_rpf(&self.links, src, entry.resolution.as_ref());
        if entry.state != state {
            entry.state = state;
            self.rpf_changed(src, state);
        }
    }

    /// Interface/address topology changed: recompute every tracked
    /// source (connected-ness may have flipped even without a RIB
    /// resolution change).
    pub(crate) fn rpf_recompute_all(&mut self) {
        let sources: Vec<A::Addr> = self.rpf.keys().copied().collect();
        for src in sources {
            let Some(entry) = self.rpf.get_mut(&src) else {
                continue;
            };
            let state = compute_rpf(&self.links, src, entry.resolution.as_ref());
            if entry.state != state {
                entry.state = state;
                self.rpf_changed(src, state);
            }
        }
    }

    /// Assert-metric inputs for a tracked address: (preference,
    /// metric). Connected beats any gateway route; unresolved is
    /// infinitely bad.
    pub(crate) fn rpf_pref_metric(&self, addr: A::Addr) -> (u32, u32) {
        match self.rpf.get(&addr).map(|e| e.state) {
            Some(RpfState::Connected { .. }) => (0, 0),
            Some(RpfState::Gateway { .. }) => {
                let metric = self
                    .rpf
                    .get(&addr)
                    .and_then(|e| e.resolution.as_ref())
                    .map(|r| r.metric)
                    .unwrap_or(0);
                (100, metric)
            }
            _ => (u32::MAX, u32::MAX),
        }
    }

    /// Propagate an RPF change into every TIB entry tracking that
    /// address ((S,G) sources and (*,G) RPs alike): prune off the old
    /// upstream, adopt the new state, re-evaluate.
    fn rpf_changed(&mut self, addr: A::Addr, state: RpfState<A>) {
        let keys: Vec<SgKey<A>> = self
            .tib
            .iter()
            .filter(|(_, e)| e.rpf_target == Some(addr))
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            self.tib_rpf_change(key, state);
        }
    }
}

fn compute_rpf<A: PimAf>(
    links: &BTreeMap<u32, super::link::PimLink<A>>,
    src: A::Addr,
    resolution: Option<&NexthopResolution>,
) -> RpfState<A> {
    // On-link check first: a directly-connected source needs no
    // upstream neighbor regardless of what the RIB says.
    for link in links.values() {
        if link.link_up && link.addrs.iter().any(|p| A::prefix_contains(p, &src)) {
            return RpfState::Connected {
                ifindex: link.ifindex,
            };
        }
    }
    let Some(resolution) = resolution else {
        return RpfState::Unresolved;
    };
    if !resolution.reachable {
        return RpfState::Unresolved;
    }
    // ECMP: take the RIB's first resolved nexthop as-is (no PIM-side
    // hashing in this phase).
    let Some(nexthop) = resolution.nexthops.first() else {
        return RpfState::Unresolved;
    };
    let Some(gw) = A::from_ip(nexthop.addr) else {
        return RpfState::Unresolved;
    };
    if gw == src {
        return RpfState::Connected {
            ifindex: nexthop.ifindex,
        };
    }
    RpfState::Gateway {
        ifindex: nexthop.ifindex,
        nexthop: gw,
    }
}
