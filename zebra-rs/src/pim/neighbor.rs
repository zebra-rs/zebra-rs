//! PIM neighbor state driven by Hello RX (RFC 7761 §4.3): creation,
//! option tracking (holdtime, DR priority, Generation ID, LAN Prune
//! Delay), holdtime expiry and Generation-ID bounce detection.

use std::net::Ipv4Addr;
use std::time::Instant;

use pim_packet::PimHello;

use crate::context::Timer;

use super::inst::{Message, Pim};

/// RFC 7761: a holdtime of 0xffff means "never time out".
const HOLDTIME_INFINITE: u16 = 0xffff;

/// Default holdtime when the Hello carries no Holdtime option:
/// 3.5 × the default 30 s hello period.
const HOLDTIME_DEFAULT: u16 = 105;

pub struct Neighbor {
    pub addr: Ipv4Addr,
    pub holdtime: u16,
    pub dr_priority: Option<u32>,
    pub gen_id: Option<u32>,
    /// (T bit, propagation delay ms, override interval ms).
    pub lan_prune_delay: Option<(bool, u16, u16)>,
    pub uptime: Instant,
    pub expiry: Option<Timer>,
}

fn expiry_timer(
    tx: &tokio::sync::mpsc::UnboundedSender<Message>,
    ifindex: u32,
    addr: Ipv4Addr,
    holdtime: u16,
) -> Option<Timer> {
    if holdtime == HOLDTIME_INFINITE {
        return None;
    }
    let tx = tx.clone();
    Some(Timer::once(holdtime as u64, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::NeighborExpiry(ifindex, addr));
        }
    }))
}

impl Pim {
    pub(crate) fn hello_recv(&mut self, ifindex: u32, src: Ipv4Addr, hello: &PimHello) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled || link.is_my_addr(&src) {
            return;
        }
        if self.link_config(&link.name).passive() {
            return;
        }

        let holdtime = hello.holdtime().unwrap_or(HOLDTIME_DEFAULT);
        if holdtime == 0 {
            // Goodbye hello: the neighbor is shutting down this
            // interface.
            self.neighbor_delete(ifindex, src, "goodbye");
            return;
        }

        let gen_id = hello.generation_id();
        let timer = expiry_timer(&self.tx, ifindex, src, holdtime);
        let link = self.links.get_mut(&ifindex).unwrap();
        let mut is_new = false;
        let mut bounced = false;
        link.nbrs
            .entry(src)
            .and_modify(|nbr| {
                if nbr.gen_id != gen_id {
                    // Generation-ID change without an expiry: the
                    // neighbor restarted. Treat as a bounce so its
                    // uptime and (in later phases) tree state reset.
                    bounced = true;
                    nbr.uptime = Instant::now();
                }
                nbr.holdtime = holdtime;
                nbr.dr_priority = hello.dr_priority();
                nbr.gen_id = gen_id;
                nbr.lan_prune_delay = hello.lan_prune_delay();
            })
            .or_insert_with(|| {
                is_new = true;
                Neighbor {
                    addr: src,
                    holdtime,
                    dr_priority: hello.dr_priority(),
                    gen_id,
                    lan_prune_delay: hello.lan_prune_delay(),
                    uptime: Instant::now(),
                    expiry: None,
                }
            });
        link.nbrs.get_mut(&src).unwrap().expiry = timer;

        if is_new {
            tracing::info!("pim: neighbor {} up on {}", src, link.name);
            // Triggered hello so a newly-heard neighbor learns us
            // without waiting out our hello period (RFC 7761 §4.3.1).
            self.hello_send(ifindex);
            // Entries parked for lack of this upstream neighbor can
            // join now.
            self.tib_neighbor_up(ifindex, src);
        } else if bounced {
            tracing::info!(
                "pim: neighbor {} on {} restarted (GenID change)",
                src,
                link.name
            );
        }
        self.dr_election(ifindex);
    }

    pub(crate) fn neighbor_expiry(&mut self, ifindex: u32, addr: Ipv4Addr) {
        self.neighbor_delete(ifindex, addr, "holdtime expired");
    }

    fn neighbor_delete(&mut self, ifindex: u32, addr: Ipv4Addr, reason: &str) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        if link.nbrs.remove(&addr).is_some() {
            tracing::info!("pim: neighbor {} down on {} ({})", addr, link.name, reason);
            self.dr_election(ifindex);
            self.tib_neighbor_down(ifindex, addr);
        }
    }
}
