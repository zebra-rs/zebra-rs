use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net};
use isis_packet::SidLabelValue;
use netlink_packet_route::link::LinkFlags;
use ospf_packet::*;
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::Ospfv2;
use crate::ospf::addr::OspfAddr;
use crate::ospf::packet::{ospf_db_desc_recv, ospf_hello_recv, ospf_hello_send};
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::{self, Link, RibType};
use crate::spf::label_block::LabelConfig;
use crate::{
    config::{Args, ConfigChannel, ConfigRequest, path_from_command},
    context::Task,
};

use super::area::{OspfArea, OspfAreaMap};
use super::config::Callback;
use super::ifsm::{IfsmEvent, IfsmState, ospf_ifsm};
use super::link::{OspfLink, OspfNetworkType};
use super::lsdb::{LsdbEvent, OspfLsaKey, v2_lsa_key_unpack};
use super::network::{read_packet, write_packet};
use super::nfsm::{NfsmEvent, ospf_nfsm};
use super::socket::ospf_socket_ipv4;
use super::task::{Timer, TimerType};
use super::tracing::OspfTracing;
use super::version::{OspfVersion, Ospfv3};
use super::{
    AREA0, Identity, Lsdb, Neighbor, NfsmState, ospf_ls_ack_recv, ospf_ls_req_recv,
    ospf_ls_upd_recv,
};

pub type ShowCallback = fn(&Ospf, Args, bool) -> Result<String, std::fmt::Error>;

/// OSPF protocol instance.
///
/// Parameterized over `V: OspfVersion` (default `Ospfv2`) so the
/// embedded link/area/LSDB state can specialize per version while
/// keeping every existing v2 callsite resolving to `Ospf<Ospfv2>`
/// without textual churn. Methods on `Ospf` are still v2-bound and
/// live in `impl Ospf<Ospfv2>` below — they manipulate v2-specific
/// LSA bodies (`OspfLsp::OpaqueAreaRouterInfo`, etc.) and the v2
/// `Message` enum directly. They generalize when the
/// `OspfVersion` trait grows accessor methods, in a future round
/// of trait expansion.
pub struct Ospf<V: OspfVersion = Ospfv2> {
    pub tx: UnboundedSender<Message<V>>,
    pub rx: UnboundedReceiver<Message<V>>,
    pub ptx: UnboundedSender<Message<V>>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback<V>>,
    pub ctx: crate::context::ProtoContext,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink<V>>,
    pub areas: OspfAreaMap<V>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub router_id: Ipv4Addr,
    pub lsdb_as: Lsdb<V>,
    pub lsp_map: LspMap,
    pub spf_result: Option<BTreeMap<usize, Path>>,
    pub graph: Option<spf::Graph>,
    pub rib: PrefixMap<Ipv4Net, SpfRoute>,
    pub tracing: OspfTracing,
    pub segment_routing: super::srmpls::SegmentRoutingMode,
    pub spf_last: Option<Instant>,
    pub spf_duration: Option<Duration>,
    /// v3-only outbound packet channel. `Ospf<Ospfv3>::new` spawns
    /// `network_v6::write_packet_v6` consuming the matching receiver;
    /// producers of v3 outgoing packets (the v3 IFSM/NFSM, once they
    /// land) clone this sender to push packets. `None` on v2.
    #[allow(dead_code)]
    pub v3_send_tx: Option<UnboundedSender<super::network_v6::Ospfv3Send>>,
    /// v3-only inbound packet channel. `Ospf<Ospfv3>::new` spawns
    /// `network_v6::read_packet_v6` producing into the matching
    /// sender; the v3 serve loop (once it lands) will `take()` this
    /// receiver. `None` on v2.
    #[allow(dead_code)]
    pub v3_recv_rx: Option<UnboundedReceiver<super::network_v6::Ospfv3Recv>>,
}

// OSPF inteface structure which points out upper layer struct members.
//
// Parameterized over V: OspfVersion via the borrowed references
// into v3-shaped state (Identity<V>, Lsdb<V>, Vec<OspfAddr<V>>).
// Default V = Ospfv2 keeps function signatures unchanged at callsites.
pub struct OspfInterface<'a, V: OspfVersion = Ospfv2> {
    pub tx: &'a UnboundedSender<Message<V>>,
    pub router_id: &'a Ipv4Addr,
    pub ident: &'a Identity<V>,
    pub addr: &'a Vec<OspfAddr<V>>,
    pub mtu: u32,
    pub db_desc_in: &'a mut usize,
    pub lsdb: &'a mut Lsdb<V>,
    pub lsdb_as: &'a mut Lsdb<V>,
    pub area_id: Ipv4Addr,
    pub area_type: super::area::AreaType,
    pub exchange_loading_count: usize,
    pub mtu_ignore: bool,
    pub retransmit_interval: u16,
    pub tracing: &'a OspfTracing,
    /// v3-only outbound packet channel borrow. Carries the `Ospfv3Send`
    /// sender that the `network_v6::write_packet_v6` task consumes.
    /// `None` on v2 (where the v2 `Message::Send` path on `tx` is used
    /// instead). Populated by `Ospf<Ospfv3>::ospf_interface` from
    /// `self.v3_send_tx`.
    pub v3_send_tx: Option<&'a UnboundedSender<super::network_v6::Ospfv3Send>>,
    /// Per-link LSDB (RFC 5340 §A.4.9). Holds link-scope LSAs that
    /// flood only on the segment they originated on. Always
    /// borrowed from `OspfLink::lsdb`; on v2 it's empty (no
    /// link-scope LSA types in RFC 2328).
    pub link_lsdb: &'a mut Lsdb<V>,
}

// Version-agnostic helpers. These methods touch only generic-safe
// fields on `Ospf<V>` (links, areas, lsdb_as, router_id, tracing,
// the v2-shaped tx channel) and produce `OspfInterface<V>` /
// `&Neighbor<V>` values typed by `V`. They moved here from
// `impl Ospf<Ospfv2>` as part of the Phase 6 behavioral migration
// — same code, just no longer pinned to `Ospfv2`.
impl<V: OspfVersion> Ospf<V> {
    pub fn ospf_interface<'a>(
        &'a mut self,
        ifindex: u32,
        src: &Ipv4Addr,
    ) -> Option<(OspfInterface<'a, V>, &'a mut Neighbor<V>)> {
        // Compute area-wide exchange/loading count before borrowing mutably.
        let exchange_loading_count = self.count_exchange_loading_neighbors(ifindex);
        self.links.get_mut(&ifindex).and_then(|link| {
            let link_area = link.area;
            let retransmit_interval = link.retransmit_interval();
            self.areas.get_mut(link_area).and_then(|area| {
                let area_type = area.area_type;
                link.nbrs.get_mut(src).map(|nbr| {
                    (
                        OspfInterface {
                            tx: &self.tx,
                            router_id: &self.router_id,
                            ident: &link.ident,
                            addr: &link.addr,
                            mtu: link.mtu,
                            db_desc_in: &mut link.db_desc_in,
                            lsdb: &mut area.lsdb,
                            lsdb_as: &mut self.lsdb_as,
                            area_id: link_area,
                            area_type,
                            exchange_loading_count,
                            mtu_ignore: link.config.mtu_ignore,
                            retransmit_interval,
                            tracing: &self.tracing,
                            v3_send_tx: self.v3_send_tx.as_ref(),
                            link_lsdb: &mut link.lsdb,
                        },
                        nbr,
                    )
                })
            })
        })
    }

    /// Count Exchange/Loading neighbors across all links in the same area.
    fn count_exchange_loading_neighbors(&self, ifindex: u32) -> usize {
        let Some(link) = self.links.get(&ifindex) else {
            return 0;
        };
        let area_id = link.area;
        let Some(area) = self.areas.get(area_id) else {
            return 0;
        };
        let mut count = 0;
        for &link_ifindex in area.links.iter() {
            if let Some(area_link) = self.links.get(&link_ifindex) {
                for (_, nbr) in area_link.nbrs.iter() {
                    if nbr.state == NfsmState::Exchange || nbr.state == NfsmState::Loading {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.name.clone())
    }
}

impl Ospf<Ospfv2> {
    pub fn new(ctx: crate::context::ProtoContext, rib_rx: UnboundedReceiver<RibRx>) -> Self {
        let sock = Arc::new(AsyncFd::new(ospf_socket_ipv4(&ctx).unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, prx) = mpsc::unbounded_channel();
        let mut ospf = Self {
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx,
            ctx,
            links: BTreeMap::new(),
            areas: OspfAreaMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            router_id: Ipv4Addr::from_str("10.0.0.1").unwrap(),
            lsdb_as: Lsdb::new(),
            lsp_map: LspMap::default(),
            spf_result: None,
            graph: None,
            rib: PrefixMap::new(),
            tracing: OspfTracing::default(),
            segment_routing: super::srmpls::SegmentRoutingMode::default(),
            spf_last: None,
            spf_duration: None,
            sock,
            v3_send_tx: None,
            v3_recv_rx: None,
        };
        ospf.callback_build();
        ospf.show_build();

        let tx = ospf.tx.clone();
        let sock = ospf.sock.clone();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });
        let sock = ospf.sock.clone();
        tokio::spawn(async move {
            write_packet(sock, prx).await;
        });
        ospf
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    fn ospf_spf_timer(tx: &UnboundedSender<Message>, area_id: Ipv4Addr) -> Timer {
        let tx = tx.clone();
        Timer::new(Timer::second(1), TimerType::Once, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::SpfCalc(area_id));
            }
        })
    }

    fn ospf_spf_schedule(tx: &UnboundedSender<Message>, area: &mut OspfArea) {
        if area.spf_timer.is_none() {
            area.spf_timer = Some(Self::ospf_spf_timer(tx, area.id));
        }
    }

    fn router_lsa_stub_link(prefix: Ipv4Net, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_id: prefix.network(),
            link_data: prefix.netmask(),
            link_type: OspfLinkType::Stub,
            num_tos: 0,
            tos_0_metric: metric,
            toses: vec![],
        }
    }

    fn link_has_transit_adjacency(link: &OspfLink) -> bool {
        if link.state == IfsmState::Waiting || link.full_nbr_count == 0 {
            return false;
        }
        if Ospfv2::is_declared_dr(&link.ident) {
            return true;
        }
        if let Some(dr_nbr) = link.nbrs.get(&link.ident.d_router) {
            return dr_nbr.state == NfsmState::Full;
        }
        false
    }

    fn router_lsa_build(&self) -> RouterLsa {
        let mut router_lsa = RouterLsa::default();

        for link in self.links.values() {
            if !link.enabled {
                continue;
            }

            let metric = link.output_cost.min(u16::MAX as u32) as u16;
            let use_transit = matches!(
                link.network_type,
                OspfNetworkType::Broadcast | OspfNetworkType::NBMA
            ) && Self::link_has_transit_adjacency(link);

            for addr in &link.addr {
                // Skip loopback addresses (127.0.0.0/8).
                if addr.prefix.addr().octets()[0] == 127 {
                    continue;
                }
                let lsa_link = if use_transit {
                    RouterLsaLink {
                        // Transit link points to DR interface address.
                        link_id: link.ident.d_router,
                        link_data: addr.prefix.addr(),
                        link_type: OspfLinkType::Transit,
                        num_tos: 0,
                        tos_0_metric: metric,
                        toses: vec![],
                    }
                } else {
                    Self::router_lsa_stub_link(addr.prefix, metric)
                };
                router_lsa.links.push(lsa_link);
            }
        }

        router_lsa.num_links = router_lsa.links.len() as u16;
        router_lsa
    }

    fn router_lsa_originate_with_min_seq(&mut self, min_seq: Option<u32>) {
        let router_lsa = self.router_lsa_build();
        let flood_lsa = if let Some(area) = self.areas.get_mut(AREA0) {
            let current_seq = area
                .lsdb
                .lookup_by_id(OspfLsType::Router, self.router_id, self.router_id)
                .map(|lsa| lsa.h.ls_seq_number);

            let lsah = OspfLsaHeader::new(OspfLsType::Router, self.router_id, self.router_id);
            let mut lsa = OspfLsa::from(lsah, router_lsa.into());

            if let Some(seq) = current_seq {
                lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(seq.saturating_add(1));
            }
            if let Some(seq) = min_seq {
                lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(seq.saturating_add(1));
            }

            lsa.update();
            let flood_lsa = lsa.clone();
            area.lsdb.insert_self_originated(lsa, &self.tx, Some(AREA0));
            Self::ospf_spf_schedule(&self.tx, area);
            Some(flood_lsa)
        } else {
            None
        };

        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(AREA0, &lsa);
        }
    }

    pub fn router_lsa_originate(&mut self) {
        tracing::info!("Router LSA Originate");
        self.router_lsa_originate_with_min_seq(None);
    }

    pub fn router_info_lsa_originate(&mut self) {
        use super::srmpls::SegmentRoutingMode;

        let ls_id = Ipv4Addr::from((OpaqueLsaType::ROUTER_INFO as u32) << 24);

        if self.segment_routing == SegmentRoutingMode::Mpls {
            let mut lsa = super::srmpls::router_info_lsa_build(self.router_id);

            // Preserve sequence number if re-originating.
            if let Some(area) = self.areas.get(AREA0)
                && let Some(existing) =
                    area.lsdb
                        .lookup_by_id(OspfLsType::OpaqueAreaLocal, ls_id, self.router_id)
            {
                lsa.h.ls_seq_number = lsa
                    .h
                    .ls_seq_number
                    .max(existing.h.ls_seq_number.saturating_add(1));
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.insert_self_originated(lsa, &self.tx, Some(AREA0));
            }
            self.flood_self_originated_lsa(AREA0, &flood_lsa);
        } else {
            // Flush Router Info LSA when SR is disabled.
            let flushed = if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.flush_lsa(
                    OspfLsType::OpaqueAreaLocal,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(AREA0),
                )
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(AREA0, &lsa);
            }
        }
    }

    pub fn ext_prefix_lsa_originate(&mut self, ifindex: u32) {
        use super::srmpls::SegmentRoutingMode;

        let opaque_id = ifindex & 0x00FF_FFFF;
        let ls_id = Ipv4Addr::from(((OpaqueLsaType::EXT_PREFIX as u32) << 24) | opaque_id);

        let link = self.links.get(&ifindex);
        let should_originate = self.segment_routing == SegmentRoutingMode::Mpls
            && link.is_some_and(|l| l.enabled && l.config.prefix_sid.is_some());

        if should_originate {
            let link = link.unwrap();
            let prefix_sid = link.config.prefix_sid.unwrap();
            // Use the first non-loopback address as a /32 host prefix.
            let Some(addr) = link.addr.iter().find(|a| !a.prefix.addr().is_loopback()) else {
                return;
            };
            let prefix = ipnet::Ipv4Net::new(addr.prefix.addr(), 32).unwrap_or(addr.prefix);

            let mut lsa =
                super::srmpls::ext_prefix_lsa_build(self.router_id, prefix, &prefix_sid, opaque_id);

            // Preserve sequence number if re-originating.
            if let Some(area) = self.areas.get(AREA0)
                && let Some(existing) =
                    area.lsdb
                        .lookup_by_id(OspfLsType::OpaqueAreaLocal, ls_id, self.router_id)
            {
                lsa.h.ls_seq_number = lsa
                    .h
                    .ls_seq_number
                    .max(existing.h.ls_seq_number.saturating_add(1));
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.insert_self_originated(lsa, &self.tx, Some(AREA0));
            }
            self.flood_self_originated_lsa(AREA0, &flood_lsa);
        } else {
            // Flush Extended Prefix LSA when SR is disabled or prefix-sid removed.
            let flushed = if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.flush_lsa(
                    OspfLsType::OpaqueAreaLocal,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(AREA0),
                )
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(AREA0, &lsa);
            }
        }
    }

    fn process_lsdb(&mut self, ev: LsdbEvent, area_id: Option<Ipv4Addr>, key: OspfLsaKey) {
        // Unpack the widened key back into v2-typed components for the
        // v2-bound match arms / method calls below.
        let (ls_type, ls_id, adv_router) = v2_lsa_key_unpack(key);

        // Handle SelfOriginatedReceived before borrowing lsdb, since
        // re-origination needs full &mut self access.
        if ev == LsdbEvent::SelfOriginatedReceived {
            self.process_self_originated_lsa(area_id, ls_type, ls_id, adv_router);
            return;
        }

        // Handle RefreshTimerExpire: rebuild the LSA from current state when
        // a dedicated originator exists (Router / Network LSA). Otherwise
        // fall back to cloning the old body and bumping the sequence number.
        if ev == LsdbEvent::RefreshTimerExpire {
            tracing::info!(
                "LSDB refresh timer expired: type={} id={} adv={}",
                ls_type,
                ls_id,
                adv_router
            );

            // Self-originated only. Defensive — refresh timers should only
            // ever be armed for our own LSAs.
            if adv_router != self.router_id {
                return;
            }

            match ls_type {
                OspfLsType::Router => {
                    self.router_lsa_originate();
                    return;
                }
                OspfLsType::Network => {
                    // The Network LSA's LS-ID is the DR interface IP. Find
                    // the matching interface and rebuild from its current
                    // Full-adjacency set.
                    let ifindex = self.links.iter().find_map(|(idx, link)| {
                        link.addr
                            .iter()
                            .any(|a| a.prefix.addr() == ls_id)
                            .then_some(*idx)
                    });
                    if let Some(ifindex) = ifindex {
                        self.update_network_lsa_by_interface(ifindex);
                    }
                    return;
                }
                _ => {}
            }

            // Fallback: clone body, bump seq#, reinstall, then flood.
            let refreshed = {
                let lsdb = if let Some(area_id) = area_id {
                    let Some(area) = self.areas.get_mut(area_id) else {
                        return;
                    };
                    &mut area.lsdb
                } else {
                    &mut self.lsdb_as
                };
                lsdb.refresh_lsa(ls_type, ls_id, adv_router, &self.tx, area_id);
                lsdb.lookup_by_id(ls_type, ls_id, adv_router).cloned()
            };
            if let Some(lsa) = refreshed
                && let Some(area_id) = area_id
            {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        }

        {
            let lsdb = if let Some(area_id) = area_id {
                let Some(area) = self.areas.get_mut(area_id) else {
                    return;
                };
                &mut area.lsdb
            } else {
                &mut self.lsdb_as
            };
            match ev {
                LsdbEvent::HoldTimerExpire => {
                    tracing::info!(
                        "LSDB hold timer expired: type={} id={} adv={}",
                        ls_type,
                        ls_id,
                        adv_router
                    );
                    lsdb.remove_lsa(ls_type, ls_id, adv_router);
                }
                _ => unreachable!(),
            }
        }

        if ev == LsdbEvent::HoldTimerExpire {
            match ls_type {
                OspfLsType::Router | OspfLsType::Network | OspfLsType::Summary => {
                    if let Some(area_id) = area_id
                        && let Some(area) = self.areas.get_mut(area_id)
                    {
                        Self::ospf_spf_schedule(&self.tx, area);
                    }
                }
                OspfLsType::AsExternal => {
                    // AS-scoped; reschedule SPF on every area.
                    let _ = self.tx.send(Message::SpfSchedule(None));
                }
                _ => {}
            }
        }
    }

    /// Handle a self-originated LSA received from a neighbor (RFC 2328 Section 13.4).
    /// If we still own this LSA, re-originate with seq# = max(current, received) + 1.
    /// If we no longer own it, flush it from the LSDB.
    fn process_self_originated_lsa(
        &mut self,
        area_id: Option<Ipv4Addr>,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) {
        // Get the received seq# from the LSDB entry.
        let received_seq = {
            let lsdb = if let Some(area_id) = area_id {
                let Some(area) = self.areas.get(area_id) else {
                    return;
                };
                &area.lsdb
            } else {
                &self.lsdb_as
            };
            let Some(lsa) = lsdb.lookup_lsa(ls_type, ls_id, adv_router) else {
                return;
            };
            lsa.data.h.ls_seq_number
        };

        match ls_type {
            OspfLsType::Router => {
                tracing::info!(
                    "[Self-Originated] Re-originating Router LSA id={} seq={:#x}",
                    ls_id,
                    received_seq
                );
                self.router_lsa_reoriginate(received_seq);
            }
            OspfLsType::Network => {
                if self.is_dr_for_network_lsa(ls_id) {
                    tracing::info!(
                        "[Self-Originated] Re-originating Network LSA id={} seq={:#x}",
                        ls_id,
                        received_seq
                    );
                    // Re-originate by refreshing with min_seq from received LSA.
                    if let Some(area_id) = area_id {
                        let refreshed = {
                            let Some(area) = self.areas.get_mut(area_id) else {
                                return;
                            };
                            area.lsdb.refresh_lsa_with_seq(
                                ls_type,
                                ls_id,
                                adv_router,
                                received_seq,
                                &self.tx,
                                Some(area_id),
                            );
                            area.lsdb.lookup_by_id(ls_type, ls_id, adv_router).cloned()
                        };
                        if let Some(lsa) = refreshed {
                            self.flood_self_originated_lsa(area_id, &lsa);
                        }
                    }
                } else {
                    tracing::info!(
                        "[Self-Originated] Flushing Network LSA id={} (no longer DR)",
                        ls_id
                    );
                    if let Some(area_id) = area_id {
                        let flushed = {
                            let Some(area) = self.areas.get_mut(area_id) else {
                                return;
                            };
                            area.lsdb
                                .flush_lsa(ls_type, ls_id, adv_router, &self.tx, Some(area_id))
                        };
                        if let Some(lsa) = flushed {
                            self.flood_self_originated_lsa(area_id, &lsa);
                        }
                    }
                }
            }
            _ => {
                // Summary/AS-External origination not yet implemented; flush with MaxAge.
                tracing::info!(
                    "[Self-Originated] Flushing LSA type={:?} id={} (not re-originable)",
                    ls_type,
                    ls_id
                );
                let flushed = {
                    let lsdb = if let Some(area_id) = area_id {
                        let Some(area) = self.areas.get_mut(area_id) else {
                            return;
                        };
                        &mut area.lsdb
                    } else {
                        &mut self.lsdb_as
                    };
                    lsdb.flush_lsa(ls_type, ls_id, adv_router, &self.tx, area_id)
                };
                if let Some(lsa) = flushed
                    && let Some(area_id) = area_id
                {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
        }
    }

    /// Re-originate Router LSA with seq# >= min_seq + 1.
    fn router_lsa_reoriginate(&mut self, min_seq: u32) {
        tracing::info!("Router LSA Re-originate (min_seq={:#x})", min_seq);
        self.router_lsa_originate_with_min_seq(Some(min_seq));
    }

    fn update_network_lsa_by_interface(&mut self, ifindex: u32) {
        let (area_id, ls_id, netmask, attached_routers, full_nbr_count) = {
            let Some(link) = self.links.get_mut(&ifindex) else {
                return;
            };
            if !link.enabled {
                return;
            }

            let Some(primary_addr) = link.addr.first() else {
                return;
            };

            let mut attached_routers = Vec::with_capacity(link.nbrs.len() + 1);
            attached_routers.push(self.router_id);
            for nbr in link.nbrs.values() {
                if nbr.state == NfsmState::Full {
                    attached_routers.push(nbr.ident.router_id);
                }
            }
            attached_routers.sort_unstable();
            attached_routers.dedup();

            link.full_nbr_count = link
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();

            (
                link.area,
                primary_addr.prefix.addr(),
                primary_addr.prefix.netmask(),
                attached_routers,
                link.full_nbr_count,
            )
        };

        let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
            if full_nbr_count == 0 {
                area.lsdb.flush_lsa(
                    OspfLsType::Network,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(area_id),
                )
            } else {
                let current_seq = area
                    .lsdb
                    .lookup_by_id(OspfLsType::Network, ls_id, self.router_id)
                    .map(|lsa| lsa.h.ls_seq_number);

                let lsah = OspfLsaHeader::new(OspfLsType::Network, ls_id, self.router_id);
                let mut lsa = OspfLsa::from(
                    lsah,
                    OspfLsp::Network(NetworkLsa {
                        netmask,
                        attached_routers,
                    }),
                );
                if let Some(seq) = current_seq {
                    lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(seq.saturating_add(1));
                }

                lsa.update();
                let flood_lsa = lsa.clone();
                area.lsdb
                    .insert_self_originated(lsa, &self.tx, Some(area_id));
                Some(flood_lsa)
            }
        } else {
            None
        };

        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(area_id, &lsa);
            if let Some(area) = self.areas.get_mut(area_id) {
                Self::ospf_spf_schedule(&self.tx, area);
            }
        }
    }

    fn process_neighbor_state_change(
        &mut self,
        ifindex: u32,
        nbr_addr: Ipv4Addr,
        old_state: NfsmState,
        new_state: NfsmState,
    ) {
        if old_state == new_state {
            return;
        }

        let full_state_changed = (old_state == NfsmState::Full && new_state != NfsmState::Full)
            || (old_state != NfsmState::Full && new_state == NfsmState::Full);
        if !full_state_changed {
            return;
        }

        let if_state = {
            let Some(link) = self.links.get_mut(&ifindex) else {
                return;
            };
            link.full_nbr_count = link
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();
            link.state
        };

        tracing::info!(
            "[NFSM:FullTransition] ifindex={} nbr={} {} -> {}",
            ifindex,
            nbr_addr,
            old_state,
            new_state
        );

        // Router-LSA must be re-originated whenever Full adjacency count changes.
        self.router_lsa_originate();

        // DR updates/flushes its Network-LSA based on current full adjacency set.
        if if_state == IfsmState::DR {
            self.update_network_lsa_by_interface(ifindex);
        }
    }

    /// Check if we are currently the DR for the network identified by ls_id.
    fn is_dr_for_network_lsa(&self, ls_id: Ipv4Addr) -> bool {
        for (_, link) in self.links.iter() {
            if !link.enabled {
                continue;
            }
            for addr in link.addr.iter() {
                if addr.prefix.addr() == ls_id {
                    return Ospfv2::is_declared_dr(&link.ident);
                }
            }
        }
        false
    }

    /// Flood an LSA to all eligible neighbors in an area (RFC 2328 Section 13.3).
    ///
    /// When `source` is `Some((ifindex, addr))`, the neighbor identified by that
    /// (interface, address) pair is skipped (it sent us this LSA). When `source`
    /// is `None` (self-originated), no neighbor is skipped.
    fn flood_lsa_through_area(
        &mut self,
        area_id: Ipv4Addr,
        lsa: &OspfLsa,
        source: Option<(u32, Ipv4Addr)>,
    ) {
        let Some(area) = self.areas.get(area_id) else {
            return;
        };
        let link_indices: Vec<u32> = area.links.iter().copied().collect();
        for ifindex in link_indices {
            let Some(link) = self.links.get_mut(&ifindex) else {
                continue;
            };
            let retransmit_interval = link.retransmit_interval();
            let link_state = link.state;

            // RFC 2328 Section 13.3 Step 2-4: DR/BDR flooding decision.
            let is_source_iface = source.is_some_and(|(src_if, _)| src_if == ifindex);

            // RFC 2328 Section 13.3 Step 3: If interface state is Backup and
            // LSA was received on this interface, do not flood back out.
            if is_source_iface && link_state == IfsmState::Backup {
                continue;
            }

            // RFC 2328 Section 13.3 Step 4: For broadcast/NBMA interfaces in
            // state DROther, only flood if we received from DR or BDR.
            if is_source_iface
                && link_state == IfsmState::DROther
                && let Some((_, src_addr)) = source
            {
                let dr = link.ident.d_router;
                let bdr = link.ident.bd_router;
                if src_addr != dr && src_addr != bdr {
                    continue;
                }
            }

            for (_, nbr) in link.nbrs.iter_mut() {
                // RFC 2328 Section 13.3 Step 1(a): Skip neighbors below Exchange.
                if nbr.state < NfsmState::Exchange {
                    continue;
                }

                // RFC 2328 Section 13.3 Step 1(c): Skip the source neighbor.
                if let Some((src_ifindex, src_addr)) = source
                    && nbr.ifindex == src_ifindex
                    && nbr.ident.prefix.addr() == src_addr
                {
                    continue;
                }

                // RFC 2328 Section 13.3 Step 1(b): For neighbors in
                // Exchange or Loading state, remove from ls_req if present.
                if nbr.state >= NfsmState::Exchange
                    && nbr.state < NfsmState::Full
                    && let Some(idx) = super::ospf_ls_request_lookup(nbr, &lsa.h)
                {
                    nbr.ls_req.remove(idx);
                }

                // RFC 2328 Section 13.3 Step 1(d): Add LSA to retransmit list.
                super::flood::ospf_ls_retransmit_add(nbr, lsa, retransmit_interval);

                let ls_upd = OspfLsUpdate {
                    num_adv: 1,
                    lsas: vec![lsa.clone()],
                };
                let packet =
                    Ospfv2Packet::new(&self.router_id, &area_id, Ospfv2Payload::LsUpdate(ls_upd));
                tracing::info!(
                    "[Flood] Sending LSA type={:?} id={} adv={} to nbr={}",
                    lsa.h.ls_type,
                    lsa.h.ls_id,
                    lsa.h.adv_router,
                    nbr.ident.prefix.addr()
                );
                let _ = nbr.ptx.send(Message::Send(
                    packet,
                    nbr.ifindex,
                    Some(nbr.ident.prefix.addr()),
                ));
            }
        }
    }

    /// Flood a self-originated LSA to all eligible neighbors in an area.
    fn flood_self_originated_lsa(&mut self, area_id: Ipv4Addr, lsa: &OspfLsa) {
        self.flood_lsa_through_area(area_id, lsa, None);
    }

    /// Flood an AS-scoped LSA to all non-stub areas.
    fn flood_lsa_through_as(&mut self, lsa: &OspfLsa, source: Option<(u32, Ipv4Addr)>) {
        // Collect area IDs to avoid borrowing issues.
        let area_ids: Vec<(Ipv4Addr, super::area::AreaType)> = self
            .areas
            .iter()
            .map(|(&id, area)| (id, area.area_type))
            .collect();
        for (area_id, area_type) in area_ids {
            if area_type != super::area::AreaType::Normal {
                continue;
            }
            self.flood_lsa_through_area(area_id, lsa, source);
        }
    }

    /// Handle retransmit timer firing for a neighbor.
    fn process_retransmit(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let retransmit_interval = link.retransmit_interval();
        let area_id = link.area;
        let Some(nbr) = link.nbrs.get_mut(&addr) else {
            return;
        };
        if nbr.ls_rxmt.is_empty() {
            nbr.timer.ls_rxmt = None;
            return;
        }
        let lsas: Vec<OspfLsa> = nbr.ls_rxmt.values().cloned().collect();
        tracing::info!("[Retransmit] Sending {} LSAs to {}", lsas.len(), addr);
        let ls_upd = OspfLsUpdate {
            num_adv: lsas.len() as u32,
            lsas,
        };
        let packet = Ospfv2Packet::new(&self.router_id, &area_id, Ospfv2Payload::LsUpdate(ls_upd));
        let _ = nbr.ptx.send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ));
        // Restart retransmit timer.
        nbr.timer.ls_rxmt = Some(super::flood::ospf_retransmit_timer(
            nbr,
            retransmit_interval,
        ));
    }

    /// Handle Database Description master-retransmit timer firing
    /// (RFC 2328 §10.8). Resend the DD packet stored in `nbr.dd.sent` while
    /// the master is still in ExStart or Exchange. The timer is replaced
    /// (not cancelled) when the master sends the next DD; once the neighbor
    /// progresses past Exchange the regular timer-set logic clears it.
    fn process_dd_retransmit(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let Some((link, nbr)) = self.ospf_interface(ifindex, &addr) else {
            return;
        };
        if (nbr.state != NfsmState::ExStart && nbr.state != NfsmState::Exchange)
            || !nbr.dd.flags.master()
        {
            nbr.timer.db_desc = None;
            return;
        }
        let Some(ref sent) = nbr.dd.sent else {
            return;
        };
        let packet = Ospfv2Packet::new(
            link.router_id,
            &link.area_id,
            Ospfv2Payload::DbDesc(sent.clone()),
        );
        tracing::info!("[DB Desc:Retransmit] to {} seq={:#x}", addr, sent.seqnum);
        let _ = nbr.ptx.send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ));
    }

    /// Handle Link State Request retransmit timer firing for a neighbor
    /// (RFC 2328 §10.9). Resend the pending LS Request packet built from
    /// `nbr.ls_req`. Stop the timer once the list is empty or the neighbor
    /// has left Exchange/Loading.
    fn process_ls_req_retransmit(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let Some((mut link, nbr)) = self.ospf_interface(ifindex, &addr) else {
            return;
        };
        if nbr.state < NfsmState::Exchange || nbr.state >= NfsmState::Full || nbr.ls_req.is_empty()
        {
            nbr.timer.ls_req = None;
            return;
        }
        let ident = link.ident;
        super::ospf_ls_req_send(&mut link, nbr, ident);
    }

    /// Handle delayed ack timer firing for an interface.
    fn process_delayed_ack(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        // This is a one-shot timer; clear the handle so future queued acks can re-arm it.
        link.timer.ls_ack = None;
        if link.ls_ack_delayed.is_empty() {
            return;
        }
        let ack_headers: Vec<OspfLsaHeader> = link.ls_ack_delayed.drain(..).collect();
        tracing::info!(
            "[DelayedAck] Sending {} acks on ifindex={}",
            ack_headers.len(),
            ifindex
        );
        let ls_ack = OspfLsAck {
            lsa_headers: ack_headers,
        };
        let packet = Ospfv2Packet::new(&self.router_id, &link.area, Ospfv2Payload::LsAck(ls_ack));
        // Send to AllSPFRouters multicast.
        let _ = link.ptx.send(Message::Send(packet, ifindex, None));
    }

    /// Queue delayed ack headers and start delayed ack timer if needed.
    fn queue_delayed_acks(&mut self, ifindex: u32, headers: Vec<OspfLsaHeader>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.ls_ack_delayed.extend(headers);
        // Start delayed ack timer if not already running (1 second interval).
        if link.timer.ls_ack.is_none() {
            let tx = self.tx.clone();
            link.timer.ls_ack = Some(super::task::Timer::new(
                std::time::Duration::from_secs(1),
                super::task::TimerType::Once,
                move || {
                    let tx = tx.clone();
                    async move {
                        let _ = tx.send(Message::DelayedAck(ifindex));
                    }
                },
            ));
        }
    }

    fn router_id_update(&mut self, router_id: Ipv4Addr) {
        self.router_id = router_id;
        for (_, link) in self.links.iter_mut() {
            link.ident.router_id = router_id;
        }
        self.router_lsa_originate();
    }

    fn link_add(&mut self, link: Link) {
        // println!("OSPF: LinkAdd {} {}", link.name, link.index);
        if let Some(_link) = self.links.get_mut(&link.index) {
            //
        } else {
            let link = OspfLink::from(
                self.tx.clone(),
                link,
                self.sock.clone(),
                self.router_id,
                self.ptx.clone(),
            );
            self.links.insert(link.index, link);
        }
    }

    fn addr_add(&mut self, addr: LinkAddr) {
        // println!("OSPF: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        let addr = OspfAddr::from(&addr, prefix);
        link.addr.push(addr.clone());
        link.ident.prefix = *prefix;
    }

    fn addr_del(&mut self, addr: LinkAddr) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        link.addr.retain(|a| a.prefix != *prefix);

        // Re-evaluate enable state after address removal.
        let (next, next_id) = super::config::link_should_enable(link);
        super::config::apply_link_enable_transition(link, next, next_id);
    }

    fn link_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.link_flags |= LinkFlags::Up | LinkFlags::LowerUp;

        // If OSPF is enabled on this link, bring it up.
        if link.enabled {
            let _ = self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
        }
    }

    fn link_down(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.link_flags &= !LinkFlags::LowerUp;

        // If OSPF is enabled on this link, bring it down.
        if link.enabled {
            let area_id = link.area_id;
            let _ = self.tx.send(Message::Disable(ifindex, area_id));
        }
    }

    async fn process_recv(
        &mut self,
        packet: Ospfv2Packet,
        src: Ipv4Addr,
        _from: Ipv4Addr,
        index: u32,
        _dest: Ipv4Addr,
    ) {
        // Drop self-originated packets (e.g. received on loopback interface).
        if packet.router_id == self.router_id {
            return;
        }

        match packet.typ {
            OspfType::Hello => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_hello_recv(&self.router_id, link, &packet, &src, &self.tracing);
            }
            OspfType::DbDesc => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_db_desc_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsRequest => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_ls_req_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsUpdate => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_ls_upd_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsAck => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                ospf_ls_ack_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::Unknown(_typ) => {
                // println!("Unknown: packet type {}", typ);
            }
        }
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Enable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = true;
                link.area = area_id;
                link.area_id = area_id;
                let area = self.areas.fetch(area_id);
                area.links.insert(ifindex);
                self.router_lsa_originate();
                let _ = self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
            }
            Message::Disable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = false;
                link.area = Ipv4Addr::UNSPECIFIED;
                link.area_id = Ipv4Addr::UNSPECIFIED;
                let area = self.areas.fetch(area_id);
                area.links.remove(&ifindex);
                self.router_lsa_originate();
                let _ = self
                    .tx
                    .send(Message::Ifsm(ifindex, IfsmEvent::InterfaceDown));
            }
            Message::Recv(packet, src, from, index, dest) => {
                self.process_recv(packet, src, from, index, dest).await;
            }
            Message::Ifsm(index, ev) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_ifsm(link, ev);
            }
            Message::Nfsm(index, src, ev) => {
                let old_state = self
                    .links
                    .get(&index)
                    .and_then(|link| link.nbrs.get(&src))
                    .map(|nbr| nbr.state);

                if let Some((mut link, nbr)) = self.ospf_interface(index, &src) {
                    let ident = link.ident;
                    ospf_nfsm(&mut link, nbr, ev, ident);
                }

                let new_state = self
                    .links
                    .get(&index)
                    .and_then(|link| link.nbrs.get(&src))
                    .map(|nbr| nbr.state);

                if let (Some(old_state), Some(new_state)) = (old_state, new_state) {
                    self.process_neighbor_state_change(index, src, old_state, new_state);
                }
            }
            Message::HelloTimer(index) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_hello_send(link);
            }
            Message::Lsdb(ev, area_id, key) => {
                self.process_lsdb(ev, area_id, key);
            }
            Message::Flood(area_id, lsa, source_ifindex, source_nbr_addr) => {
                self.flood_lsa_through_area(area_id, &lsa, Some((source_ifindex, source_nbr_addr)));
            }
            Message::FloodAs(lsa, source_ifindex, source_nbr_addr) => {
                self.flood_lsa_through_as(&lsa, Some((source_ifindex, source_nbr_addr)));
            }
            Message::Retransmit(ifindex, addr) => {
                self.process_retransmit(ifindex, addr);
            }
            Message::LsReqRetransmit(ifindex, addr) => {
                self.process_ls_req_retransmit(ifindex, addr);
            }
            Message::DdRetransmit(ifindex, addr) => {
                self.process_dd_retransmit(ifindex, addr);
            }
            Message::DelayedAck(ifindex) => {
                self.process_delayed_ack(ifindex);
            }
            Message::DelayedAckQueue(ifindex, headers) => {
                self.queue_delayed_acks(ifindex, headers);
            }
            Message::SpfSchedule(area_id) => {
                if let Some(area_id) = area_id {
                    if let Some(area) = self.areas.get_mut(area_id) {
                        Self::ospf_spf_schedule(&self.tx, area);
                    }
                } else {
                    // None = AS-scope event (e.g. AS-external LSA install /
                    // expiry); recompute SPF on every attached area so each
                    // area's RIB picks up the new external routes.
                    let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
                    for id in area_ids {
                        if let Some(area) = self.areas.get_mut(id) {
                            Self::ospf_spf_schedule(&self.tx, area);
                        }
                    }
                }
            }
            Message::SpfCalc(area_id) => {
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.spf_timer = None;
                }
                tracing::info!("[SPF] Calculation triggered for area {}", area_id);
                perform_spf_calculation(self, area_id);
            }
            _ => {}
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::RouterIdUpdate(router_id) => {
                self.router_id_update(router_id);
            }
            RibRx::LinkAdd(link) => {
                self.link_add(link);
            }
            RibRx::LinkUp(ifindex) => {
                self.link_up(ifindex);
            }
            RibRx::LinkDown(ifindex) => {
                self.link_down(ifindex);
            }
            RibRx::AddrAdd(addr) => {
                self.addr_add(addr);
            }
            RibRx::AddrDel(addr) => {
                self.addr_del(addr);
            }
            _ => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => break,
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

/// v3-specific methods on the parameterized `Ospf` instance.
///
/// First piece of v3 protocol logic that walks `Ospf<Ospfv3>`
/// state and produces a wire LSA. Currently dead code -- no caller
/// constructs `Ospf<Ospfv3>` yet (that lands when the v3
/// instance's `new()` is written). The method exists so the
/// builder can be reviewed and tested ahead of the spawn wiring.
#[allow(dead_code)]
impl Ospf<Ospfv3> {
    /// Construct an `Ospf<Ospfv3>` instance.
    ///
    /// Mirrors the shape of `Ospf<Ospfv2>::new` (see above) so the
    /// two version-specific constructors stay readable side by side.
    /// The differences from v2:
    ///
    /// - **Socket.** Uses `ospf_socket_ipv6` — same IP protocol
    ///   number 89, but `Domain::IPV6` with `IPV6_V6ONLY`,
    ///   `IPV6_MULTICAST_HOPS=1`, and `IPV6_RECVPKTINFO` enabled.
    /// - **Router-id default.** Still 32-bit (RFC 5340 §2.1).
    /// - **No `callback_build` / `show_build`.** The v2 versions
    ///   register paths under `/router/ospf/...`; the v3 schema is
    ///   currently an empty `container ospfv3` stub with no Rust
    ///   handlers wired. The `callbacks` and `show_cb` maps stay
    ///   empty for v3 until the v3 config plumbing lands.
    /// - **No network read/write task spawn.** The v2 path uses
    ///   `read_packet` / `write_packet`, which are typed against
    ///   `Message<Ospfv2>` and the v2 wire format. The v3 wire path
    ///   uses `network_v6::{read_packet_v6, write_packet_v6}` —
    ///   spawned here, but the channels they drive are not yet
    ///   bridged into `Message<Ospfv3>` events. Until the v3 IFSM /
    ///   NFSM lands the rx side just buffers; producers will clone
    ///   `v3_send_tx` to push outgoing packets through the v6
    ///   socket. The four `build_*_lsa` self-origination helpers
    ///   above can still be exercised from tests.
    ///
    /// Behind `#[allow(dead_code)]` until `main.rs` learns to spawn
    /// an `Ospf<Ospfv3>` alongside (or in place of) the v2 instance.
    pub fn new(ctx: crate::context::ProtoContext, rib_rx: UnboundedReceiver<RibRx>) -> Self {
        let sock = Arc::new(AsyncFd::new(super::socket::ospf_socket_ipv6(&ctx).unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, _prx) = mpsc::unbounded_channel();

        // v3 raw-IPv6 packet path. `read_packet_v6` recvmsg's,
        // verifies the RFC 5340 §4.4 pseudo-header checksum, parses
        // `Ospfv3Packet`, and pushes `Ospfv3Recv` items. `write_packet_v6`
        // consumes `Ospfv3Send` items, stamps the checksum using the
        // supplied (src, dst) v6, and sendmsg's with an `in6_pktinfo`
        // ancillary so the kernel emits from the chosen ifindex /
        // link-local source.
        let (v3_send_tx, v3_send_rx) = mpsc::unbounded_channel();
        let (v3_recv_tx, v3_recv_rx) = mpsc::unbounded_channel();
        {
            let sock = sock.clone();
            tokio::spawn(async move {
                super::network_v6::read_packet_v6(sock, v3_recv_tx).await;
            });
        }
        {
            let sock = sock.clone();
            tokio::spawn(async move {
                super::network_v6::write_packet_v6(sock, v3_send_rx).await;
            });
        }

        let mut ospf = Self {
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx,
            ctx,
            links: BTreeMap::new(),
            areas: OspfAreaMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            router_id: Ipv4Addr::from_str("10.0.0.1").unwrap(),
            lsdb_as: Lsdb::new(),
            lsp_map: LspMap::default(),
            spf_result: None,
            graph: None,
            rib: PrefixMap::new(),
            tracing: OspfTracing::default(),
            segment_routing: super::srmpls::SegmentRoutingMode::default(),
            spf_last: None,
            spf_duration: None,
            sock,
            v3_send_tx: Some(v3_send_tx),
            v3_recv_rx: Some(v3_recv_rx),
        };
        ospf.callback_build();
        ospf
    }

    /// Look up the v3 YANG-path handler for `msg.paths` and invoke
    /// it. Mirrors v2's `process_cm_msg`. Currently only
    /// `/router/ospfv3/area/interface/enable` is registered (#791-stub
    /// path); more leaves land alongside the YANG schema expansion.
    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    /// Build the v3 Intra-Area-Prefix-LSA that references this
    /// router's Router-LSA in `area_id` (RFC 5340 §A.4.10).
    ///
    /// v3 separates topology (Router-LSA / Network-LSA) from prefix
    /// advertisement. This LSA carries the IPv6 prefixes that this
    /// router contributes to the area, hanging them off the
    /// Router-LSA reference triple
    /// `(referenced_ls_type = Router-LSA,
    ///   referenced_link_state_id = 0,
    ///   referenced_advertising_router = self.router_id)`.
    ///
    /// Iterates every enabled link in `area_id`, walks each
    /// link's configured IPv6 addresses, and emits one
    /// `Ospfv3IntraAreaPrefix` per non-link-local prefix with the
    /// link's `output_cost` as the metric.
    ///
    /// Returns `None` if there are no advertisable prefixes in
    /// the area — there's nothing to originate.
    ///
    /// The DR's Network-LSA-referenced variant (which aggregates
    /// per-segment Link-LSA prefixes into a single area-scope
    /// LSA) lands in a follow-up; the two share the same body
    /// shape but differ on which LSA they reference.
    pub fn build_router_intra_area_prefix_lsa(
        &self,
        area_id: Ipv4Addr,
    ) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE, Ospfv3IntraAreaPrefix,
            Ospfv3IntraAreaPrefixLsa, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader,
            Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };

        let mut prefixes: Vec<Ospfv3IntraAreaPrefix> = Vec::new();
        for link in self.links.values() {
            if !link.enabled || link.area != area_id {
                continue;
            }
            let metric = link.output_cost as u16;
            for a in link.addr.iter() {
                // Skip link-local addresses — those are
                // advertised by Link-LSAs (RFC 5340 §A.4.9), not
                // by Intra-Area-Prefix-LSAs (§A.4.10).
                if a.prefix.addr().segments()[0] == 0xfe80 {
                    continue;
                }
                let net = &a.prefix;
                let prefix_length = net.prefix_len();
                let wire_len = ospfv3_prefix_wire_len(prefix_length);
                let mut address_prefix = vec![0u8; wire_len];
                let bytes = net.addr().octets();
                let copy_len = prefix_length.div_ceil(8) as usize;
                address_prefix[..copy_len].copy_from_slice(&bytes[..copy_len]);
                prefixes.push(Ospfv3IntraAreaPrefix {
                    prefix_length,
                    prefix_options: Ospfv3PrefixOptions::default(),
                    metric,
                    address_prefix,
                });
            }
        }

        if prefixes.is_empty() {
            return None;
        }

        let body = Ospfv3IntraAreaPrefixLsa {
            referenced_ls_type: OSPFV3_ROUTER_LSA_TYPE,
            referenced_link_state_id: 0,
            referenced_advertising_router: self.router_id,
            prefixes,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
                // First (and so far only) fragment uses LS-ID 0;
                // a future PR that splits large prefix sets across
                // multiple Intra-Area-Prefix-LSAs will use distinct
                // LS-IDs per fragment.
                link_state_id: 0,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::IntraAreaPrefix(body),
        };
        lsa.update();
        Some(lsa)
    }

    /// Build the v3 Link-LSA for a given interface (RFC 5340 §A.4.9).
    ///
    /// Originated by every router on every active interface with
    /// **link-local scope** — never flooded beyond the segment.
    /// Carries:
    ///   - our Hello priority for the link,
    ///   - our options bits,
    ///   - our IPv6 link-local address on the link (so other
    ///     routers on the segment can install a usable next hop),
    ///   - the IPv6 prefixes configured on the interface (the DR
    ///     aggregates these into the Intra-Area-Prefix-LSA the
    ///     Network-LSA references).
    ///
    /// LS-ID = the local Interface ID (RFC 5340 §A.4.9).
    ///
    /// Returns `None` for unknown / disabled interfaces. If no
    /// link-local address is configured yet (interface coming up
    /// before netlink populates addresses), the Link-LSA carries
    /// `::` as a placeholder — the interface-enable path will
    /// re-originate once the address lands.
    pub fn build_link_lsa(&self, ifindex: u32) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_LINK_LSA_TYPE, Ospfv3LinkLsa, Ospfv3LinkLsaPrefix, Ospfv3LsBody, Ospfv3Lsa,
            Ospfv3LsaHeader, Ospfv3Options, Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };
        use std::net::Ipv6Addr;

        let link = self.links.get(&ifindex)?;
        if !link.enabled {
            return None;
        }

        // Pick a link-local. v3 hellos source from the link-local
        // and v3 Link-LSAs advertise it (RFC 5340 §A.4.9). Until
        // netlink reports one we publish `::` as a placeholder.
        let link_local_address: Ipv6Addr = link
            .addr
            .iter()
            .map(|a| a.prefix.addr())
            .find(|a| a.segments()[0] == 0xfe80)
            .unwrap_or(Ipv6Addr::UNSPECIFIED);

        // Every non-link-local prefix configured on the interface
        // gets advertised. Each prefix's wire bytes are the
        // address octets truncated to `ceil(prefix_len / 8)`,
        // then padded to a 32-bit boundary by
        // `ospfv3_prefix_wire_len`.
        let prefixes: Vec<Ospfv3LinkLsaPrefix> = link
            .addr
            .iter()
            .filter(|a| a.prefix.addr().segments()[0] != 0xfe80)
            .map(|a| {
                let net = &a.prefix;
                let prefix_length = net.prefix_len();
                let wire_len = ospfv3_prefix_wire_len(prefix_length);
                let mut address_prefix = vec![0u8; wire_len];
                let addr_bytes = net.addr().octets();
                let copy_len = prefix_length.div_ceil(8) as usize;
                address_prefix[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);
                Ospfv3LinkLsaPrefix {
                    prefix_length,
                    prefix_options: Ospfv3PrefixOptions::default(),
                    address_prefix,
                }
            })
            .collect();

        let body = Ospfv3LinkLsa {
            priority: link.priority(),
            options: Ospfv3Options::default(),
            link_local_address,
            prefixes,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_LINK_LSA_TYPE,
                link_state_id: link.interface_id,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Link(body),
        };
        lsa.update();
        Some(lsa)
    }

    /// Build the v3 Network-LSA for a broadcast / NBMA segment
    /// on which this router is the elected DR (RFC 5340 §A.4.4).
    ///
    /// Returns `None` if any of these conditions hold:
    ///   - the ifindex doesn't name an enabled link
    ///   - the link isn't Broadcast / NBMA
    ///   - this router is not the DR on the link (i.e.
    ///     `link.ident.d_router != self.router_id`)
    ///
    /// LS-ID = the local Interface ID for the link (§A.4.4 — v3
    /// Network-LSA LS-ID is the DR's Interface ID, not the
    /// interface's IP as in v2). Attached routers = every
    /// neighbor in Full state plus ourselves.
    ///
    /// Unlike v2's Network-LSA, the v3 body carries no netmask /
    /// prefix info — those move to the Intra-Area-Prefix-LSA.
    pub fn build_network_lsa(&self, ifindex: u32) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_NETWORK_LSA_TYPE, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader, Ospfv3NetworkLsa,
            Ospfv3Options,
        };

        let link = self.links.get(&ifindex)?;
        if !link.enabled {
            return None;
        }
        if !matches!(link.network_type, OspfNetworkType::Broadcast) {
            return None;
        }
        if link.ident.d_router != self.router_id {
            return None;
        }

        // RFC 5340 §A.4.4: the DR's Network-LSA enumerates every
        // router fully adjacent to it on the segment, including
        // the DR itself.
        let mut attached_routers: Vec<Ipv4Addr> = vec![self.router_id];
        attached_routers.extend(
            link.nbrs
                .values()
                .filter(|n| n.state == NfsmState::Full)
                .map(|n| n.ident.router_id),
        );

        let body = Ospfv3NetworkLsa {
            options: Ospfv3Options::default(),
            attached_routers,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_NETWORK_LSA_TYPE,
                link_state_id: link.interface_id,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Network(body),
        };
        lsa.update();
        Some(lsa)
    }

    /// Build the Router-LSA for self-origination (RFC 5340 §A.4.3).
    ///
    /// Walks every enabled `OspfLink<Ospfv3>` and emits one
    /// `Ospfv3RouterLsaLink` per qualifying adjacency:
    ///
    ///   - Broadcast network with a full-state DR adjacency
    ///     -> TransitNetwork link naming the DR's interface_id +
    ///     router-id (per §A.4.3 the "neighbor" fields on Transit
    ///     links point at the DR, not at every adjacent peer).
    ///
    /// PointToPoint and VirtualLink emission lands when the
    /// matching `OspfNetworkType` variants surface in zebra-rs
    /// (currently the enum has only Broadcast and NBMA; v3 needs
    /// PointToPoint as a network type for Router-LSA link type 1
    /// to be emittable).
    ///
    /// Returns an `Ospfv3Lsa` with checksum + length stamped via
    /// `Ospfv3Lsa::update` (PR 7i). Ready to install through
    /// `Lsdb::install_originated` (PR 7j).
    pub fn build_router_lsa(&self) -> ospf_packet::Ospfv3Lsa {
        use ospf_packet::{
            OSPFV3_ROUTER_LSA_FLAG_E, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody, Ospfv3Lsa,
            Ospfv3LsaHeader, Ospfv3Options, Ospfv3RouterLsa, Ospfv3RouterLsaLink,
        };

        let mut links = Vec::new();
        for link in self.links.values() {
            if !link.enabled {
                continue;
            }
            let cost = link.output_cost as u16;
            let my_iid = link.interface_id;

            if matches!(link.network_type, OspfNetworkType::Broadcast) {
                let dr_router_id = link.ident.d_router;
                if dr_router_id == Ipv4Addr::UNSPECIFIED {
                    continue;
                }
                if let Some(dr_nbr) = link.nbrs.get(&dr_router_id)
                    && dr_nbr.state == NfsmState::Full
                {
                    links.push(Ospfv3RouterLsaLink::transit_network(
                        cost,
                        my_iid,
                        dr_nbr.interface_id,
                        dr_router_id,
                    ));
                }
            }
        }

        let body = Ospfv3RouterLsa::new(OSPFV3_ROUTER_LSA_FLAG_E, Ospfv3Options::default(), links);
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_ROUTER_LSA_TYPE,
                link_state_id: 0,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Router(body),
        };
        lsa.update();
        lsa
    }

    /// Originate this router's Router-LSA into AREA0's LSDB.
    /// Mirrors v2's `router_lsa_originate_with_min_seq` shape with
    /// the v3-specific differences:
    ///
    /// - v3 carries `ls_type` as a raw `u16` (RFC 5340 §A.4.2.1);
    ///   the AREA0 LSDB lookup uses `lookup_by_raw_key` with the
    ///   3-tuple `(OSPFV3_ROUTER_LSA_TYPE, link_state_id=0,
    ///   advertising_router=self.router_id)`.
    /// - Checksum / length are restamped via `Ospfv3Lsa::update`
    ///   after the sequence number bump.
    /// - Install via the already-generic
    ///   `Lsdb::install_originated` (no v2-specific seq logic to
    ///   thread through `insert_self_originated`).
    /// - After install, flood the LSA to every Exchange-or-later
    ///   neighbor in the area via `flood_self_originated_lsa`.
    pub fn router_lsa_originate(&mut self) {
        use ospf_packet::OSPFV3_ROUTER_LSA_TYPE;
        let mut lsa = self.build_router_lsa();

        let key: super::lsdb::OspfLsaKey = (OSPFV3_ROUTER_LSA_TYPE, 0, self.router_id);
        if let Some(area) = self.areas.get(AREA0) {
            let current_seq = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number);
            if let Some(seq) = current_seq {
                lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(seq.saturating_add(1));
            }
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(AREA0) {
            area.lsdb.install_originated(lsa, &self.tx, Some(AREA0));
        }

        self.flood_self_originated_lsa(AREA0, &flood_lsa);
    }

    /// Flood a self-originated v3 LSA to every Exchange-or-later
    /// neighbor in the area. Minimal RFC 2328 §13.3 — no DR / BDR
    /// ordering, no retransmit-list bookkeeping, no ls_req cleanup
    /// for Exchange / Loading neighbors. Those land alongside the
    /// §13.1 hardening of `ospfv3_ls_upd_recv`.
    ///
    /// The LSU goes through the dedicated `Ospfv3Send` channel so
    /// `network_v6::write_packet_v6` stamps the IPv6 pseudo-header
    /// checksum. Source = the link's first link-local v6; dest =
    /// the neighbor's link-local (the `/128` captured in
    /// `ospfv3_hello_recv`).
    fn flood_self_originated_lsa(&mut self, area_id: Ipv4Addr, lsa: &ospf_packet::Ospfv3Lsa) {
        use ospf_packet::{Ospfv3LsUpdate, Ospfv3Packet, Ospfv3Payload};

        let Some(tx) = self.v3_send_tx.as_ref().cloned() else {
            return;
        };
        let Some(area) = self.areas.get(area_id) else {
            return;
        };
        let link_indices: Vec<u32> = area.links.iter().copied().collect();

        for ifindex in link_indices {
            let Some(link) = self.links.get(&ifindex) else {
                continue;
            };
            let Some(src) = link.addr.iter().find_map(|a| {
                let addr = a.prefix.addr();
                addr.is_unicast_link_local().then_some(addr)
            }) else {
                continue;
            };

            // Snapshot Exchange-or-later neighbors as (router_id,
            // link-local v6) so we can release the &link borrow
            // before pushing into the channel.
            let recipients: Vec<(Ipv4Addr, std::net::Ipv6Addr)> = link
                .nbrs
                .values()
                .filter(|n| n.state >= NfsmState::Exchange)
                .map(|n| (n.ident.router_id, n.ident.prefix.addr()))
                .collect();

            for (_nbr_rid, nbr_v6) in recipients {
                let ls_upd = Ospfv3LsUpdate {
                    lsas: vec![lsa.clone()],
                };
                let packet = Ospfv3Packet::new(
                    &self.router_id,
                    &area_id,
                    0,
                    Ospfv3Payload::LsUpdate(ls_upd),
                );
                let item = super::network_v6::Ospfv3Send {
                    packet,
                    ifindex,
                    dest: Some(nbr_v6),
                    src,
                };
                if let Err(e) = tx.send(item) {
                    tracing::warn!("[v3 Flood] channel send failed: {}", e);
                }
            }
        }
    }

    /// Dispatch one v3 instance-level message.
    ///
    /// Subset of v2's `process_msg` covering the IFSM-driver scope:
    /// `Enable` / `Disable` (toggle the link's enabled flag and emit
    /// the IFSM transition event), `Ifsm` (drive the FSM), and
    /// `HelloTimer` (emit a v3 Hello via the v3 send channel).
    ///
    /// Other `Message<Ospfv3>` variants (Recv / Nfsm / Send / Flood /
    /// Lsdb / SpfSchedule / SpfCalc) need additional v3-side wiring
    /// — packet recv bridging, v3 NFSM dispatch, v3 LSA flooding —
    /// and land in subsequent PRs. They fall through to a debug log
    /// for now so traffic that arrives early doesn't panic.
    pub async fn process_msg(&mut self, msg: Message<Ospfv3>) {
        match msg {
            Message::Enable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = true;
                link.area = area_id;
                link.area_id = area_id;
                let area = self.areas.fetch(area_id);
                area.links.insert(ifindex);
                self.router_lsa_originate();
                self.router_intra_area_prefix_lsa_originate(area_id);
                self.link_lsa_originate(ifindex);
                let _ = self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
            }
            Message::Disable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = false;
                link.area = Ipv4Addr::UNSPECIFIED;
                link.area_id = Ipv4Addr::UNSPECIFIED;
                let area = self.areas.fetch(area_id);
                area.links.remove(&ifindex);
                self.router_lsa_originate();
                self.router_intra_area_prefix_lsa_originate(area_id);
                let _ = self
                    .tx
                    .send(Message::Ifsm(ifindex, IfsmEvent::InterfaceDown));
            }
            Message::Ifsm(index, ev) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_ifsm(link, ev);
            }
            Message::HelloTimer(index) => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                let Some(tx) = self.v3_send_tx.as_ref() else {
                    return;
                };
                super::packet_v3::ospfv3_hello_send(link, tx);
            }
            Message::Nfsm(index, src, ev) => {
                let old_state = self
                    .links
                    .get(&index)
                    .and_then(|link| link.nbrs.get(&src))
                    .map(|nbr| nbr.state);

                if let Some((mut link, nbr)) = self.ospf_interface(index, &src) {
                    let ident = link.ident;
                    super::nfsm::ospf_nfsm(&mut link, nbr, ev, ident);
                }

                let new_state = self
                    .links
                    .get(&index)
                    .and_then(|link| link.nbrs.get(&src))
                    .map(|nbr| nbr.state);

                if let (Some(old_state), Some(new_state)) = (old_state, new_state) {
                    self.process_neighbor_state_change(index, src, old_state, new_state);
                }
            }
            other => {
                tracing::debug!(
                    "v3 process_msg: unhandled variant {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    /// Originate this router's Link-LSA for `ifindex` into the
    /// per-link LSDB (RFC 5340 §A.4.9). Mirrors
    /// `router_lsa_originate`'s shape, with two differences forced
    /// by the link scope:
    ///
    /// - Lookup / install go into `OspfLink::lsdb` (not the area
    ///   LSDB), since RFC 5340 §4.5.2 forbids Link-LSAs from
    ///   leaving the segment.
    /// - Flooding uses `flood_link_scope_lsa(ifindex, lsa)`, which
    ///   walks only the neighbors on this one link.
    ///
    /// Returns silently if `build_link_lsa(ifindex)` declines (the
    /// interface is unknown or disabled).
    pub fn link_lsa_originate(&mut self, ifindex: u32) {
        use ospf_packet::OSPFV3_LINK_LSA_TYPE;

        let Some(mut lsa) = self.build_link_lsa(ifindex) else {
            return;
        };

        let key: super::lsdb::OspfLsaKey = (OSPFV3_LINK_LSA_TYPE, ifindex, self.router_id);

        // Pull the prior sequence number out of the link's LSDB.
        if let Some(link) = self.links.get(&ifindex)
            && let Some(prev_seq) = link
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(link) = self.links.get_mut(&ifindex) {
            // Link-LSA lives in the per-link LSDB; no area_id is
            // associated with link-scope LSAs in the hold-timer
            // protocol, so pass `None`.
            link.lsdb.install_originated(lsa, &self.tx, None);
        }
        self.flood_link_scope_lsa(ifindex, &flood_lsa);
    }

    /// Flood a link-scope LSA to every Exchange-or-later neighbor
    /// on the originating link only. Counterpart to
    /// `flood_self_originated_lsa` which walks the whole area;
    /// RFC 5340 §4.5.2 bounds link-scope flooding to the segment.
    fn flood_link_scope_lsa(&mut self, ifindex: u32, lsa: &ospf_packet::Ospfv3Lsa) {
        use ospf_packet::{Ospfv3LsUpdate, Ospfv3Packet, Ospfv3Payload};

        let Some(tx) = self.v3_send_tx.as_ref().cloned() else {
            return;
        };
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let Some(src) = link.addr.iter().find_map(|a| {
            let addr = a.prefix.addr();
            addr.is_unicast_link_local().then_some(addr)
        }) else {
            return;
        };

        let recipients: Vec<std::net::Ipv6Addr> = link
            .nbrs
            .values()
            .filter(|n| n.state >= NfsmState::Exchange)
            .map(|n| n.ident.prefix.addr())
            .collect();

        for nbr_v6 in recipients {
            let ls_upd = Ospfv3LsUpdate {
                lsas: vec![lsa.clone()],
            };
            let packet = Ospfv3Packet::new(
                &self.router_id,
                &area_id,
                0,
                Ospfv3Payload::LsUpdate(ls_upd),
            );
            let item = super::network_v6::Ospfv3Send {
                packet,
                ifindex,
                dest: Some(nbr_v6),
                src,
            };
            if let Err(e) = tx.send(item) {
                tracing::warn!("[v3 Link-LSA Flood] channel send failed: {}", e);
            }
        }
    }

    /// Originate (or flush) this router's Router-referenced
    /// Intra-Area-Prefix-LSA for `area_id` (RFC 5340 §A.4.10).
    /// Mirrors `router_lsa_originate`'s shape:
    ///
    /// - Build via `build_router_intra_area_prefix_lsa`. Returns
    ///   `None` when no advertisable prefixes exist in the area —
    ///   in that case, flush the previous LSA so receivers age it
    ///   out.
    /// - Look up the existing area-LSDB entry via
    ///   `lookup_by_raw_key` (#779). Key is
    ///   `(OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, link_state_id=0,
    ///   advertising_router=self.router_id)`.
    /// - Bump `ls_seq_number` past the prior entry, restamp via
    ///   `Ospfv3Lsa::update`, install through `install_originated`,
    ///   flood via `flood_self_originated_lsa`.
    ///
    /// Called from `Message::Enable` / `Message::Disable` arms in
    /// `process_msg` — the link's address set changes when an
    /// interface joins or leaves the area.
    pub fn router_intra_area_prefix_lsa_originate(&mut self, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE;

        let key: super::lsdb::OspfLsaKey = (OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, 0, self.router_id);

        // No prefixes to advertise — flush any existing copy.
        let Some(mut lsa) = self.build_router_intra_area_prefix_lsa(area_id) else {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        };

        if let Some(area) = self.areas.get(area_id)
            && let Some(prev_seq) = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Detect Full state transitions on `nbr` and re-originate the
    /// LSAs that depend on the full-adjacency set. Mirrors v2's
    /// `process_neighbor_state_change`:
    ///
    /// - Router-LSA always re-originates when Full changes (since
    ///   transit-network link records list only Full-DR adjacencies).
    /// - Network-LSA (DR only) re-originates / flushes based on the
    ///   updated Full-neighbor set.
    fn process_neighbor_state_change(
        &mut self,
        ifindex: u32,
        nbr_addr: Ipv4Addr,
        old_state: NfsmState,
        new_state: NfsmState,
    ) {
        if old_state == new_state {
            return;
        }
        let full_state_changed = (old_state == NfsmState::Full && new_state != NfsmState::Full)
            || (old_state != NfsmState::Full && new_state == NfsmState::Full);
        if !full_state_changed {
            return;
        }

        let if_state = {
            let Some(link) = self.links.get_mut(&ifindex) else {
                return;
            };
            link.full_nbr_count = link
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();
            link.state
        };

        tracing::info!(
            "[v3 NFSM:FullTransition] ifindex={} nbr={} {} -> {}",
            ifindex,
            nbr_addr,
            old_state,
            new_state
        );

        self.router_lsa_originate();

        if if_state == IfsmState::DR {
            self.network_lsa_originate(ifindex);
        }
    }

    /// Originate (or flush) the v3 Network-LSA for the broadcast
    /// segment on `ifindex`. Mirrors v2's
    /// `update_network_lsa_by_interface` with the v3-specific
    /// differences:
    ///
    /// - LS-ID is the DR's **Interface ID** (RFC 5340 §A.4.4),
    ///   not the DR's interface IP as in v2.
    /// - LSA-type is `OSPFV3_NETWORK_LSA_TYPE` (0x2002) — the v3
    ///   ls_type doesn't compress to a v2 `OspfLsType`, so the
    ///   LSDB flush uses `flush_lsa_by_raw_key`.
    /// - The v3 body carries no netmask (prefixes move to
    ///   Intra-Area-Prefix-LSA in v3).
    ///
    /// Flushes the existing Network-LSA when this router is no
    /// longer DR or has no Full-adjacent neighbors on the segment;
    /// otherwise installs the fresh LSA and floods it to every
    /// Exchange-or-later neighbor in the area.
    pub fn network_lsa_originate(&mut self, ifindex: u32) {
        use ospf_packet::OSPFV3_NETWORK_LSA_TYPE;

        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let interface_id = link.interface_id;
        let is_dr = link.ident.d_router == self.router_id;
        let full_nbr_count = link
            .nbrs
            .values()
            .filter(|n| n.state == NfsmState::Full)
            .count();

        let key: super::lsdb::OspfLsaKey = (OSPFV3_NETWORK_LSA_TYPE, interface_id, self.router_id);

        // No Full neighbors (or no longer DR): flush the LSA so
        // receivers age it out of their LSDBs.
        if !is_dr || full_nbr_count == 0 {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        }

        let Some(mut lsa) = self.build_network_lsa(ifindex) else {
            return;
        };

        if let Some(area) = self.areas.get(area_id)
            && let Some(prev_seq) = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = lsa.h.ls_seq_number.max(prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Dispatch one v3 packet received off the wire (`network_v6`).
    /// Bridges the `Ospfv3Recv` channel into the v3 instance by
    /// looking up the ingress link and routing by payload type.
    /// Only Hello is handled at the moment; the four other v3 packet
    /// types (DBD / LSReq / LSUpd / LSAck) fall through with a debug
    /// log until their recv handlers land.
    pub fn process_recv(&mut self, recv: super::network_v6::Ospfv3Recv) {
        let super::network_v6::Ospfv3Recv {
            packet,
            src,
            dst: _,
            ifindex,
        } = recv;
        let our_router_id = self.router_id;
        let nbr_router_id = packet.router_id;
        match &packet.payload {
            Ospfv3Payload::Hello(_) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                super::packet_v3::ospfv3_hello_recv(&our_router_id, link, &packet, &src);
            }
            Ospfv3Payload::DbDesc(_) => {
                // v3 keys neighbors by router-id, which lives on the
                // packet header; pass it as the nbr-key to
                // `ospf_interface` to fetch the (link, nbr) pair.
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_db_desc_recv(&mut oi, nbr, &packet, &src);
                }
            }
            Ospfv3Payload::LsRequest(_) => {
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_ls_req_recv(&mut oi, nbr, &packet, &src);
                }
            }
            Ospfv3Payload::LsUpdate(_) => {
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_ls_upd_recv(&mut oi, nbr, &packet, &src);
                }
            }
            other => {
                tracing::debug!(
                    "v3 process_recv: unhandled packet payload {:?}",
                    std::mem::discriminant(other)
                );
            }
        }
    }

    /// Main event loop for the v3 instance. Mirrors v2's `event_loop`:
    /// pulls instance events from `rx`, RIB updates from `rib_rx`,
    /// config-manager requests from `cm.rx`, show requests from
    /// `show.rx`, and v3 packets from `v3_recv_rx`.
    ///
    /// `self.v3_recv_rx` is taken out of the `Option` at start so
    /// the `select!` arm doesn't have to re-borrow it through the
    /// `&mut self` used by `process_*`. `Ospf<Ospfv3>::new` always
    /// populates it (#768).
    pub async fn event_loop(&mut self) {
        let mut v3_recv_rx = self
            .v3_recv_rx
            .take()
            .expect("Ospf<Ospfv3> has no v3 recv channel");
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(_msg) = self.rib_rx.recv() => {
                    // v3 RIB integration TBD; drain for now so the
                    // channel doesn't back-pressure the rib client.
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(_msg) = self.show.rx.recv() => {
                    // v3 show path TBD; drain for now.
                }
                Some(recv) = v3_recv_rx.recv() => {
                    self.process_recv(recv);
                }
            }
        }
    }
}

pub fn serve(mut ospf: Ospf) -> Task<()> {
    Task::spawn(async move {
        ospf.event_loop().await;
    })
}

/// Spawn the v3 instance's main event loop. Symmetric with v2's
/// `serve`. Currently unused — `main.rs` doesn't yet construct an
/// `Ospf<Ospfv3>`; the spawn wiring lands when the v3 config schema
/// and `spawn_ospfv3` path follow.
#[allow(dead_code)]
pub fn serve_v3(mut ospf: Ospf<Ospfv3>) -> Task<()> {
    Task::spawn(async move {
        ospf.event_loop().await;
    })
}

/// Internal control / data messages threaded through the OSPF
/// instance's main mpsc channel.
///
/// Parameterized over `V: OspfVersion` (default `Ospfv2`) so the
/// variants carrying wire-shaped data (`Recv` / `Send` /
/// `Flood` / `FloodAs` / `DelayedAckQueue`) specialize on the
/// per-version packet, LSA, and address types. The remaining 13
/// variants don't carry version-specific data — they're agnostic
/// in shape even though they live on a `Message<V>` enum.
///
/// Default `V = Ospfv2` keeps every existing v2 callsite — both
/// pattern matches and `Message::Foo(...)` constructions —
/// resolving transparently to `Message<Ospfv2>`.
pub enum Message<V: OspfVersion = Ospfv2> {
    Enable(u32, Ipv4Addr),
    Disable(u32, Ipv4Addr),
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, Ipv4Addr, NfsmEvent),
    HelloTimer(u32),
    /// Packet received off the wire. v2 carries
    /// `(Ospfv2Packet, src_addr, dst_group, ifindex, ifaddr)` where
    /// every address is `Ipv4Addr`; v3 will use `Ipv6Addr` for
    /// src/dst/ifaddr per its raw IPv6 socket layer.
    Recv(V::Packet, V::Addr, V::Addr, u32, V::Addr),
    /// Packet to send. v2 carries
    /// `(Ospfv2Packet, ifindex, Option<Ipv4Addr>)` — the optional
    /// destination is the multicast group or unicast nbr address.
    /// v3 uses `V::Addr = Ipv6Addr` accordingly.
    Send(V::Packet, u32, Option<V::Addr>),
    Lsdb(LsdbEvent, Option<Ipv4Addr>, OspfLsaKey),
    /// Flood LSA through area, excluding source neighbor.
    /// (area_id, lsa, source_ifindex, source_nbr_addr)
    Flood(Ipv4Addr, V::Lsa, u32, V::Addr),
    /// Flood AS-scoped LSA through all normal areas, excluding source neighbor.
    /// (lsa, source_ifindex, source_nbr_addr)
    FloodAs(V::Lsa, u32, V::Addr),
    /// Retransmit LSAs to a specific neighbor.
    /// (ifindex, nbr_addr)
    Retransmit(u32, Ipv4Addr),
    /// Retransmit pending Link State Request packet to a neighbor in
    /// Exchange or Loading. (ifindex, nbr_addr)
    LsReqRetransmit(u32, Ipv4Addr),
    /// Master retransmit of pending Database Description packet.
    /// (ifindex, nbr_addr)
    DdRetransmit(u32, Ipv4Addr),
    /// Send delayed LS Acks on an interface.
    /// (ifindex)
    DelayedAck(u32),
    /// Queue delayed ack headers on an interface.
    /// (ifindex, headers)
    DelayedAckQueue(u32, Vec<V::LsaHeader>),
    /// Request SPF scheduling for an area.
    SpfSchedule(Option<Ipv4Addr>),
    /// Timer-fired: perform SPF calculation for an area.
    SpfCalc(Ipv4Addr),
}

use crate::spf::{self, Path};

#[derive(Default)]
pub struct LspMap {
    map: HashMap<Ipv4Addr, usize>,
    val: Vec<Ipv4Addr>,
}

impl LspMap {
    fn get(&mut self, router_id: Ipv4Addr) -> usize {
        if let Some(index) = self.map.get(&router_id) {
            *index
        } else {
            let index = self.val.len();
            self.map.insert(router_id, index);
            self.val.push(router_id);
            index
        }
    }

    pub fn resolve(&self, id: usize) -> Option<&Ipv4Addr> {
        self.val.get(id)
    }

    /// Read-only lookup. Returns None if `router_id` is not in the map.
    /// Use this when iterating LSAs that reference a router_id whose
    /// vertex may not have been allocated (e.g. ABR for an unreachable
    /// network).
    pub fn lookup(&self, router_id: Ipv4Addr) -> Option<usize> {
        self.map.get(&router_id).copied()
    }
}

/// Build SPF graph from OSPF LSDB (Router-LSAs and Network-LSAs).
///
/// Filters per RFC 2328 §16.1:
///  - step 1: MaxAge LSAs are excluded from the SPF tree
///  - step 2(b): the destination LSA must carry a back-link to us. For
///    Router→Router (P2P/Virtual) edges the peer's Router-LSA must list
///    our router-id as a P2P/Virtual link; for Router→Network (Transit)
///    edges the Network-LSA must list our router-id in its
///    attached_routers, and each attached router must itself have a
///    valid Router-LSA before its edge is emitted.
fn graph(top: &mut Ospf, area_id: Ipv4Addr) -> (spf::Graph, Option<usize>) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    let mut graph = spf::Graph::new();
    let mut source_node = None;

    let Some(area) = top.areas.get(area_id) else {
        return (graph, source_node);
    };

    // Collect non-MaxAge Router-LSA data.
    let mut router_lsas = Vec::new();
    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        router_lsas.push((adv_router, lsa.originated, lsa.data.clone()));
    }

    // Side-table for the bidirectional back-link check on P2P / Virtual
    // edges. Keyed by adv_router; refs into the local router_lsas Vec.
    let mut router_lsa_by_id: HashMap<Ipv4Addr, &RouterLsa> = HashMap::new();
    for (adv_router, _, lsa_data) in &router_lsas {
        if let OspfLsp::Router(ref router_lsa) = lsa_data.lsp {
            router_lsa_by_id.insert(*adv_router, router_lsa);
        }
    }

    // Collect non-MaxAge Network-LSA attached routers for transit
    // network expansion.
    let mut network_lsas: HashMap<Ipv4Addr, Vec<Ipv4Addr>> = HashMap::new();
    for ((ls_id, _adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if let OspfLsp::Network(ref net_lsa) = lsa.data.lsp {
            network_lsas.insert(ls_id, net_lsa.attached_routers.clone());
        }
    }

    // Process each Router-LSA to build graph vertices and edges.
    for (adv_router, originated, lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);

        if *originated {
            source_node = Some(node_id);
        }

        let mut vertex = spf::Vertex {
            id: node_id,
            name: adv_router.to_string(),
            sys_id: adv_router.to_string(),
            ..Default::default()
        };

        if let OspfLsp::Router(ref router_lsa) = lsa_data.lsp {
            for link in &router_lsa.links {
                match link.link_type {
                    OspfLinkType::P2p | OspfLinkType::VirtualLink => {
                        // Bidirectional check: peer's Router-LSA must exist
                        // (non-MaxAge) AND carry a P2P/Virtual link back to
                        // us. Otherwise the edge is one-way and SPF would
                        // compute a route to a destination that can't route
                        // back.
                        let Some(peer_lsa) = router_lsa_by_id.get(&link.link_id) else {
                            continue;
                        };
                        let has_backlink = peer_lsa.links.iter().any(|l| {
                            matches!(l.link_type, OspfLinkType::P2p | OspfLinkType::VirtualLink)
                                && l.link_id == *adv_router
                        });
                        if !has_backlink {
                            continue;
                        }
                        let to_id = top.lsp_map.get(link.link_id);
                        vertex.olinks.push(spf::Link {
                            from: node_id,
                            to: to_id,
                            cost: link.tos_0_metric as u32,
                            link_id: 0,
                        });
                    }
                    OspfLinkType::Transit => {
                        // Bidirectional check: the Network-LSA must list us
                        // in its attached_routers; otherwise our claim of
                        // membership doesn't match the DR's view and the
                        // back-edge is missing.
                        //
                        // link_id = DR's interface IP, which is the
                        // Network-LSA's ls_id.
                        let Some(attached) = network_lsas.get(&link.link_id) else {
                            continue;
                        };
                        if !attached.contains(adv_router) {
                            continue;
                        }
                        for attached_router in attached {
                            if *attached_router == *adv_router {
                                continue;
                            }
                            // Each peer router on the network must itself
                            // have a valid Router-LSA. Without one, the
                            // back-link from the pseudo-node to that
                            // router is missing.
                            if !router_lsa_by_id.contains_key(attached_router) {
                                continue;
                            }
                            let to_id = top.lsp_map.get(*attached_router);
                            vertex.olinks.push(spf::Link {
                                from: node_id,
                                to: to_id,
                                cost: link.tos_0_metric as u32,
                                link_id: 0,
                            });
                        }
                    }
                    OspfLinkType::Stub => {
                        // Stub (3): destination prefix, not an SPF edge.
                        // Consumed by build_rib_from_spf.
                    }
                }
            }
        }

        graph.insert(node_id, vertex);
    }

    (graph, source_node)
}

#[derive(Debug, PartialEq)]
pub struct SpfRoute {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
    pub router_id: Option<Ipv4Addr>,
}

fn rib_insert(rib: &mut PrefixMap<Ipv4Net, SpfRoute>, prefix: Ipv4Net, route: SpfRoute) {
    if let Some(curr) = rib.get_mut(&prefix) {
        if curr.metric > route.metric {
            *curr = route;
        } else if curr.metric == route.metric {
            for (addr, nhop) in route.nhops {
                curr.nhops.insert(addr, nhop);
            }
        }
    } else {
        rib.insert(prefix, route);
    }
}

/// Build the nexthop map for an SPF destination vertex. The set is
/// computed from `path.nexthops` (which each begin with the first-hop
/// neighbor's vertex id) by walking our links and matching neighbors
/// by router-id. Shared by intra-area and inter-area route building.
fn build_spf_nexthops(
    top: &Ospf,
    target_id: usize,
    path: &spf::Path,
) -> BTreeMap<Ipv4Addr, SpfNexthop> {
    let mut nhops = BTreeMap::new();
    for p in &path.nexthops {
        // p.is_empty() means the destination is the SPF root (us).
        if p.is_empty() {
            continue;
        }
        let Some(nhop_id) = top.lsp_map.resolve(p[0]) else {
            continue;
        };
        for (ifindex, link) in top.links.iter() {
            for (_, nbr) in link.nbrs.iter() {
                if *nhop_id == nbr.ident.router_id {
                    let addr = nbr.ident.prefix.addr();
                    let nhop = SpfNexthop {
                        ifindex: *ifindex,
                        adjacency: p[0] == target_id,
                        router_id: Some(*nhop_id),
                    };
                    nhops.insert(addr, nhop);
                }
            }
        }
    }
    nhops
}

/// Walk Type 3 (Network Summary) LSAs in `area`'s LSDB and install
/// inter-area routes per RFC 2328 §16.2. For each Summary LSA whose
/// advertising router is reachable via SPF, install a route at cost
/// SPF(ABR) + LSA.metric, with the ABR's nexthops.
///
/// Type 4 (ASBR Summary) LSAs are consumed by AS-external route
/// computation (§16.4), not direct prefix install — they're handled
/// separately when that path lands.
fn add_inter_area_routes(
    top: &Ospf,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<Ipv4Net, SpfRoute>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    // OSPF metrics are 24-bit; 0xFFFFFF = LSInfinity (unreachable).
    const LS_INFINITY: u32 = 0x00FF_FFFF;

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for ((ls_id, _key_adv), lsa) in area.lsdb.iter_by_type(OspfLsType::Summary) {
        // RFC 2328 §16.2: skip MaxAge LSAs.
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        // Skip self-originated summaries — we are the ABR for these.
        if lsa.data.h.adv_router == top.router_id {
            continue;
        }
        let OspfLsp::Summary(ref summary) = lsa.data.lsp else {
            continue;
        };
        if summary.metric >= LS_INFINITY {
            continue;
        }

        // Resolve the advertising router (the ABR) to its SPF vertex.
        // If the ABR has no allocated vertex, or isn't reachable in
        // this SPF run, the inter-area destination is unreachable.
        let Some(abr_vertex) = top.lsp_map.lookup(lsa.data.h.adv_router) else {
            continue;
        };
        let Some(abr_path) = spf_result.get(&abr_vertex) else {
            continue;
        };

        let mask = u32::from(summary.netmask).leading_ones() as u8;
        let Ok(prefix) = Ipv4Net::new(ls_id, mask) else {
            continue;
        };
        let prefix = prefix.trunc();

        let nhops = build_spf_nexthops(top, abr_vertex, abr_path);
        if nhops.is_empty() {
            continue;
        }

        let total_metric = abr_path.cost.saturating_add(summary.metric);
        let spf_route = SpfRoute {
            metric: total_metric,
            nhops,
            sid: None,
            prefix_sid: None,
        };
        rib_insert(rib, prefix, spf_route);
    }
}

fn build_rib_from_spf(
    top: &Ospf,
    area_id: Ipv4Addr,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> PrefixMap<Ipv4Net, SpfRoute> {
    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();

    let Some(area) = top.areas.get(area_id) else {
        return rib;
    };

    // Intra-area: walk each SPF destination's Router-LSA links.
    for (node, nhops) in spf_result {
        // Skip self node.
        if *node == source {
            continue;
        }

        // Resolve node to router-id.
        let Some(router_id) = top.lsp_map.resolve(*node) else {
            continue;
        };

        let spf_nhops = build_spf_nexthops(top, *node, nhops);

        if let Some(lsa) = area
            .lsdb
            .lookup_by_id(OspfLsType::Router, *router_id, *router_id)
            && let OspfLsp::Router(ref router_lsa) = lsa.lsp
        {
            for link in &router_lsa.links {
                match link.link_type {
                    OspfLinkType::Transit => {
                        // Transit Network: look up Network-LSA to get the
                        // network prefix (link_id = dr's interface ip).
                        for ((_ls_id, _adv), nlsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
                            if let OspfLsp::Network(ref net) = nlsa.data.lsp
                                && nlsa.data.h.ls_id == link.link_id
                            {
                                let mask = u32::from(net.netmask).leading_ones() as u8;
                                if let Ok(prefix) = Ipv4Net::new(link.link_id, mask) {
                                    let prefix = prefix.trunc();

                                    let spf_route = SpfRoute {
                                        metric: nhops.cost,
                                        nhops: spf_nhops.clone(),
                                        sid: None,
                                        prefix_sid: None,
                                    };
                                    rib_insert(&mut rib, prefix, spf_route);
                                }
                                break;
                            }
                        }
                    }
                    OspfLinkType::Stub => {
                        // Stub Network: link_id = network addr,
                        // link_data = netmask.
                        let mask = u32::from(link.link_data).leading_ones() as u8;
                        if let Ok(prefix) = Ipv4Net::new(link.link_id, mask) {
                            let prefix = prefix.trunc();
                            let spf_route = SpfRoute {
                                metric: nhops.cost,
                                nhops: spf_nhops.clone(),
                                sid: None,
                                prefix_sid: None,
                            };
                            rib_insert(&mut rib, prefix, spf_route);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Inter-area: walk Type 3 Summary LSAs and install via SPF nexthop
    // to the originating ABR.
    add_inter_area_routes(top, area_id, spf_result, &mut rib);

    // AS-external: walk Type 5 LSAs and install via SPF nexthop to the
    // originating ASBR. Uses this area's SPF result to resolve the
    // ASBR -- correct for single-area today; multi-area routers should
    // pick the best per-area SPF cost when this lands.
    add_as_external_routes(top, spf_result, &mut rib);

    rib
}

/// Walk Type 5 (AS-External) LSAs in the AS-scoped LSDB and install
/// external routes per RFC 2328 §16.4.
///
/// For each LSA whose advertising router (ASBR) is reachable via SPF
/// in the current area, compute the route metric per the LSA's E bit:
///   - Type 1 external: SPF(ASBR) + LSA.metric
///   - Type 2 external: LSA.metric only (SPF cost is the tiebreak,
///     but the FIB-installed metric is the external cost)
///
/// Non-zero forwarding-address LSAs are skipped for now. §16.4 step 3
/// requires resolving the forwarding address against an intra-area
/// route, which is a separate code path.
fn add_as_external_routes(
    top: &Ospf,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<Ipv4Net, SpfRoute>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    // OSPF metrics are 24-bit; 0xFFFFFF = LSInfinity (unreachable).
    const LS_INFINITY: u32 = 0x00FF_FFFF;
    // E flag in the AS-external LSA's `ext_and_resvd` byte.
    const E_FLAG: u8 = 0x80;

    for ((ls_id, _key_adv), lsa) in top.lsdb_as.iter_by_type(OspfLsType::AsExternal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.adv_router == top.router_id {
            continue;
        }
        let OspfLsp::AsExternal(ref ext) = lsa.data.lsp else {
            continue;
        };
        if ext.metric >= LS_INFINITY {
            continue;
        }
        // Forwarding-address resolution (§16.4 step 3) deferred.
        if !ext.forwarding_address.is_unspecified() {
            continue;
        }

        let Some(asbr_vertex) = top.lsp_map.lookup(lsa.data.h.adv_router) else {
            continue;
        };
        let Some(asbr_path) = spf_result.get(&asbr_vertex) else {
            continue;
        };

        let is_type2 = (ext.ext_and_resvd & E_FLAG) != 0;
        let metric = if is_type2 {
            ext.metric
        } else {
            asbr_path.cost.saturating_add(ext.metric)
        };

        let mask = u32::from(ext.netmask).leading_ones() as u8;
        let Ok(prefix) = Ipv4Net::new(ls_id, mask) else {
            continue;
        };
        let prefix = prefix.trunc();

        let nhops = build_spf_nexthops(top, asbr_vertex, asbr_path);
        if nhops.is_empty() {
            continue;
        }

        let spf_route = SpfRoute {
            metric,
            nhops,
            sid: None,
            prefix_sid: None,
        };
        rib_insert(rib, prefix, spf_route);
    }
}

fn perform_spf_calculation(top: &mut Ospf, area_id: Ipv4Addr) {
    let (graph, source_node) = graph(top, area_id);

    if let Some(source) = source_node {
        let start = Instant::now();
        let spf_result = spf::spf(&graph, source, &spf::SpfOpt::default());
        let end = Instant::now();
        top.spf_duration = Some(end.duration_since(start));
        top.spf_last = Some(end);
        // println!("[SPF] area {} nodes: {}", area_id, spf_result.len());
        // for (node_id, path) in &spf_result {
        //     if let Some(node) = graph.get(node_id) {
        //         println!(
        //             "[SPF]   {} cost {} nexthops {:?}",
        //             node.name, path.cost, path.nexthops
        //         );
        //     }
        // }

        let rib = build_rib_from_spf(top, area_id, source, &spf_result);

        // Store the SPF result and graph in OSPF instance.
        top.spf_result = Some(spf_result);
        top.graph = Some(graph);

        apply_routing_updates(top, rib);
    }
}

pub type DiffResult<'a> = spf::TableDiffResult<'a, Ipv4Net, SpfRoute>;

fn nhop_to_nexthop_uni(key: &Ipv4Addr, route: &SpfRoute, value: &SpfNexthop) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::from(*key, route.metric, mpls);
    // OSPF, like IS-IS, learns the egress link from the adjacency
    // state machine, so record it as the origin and let the RIB
    // resolver leave it alone. 0 means "no usable adjacency ifindex"
    // — record as None so callers can detect that case.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

fn make_rib_entry(route: &SpfRoute) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Ospf);
    rib.distance = 110;
    rib.metric = route.metric;

    rib.nexthop = if route.nhops.len() == 1 {
        if let Some((key, value)) = route.nhops.iter().next() {
            rib::Nexthop::Uni(nhop_to_nexthop_uni(key, route, value))
        } else {
            rib::Nexthop::default()
        }
    } else {
        let multi = rib::NexthopMulti {
            metric: route.metric,
            nexthops: route
                .nhops
                .iter()
                .map(|(key, value)| nhop_to_nexthop_uni(key, route, value))
                .collect(),
            ..Default::default()
        };
        rib::Nexthop::Multi(multi)
    };

    rib
}

pub fn diff_apply(rib_client: &crate::rib::client::RibClient, diff: &DiffResult) {
    // Delete.
    for (prefix, route) in diff.only_curr.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Del {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (changed).
    for (prefix, _, route) in diff.different.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (new).
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
}

/// Apply routing updates to RIB subsystem
fn apply_routing_updates(top: &mut Ospf, rib: PrefixMap<Ipv4Net, SpfRoute>) {
    // Update RIB
    let diff = spf::table_diff(top.rib.iter(), rib.iter());
    diff_apply(&top.ctx.rib, &diff);

    top.rib = rib;
}
