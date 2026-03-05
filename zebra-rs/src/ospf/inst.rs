use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net};
use netlink_packet_route::link::LinkFlags;
use ospf_packet::*;
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::addr::OspfAddr;
use crate::ospf::packet::{ospf_db_desc_recv, ospf_hello_recv, ospf_hello_send};
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::{self, Link, RibType};
use crate::{
    config::{Args, ConfigChannel, ConfigOp, ConfigRequest, path_from_command},
    context::Context,
    rib::RibRxChannel,
};

use super::area::{OspfArea, OspfAreaMap};
use super::config::{Callback, OspfNetworkConfig};
use super::ifsm::{IfsmEvent, IfsmState, ospf_ifsm};
use super::link::{OspfLink, OspfNetworkType};
use super::lsdb::{LsdbEvent, OspfLsaKey};
use super::network::{read_packet, write_packet};
use super::nfsm::{NfsmEvent, ospf_nfsm};
use super::socket::ospf_socket_ipv4;
use super::task::{Timer, TimerType};
use super::tracing::OspfTracing;
use super::{
    AREA0, Identity, Lsdb, Neighbor, NfsmState, ospf_ls_ack_recv, ospf_ls_req_recv,
    ospf_ls_upd_recv,
};

pub type ShowCallback = fn(&Ospf, Args, bool) -> Result<String, std::fmt::Error>;

pub struct Ospf {
    ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub ptx: UnboundedSender<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_tx: UnboundedSender<rib::Message>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink>,
    pub areas: OspfAreaMap,
    pub table: PrefixMap<Ipv4Net, OspfNetworkConfig>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub router_id: Ipv4Addr,
    pub lsdb_as: Lsdb,
    pub lsp_map: LspMap,
    pub spf_result: Option<BTreeMap<usize, Path>>,
    pub graph: Option<spf::Graph>,
    pub rib: PrefixMap<Ipv4Net, SpfRoute>,
    pub tracing: OspfTracing,
    pub spf_last: Option<Instant>,
    pub spf_duration: Option<Duration>,
}

// OSPF inteface structure which points out upper layer struct members.
pub struct OspfInterface<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub router_id: &'a Ipv4Addr,
    pub ident: &'a Identity,
    pub addr: &'a Vec<OspfAddr>,
    pub mtu: u32,
    pub db_desc_in: &'a mut usize,
    pub lsdb: &'a mut Lsdb,
    pub lsdb_as: &'a mut Lsdb,
    pub area_id: Ipv4Addr,
    pub area_type: super::area::AreaType,
    pub if_state: super::ifsm::IfsmState,
    pub exchange_loading_count: usize,
    pub tracing: &'a OspfTracing,
}

impl Ospf {
    pub fn ospf_interface<'a>(
        &'a mut self,
        ifindex: u32,
        src: &Ipv4Addr,
    ) -> Option<(OspfInterface<'a>, &'a mut Neighbor)> {
        // Compute area-wide exchange/loading count before borrowing mutably.
        let exchange_loading_count = self.count_exchange_loading_neighbors(ifindex);
        self.links.get_mut(&ifindex).and_then(|link| {
            let link_area = link.area;
            let if_state = link.state;
            self.areas.get_mut(link_area).and_then(|area| {
                let area_type = area.area_type;
                link.nbrs.get_mut(&src).map(|nbr| {
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
                            if_state,
                            exchange_loading_count,
                            tracing: &self.tracing,
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

    pub fn new(ctx: Context, rib_tx: UnboundedSender<crate::rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = crate::rib::Message::Subscribe {
            proto: "ospf".to_string(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        let sock = Arc::new(AsyncFd::new(ospf_socket_ipv4().unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, prx) = mpsc::unbounded_channel();
        let mut ospf = Self {
            ctx,
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            rib_tx,
            links: BTreeMap::new(),
            areas: OspfAreaMap::new(),
            table: PrefixMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            router_id: Ipv4Addr::from_str("10.0.0.1").unwrap(),
            lsdb_as: Lsdb::new(),
            lsp_map: LspMap::default(),
            spf_result: None,
            graph: None,
            rib: PrefixMap::new(),
            tracing: OspfTracing::default(),
            spf_last: None,
            spf_duration: None,
            sock,
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
            link_type: OspfLinkType::Stub as u8,
            num_tos: 0,
            tos_0_metric: metric,
            toses: vec![],
        }
    }

    fn link_has_transit_adjacency(link: &OspfLink) -> bool {
        if link.state == IfsmState::Waiting || link.full_nbr_count == 0 {
            return false;
        }
        if link.ident.is_declared_dr() {
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
                let lsa_link = if use_transit {
                    RouterLsaLink {
                        // Transit link points to DR interface address.
                        link_id: link.ident.d_router,
                        link_data: addr.prefix.addr(),
                        link_type: OspfLinkType::Transit as u8,
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

    fn process_lsdb(&mut self, ev: LsdbEvent, area_id: Option<Ipv4Addr>, key: OspfLsaKey) {
        let (ls_type, ls_id, adv_router) = key;

        // Handle SelfOriginatedReceived before borrowing lsdb, since
        // re-origination needs full &mut self access.
        if ev == LsdbEvent::SelfOriginatedReceived {
            self.process_self_originated_lsa(area_id, ls_type, ls_id, adv_router);
            return;
        }

        // Handle RefreshTimerExpire: refresh in LSDB then flood to neighbors.
        if ev == LsdbEvent::RefreshTimerExpire {
            tracing::info!(
                "LSDB refresh timer expired: type={} id={} adv={}",
                ls_type,
                ls_id,
                adv_router
            );
            // Refresh the LSA and clone it for flooding.
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
            // Flood the refreshed LSA to all Full neighbors in the area.
            if let Some(lsa) = refreshed {
                if let Some(area_id) = area_id {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
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

        if ev == LsdbEvent::HoldTimerExpire
            && (ls_type == OspfLsType::Router || ls_type == OspfLsType::Network)
        {
            if let Some(area_id) = area_id {
                if let Some(area) = self.areas.get_mut(area_id) {
                    Self::ospf_spf_schedule(&self.tx, area);
                }
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
                if let Some(lsa) = flushed {
                    if let Some(area_id) = area_id {
                        self.flood_self_originated_lsa(area_id, &lsa);
                    }
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
                    return link.ident.is_declared_dr();
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
            let is_source_iface = source.map_or(false, |(src_if, _)| src_if == ifindex);

            // RFC 2328 Section 13.3 Step 3: If interface state is Backup and
            // LSA was received on this interface, do not flood back out.
            if is_source_iface && link_state == IfsmState::Backup {
                continue;
            }

            // RFC 2328 Section 13.3 Step 4: For broadcast/NBMA interfaces in
            // state DROther, only flood if we received from DR or BDR.
            if is_source_iface && link_state == IfsmState::DROther {
                if let Some((_, src_addr)) = source {
                    let dr = link.ident.d_router;
                    let bdr = link.ident.bd_router;
                    if src_addr != dr && src_addr != bdr {
                        continue;
                    }
                }
            }

            for (_, nbr) in link.nbrs.iter_mut() {
                // RFC 2328 Section 13.3 Step 1(a): Skip neighbors below Exchange.
                if nbr.state < NfsmState::Exchange {
                    continue;
                }

                // RFC 2328 Section 13.3 Step 1(c): Skip the source neighbor.
                if let Some((src_ifindex, src_addr)) = source {
                    if nbr.ifindex == src_ifindex && nbr.ident.prefix.addr() == src_addr {
                        continue;
                    }
                }

                // RFC 2328 Section 13.3 Step 1(b): For neighbors in
                // Exchange or Loading state, remove from ls_req if present.
                if nbr.state >= NfsmState::Exchange && nbr.state < NfsmState::Full {
                    if let Some(idx) = super::ospf_ls_request_lookup(nbr, &lsa.h) {
                        nbr.ls_req.remove(idx);
                    }
                }

                // RFC 2328 Section 13.3 Step 1(d): Add LSA to retransmit list.
                super::flood::ospf_ls_retransmit_add(nbr, lsa, retransmit_interval);

                let ls_upd = OspfLsUpdate {
                    num_adv: 1,
                    lsas: vec![lsa.clone()],
                };
                let packet = Ospfv2Packet::new(
                    &self.router_id,
                    &Ipv4Addr::UNSPECIFIED,
                    Ospfv2Payload::LsUpdate(ls_upd),
                );
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
        let packet = Ospfv2Packet::new(
            &self.router_id,
            &Ipv4Addr::UNSPECIFIED,
            Ospfv2Payload::LsUpdate(ls_upd),
        );
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
        let packet = Ospfv2Packet::new(
            &self.router_id,
            &Ipv4Addr::UNSPECIFIED,
            Ospfv2Payload::LsAck(ls_ack),
        );
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
        let (next, next_id) = super::config::link_should_enable(link, &self.table);
        super::config::apply_link_enable_transition(link, next, next_id);
    }

    fn link_del(&mut self, link: Link) {
        let Some(ospf_link) = self.links.get(&link.index) else {
            return;
        };
        if ospf_link.enabled {
            let area_id = ospf_link.area_id;
            ospf_link.tx.send(Message::Disable(link.index, area_id));
        }
        self.links.remove(&link.index);
    }

    fn link_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.link_flags |= LinkFlags::Up | LinkFlags::LowerUp;

        // If OSPF is enabled on this link, bring it up.
        if link.enabled {
            self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
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
            self.tx.send(Message::Disable(ifindex, area_id));
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
            OspfType::Unknown(typ) => {
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
                let area = self.areas.fetch(area_id);
                area.links.insert(ifindex);
                self.router_lsa_originate();
                self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
            }
            Message::Disable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = false;
                let area = self.areas.fetch(area_id);
                area.links.remove(&ifindex);
                self.router_lsa_originate();
                self.tx
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
                } else {
                    println!("NFSM: Packet from unknown neighbor {}", src);
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
            RibRx::LinkDel(link) => {
                self.link_del(link);
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

pub fn serve(mut ospf: Ospf) {
    tokio::spawn(async move {
        ospf.event_loop().await;
    });
}

pub enum Message {
    Enable(u32, Ipv4Addr),
    Disable(u32, Ipv4Addr),
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, Ipv4Addr, NfsmEvent),
    HelloTimer(u32),
    Recv(Ospfv2Packet, Ipv4Addr, Ipv4Addr, u32, Ipv4Addr),
    Send(Ospfv2Packet, u32, Option<Ipv4Addr>),
    Lsdb(LsdbEvent, Option<Ipv4Addr>, OspfLsaKey),
    /// Flood LSA through area, excluding source neighbor.
    /// (area_id, lsa, source_ifindex, source_nbr_addr)
    Flood(Ipv4Addr, OspfLsa, u32, Ipv4Addr),
    /// Flood AS-scoped LSA through all normal areas, excluding source neighbor.
    /// (lsa, source_ifindex, source_nbr_addr)
    FloodAs(OspfLsa, u32, Ipv4Addr),
    /// Retransmit LSAs to a specific neighbor.
    /// (ifindex, nbr_addr)
    Retransmit(u32, Ipv4Addr),
    /// Send delayed LS Acks on an interface.
    /// (ifindex)
    DelayedAck(u32),
    /// Queue delayed ack headers on an interface.
    /// (ifindex, headers)
    DelayedAckQueue(u32, Vec<OspfLsaHeader>),
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
            return *index;
        } else {
            let index = self.val.len();
            self.map.insert(router_id, index);
            self.val.push(router_id);
            return index;
        }
    }

    pub fn resolve(&self, id: usize) -> Option<&Ipv4Addr> {
        self.val.get(id)
    }
}

/// Build SPF graph from OSPF LSDB (Router-LSAs and Network-LSAs).
fn graph(top: &mut Ospf, area_id: Ipv4Addr) -> (spf::Graph, Option<usize>) {
    let mut graph = spf::Graph::new();
    let mut source_node = None;

    let Some(area) = top.areas.get(area_id) else {
        return (graph, source_node);
    };

    // Collect Router-LSA data.
    let mut router_lsas = Vec::new();
    for ((_ls_id, adv_router), lsa) in area.lsdb.tables.router.iter() {
        router_lsas.push((*adv_router, lsa.originated, lsa.data.clone()));
    }

    // Collect Network-LSA attached routers for transit network expansion.
    let mut network_lsas: HashMap<Ipv4Addr, Vec<Ipv4Addr>> = HashMap::new();
    for ((ls_id, _adv_router), lsa) in area.lsdb.tables.network.iter() {
        if let OspfLsp::Network(ref net_lsa) = lsa.data.lsp {
            network_lsas.insert(*ls_id, net_lsa.attached_routers.clone());
        }
    }

    // Process each Router-LSA to build graph nodes and edges.
    for (adv_router, originated, lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);

        if *originated {
            source_node = Some(node_id);
        }

        let mut node = spf::Node {
            id: node_id,
            name: adv_router.to_string(),
            sys_id: adv_router.to_string(),
            ..Default::default()
        };

        if let OspfLsp::Router(ref router_lsa) = lsa_data.lsp {
            for link in &router_lsa.links {
                match link.link_type {
                    1 | 4 => {
                        // Point-to-Point or Virtual Link: link_id = neighbor router ID.
                        let to_id = top.lsp_map.get(link.link_id);
                        node.olinks.push(spf::Link {
                            from: node_id,
                            to: to_id,
                            cost: link.tos_0_metric as u32,
                        });
                    }
                    2 => {
                        // Transit Network: expand through the Network-LSA pseudo-node.
                        // link_id = DR's interface IP, which is the Network-LSA's ls_id.
                        if let Some(attached) = network_lsas.get(&link.link_id) {
                            for attached_router in attached {
                                if *attached_router != *adv_router {
                                    let to_id = top.lsp_map.get(*attached_router);
                                    node.olinks.push(spf::Link {
                                        from: node_id,
                                        to: to_id,
                                        cost: link.tos_0_metric as u32,
                                    });
                                }
                            }
                        }
                    }
                    _ => {
                        // Stub (3) and unknown: not part of the SPF graph.
                    }
                }
            }
        }

        graph.insert(node_id, node);
    }

    (graph, source_node)
}

#[derive(Debug, PartialEq)]
pub struct SpfRoute {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub sid: Option<u32>,
    // pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
    pub router_id: Option<Ipv4Addr>,
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

    // Process each node in the SPF result
    for (node, nhops) in spf_result {
        // Skip self node
        if *node == source {
            continue;
        }

        // Resolve node to system ID
        let Some(router_id) = top.lsp_map.resolve(*node) else {
            continue;
        };

        // Build nexthop map
        let mut spf_nhops = BTreeMap::new();
        for p in &nhops.nexthops {
            // p.is_empty() means myself
            if !p.is_empty() {
                if let Some(nhop_id) = top.lsp_map.resolve(p[0]) {
                    // Find nhop from links
                    for (ifindex, link) in top.links.iter() {
                        for (_, nbr) in link.nbrs.iter() {
                            if *nhop_id == nbr.ident.router_id {
                                let addr = nbr.ident.prefix.addr();
                                let nhop = SpfNexthop {
                                    ifindex: *ifindex,
                                    adjacency: p[0] == *node,
                                    router_id: Some(*nhop_id),
                                };
                                spf_nhops.insert(addr, nhop);
                            }
                        }
                    }
                }
            }
        }

        // Process reachability entries for this node.
        if let Some(lsa) = area
            .lsdb
            .lookup_by_id(OspfLsType::Router, *router_id, *router_id)
        {
            if let OspfLsp::Router(ref router_lsa) = lsa.lsp {
                for link in &router_lsa.links {
                    let route = |prefix: Ipv4Net| SpfRoute {
                        metric: nhops.cost,
                        nhops: spf_nhops.clone(),
                        sid: None,
                    };
                    let insert = |rib: &mut PrefixMap<Ipv4Net, SpfRoute>,
                                  prefix: Ipv4Net,
                                  route: SpfRoute| {
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
                    };
                    match link.link_type {
                        2 => {
                            // Transit Network: look up Network-LSA to get the
                            // network prefix (link_id = dr's interface ip).
                            for ((_ls_id, _adv), nlsa) in area.lsdb.tables.network.iter() {
                                if let OspfLsp::Network(ref net) = nlsa.data.lsp {
                                    if nlsa.data.h.ls_id == link.link_id {
                                        let mask = u32::from(net.netmask).leading_ones() as u8;
                                        if let Ok(prefix) = Ipv4Net::new(link.link_id, mask) {
                                            let prefix = prefix.trunc();
                                            insert(&mut rib, prefix, route(prefix));
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        3 => {
                            // Stub Network: link_id = network addr,
                            // link_data = netmask.
                            let mask = u32::from(link.link_data).leading_ones() as u8;
                            if let Ok(prefix) = Ipv4Net::new(link.link_id, mask) {
                                let prefix = prefix.trunc();
                                insert(&mut rib, prefix, route(prefix));
                            }
                        }
                        _ => {
                            // Just ignore.
                        }
                    }
                }
            }
        }
    }

    rib
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
    rib::NexthopUni::from(*key, route.metric, mpls)
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
        let mut multi = rib::NexthopMulti::default();
        multi.metric = route.metric;
        for (key, value) in route.nhops.iter() {
            multi.nexthops.push(nhop_to_nexthop_uni(key, route, value));
        }
        rib::Nexthop::Multi(multi)
    };

    rib
}

pub fn diff_apply(rib_tx: UnboundedSender<rib::Message>, diff: &DiffResult) {
    // Delete.
    for (prefix, route) in diff.only_curr.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Del {
                prefix: **prefix,
                rib,
            };
            rib_tx.send(msg).unwrap();
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
            rib_tx.send(msg).unwrap();
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
            rib_tx.send(msg).unwrap();
        }
    }
}

/// Apply routing updates to RIB subsystem
fn apply_routing_updates(top: &mut Ospf, rib: PrefixMap<Ipv4Net, SpfRoute>) {
    // Update RIB
    let diff = spf::table_diff(top.rib.iter(), rib.iter());
    diff_apply(top.rib_tx.clone(), &diff);

    top.rib = rib;
}
