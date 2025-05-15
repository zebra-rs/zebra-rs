use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::IpNet;
use isis_packet::*;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::isis::addr::IsisAddr;
use crate::isis::nfsm::isis_nfsm;
use crate::isis::{ifsm, lsdb};
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::{self, Link, MacAddr};
use crate::{
    config::{path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest},
    context::Context,
    rib::RibRxChannel,
};

use super::config::IsisConfig;
use super::link::{IsisLink, IsisLinks, LinkTop};
use super::network::{read_packet, write_packet};
use super::socket::isis_socket;
use super::task::{Timer, TimerType};
use super::{process_packet, Level, Levels, NfsmState};
use super::{Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent};

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> String;

pub struct Isis {
    pub ctx: Context,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub ptx: UnboundedSender<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: IsisLinks,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub l2lsp: Option<IsisLsp>,
    pub config: IsisConfig,
    pub lsdb: Levels<Lsdb>,
    pub hostname: Levels<Hostname>,
}

pub struct IsisTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub links: &'a mut IsisLinks,
    pub config: &'a IsisConfig,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub hostname: &'a mut Levels<Hostname>,
}

pub struct NeighborTop<'a> {
    pub dis: &'a mut Levels<Option<IsisSysId>>,
    pub lan_id: &'a mut Levels<Option<IsisNeighborId>>,
}

impl Isis {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        let sock = Arc::new(AsyncFd::new(isis_socket().unwrap()).unwrap());

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, prx) = mpsc::unbounded_channel();
        let mut isis = Self {
            ctx,
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx: chan.rx,
            links: IsisLinks::default(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            sock,
            config: IsisConfig::default(),
            lsdb: Levels::<Lsdb>::default(),
            hostname: Levels::<Hostname>::default(),
            l2lsp: None,
        };
        isis.callback_build();
        isis.show_build();

        let tx = isis.tx.clone();
        let sock = isis.sock.clone();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });
        let sock = isis.sock.clone();
        tokio::spawn(async move {
            write_packet(sock, prx).await;
        });
        isis
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        // println!("XX path {} args {:?}", path, args);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::LinkAdd(link) => {
                self.link_add(link);
            }
            RibRx::AddrAdd(addr) => {
                self.addr_add(addr);
            }
            _ => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args, msg.json);
            msg.resp.send(output).await;
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Recv(packet, ifindex, mac) => {
                let mut top = self.top();
                process_packet(&mut top, packet, ifindex, mac);
            }
            Message::LspOriginate(level, ifindex) => {
                match level {
                    Level::L1 => {
                        //
                    }
                    Level::L2 => {
                        if let Some(lsp) = self.l2lsp_gen() {
                            self.l2lsp = Some(lsp);
                            // self.l2lspgen = Some(timer);
                        }
                        self.lsp_send(ifindex);
                        // self.l2seqnum += 1
                    }
                }
            }
            Message::Ifsm(ev, ifindex, level) => {
                let Some(mut top) = self.link_top(ifindex) else {
                    return;
                };
                match ev {
                    IfsmEvent::InterfaceUp => {
                        //
                    }
                    IfsmEvent::InterfaceDown => {
                        //
                    }
                    IfsmEvent::Start => {
                        ifsm::start(&mut top);
                    }
                    IfsmEvent::Stop => {
                        ifsm::stop(&mut top);
                    }
                    IfsmEvent::HelloTimerExpire => {
                        ifsm::hello_send(&mut top, level.unwrap());
                    }
                    IfsmEvent::HelloOriginate => match level {
                        Some(level) => ifsm::hello_originate(&mut top, level),
                        None => {
                            // In case of level is None, originate both L1/L2 Hello.
                            ifsm::hello_originate(&mut top, Level::L1);
                            ifsm::hello_originate(&mut top, Level::L2);
                        }
                    },
                    IfsmEvent::DisSelection => {
                        ifsm::dis_selection(&mut top, level.unwrap());
                    }
                }
            }
            Message::Nfsm(ev, ifindex, sysid, level) => {
                let ltop = self.link_top(ifindex);
                let Some(mut ltop) = ltop else {
                    return;
                };
                let mut ntop = NeighborTop {
                    dis: &mut ltop.state.dis,
                    lan_id: &mut ltop.state.lan_id,
                };
                let Some(nbr) = ltop.state.nbrs.get_mut(&level).get_mut(&sysid) else {
                    return;
                };

                isis_nfsm(&mut ntop, nbr, ev, &None, level);

                if nbr.state == NfsmState::Down {
                    ltop.state.nbrs.get_mut(&level).remove(&sysid);
                    // TODO.  Schedule SPF calculation.
                }
            }
            Message::Lsdb(ev, level, key) => {
                use LsdbEvent::*;
                let mut top = self.top();
                match ev {
                    RefreshTimerExpire => {
                        lsdb::refresh_lsp(&mut top, level, key);
                    }
                    HoldTimerExpire => {
                        lsdb::remove_lsp(&mut top, level, key);
                    }
                }
            }
            _ => {
                //
            }
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
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
            }
        }
    }
    pub fn top(&mut self) -> IsisTop {
        let top = IsisTop {
            links: &mut self.links,
            lsdb: &mut self.lsdb,
            hostname: &mut self.hostname,
            config: &self.config,
            tx: &self.tx,
        };
        top
    }

    pub fn link_top<'a>(&'a mut self, ifindex: u32) -> Option<LinkTop<'a>> {
        self.links.get_mut(&ifindex).map(|link| LinkTop {
            tx: &self.tx,
            ptx: &self.ptx,
            up_config: &self.config,
            config: &mut link.config,
            state: &mut link.state,
            timer: &mut link.timer,
        })
    }

    pub fn l2lsp_gen(&mut self) -> Option<IsisLsp> {
        let level = Level::L2;

        // LSP ID with no pseudo id and no fragmentation.
        let lsp_id = IsisLspId::new(self.config.net.sys_id(), 0, 0);

        // Generate own LSP for L2.
        let mut lsp = IsisLsp {
            hold_time: 1200,
            lsp_id,
            seq_number: 1,
            ..Default::default()
        };

        // Area address.
        let area_addr = self.config.net.area_id.clone();
        lsp.tlvs.push(IsisTlvAreaAddr { area_addr }.into());

        // Supported protocol
        let nlpids = vec![IsisProto::Ipv4.into()];
        lsp.tlvs.push(IsisTlvProtoSupported { nlpids }.into());

        // Hostname.
        let hostname = self.config.hostname();
        self.hostname
            .get_mut(&level)
            .insert_originate(self.config.net.sys_id(), hostname.clone());
        lsp.tlvs.push(IsisTlvHostname { hostname }.into());

        // Router capability. When TE-Router ID is configured, use the value. If
        // not when Router ID is configured, use the value. Otherwise system
        // default Router ID will be used.
        let router_id: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let mut cap = IsisTlvRouterCap {
            router_id,
            flags: 0.into(),
            subs: Vec::new(),
        };
        // Sub: SR Capability
        let mut flags = SegmentRoutingCapFlags::default();
        flags.set_i_flag(true);
        flags.set_v_flag(true);
        let sid_label = SidLabelTlv::Label(16000);
        let sr_cap = IsisSubSegmentRoutingCap {
            flags,
            range: 8000,
            sid_label,
        };
        cap.subs.push(sr_cap.into());

        // Sub: SR Algorithms
        let algo = IsisSubSegmentRoutingAlgo {
            algo: vec![Algo::Spf],
        };
        cap.subs.push(algo.into());

        // Sub: SR Local Block
        let sid_label = SidLabelTlv::Label(15000);
        let lb = IsisSubSegmentRoutingLB {
            flags: 0,
            range: 3000,
            sid_label,
        };
        cap.subs.push(lb.into());
        lsp.tlvs.push(cap.into());

        // TE Router ID.
        let te_router_id = IsisTlvTeRouterId { router_id };
        lsp.tlvs.push(te_router_id.into());

        // IS Reachability.
        for (_, link) in self.links.iter() {
            let Some(adj) = &link.state.adj.get(&level) else {
                continue;
            };
            // Ext IS Reach.
            let mut ext_is_reach = IsisTlvExtIsReach::default();
            let is_reach = IsisTlvExtIsReachEntry {
                neighbor_id: adj.clone(),
                metric: 10,
                subs: Vec::new(),
            };
            ext_is_reach.entries.push(is_reach);
            lsp.tlvs.push(ext_is_reach.into());
        }

        // IPv4 Reachability.

        // IPv6 Reachability.

        // Update LSDB.
        Some(lsp)
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.state.name.clone())
    }
}

pub fn serve(mut isis: Isis) {
    tokio::spawn(async move {
        isis.event_loop().await;
    });
}

pub enum Message {
    Recv(IsisPacket, u32, Option<MacAddr>),
    Send(IsisPacket, u32, Level),
    Ifsm(IfsmEvent, u32, Option<Level>),
    Nfsm(NfsmEvent, u32, IsisSysId, Level),
    Lsdb(LsdbEvent, Level, IsisLspId),
    LspOriginate(Level, u32),
}
