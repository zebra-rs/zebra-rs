use super::api::{RibRx, RibTx};
use super::entry::RibEntry;
use super::link::{LinkConfig, link_config_exec};
use super::{
    BridgeBuilder, BridgeConfig, Link, MplsConfig, Nexthop, NexthopMap, RibTxChannel, RibType,
    StaticConfig, Vxlan, VxlanBuilder, VxlanConfig,
};

use crate::config::{Args, path_from_command};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::fib::fib_dump;
use crate::fib::sysctl::sysctl_enable;
use crate::fib::{FibChannel, FibHandle, FibMessage};
use crate::rib::route::{ipv4_nexthop_sync, ipv4_route_sync};
use crate::rib::{Bridge, RibEntries};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

pub type ShowCallback = fn(&Rib, Args, bool) -> String;

pub enum Message {
    LinkUp {
        ifindex: u32,
    },
    LinkDown {
        ifindex: u32,
    },
    Ipv4Add {
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv4Del {
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv6Add {
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    Ipv6Del {
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    IlmAdd {
        label: u32,
        ilm: IlmEntry,
    },
    IlmDel {
        label: u32,
        ilm: IlmEntry,
    },
    BridgeAdd {
        name: String,
        config: BridgeConfig,
    },
    BridgeDel {
        name: String,
    },
    VxlanAdd {
        name: String,
        config: VxlanConfig,
    },
    VxlanDel {
        name: String,
    },
    Shutdown {
        tx: oneshot::Sender<()>,
    },
    Resolve,
    Subscribe {
        proto: String,
        tx: UnboundedSender<RibRx>,
    },
}

#[derive(Default, Debug, Clone, PartialEq)]
pub enum IlmType {
    #[default]
    None,
    Node(u32),
    Adjacency(u32),
}

#[derive(Default, Debug, Clone)]
pub struct IlmEntry {
    pub rtype: RibType,
    pub ilm_type: IlmType,
    pub nexthop: Nexthop,
}

impl IlmEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            ilm_type: IlmType::None,
            nexthop: Nexthop::default(),
        }
    }
}

pub struct Rib {
    pub api: RibTxChannel,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub fib: FibChannel,
    pub fib_handle: FibHandle,
    pub redists: Vec<UnboundedSender<RibRx>>,
    pub links: BTreeMap<u32, Link>,
    pub bridges: BTreeMap<String, Bridge>,
    pub vxlan: BTreeMap<String, Vxlan>,
    pub table: PrefixMap<Ipv4Net, RibEntries>,
    pub table_v6: PrefixMap<Ipv6Net, RibEntries>,
    pub ilm: BTreeMap<u32, IlmEntry>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub static_config: StaticConfig,
    pub mpls_config: MplsConfig,
    pub link_config: LinkConfig,
    pub bridge_config: BridgeBuilder,
    pub vxlan_config: VxlanBuilder,
    pub nmap: NexthopMap,
    pub router_id: Ipv4Addr,
}

impl Rib {
    pub fn new() -> anyhow::Result<Self> {
        let fib = FibChannel::new();
        let fib_handle = FibHandle::new(fib.tx.clone())?;
        let (tx, rx) = mpsc::unbounded_channel();
        let mut rib = Rib {
            api: RibTxChannel::new(),
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            fib,
            fib_handle,
            redists: Vec::new(),
            links: BTreeMap::new(),
            bridges: BTreeMap::new(),
            vxlan: BTreeMap::new(),
            table: PrefixMap::new(),
            table_v6: PrefixMap::new(),
            ilm: BTreeMap::new(),
            tx,
            rx,
            static_config: StaticConfig::new(),
            mpls_config: MplsConfig::new(),
            link_config: LinkConfig::new(),
            bridge_config: BridgeBuilder::new(),
            vxlan_config: VxlanBuilder::new(),
            nmap: NexthopMap::default(),
            router_id: Ipv4Addr::UNSPECIFIED,
        };
        rib.show_build();
        Ok(rib)
    }

    pub fn subscribe(&mut self, tx: UnboundedSender<RibRx>, _proto: String) {
        // Link dump.
        for (_, link) in self.links.iter() {
            let msg = RibRx::LinkAdd(link.clone());
            tx.send(msg).unwrap();
            for addr in link.addr4.iter() {
                let msg = RibRx::AddrAdd(addr.clone());
                tx.send(msg).unwrap();
            }
            for addr in link.addr6.iter() {
                let msg = RibRx::AddrAdd(addr.clone());
                tx.send(msg).unwrap();
            }
        }
        self.redists.push(tx.clone());
        if !self.router_id.is_unspecified() {
            let msg = RibRx::RouterIdUpdate(self.router_id);
            tx.send(msg).unwrap();
        }
        tx.send(RibRx::EoR).unwrap();
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Ipv4Add { prefix, rib } => {
                self.ipv4_route_add(&prefix, rib).await;
            }
            Message::Ipv4Del { prefix, rib } => {
                self.ipv4_route_del(&prefix, rib).await;
            }
            Message::Ipv6Add { prefix, rib } => {
                self.ipv6_route_add(&prefix, rib).await;
            }
            Message::Ipv6Del { prefix, rib } => {
                self.ipv6_route_del(&prefix, rib).await;
            }
            Message::IlmAdd { label, ilm } => {
                self.ilm_add(label, ilm).await;
            }
            Message::IlmDel { label, ilm } => {
                self.ilm_del(label, ilm).await;
            }
            Message::BridgeAdd { name, config } => {
                let bridge = Bridge {
                    name: name.clone(),
                    addr_gen_mode: config.addr_gen_mode,
                    ..Default::default()
                };
                self.bridges.insert(name.clone(), bridge.clone());
                self.fib_handle.bridge_add(&bridge).await;
            }
            Message::BridgeDel { name } => {
                let bridge = Bridge {
                    name: name.clone(),
                    ..Default::default()
                };
                self.bridges.remove(&name);
                self.fib_handle.bridge_del(&bridge).await;
            }
            Message::VxlanAdd { name, config } => {
                let vxlan = Vxlan {
                    name: name.clone(),
                    vni: config.vni,
                    local_addr: config.local_addr,
                    dport: config.dport,
                    addr_gen_mode: config.addr_gen_mode,
                    ..Default::default()
                };
                self.vxlan.insert(name.clone(), vxlan.clone());
                self.fib_handle.vxlan_add(&vxlan).await;
            }
            Message::VxlanDel { name } => {
                let vxlan = Vxlan {
                    name: name.clone(),
                    ..Default::default()
                };
                self.vxlan.remove(&name);
                self.fib_handle.vxlan_del(&vxlan).await;
            }
            Message::Shutdown { tx } => {
                self.nmap.shutdown(&self.fib_handle).await;
                let ilms = self.ilm.clone();

                for (&label, ilm) in ilms.iter() {
                    self.ilm_del(label, ilm.clone()).await;
                }
                for (_, bridge) in self.bridges.iter() {
                    self.fib_handle.bridge_del(bridge).await;
                }
                for (_, vxlan) in self.vxlan.iter() {
                    self.fib_handle.vxlan_del(vxlan).await;
                }
                let _ = tx.send(());
            }
            Message::LinkUp { ifindex } => {
                // println!("LinkUp {}", ifindex);
                self.link_up(ifindex).await;
            }
            Message::LinkDown { ifindex } => {
                // println!("LinkDown {}", ifindex);
                self.link_down(ifindex).await;
            }
            Message::Resolve => {
                self.ipv6_route_resolve().await;
            }
            Message::Subscribe { tx, proto } => {
                self.subscribe(tx, proto);
            }
        }
    }

    fn ifname(&self, ifindex: u32) -> String {
        if let Some(link) = self.links.get(&ifindex) {
            link.name.clone()
        } else {
            String::new()
        }
    }

    pub async fn process_fib_msg(&mut self, msg: FibMessage) {
        match msg {
            FibMessage::NewLink(link) => {
                self.link_add(link).await;
            }
            FibMessage::DelLink(link) => {
                self.link_delete(link);
            }
            FibMessage::NewAddr(addr) => {
                self.addr_add(addr);
                ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.fib_handle).await;
                ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle, true).await;
                self.router_id_update();
            }
            FibMessage::DelAddr(addr) => {
                self.addr_del(addr);
                ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.fib_handle).await;
                ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle, true).await;
                self.router_id_update();
            }
            FibMessage::NewRoute(route) => {
                if let IpNet::V4(prefix) = route.prefix {
                    self.ipv4_route_add(&prefix, route.entry).await;
                }
            }
            FibMessage::DelRoute(route) => {
                if let IpNet::V4(prefix) = route.prefix {
                    self.ipv4_route_del(&prefix, route.entry).await;
                }
            }
        }
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if path.as_str().starts_with("/routing/static/ipv4/route") {
                    let _ = self.static_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/routing/static/mpls/label") {
                    let _ = self.mpls_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/interface") {
                    // let _ = self.link_config.exec(path, args, msg.op);
                    link_config_exec(self, path, args, msg.op).await;
                } else if path.as_str().starts_with("/bridge") {
                    let _ = self.bridge_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/vxlan") {
                    let _ = self.vxlan_config.exec(path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                self.bridge_config.commit(self.tx.clone());
                self.vxlan_config.commit(self.tx.clone());
                self.link_config.commit(self.tx.clone());
                self.static_config.commit(self.tx.clone());
                self.mpls_config.commit(self.tx.clone());
            }
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.link_comps()).unwrap();
            }
            ConfigOp::Clear => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args, msg.json);
            msg.resp.send(output).await.unwrap();
        }
    }

    async fn process_api_msg(&mut self, msg: RibTx) {
        use ipnet::IpNet;

        match msg {
            RibTx::RouteAdd { prefix, entry } => match prefix {
                IpNet::V4(prefix) => {
                    let msg = Message::Ipv4Add { prefix, rib: entry };
                    self.process_msg(msg).await;
                }
                IpNet::V6(prefix) => {
                    let msg = Message::Ipv6Add { prefix, rib: entry };
                    self.process_msg(msg).await;
                }
            },
            RibTx::RouteDel { prefix, entry } => match prefix {
                IpNet::V4(prefix) => {
                    let msg = Message::Ipv4Del { prefix, rib: entry };
                    self.process_msg(msg).await;
                }
                IpNet::V6(prefix) => {
                    let msg = Message::Ipv6Del { prefix, rib: entry };
                    self.process_msg(msg).await;
                }
            },
            RibTx::Subscribe(subscription) => {
                let msg = Message::Subscribe {
                    proto: "bgp".to_string(),
                    tx: subscription.tx,
                };
                self.process_msg(msg).await;
            }
            RibTx::NexthopRegister() => {
                // TODO: Implement nexthop registration
            }
            RibTx::NexthopUnregister() => {
                // TODO: Implement nexthop unregistration
            }
        }
    }

    pub async fn event_loop(&mut self) {
        // Before get into FIB interaction, we enable sysctl.
        sysctl_enable();

        if let Err(_err) = fib_dump(self).await {
            // warn!("FIB dump error {}", err);
        }

        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.fib.rx.recv() => {
                    self.process_fib_msg(msg).await;
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.api.rx.recv() => {
                    self.process_api_msg(msg).await;
                }
            }
        }
    }
}

pub fn serve(mut rib: Rib) {
    let rib_tx = rib.tx.clone();
    tokio::spawn(async move {
        rib.event_loop().await;
    });
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let _ = rib_tx.send(Message::Shutdown { tx });
        rx.await.unwrap();
        std::process::exit(0);
    });
}
