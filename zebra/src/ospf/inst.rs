use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use alphanumeric_sort::sort_slice_by_c_str_key;
use ipnet::{IpNet, Ipv4Net};
use nix::sys::socket::sockopt::Ipv4PacketInfo;
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::addr::OspfAddr;
use crate::rib::api::RibRx;
use crate::rib::link::LinkAddr;
use crate::rib::Link;
use crate::{
    config::{path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest},
    context::Context,
    rib::RibRxChannel,
};

use super::area::OspfArea;
use super::config::OspfNetworkConfig;
use super::link::OspfLink;
use super::network::{ospf_socket, read_packet};

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Ospf, Args, bool) -> String;

pub struct Ospf {
    ctx: Context,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink>,
    pub areas: BTreeMap<u8, OspfArea>,
    pub table: PrefixMap<Ipv4Net, OspfNetworkConfig>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
}

impl Ospf {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<crate::rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = crate::rib::Message::Subscribe {
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        let mut ospf = Self {
            ctx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rx: chan.rx,
            links: BTreeMap::new(),
            areas: BTreeMap::new(),
            table: PrefixMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
        };
        ospf.callback_build();
        ospf.show_build();

        if let Ok(sock) = ospf_socket() {
            tokio::spawn(async move {
                read_packet(sock).await;
            });
        }

        ospf
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    fn link_add(&mut self, link: Link) {
        // println!("OSPF: LinkAdd {} {}", link.name, link.index);
        if let Some(link) = self.links.get_mut(&link.index) {
            //
        } else {
            let link = OspfLink::from(link);
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
        let entry = self.table.entry(*prefix).or_default();
        entry.addr = Some(addr);

        // Going to check.  supernet's network config.
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::Link(link) => {
                self.link_add(link);
            }
            RibRx::Addr(addr) => {
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
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
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
