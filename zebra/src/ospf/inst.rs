use std::collections::{BTreeMap, HashMap};

use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

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
use super::link::OspfLink;

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;

pub struct Ospf {
    ctx: Context,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink>,
    pub areas: BTreeMap<u8, OspfArea>,
    pub table: PrefixMap<Ipv4Net, OspfAddr>,
}

impl Ospf {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<crate::rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = crate::rib::Message::Subscribe {
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        Self {
            ctx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rx: chan.rx,
            links: BTreeMap::new(),
            areas: BTreeMap::new(),
            table: PrefixMap::new(),
        }
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        // println!("path: {}", path);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    fn link_add(&mut self, link: Link) {
        println!("OSPF: LinkAdd {} {}", link.name, link.index);
        if let Some(link) = self.links.get_mut(&link.index) {
            //
        } else {
            let link = OspfLink::from(link);
            self.links.insert(link.index, link);
        }
    }

    fn addr_add(&mut self, addr: LinkAddr) {
        println!("OSPF: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        let addr = OspfAddr::from(&addr, prefix);
        link.addr.push(addr.clone());
        let entry = self.table.entry(*prefix).or_default();
        *entry = addr;
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

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.rx.recv() => {
                    self.process_rib_msg(msg);
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
