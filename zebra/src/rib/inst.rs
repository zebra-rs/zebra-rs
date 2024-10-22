use super::api::RibRx;
use super::entry::RibEntry;
use super::fib::fib_dump;
use super::fib::{FibChannel, FibHandle, FibMessage};
use super::nexthop_map::NexthopMap;
use super::{Link, RibTxChannel};

use crate::config::{path_from_command, Args};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::rib::RibType;
use crate::rib::{static_config_commit, static_config_exec};
use crate::rib::{RibEntries, StaticRoute};
use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

pub type ShowCallback = fn(&Rib, Args) -> String;

pub enum Message {
    ResolveNexthop,
}

pub struct Rib {
    pub api: RibTxChannel,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub fib: FibChannel,
    pub fib_handle: FibHandle,
    pub redists: Vec<Sender<RibRx>>,
    pub links: BTreeMap<u32, Link>,
    pub rib: PrefixMap<Ipv4Net, RibEntries>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub nexthop: NexthopMap,
    pub cache: BTreeMap<Ipv4Net, StaticRoute>,
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
            rib: PrefixMap::new(),
            tx,
            rx,
            nexthop: NexthopMap::new(),
            cache: BTreeMap::new(),
        };
        rib.show_build();
        Ok(rib)
    }

    pub fn subscribe(&mut self, tx: Sender<RibRx>) {
        self.redists.push(tx);
    }

    fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::ResolveNexthop => {
                self.resolve_nexthop();
            }
        }
    }

    fn process_fib_msg(&mut self, msg: FibMessage) {
        match msg {
            FibMessage::NewLink(link) => {
                self.link_add(link);
            }
            FibMessage::DelLink(link) => {
                self.link_delete(link);
            }
            FibMessage::NewAddr(addr) => {
                self.addr_add(addr);
            }
            FibMessage::DelAddr(addr) => {
                self.addr_del(addr);
            }
            FibMessage::NewRoute(route) => {
                self.route_add(route);
            }
            FibMessage::DelRoute(route) => {
                self.route_del(route);
            }
        }
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {}
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                static_config_exec(self, path, args, msg.op);
            }
            ConfigOp::CommitEnd => {
                static_config_commit(&mut self.rib, &mut self.cache, &self.fib_handle).await;
            }
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.link_comps()).unwrap();
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args);
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn event_loop(&mut self) {
        if let Err(_err) = fib_dump(&self.fib_handle, self.fib.tx.clone()).await {
            // warn!("FIB dump error {}", err);
        }

        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
                Some(msg) = self.fib.rx.recv() => {
                    self.process_fib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }

    fn lookup(&self, addr: &Ipv4Addr) -> bool {
        let addr = Ipv4Net::new(*addr, 32).unwrap();
        let Some((a, b)) = self.rib.get_lpm(&addr) else {
            return false;
        };
        for e in b.ribs.iter() {
            if e.rtype == RibType::Connected {
                println!("Lookup {} onlink", a);
                return true;
            }
        }
        false
    }

    fn resolve_nexthop(&mut self) {
        //nmap.need_resolve_all();
        for (prefix, ribs) in self.rib.iter() {
            for v in ribs.ribs.iter() {
                if v.rtype == RibType::Static {
                    println!(" RIB: {} {:?}", prefix, v.rtype);
                    for n in v.nexthops.iter() {
                        if let Some(nhop) = n.addr {
                            let entry = self.nexthop.map.entry(nhop).or_default();
                            println!("  Nexthop: {} Resolved: {}", nhop, entry.resolved);
                            if !entry.resolved {
                                // entry.valid = lookup(rib, &nhop);
                                entry.valid = true;
                                entry.resolved = true;
                            }
                        }
                    }
                }
            }
        }

        for (_prefix, ribs) in self.rib.iter_mut() {
            let mut _fib: Option<&mut RibEntry> = None;
            for v in ribs.ribs.iter_mut() {
                if v.fib {
                    // fib = Some(v);
                }
            }
            let mut selected: Option<&mut RibEntry> = None;
            for v in ribs.ribs.iter_mut() {
                if let Some(other) = selected.as_ref() {
                    if v.distance < other.distance {
                        selected = Some(v);
                    }
                } else {
                    selected = Some(v);
                }
            }
            if let Some(selected) = selected {
                selected.fib = true;
            }
            // if !rib_same(fib, selected) {
            //     fib_update(fib, selected);
            // }
        }
    }
}

trait IpAddrExt<T> {
    fn to_host_prefix(&self) -> T;
}

impl IpAddrExt<Ipv4Net> for Ipv4Addr {
    fn to_host_prefix(&self) -> Ipv4Net {
        Ipv4Net::new(*self, Self::BITS as u8).unwrap()
    }
}

impl IpAddrExt<Ipv6Net> for Ipv6Addr {
    fn to_host_prefix(&self) -> Ipv6Net {
        Ipv6Net::new(*self, Self::BITS as u8).unwrap()
    }
}

fn lookup(rib: &PrefixMap<Ipv4Net, Vec<RibEntry>>, addr: &Ipv4Addr) -> bool {
    let p = addr.to_host_prefix();
    let Some((_, entry)) = rib.get_lpm(&p) else {
        return false;
    };
    entry.iter().any(|x| x.rtype == RibType::Connected)
}

pub fn serve(mut rib: Rib) {
    tokio::spawn(async move {
        rib.event_loop().await;
    });
}
