use super::api::RibRx;
use super::entry::{RibEntry, RibType};
use super::fib::message::{FibAddr, FibChannel, FibLink, FibMessage, FibRoute};
use super::fib::{fib_dump, FibHandle};
use super::link::{link_show, LinkAddr};
use super::show::rib_show;
use super::{Link, RibTxChannel};
use crate::config::{
    path_from_command, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel,
};
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc::Sender;

type Callback = fn(&mut Rib, Vec<String>, ConfigOp);
type ShowCallback = fn(&Rib, Vec<String>) -> String;

pub struct Rib {
    pub api: RibTxChannel,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub fib: FibChannel,
    pub fib_handle: FibHandle,
    pub redists: Vec<Sender<RibRx>>,
    pub links: BTreeMap<u32, Link>,
    pub rib: PrefixMap<Ipv4Net, Vec<RibEntry>>,
    pub callbacks: HashMap<String, Callback>,
}

impl Rib {
    pub fn new() -> anyhow::Result<Self> {
        let fib = FibChannel::new();
        let fib_handle = FibHandle::new(fib.tx.clone())?;
        let mut rib = Rib {
            api: RibTxChannel::new(),
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            fib,
            fib_handle,
            redists: Vec::new(),
            links: BTreeMap::new(),
            rib: prefix_trie::PrefixMap::new(),
            callbacks: HashMap::new(),
        };

        rib.callback_build();
        rib.show_build();
        Ok(rib)
    }

    pub fn subscribe(&mut self, tx: Sender<RibRx>) {
        self.redists.push(tx);
    }

    pub fn link_by_name(&self, link_name: &str) -> Option<&Link> {
        self.links
            .iter()
            .find_map(|(_, v)| if v.name == link_name { Some(v) } else { None })
    }

    pub fn link_comps(&self) -> Vec<String> {
        self.links.values().map(|link| link.name.clone()).collect()
    }

    #[allow(dead_code)]
    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn callback_build(&mut self) {
        // self.callback_add("/routing/static/route", static_route);
        // self.callback_add("/routing/static/route/nexthop", static_route_nexthop);
    }

    pub fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/interfaces", link_show);
        self.show_add("/show/ip/route", rib_show);
    }

    pub fn link_add(&mut self, oslink: FibLink) {
        if !self.links.contains_key(&oslink.index) {
            let link = Link::from(oslink);
            self.links.insert(link.index, link);
        }
    }

    pub fn link_delete(&mut self, oslink: FibLink) {
        self.links.remove(&oslink.index);
    }

    pub fn addr_add(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            if link_addr_update(link, addr.clone()).is_some() {
                let mut e = RibEntry::new();
                e.rtype = RibType::CONNECTED;
                e.link_index = link.index;
                e.distance = 0;
                e.selected = true;
                if let IpNet::V4(net) = addr.addr {
                    self.ipv4_add(net, e);
                }
            }
        }
    }

    pub fn addr_del(&mut self, osaddr: FibAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            link_addr_del(link, addr);
        }
    }

    pub fn route_add(&mut self, osroute: FibRoute) {
        if let IpNet::V4(v4) = osroute.route {
            let mut e = RibEntry::new();
            e.rtype = RibType::KERNEL;
            e.distance = 0;
            e.selected = true;
            e.gateway = osroute.gateway;
            if !e.gateway.is_unspecified() {
                self.ipv4_add(v4, e);
            }
        }
    }

    pub fn route_del(&mut self, osroute: FibRoute) {
        if let IpNet::V4(v4) = osroute.route {
            if let Some(_ribs) = self.rib.get(&v4) {
                //
            }
        }
    }

    fn process_os_message(&mut self, msg: FibMessage) {
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

    async fn process_cm_message(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.link_comps()).unwrap();
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if path == "/routing/static/route" {
                    static_route(self, args.clone(), msg.op.clone()).await;
                }
                if path == "/routing/static/route/nexthop" {
                    static_route_nexthop(self, args.clone(), msg.op.clone()).await;
                }
                // if let Some(f) = self.callbacks.get(&path) {
                //     f(self, args, msg.op);
                // }
            }
        }
    }

    async fn process_show_message(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args);
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn event_loop(&mut self) {
        if let Err(_err) = fib_dump(&self.fib_handle, self.fib.tx.clone()).await {
            // Logging FIB dump error.
        }

        loop {
            tokio::select! {
                Some(msg) = self.fib.rx.recv() => {
                    self.process_os_message(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_message(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_message(msg).await;
                }
            }
        }
    }

    pub fn link_name(&self, link_index: u32) -> Option<&String> {
        match self.links.get(&link_index) {
            Some(link) => Some(&link.name),
            _ => None,
        }
    }
}

pub fn link_addr_update(link: &mut Link, addr: LinkAddr) -> Option<()> {
    if addr.is_v4() {
        for a in link.addr4.iter() {
            if a.addr == addr.addr {
                return None;
            }
        }
        link.addr4.push(addr);
    } else {
        for a in link.addr6.iter() {
            if a.addr == addr.addr {
                return None;
            }
        }
        link.addr6.push(addr);
    }
    Some(())
}

pub fn link_addr_del(link: &mut Link, addr: LinkAddr) -> Option<()> {
    if addr.is_v4() {
        if let Some(remove_index) = link.addr4.iter().position(|x| x.addr == addr.addr) {
            link.addr4.remove(remove_index);
            return Some(());
        }
    } else if let Some(remove_index) = link.addr6.iter().position(|x| x.addr == addr.addr) {
        link.addr6.remove(remove_index);
        return Some(());
    }
    None
}

async fn static_route(_rib: &mut Rib, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && !args.is_empty() {
        // let asn_str = &args[0];
        // bgp.asn = asn_str.parse().unwrap();
    }
}

async fn static_route_nexthop(rib: &mut Rib, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && args.len() > 1 {
        let dest: Ipv4Net = args[0].parse().unwrap();
        let gateway: Ipv4Addr = args[1].parse().unwrap();
        //
        let mut entry = RibEntry::new();
        entry.rtype = RibType::STATIC;
        entry.gateway = IpAddr::V4(gateway);
        // XXX rib.rib.insert(dest, entry);

        rib.fib_handle.route_ipv4_add(dest, gateway).await;
        // if let Some(handle) = rib.handle.as_ref() {
        //     route_add(handle.clone(), dest, gateway).await;
        // }
    }
}

pub fn serve(mut rib: Rib) {
    tokio::spawn(async move {
        rib.event_loop().await;
    });
}

impl Rib {
    pub fn ipv4_add(&mut self, dest: Ipv4Net, e: RibEntry) {
        if let Some(n) = self.rib.get_mut(&dest) {
            n.push(e);
        } else {
            self.rib.insert(dest, vec![e]);
        }
    }
}
