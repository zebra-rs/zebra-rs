use super::api::RibRx;
use super::link::{link_show, LinkAddr};
use super::os::message::{FibChannel, OsAddr, OsLink, OsMessage, OsRoute};
use super::os::{os_dump_spawn, FibHandle};
use super::{Link, RibTxChannel};
use crate::config::{
    path_from_command, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel,
};
use ipnet::{IpNet, Ipv4Net};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
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
    pub redists: Vec<Sender<RibRx>>,
    pub links: BTreeMap<u32, Link>,
    pub rib: prefix_trie::PrefixMap<Ipv4Net, RibEntry>,
    pub callbacks: HashMap<String, Callback>,
    pub handle: FibHandle,
}

impl Rib {
    pub fn new() -> anyhow::Result<Self> {
        let handle = FibHandle::new()?;
        let mut rib = Rib {
            api: RibTxChannel::new(),
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            fib: FibChannel::new(),
            redists: Vec::new(),
            links: BTreeMap::new(),
            rib: prefix_trie::PrefixMap::new(),
            callbacks: HashMap::new(),
            handle,
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

    pub fn link_add(&mut self, oslink: OsLink) {
        if !self.links.contains_key(&oslink.index) {
            let link = Link::from(oslink);
            self.links.insert(link.index, link);
        }
    }

    pub fn link_delete(&mut self, oslink: OsLink) {
        self.links.remove(&oslink.index);
    }

    pub fn addr_add(&mut self, osaddr: OsAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            link_addr_update(link, addr);
        }
    }

    pub fn addr_del(&mut self, osaddr: OsAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            link_addr_del(link, addr);
        }
    }

    pub fn route_add(&mut self, osroute: OsRoute) {
        if let IpNet::V4(v4) = osroute.route {
            let mut rib = RibEntry::new();
            rib.rtype = RibType::KERNEL;
            rib.selected = true;
            rib.gateway = osroute.gateway;
            self.rib.insert(v4, rib);
        }
    }

    pub fn route_del(&mut self, osroute: OsRoute) {
        if let IpNet::V4(v4) = osroute.route {
            if let Some(_ribs) = self.rib.get(&v4) {
                //
            }
        }
    }

    fn process_os_message(&mut self, msg: OsMessage) {
        match msg {
            OsMessage::NewLink(link) => {
                self.link_add(link);
            }
            OsMessage::DelLink(link) => {
                self.link_delete(link);
            }
            OsMessage::NewAddr(addr) => {
                self.addr_add(addr);
            }
            OsMessage::DelAddr(addr) => {
                self.addr_del(addr);
            }
            OsMessage::NewRoute(route) => {
                self.route_add(route);
            }
            OsMessage::DelRoute(route) => {
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
        os_dump_spawn(self.fib.tx.clone()).await.unwrap();
        // self.handle = Some(handle);

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
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Nexthop {
    nexthop: Ipv4Addr,
}

#[derive(Debug)]
#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
enum RibType {
    UNKNOWN,
    KERNEL,
    CONNECTED,
    STATIC,
    RIP,
    OSPF,
    ISIS,
    BGP,
}

impl RibType {
    pub fn char(&self) -> char {
        match self {
            Self::KERNEL => 'K',
            Self::STATIC => 'S',
            _ => '?',
        }
    }
}

#[allow(dead_code, non_camel_case_types)]
#[derive(Debug)]
enum RibSubType {
    UNKNOWN,
    OSPF_IA,
    OSPF_NSSA_1,
    OSPF_NSSA_2,
    OSPF_EXTERNAL_1,
    OSPF_EXTERNAL_2,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RibEntry {
    rtype: RibType,
    rsubtype: RibSubType,
    selected: bool,
    distance: u32,
    tag: u32,
    color: Vec<String>,
    nexthops: Vec<Nexthop>,
    gateway: IpAddr,
}

impl RibEntry {
    pub fn new() -> Self {
        Self {
            rtype: RibType::UNKNOWN,
            rsubtype: RibSubType::UNKNOWN,
            selected: false,
            distance: 0,
            tag: 0,
            color: Vec::new(),
            nexthops: Vec::new(),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

pub fn rib_show(rib: &Rib, _args: Vec<String>) -> String {
    let mut buf = String::new();

    buf.push_str(
        r#"Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area\n"#,
    );

    for (prefix, entry) in rib.rib.iter() {
        writeln!(
            buf,
            "{}  {:?}     {:?}",
            entry.rtype.char(),
            prefix,
            entry.gateway
        )
        .unwrap();
    }

    buf
}

pub fn link_addr_update(link: &mut Link, addr: LinkAddr) {
    if addr.is_v4() {
        for a in link.addr4.iter() {
            if a.addr == addr.addr {
                return;
            }
        }
        link.addr4.push(addr);
    } else {
        for a in link.addr6.iter() {
            if a.addr == addr.addr {
                return;
            }
        }
        link.addr6.push(addr);
    }
}

pub fn link_addr_del(link: &mut Link, addr: LinkAddr) {
    if addr.is_v4() {
        if let Some(remove_index) = link.addr4.iter().position(|x| x.addr == addr.addr) {
            link.addr4.remove(remove_index);
        }
    } else if let Some(remove_index) = link.addr6.iter().position(|x| x.addr == addr.addr) {
        link.addr6.remove(remove_index);
    }
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
        rib.rib.insert(dest, entry);

        rib.handle.route_ipv4_add(dest, gateway).await;
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
