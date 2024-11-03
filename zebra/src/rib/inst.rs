use super::api::RibRx;
use super::entry::RibEntry;
use super::nexthop::Nexthop;
use super::{Link, NexthopMap, RibTxChannel, StaticConfig};

use crate::config::{path_from_command, Args};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::fib::fib_dump;
use crate::fib::{FibChannel, FibHandle, FibMessage};
use crate::rib::RibEntries;
use crate::rib::RibType;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

pub type ShowCallback = fn(&Rib, Args) -> String;

pub enum Message {
    Ipv4Del {
        rtype: RibType,
        prefix: Ipv4Net,
    },
    Ipv4Add {
        rtype: RibType,
        prefix: Ipv4Net,
        ribs: Vec<RibEntry>,
    },
}

pub enum Resolve {
    Onlink(u32),
    #[allow(dead_code)]
    Recursive(Vec<usize>),
    NotFound,
}

#[derive(Default)]
pub struct ResolveOpt {
    allow_default: bool,
    #[allow(dead_code)]
    limit: u8,
}

impl ResolveOpt {
    // Use default route for recursive lookup.
    pub fn allow_default(&self) -> bool {
        self.allow_default
    }

    // Zero means infinite lookup.
    #[allow(dead_code)]
    pub fn limit(&self) -> u8 {
        self.limit
    }
}

pub fn rib_resolve(
    table: &PrefixMap<Ipv4Net, RibEntries>,
    p: Ipv4Addr,
    opt: &ResolveOpt,
) -> Resolve {
    let Ok(key) = Ipv4Net::new(p, Ipv4Addr::BITS as u8) else {
        return Resolve::NotFound;
    };

    let Some((p, entries)) = table.get_lpm(&key) else {
        return Resolve::NotFound;
    };

    if !opt.allow_default() && p.prefix_len() == 0 {
        return Resolve::NotFound;
    }

    for entry in entries.ribs.iter() {
        if entry.rtype == RibType::Connected {
            return Resolve::Onlink(entry.ifindex);
        }
        if entry.rtype == RibType::Static {
            return Resolve::Recursive(entry.nhops.clone());
        }
    }
    Resolve::NotFound
}

fn resolve(nmap: &NexthopMap, nexthops: &[usize], opt: &ResolveOpt) -> (Vec<Nexthop>, u8) {
    let mut acc: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut sea_depth: u8 = 0;
    nexthops
        .iter()
        .filter_map(|r| nmap.get(*r))
        .for_each(|nhop| {
            resolve_func(nmap, nhop, &mut acc, &mut sea_depth, opt, 0);
        });
    let mut nvec: Vec<Nexthop> = Vec::new();
    for a in acc.iter() {
        nvec.push(Nexthop::new(*a));
    }
    (nvec, sea_depth)
}

fn resolve_func(
    nmap: &NexthopMap,
    nhop: &Nexthop,
    acc: &mut BTreeSet<Ipv4Addr>,
    sea_depth: &mut u8,
    opt: &ResolveOpt,
    depth: u8,
) {
    if opt.limit() > 0 && depth >= opt.limit() {
        return;
    }

    // if sea_depth depth is not current one.
    if *sea_depth < depth {
        *sea_depth = depth;
    }

    // Early exit if the current nexthop is invalid
    if nhop.invalid {
        return;
    }

    // Directly insert if on-link, otherwise recursively resolve nexthops
    if nhop.onlink {
        acc.insert(nhop.addr);
        return;
    }

    nhop.resolved
        .iter()
        .filter_map(|r| nmap.get(*r))
        .for_each(|nhop| {
            resolve_func(nmap, nhop, acc, sea_depth, opt, depth + 1);
        });
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
    pub table: PrefixMap<Ipv4Net, RibEntries>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub static_config: StaticConfig,
    pub nmap: NexthopMap,
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
            table: PrefixMap::new(),
            tx,
            rx,
            static_config: StaticConfig::new(),
            nmap: NexthopMap::default(),
        };
        rib.show_build();
        Ok(rib)
    }

    pub fn subscribe(&mut self, tx: Sender<RibRx>) {
        self.redists.push(tx);
    }

    async fn ipv4_route_add(&mut self, rtype: RibType, prefix: &Ipv4Net, mut rib: RibEntry) {
        let replace = rib_replace(&mut self.table, prefix, rib.rtype);

        if !rib.is_system() {
            for nhop in rib.nexthops.iter_mut() {
                let ngid = self.nmap.register_group(nhop.addr);
                nhop.ngid = ngid;
            }
            for nhop in rib.nexthops.iter() {
                let ngid = nhop.ngid;
                if let Some(uni) = self.nmap.get_mut(ngid) {
                    uni.resolve(&self.table);
                    uni.sync(&self.fib_handle).await;
                }
            }
        }
        rib_add(&mut self.table, prefix, rib);

        let selected = rib_select(&self.table, prefix);
        rib_sync(&mut self.table, prefix, selected, replace, &self.fib_handle).await;
    }

    async fn ipv4_route_del(&mut self, rtype: RibType, prefix: &Ipv4Net) {
        let replace = rib_replace(&mut self.table, prefix, rtype);
        let selected = rib_select(&self.table, prefix);
        rib_sync(&mut self.table, prefix, selected, replace, &self.fib_handle).await;
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Ipv4Add {
                rtype,
                prefix,
                mut ribs,
            } => {
                while let Some(rib) = ribs.pop() {
                    self.ipv4_route_add(rtype, &prefix, rib).await;
                }
            }
            Message::Ipv4Del { rtype, prefix } => {
                self.ipv4_route_del(rtype, &prefix).await;
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
                let _ = self.static_config.exec(path, args, msg.op);
            }
            ConfigOp::CommitEnd => {
                self.static_config.commit(self.tx.clone());
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
                    self.process_msg(msg).await;
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
}

pub fn serve(mut rib: Rib) {
    tokio::spawn(async move {
        rib.event_loop().await;
    });
}

fn rib_add(rib: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = rib.entry(*prefix).or_default();
    entries.ribs.push(entry);
}

fn rib_replace(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    rtype: RibType,
) -> Vec<RibEntry> {
    let Some(entries) = rib.get_mut(prefix) else {
        return vec![];
    };
    let (remain, replace): (Vec<_>, Vec<_>) =
        entries.ribs.drain(..).partition(|x| x.rtype != rtype);
    entries.ribs = remain;
    replace
}

fn rib_select(rib: &PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net) -> Option<usize> {
    let entries = rib.get(prefix)?;
    let index = entries
        .ribs
        .iter()
        .filter(|x| x.is_valid())
        .enumerate()
        .fold(
            None,
            |acc: Option<(usize, &RibEntry)>, (index, entry)| match acc {
                Some((_, aentry))
                    if entry.distance > aentry.distance
                        || (entry.distance == aentry.distance && entry.metric > aentry.metric) =>
                {
                    acc
                }
                _ => Some((index, entry)),
            },
        )
        .map(|(index, _)| index);

    index
}

async fn rib_sync(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    index: Option<usize>,
    mut replace: Vec<RibEntry>,
    fib: &FibHandle,
) {
    let Some(entries) = rib.get_mut(prefix) else {
        return;
    };

    while let Some(entry) = replace.pop() {
        if entry.is_fib() {
            fib.route_ipv4_del(prefix, &entry).await;
        }
    }

    if let Some(sindex) = index {
        let entry = entries.ribs.get_mut(sindex).unwrap();
        fib.route_ipv4_add(prefix, &entry).await;
        entry.set_fib(true);
    }
}
