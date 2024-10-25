use super::api::RibRx;
use super::entry::RibEntry;
use super::fib::fib_dump;
use super::fib::{FibChannel, FibHandle, FibMessage};
use super::nexthop::Nexthop;
use super::util::IpAddrExt;
use super::{Link, RibTxChannel, StaticConfig};

use crate::config::{path_from_command, Args};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::rib::RibEntries;
use crate::rib::RibType;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
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
    pub static_config: StaticConfig,
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
            static_config: StaticConfig::new(),
        };
        rib.show_build();
        Ok(rib)
    }

    pub fn subscribe(&mut self, tx: Sender<RibRx>) {
        self.redists.push(tx);
    }

    async fn ipv4_route_add(&mut self, rtype: RibType, prefix: &Ipv4Net, mut ribs: Vec<RibEntry>) {
        rib_delete(&mut self.rib, prefix, rtype);
        while let Some(mut rib) = ribs.pop() {
            rib.nexthops = self.resolve_nexthop(rib.nexthops);
            rib_add(&mut self.rib, prefix, rib);
        }
        let index = rib_select(&self.rib, prefix);
        rib_sync(&mut self.rib, prefix, index, &self.fib_handle).await;
    }

    async fn ipv4_route_del(&mut self, rtype: RibType, prefix: &Ipv4Net) {
        rib_delete(&mut self.rib, prefix, rtype);
        let index = rib_select(&self.rib, prefix);
        rib_sync(&mut self.rib, prefix, index, &self.fib_handle).await;
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Ipv4Add {
                rtype,
                prefix,
                ribs,
            } => {
                self.ipv4_route_add(rtype, &prefix, ribs).await;
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

    fn resolve_nexthop(&mut self, nexthops: Vec<Nexthop>) -> Vec<Nexthop> {
        let nexthops: Vec<_> = nexthops
            .into_iter()
            .map(|mut x| {
                let key = x.addr.to_host_prefix();
                if let Some((_, entries)) = self.rib.get_lpm(&key) {
                    if entries.ribs.is_empty() {
                        x.valid = false;
                    } else {
                        let fib = entries.ribs.first().unwrap();
                        if fib.rtype == RibType::Connected {
                            x.valid = true;
                        } else if fib.rtype == RibType::Static {
                            println!("Recursive Nexthop:");
                            for n in fib.nexthops.iter() {
                                println!("N: {}", n.addr);
                            }
                            x.recursive = fib.nexthops.clone();
                        }
                    }
                }
                x
            })
            .collect();
        nexthops
    }
}

pub fn serve(mut rib: Rib) {
    tokio::spawn(async move {
        rib.event_loop().await;
    });
}

fn rib_delete(rib: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, rtype: RibType) {
    if let Some(entries) = rib.get_mut(prefix) {
        entries.ribs.retain(|x| x.rtype != rtype);
    }
}

fn rib_select(rib: &PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net) -> Option<usize> {
    let entries = rib.get(prefix)?;
    let index = entries
        .ribs
        .iter()
        .filter(|x| x.valid)
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

fn rib_add(rib: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = rib.entry(*prefix).or_default();
    entries.ribs.push(entry);
}

async fn rib_sync(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    index: Option<usize>,
    fib: &FibHandle,
) {
    let Some(entries) = rib.get_mut(prefix) else {
        return;
    };

    while let Some(entry) = entries.fibs.pop() {
        fib.route_ipv4_del(prefix, &entry).await;
    }

    if let Some(sindex) = index {
        let entry = entries.ribs.get(sindex).unwrap();
        fib.route_ipv4_add(prefix, entry).await;
        entries.fibs.push(entry.clone());
    }
}
