use super::api::RibRx;
use super::entry::RibEntry;
use super::{Link, LspConfig, NexthopMap, RibTxChannel, StaticConfig};

use crate::config::{path_from_command, Args};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::fib::fib_dump;
use crate::fib::{FibChannel, FibHandle, FibMessage};
use crate::rib::RibEntries;
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

pub type ShowCallback = fn(&Rib, Args, bool) -> String;

pub enum Message {
    LinkUp { ifindex: u32 },
    LinkDown { ifindex: u32 },
    Ipv4Del { prefix: Ipv4Net, rib: RibEntry },
    Ipv4Add { prefix: Ipv4Net, rib: RibEntry },
    Shutdown { tx: oneshot::Sender<()> },
    Resolve,
    Subscribe { tx: UnboundedSender<RibRx> },
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
    pub table: PrefixMap<Ipv4Net, RibEntries>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub static_config: StaticConfig,
    pub lsp_config: LspConfig,
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
            lsp_config: LspConfig::new(),
            nmap: NexthopMap::default(),
        };
        rib.show_build();
        Ok(rib)
    }

    pub fn subscribe(&mut self, tx: UnboundedSender<RibRx>) {
        // Link dump.
        for (_, link) in self.links.iter() {
            let msg = RibRx::Link(link.clone());
            let _ = tx.send(msg);
            for addr in link.addr4.iter() {
                let msg = RibRx::Addr(addr.clone());
                let _ = tx.send(msg);
            }
        }
        self.redists.push(tx);
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Ipv4Add { prefix, rib } => {
                self.ipv4_route_add(&prefix, rib).await;
            }
            Message::Ipv4Del { prefix, rib } => {
                self.ipv4_route_del(&prefix, rib).await;
            }
            Message::Shutdown { tx } => {
                self.nmap.shutdown(&self.fib_handle).await;
                let _ = tx.send(());
            }
            Message::LinkUp { ifindex } => {
                self.link_up(ifindex);
            }
            Message::LinkDown { ifindex } => {
                self.link_down(ifindex).await;
            }
            Message::Resolve => {
                self.ipv4_route_resolve().await;
            }
            Message::Subscribe { tx } => {
                self.subscribe(tx);
            }
        }
    }

    pub async fn process_fib_msg(&mut self, msg: FibMessage) {
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
            ConfigOp::CommitStart => {}
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                println!("Path: {path}");
                if path.as_str().starts_with("/routing/static/ipv4/route") {
                    let _ = self.static_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/routing/static/ipv4/lsp") {
                    let _ = self.lsp_config.exec(path, args, msg.op);
                }
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
            let output = f(self, args, msg.json);
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn event_loop(&mut self) {
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
