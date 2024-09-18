use super::api::RibRx;
use super::config::config_dispatch;
use super::entry::RibEntry;
use super::fib::fib_dump;
use super::fib::{FibChannel, FibHandle, FibMessage};
use super::{Link, RibTxChannel};
use crate::config::{path_from_command, Args};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
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
    pub rib: PrefixMap<Ipv4Net, Vec<RibEntry>>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
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
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.link_comps()).unwrap();
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                println!("Path: {}", path);
                config_dispatch(self, path, args, msg.op).await;
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

    pub fn rib_test(&self) {
        // static prefix 1.1.1.1/32 nexthop 10.211.55.1.
        // NexthopBuilder.address().build();
    }

    pub async fn event_loop(&mut self) {
        if let Err(_err) = fib_dump(&self.fib_handle, self.fib.tx.clone()).await {
            // warn!("FIB dump error {}", err);
        }

        // Dump done.
        self.rib_test();

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

    fn resolve_nexthop(&mut self) {
        println!("XXXXX resolve nexthop");
        for (key, _value) in self.rib.iter() {
            println!("Key: {}", key);
        }
    }
}

pub fn serve(mut rib: Rib) {
    tokio::spawn(async move {
        rib.event_loop().await;
    });
}
