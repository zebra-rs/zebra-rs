use super::peer::{fsm, Event, Peer};
use super::route::Route;
use crate::config::{
    path_from_command, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel,
};
use crate::rib::api::{RibRxChannel, RibTx};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum Message {
    Event(Ipv4Addr, Event),
    Show(Sender<String>),
}

pub type Callback = fn(&mut Bgp, Vec<String>, ConfigOp);
pub type ShowCallback = fn(&Bgp, Vec<String>) -> String;

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: BTreeMap<Ipv4Addr, Peer>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub rib: Sender<RibTx>,
    pub redist: RibRxChannel,
    pub callbacks: HashMap<String, Callback>,
    pub ptree: PrefixMap<Ipv4Net, Vec<Route>>,
}

fn bgp_global_asn(bgp: &mut Bgp, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && !args.is_empty() {
        let asn_str = &args[0];
        bgp.asn = asn_str.parse().unwrap();
    }
}
fn bgp_global_identifier(bgp: &mut Bgp, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && !args.is_empty() {
        let router_id_str = &args[0];
        bgp.router_id = router_id_str.parse().unwrap();
    }
}

fn bgp_neighbor_peer(bgp: &mut Bgp, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && !args.is_empty() {
        let peer_addr = &args[0];
        let addr: Ipv4Addr = peer_addr.parse().unwrap();
        let peer = Peer::new(addr, bgp.asn, bgp.router_id, 0u32, addr, bgp.tx.clone());
        bgp.peers.insert(addr, peer);
    }
}

fn bgp_neighbor_peer_as(bgp: &mut Bgp, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && args.len() > 1 {
        let peer_addr = &args[0];
        let peer_as = &args[1];
        let addr: Ipv4Addr = peer_addr.parse().unwrap();
        let asn: u32 = peer_as.parse().unwrap();
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.peer_as = asn;
            peer.update();
        }
    }
}

fn bgp_neighbor_local_identifier(bgp: &mut Bgp, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && args.len() > 1 {
        let peer_addr = &args[0];
        let local_identifier = &args[1];
        let addr: Ipv4Addr = peer_addr.parse().unwrap();
        let identifier: Ipv4Addr = local_identifier.parse().unwrap();
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.local_identifier = Some(identifier);
            peer.update();
        }
    }
}

fn bgp_neighbor_transport_passive(bgp: &mut Bgp, args: Vec<String>, op: ConfigOp) {
    if op == ConfigOp::Set && args.len() > 1 {
        let peer_addr = &args[0];
        let passive = &args[1];
        let addr: Ipv4Addr = peer_addr.parse().unwrap();
        let passive: bool = passive == "true";
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            println!("setting peer passive {}", passive);
            peer.config.transport.passive = passive;
            peer.timer.idle_hold_timer = None;
        }
    }
}

impl Bgp {
    pub fn new(rib: Sender<RibTx>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            ptree: PrefixMap::<Ipv4Net, Vec<Route>>::new(),
            rib,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            redist: RibRxChannel::new(),
            callbacks: HashMap::new(),
        };
        bgp.callback_build();
        bgp.show_build();
        bgp
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/routing/bgp/global/as", bgp_global_asn);
        self.callback_add("/routing/bgp/global/identifier", bgp_global_identifier);
        self.callback_add("/routing/bgp/neighbors/neighbor", bgp_neighbor_peer);
        self.callback_add(
            "/routing/bgp/neighbors/neighbor/peer-as",
            bgp_neighbor_peer_as,
        );
        self.callback_add(
            "/routing/bgp/neighbors/neighbor/local-identifier",
            bgp_neighbor_local_identifier,
        );
        self.callback_add(
            "/routing/bgp/neighbors/neighbor/transport/passive-mode",
            bgp_neighbor_transport_passive,
        );
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Event(peer, event) => {
                println!("Message::Event: {:?}", event);
                fsm(self, peer, event);
            }
            Message::Show(tx) => {
                self.tx.send(Message::Show(tx)).unwrap();
            }
        }
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
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
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
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

pub fn serve(mut bgp: Bgp) {
    tokio::spawn(async move {
        bgp.event_loop().await;
    });
}
