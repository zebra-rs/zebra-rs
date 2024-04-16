use super::{fsm, Event, Peer};
use crate::config::{path_from_command, ConfigChannel, ConfigOp, ConfigRequest, ShowChannel};
use crate::rib::api::{RibRxChannel, RibTx};
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum Message {
    Event(Ipv4Addr, Event),
    Show(Sender<String>),
}

type Callback = fn(&mut Bgp, Vec<String>, ConfigOp);

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: BTreeMap<Ipv4Addr, Peer>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub rib: Sender<RibTx>,
    pub redist: RibRxChannel,
    // pub ptree: prefix_trie::PrefixMap<Ipv4Net, u32>,
    pub callbacks: HashMap<String, Callback>,
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

impl Bgp {
    pub fn new(rib: Sender<RibTx>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            // ptree: prefix_trie::PrefixMap::<Ipv4Net, u32>::new(),
            rib,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            redist: RibRxChannel::new(),
            callbacks: HashMap::new(),
        };
        bgp.callback_build();
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
    }

    pub fn process_message(&mut self, msg: Message) {
        match msg {
            Message::Event(peer, event) => {
                println!("Message::Event: {:?}", event);
                let peer = self.peers.get_mut(&peer).unwrap();
                fsm(peer, event);
            }
            Message::Show(tx) => {
                self.tx.send(Message::Show(tx)).unwrap();
            }
        }
    }

    pub fn process_cm_message(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_message(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_message(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.tx.send(Message::Show(msg.resp)).unwrap();
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
