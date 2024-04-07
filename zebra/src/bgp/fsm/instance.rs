use super::{fsm, Event, Peer};
use crate::config::DisplayRequest;
use ipnet::Ipv4Net;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum Message {
    Event(Ipv4Addr, Event),
    Show(Sender<String>),
}

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: BTreeMap<Ipv4Addr, Peer>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm_rx: UnboundedReceiver<String>,
    pub show_rx: UnboundedReceiver<DisplayRequest>,
    pub ptree: prefix_trie::PrefixMap<Ipv4Net, u32>,
}

fn bgp_global_set_asn(bgp: &mut Bgp, asn_str: String) {
    bgp.asn = asn_str.parse().unwrap();
}

fn bgp_global_set_router_id(bgp: &mut Bgp, router_id_str: String) {
    bgp.router_id = router_id_str.parse().unwrap();
}

fn bgp_peer_add(bgp: &mut Bgp, address: String, asn_str: String) {
    let ident: Ipv4Addr = address.parse().unwrap();
    let addr: Ipv4Addr = address.parse().unwrap();
    let asn: u32 = asn_str.parse().unwrap();
    let peer = Peer::new(ident, bgp.asn, bgp.router_id, asn, addr, bgp.tx.clone());
    bgp.peers.insert(ident, peer);
}

fn bgp_config_set(bgp: &mut Bgp, conf: String) {
    let paths: Vec<&str> = conf.split(' ').collect();
    if paths.len() < 4 {
        return;
    }
    println!("CM: {:?}", paths);
    match paths[2] {
        "global" => match paths[3] {
            "as" => {
                bgp_global_set_asn(bgp, paths[4].to_string());
            }
            "identifier" => {
                bgp_global_set_router_id(bgp, paths[4].to_string());
            }
            _ => {}
        },
        "neighbors" => {
            if paths.len() < 6 {
                return;
            }
            bgp_peer_add(bgp, paths[4].to_string(), paths[6].to_string());
        }
        _ => {}
    }
}

impl Bgp {
    pub fn new(
        cm_rx: UnboundedReceiver<String>,
        show_rx: UnboundedReceiver<DisplayRequest>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            cm_rx,
            show_rx,
            ptree: prefix_trie::PrefixMap::<Ipv4Net, u32>::new(),
        }
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

    pub fn process_cm_message(&mut self, msg: String) {
        bgp_config_set(self, msg);
    }
}
