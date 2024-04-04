use super::{fsm, Event, Peer};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum Message {
    Config(String),
    Event(Ipv4Addr, Event),
}

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: BTreeMap<Ipv4Addr, Peer>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm_rx: UnboundedReceiver<String>,
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
    let paths: Vec<&str> = conf.split('/').collect();
    if paths.len() < 5 {
        return;
    }
    match paths[3] {
        "global" => match paths[4] {
            "as" => {
                bgp_global_set_asn(bgp, paths[5].to_string());
            }
            "identifier" => {
                bgp_global_set_router_id(bgp, paths[5].to_string());
            }
            _ => {}
        },
        "neighbors" => {
            if paths.len() < 7 {
                return;
            }
            bgp_peer_add(bgp, paths[5].to_string(), paths[7].to_string());
        }
        _ => {}
    }
}

fn bgp_config_set_init(bgp: &mut Bgp) {
    bgp.set("/routing/bgp/global/as/1");
    bgp.set("/routing/bgp/global/identifier/10.211.65.2");
    bgp.set("/routing/bgp/neighbors/neighbor/10.211.55.65/peer-as/100");
}

impl Bgp {
    pub fn new(cm_rx: UnboundedReceiver<String>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            cm_rx,
        };
        bgp_config_set_init(&mut bgp);
        bgp.subscribe();
        bgp
    }

    fn subscribe(&self) {
        //let sub = SubscribeRequest {};
    }

    pub fn set(&self, s: &str) {
        let _ = self.tx.send(Message::Config(String::from(s)));
    }

    pub fn process_message(&mut self, msg: Message) {
        match msg {
            Message::Config(conf) => {
                println!("Message::Config: {conf}");
                bgp_config_set(self, conf);
            }
            Message::Event(peer, event) => {
                println!("Message::Event: {:?}", event);
                let peer = self.peers.get_mut(&peer).unwrap();
                fsm(peer, event);
            }
        }
    }

    pub fn process_cm_message(&mut self, msg: String) {
        println!("CM: {}", msg);
    }
}
