use crate::{fsm, Event, Peer};
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
}

fn bgp_global_set_asn(bgp: &mut Bgp, asn_str: String) {
    bgp.asn = asn_str.parse().unwrap();
}

fn bgp_global_set_router_id(bgp: &mut Bgp, router_id_str: String) {
    bgp.router_id = router_id_str.parse().unwrap();
}

fn bgp_peer_add(bgp: &mut Bgp, address: String, asn_str: String) {
    let addr: Ipv4Addr = address.parse().unwrap();
    let asn: u32 = asn_str.parse().unwrap();
    let peer = Peer::new(bgp.asn, bgp.router_id, asn, addr, bgp.tx.clone());
    bgp.peers.insert(addr, peer);
}

fn bgp_config_set(bgp: &mut Bgp, conf: String) {
    println!("{conf}");
    let paths: Vec<&str> = conf.split('/').collect();
    if paths.len() < 5 {
        return;
    }
    match paths[2] {
        "global" => match paths[3] {
            "as" => {
                bgp_global_set_asn(bgp, paths[4].to_string());
            }
            "router-id" => {
                bgp_global_set_router_id(bgp, paths[4].to_string());
            }
            _ => {}
        },
        "neighbors" => {
            if paths.len() < 7 {
                return;
            }
            bgp_peer_add(bgp, paths[4].to_string(), paths[6].to_string());
        }
        _ => {}
    }
}

impl Bgp {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
        }
    }

    pub fn set(&self, s: &str) {
        let _ = self.tx.send(Message::Config(String::from(s)));
    }

    pub async fn fetch(&mut self) -> Message {
        loop {
            if let Some(m) = self.rx.recv().await {
                return m;
            }
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            let msg = self.fetch().await;
            match msg {
                Message::Config(x) => {
                    bgp_config_set(self, x);
                }
                Message::Event(peer, event) => {
                    let peer = self.peers.get_mut(&peer).unwrap();
                    fsm(peer, event);
                }
            }
        }
    }
}

impl Default for Bgp {
    fn default() -> Self {
        Self::new()
    }
}
