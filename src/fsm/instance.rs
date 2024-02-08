use crate::Peer;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: Vec<Peer>,
    pub tx: UnboundedSender<String>,
    pub rx: UnboundedReceiver<String>,
}

pub fn bgp_global_set_asn(bgp: &mut Bgp, asn_str: String) {
    bgp.asn = asn_str.parse().unwrap();
}

fn bgp_global_set_router_id(bgp: &mut Bgp, router_id_str: String) {
    bgp.router_id = router_id_str.parse().unwrap();
}

fn bgp_peer_add(bgp: &mut Bgp, address: String, asn_str: String) {
    let addr: Ipv4Addr = address.parse().unwrap();
    let asn: u32 = asn_str.parse().unwrap();
    let peer = Peer::new(bgp.asn, bgp.router_id, asn, addr);
    bgp.peers.push(peer);
}

fn bgp_config_set(bgp: &mut Bgp, conf: String) {
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
        let (tx, rx) = mpsc::unbounded_channel::<String>();
        Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: Vec::new(),
            tx,
            rx,
        }
    }

    pub fn set(&self, s: &str) {
        let _ = self.tx.send(String::from(s));
    }

    pub async fn fetch(&mut self) -> String {
        match self.rx.recv().await {
            Some(s) => s,
            None => String::from(""),
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            let msg = self.fetch().await;
            bgp_config_set(self, msg);
        }
    }
}

impl Default for Bgp {
    fn default() -> Self {
        Self::new()
    }
}
