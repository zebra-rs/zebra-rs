use std::net::Ipv4Addr;

use crate::config::ConfigOp;

use super::{peer::Peer, Bgp};

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
}
