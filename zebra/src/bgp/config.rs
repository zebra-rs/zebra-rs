use super::{
    peer::{fsm_init, Peer},
    AfiSafi, Bgp,
};
use crate::config::{Args, ConfigOp};
use std::net::Ipv4Addr;

fn bgp_global_asn(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set && !args.is_empty() {
        let asn = args.u32()?;
        bgp.asn = asn;
    }
    Some(())
}
fn bgp_global_identifier(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let router_id = args.v4addr()?;
        bgp.router_id = router_id;
    }
    Some(())
}

fn bgp_neighbor_peer(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr: Ipv4Addr = args.v4addr()?;
        let peer = Peer::new(addr, bgp.asn, bgp.router_id, 0u32, addr, bgp.tx.clone());
        bgp.peers.insert(addr, peer);
    }
    Some(())
}

fn bgp_neighbor_peer_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr: Ipv4Addr = args.v4addr()?;
        let asn: u32 = args.u32()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.peer_as = asn;
            peer.update();
        }
    }
    Some(())
}

fn bgp_neighbor_afi_safi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr: Ipv4Addr = args.v4addr()?;
        let afi_safi: AfiSafi = args.afi_safi()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            if peer.config.afi_safi.has(&afi_safi) {
                peer.config.afi_safi.push(afi_safi);
            }
        }
    }
    Some(())
}

fn bgp_neighbor_local_identifier(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr: Ipv4Addr = args.v4addr()?;
        let identifier: Ipv4Addr = args.v4addr()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.local_identifier = Some(identifier);
            peer.update();
        }
    }
    Some(())
}

fn bgp_neighbor_transport_passive(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.v4addr()?;
    let passive = args.boolean()?;

    if op == ConfigOp::Set {
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.config.transport.passive = passive;
            peer.timer.idle_hold_timer = None;
            peer.state = fsm_init(peer);
        }
    }
    Some(())
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
        self.callback_add(
            "/routing/bgp/neighbors/neighbor/afi-safis/afi-safi/enabled",
            bgp_neighbor_afi_safi,
        );
    }
}
