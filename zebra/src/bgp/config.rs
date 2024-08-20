use super::{
    handler::Callback,
    peer::{fsm_init, Peer, PeerType},
    AfiSafi, Bgp,
};

use crate::config::{Args, ConfigOp};
use std::net::Ipv4Addr;

fn config_global_asn(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set && !args.is_empty() {
        let asn = args.u32()?;
        bgp.asn = asn;
    }
    Some(())
}
fn config_global_identifier(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let router_id = args.v4addr()?;
        bgp.router_id = router_id;
    }
    Some(())
}

fn config_peer(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        if let Some(addr) = args.v4addr() {
            let peer = Peer::new(addr, bgp.asn, bgp.router_id, 0u32, addr, bgp.tx.clone());
            bgp.peers.insert(addr, peer);
        } else if let Some(addr) = args.v6addr() {
            println!("XXXX IPv6 address peer {}", addr);
            //let peer = Peer::new(addr, bgp.asn, bgp.router_id, 0u32, addr, bgp.tx.clone());
            //bgp.peers.insert(addr, peer);
        }
    }
    Some(())
}

fn config_peer_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        if let Some(addr) = args.v4addr() {
            let asn: u32 = args.u32()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.peer_as = asn;
                peer.peer_type = if peer.peer_as == bgp.asn {
                    PeerType::Internal
                } else {
                    PeerType::External
                };
                peer.update();
            }
        } else if let Some(addr) = args.v6addr() {
            println!("XXXX IPv6 address peer {}", addr);
        }
    }
    Some(())
}

fn config_afi_safi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr: Ipv4Addr = args.v4addr()?;
        let afi_safi: AfiSafi = args.afi_safi()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            if !peer.config.afi_safi.has(&afi_safi) {
                peer.config.afi_safi.push(afi_safi);
            }
        }
    }
    Some(())
}

fn config_local_identifier(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
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

fn config_transport_passive(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
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

fn config_hold_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr: Ipv4Addr = args.v4addr()?;
        let hold_time: u16 = args.u16()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.config.hold_time = Some(hold_time);
        }
    }
    Some(())
}

// fn config_clist(_bgp: &mut Bgp, mut _args: Args, _op: ConfigOp) -> Option<()> {
//     let _x = CommunityMember::Regexp(String::from("x"));
//     Some(())
// }

impl Bgp {
    fn callback_peer(&mut self, path: &str, cb: Callback) {
        let neighbor_prefix = String::from("/routing/bgp/neighbors/neighbor");
        self.callbacks.insert(neighbor_prefix + path, cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/routing/bgp/global/as", config_global_asn);
        self.callback_add("/routing/bgp/global/identifier", config_global_identifier);
        self.callback_peer("", config_peer);
        self.callback_peer("/peer-as", config_peer_as);
        self.callback_peer("/local-identifier", config_local_identifier);
        self.callback_peer("/transport/passive-mode", config_transport_passive);
        self.callback_peer("/afi-safis/afi-safi/enabled", config_afi_safi);
        self.callback_peer("/timers/hold-time", config_hold_time);
    }
}
