use crate::bgp::InOut;

use bgp_packet::{
    Afi, AfiSafi, Safi,
    addpath::{AddPathSendReceive, AddPathValue},
};

use super::{
    Bgp,
    inst::Callback,
    peer::{Peer, PeerType},
    timer,
};

use crate::config::{Args, ConfigOp};
use crate::policy::com_list::*;
use std::net::{IpAddr, Ipv4Addr};

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
            let addr = IpAddr::V4(addr);
            let peer = Peer::new(addr, bgp.asn, bgp.router_id, 0u32, addr, bgp.tx.clone());
            bgp.peers.insert(addr, peer);
        } else if let Some(addr) = args.v6addr() {
            let addr = IpAddr::V6(addr);
            let peer = Peer::new(addr, bgp.asn, bgp.router_id, 0u32, addr, bgp.tx.clone());
            bgp.peers.insert(addr, peer);
        }
    }
    Some(())
}

fn config_peer_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        if let Some(addr) = args.v4addr() {
            let addr = IpAddr::V4(addr);
            let asn: u32 = args.u32()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.peer_as = asn;
                peer.peer_type = if peer.peer_as == bgp.asn {
                    PeerType::IBGP
                } else {
                    PeerType::EBGP
                };
                peer.start();
            }
        } else if let Some(addr) = args.v6addr() {
            let addr = IpAddr::V6(addr);
            let asn: u32 = args.u32()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.peer_as = asn;
                peer.peer_type = if peer.peer_as == bgp.asn {
                    PeerType::IBGP
                } else {
                    PeerType::EBGP
                };
                peer.start();
            }
        }
    }
    Some(())
}

fn config_policy_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };
    let Some(peer) = bgp.peers.get_mut(&addr) else {
        return None;
    };
    let policy = args.string()?;
    if op.is_set() {
        peer.policy_out = Some(policy);
    } else {
        peer.policy_out = None;
    }
    Some(())
}

use crate::policy;

fn config_prefix_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };
    let Some(peer) = bgp.peers.get_mut(&addr) else {
        return None;
    };
    let policy = args.string()?;
    if op.is_set() {
        let config = peer.prefix_set.get_mut(&InOut::Output);
        config.name = Some(policy.clone());

        let msg = policy::Message::Register {
            proto: "bgp".to_string(),
            name: policy,
            ident: peer.ident,
            policy_type: policy::PolicyType::PrefixSetOut,
        };
        let _ = bgp.policy_tx.send(msg);
    } else {
        let config = peer.prefix_set.get_mut(&InOut::Output);
        config.name = None;

        let msg = policy::Message::Unregister {
            proto: "bgp".to_string(),
            name: policy,
            ident: peer.ident,
            policy_type: policy::PolicyType::PrefixSetOut,
        };
        let _ = bgp.policy_tx.send(msg);
    }
    Some(())
}

fn config_route_reflector(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let Some(peer) = bgp.peers.get_mut(&addr) else {
        return None;
    };

    if op.is_set() && flag {
        peer.reflector_client = true;
    } else {
        peer.reflector_client = false;
    }
    None
}

fn config_afi_safi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        if let Some(addr) = args.v4addr() {
            let addr = IpAddr::V4(addr);
            let afi_safi: AfiSafi = args.afi_safi()?;
            let enabled: bool = args.boolean()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                if enabled {
                    if !peer.config.afi_safi.has(&afi_safi) {
                        peer.config.afi_safi.push(afi_safi);
                    }
                } else {
                    peer.config.afi_safi.remove(&afi_safi);
                }
            }
        } else if let Some(addr) = args.v6addr() {
            let addr = IpAddr::V6(addr);
            let afi_safi: AfiSafi = args.afi_safi()?;
            let enabled: bool = args.boolean()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                if enabled {
                    peer.config.afi_safi.set(afi_safi);
                } else {
                    peer.config.afi_safi.remove(&afi_safi);
                }
            }
        }
    }
    Some(())
}

fn config_rtc(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::Rtc);
    if let Some(peer) = bgp.peers.get_mut(&addr) {
        if op.is_set() {
            if !peer.config.afi_safi.has(&afi_safi) {
                peer.config.afi_safi.push(afi_safi);
            }
        } else {
            peer.config.afi_safi.remove(&afi_safi);
        }
    }
    Some(())
}

fn config_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    let network = args.v4net()?;
    if afi_safi.afi != Afi::Ip || afi_safi.safi != Safi::Unicast {
        return None;
    }
    if op.is_set() {
        bgp.route_add(network);
    } else {
        bgp.route_del(network);
    }
    Some(())
}

fn config_add_path(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        if let Some(addr) = args.v4addr() {
            let addr = IpAddr::V4(addr);
            let afi_safi: AfiSafi = args.afi_safi()?;
            let add_path_str: String = args.string()?;
            let send_receive: AddPathSendReceive = add_path_str.parse().ok()?;
            let add_path = AddPathValue {
                afi: afi_safi.afi,
                safi: afi_safi.safi,
                send_receive,
            };
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.config.add_path.insert(add_path);
            } else {
                // TODO
            }
        } else if let Some(addr) = args.v6addr() {
            let addr = IpAddr::V6(addr);
            let afi_safi: AfiSafi = args.afi_safi()?;
            let add_path_str: String = args.string()?;
            let send_receive: AddPathSendReceive = add_path_str.parse().ok()?;
            let add_path = AddPathValue {
                afi: afi_safi.afi,
                safi: afi_safi.safi,
                send_receive,
            };
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.config.add_path.insert(add_path);
            } else {
                // TODO
            }
        }
    }
    Some(())
}

fn config_restart(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.graceful_restart = Some(1);
    } else {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.graceful_restart = None;
    }
    Some(())
}

fn config_llgr(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.llgr = Some(1);
    } else {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.llgr = None;
    }
    Some(())
}

fn config_llgr_restart_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;
    let time = args.u32()?;

    if op.is_set() {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.llgr = Some(time);
    } else {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.llgr = Some(1);
    }

    Some(())
}

fn config_local_identifier(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let addr = if let Some(addr) = args.v4addr() {
            IpAddr::V4(addr)
        } else if let Some(addr) = args.v6addr() {
            IpAddr::V6(addr)
        } else {
            return None;
        };
        let identifier: Ipv4Addr = args.v4addr()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.local_identifier = Some(identifier);
            peer.start();
        }
    }
    Some(())
}

fn config_transport_passive(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };
    let passive = args.boolean()?;

    if let Some(peer) = bgp.peers.get_mut(&addr) {
        if op == ConfigOp::Set {
            peer.config.transport.passive = passive;
        } else {
            peer.config.transport.passive = false;
        }
    }

    Some(())
}

fn config_debug_category(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let category = args.string()?;
    let enable = op == ConfigOp::Set;

    match category.as_str() {
        "all" => {
            if enable {
                bgp.debug_flags.enable_all();
            } else {
                bgp.debug_flags.disable_all();
            }
        }
        "event" => bgp.debug_flags.event = enable,
        "update" => bgp.debug_flags.update = enable,
        "open" => bgp.debug_flags.open = enable,
        "notification" => bgp.debug_flags.notification = enable,
        "keepalive" => bgp.debug_flags.keepalive = enable,
        "fsm" => bgp.debug_flags.fsm = enable,
        "graceful-restart" => bgp.debug_flags.graceful_restart = enable,
        "route" => bgp.debug_flags.route = enable,
        "policy" => bgp.debug_flags.policy = enable,
        "packet-dump" => bgp.debug_flags.packet_dump = enable,
        _ => return None,
    }
    Some(())
}

impl Bgp {
    fn callback_peer(&mut self, path: &str, cb: Callback) {
        let neighbor_prefix = String::from("/routing/bgp/neighbor");
        self.callbacks.insert(neighbor_prefix + path, cb);
    }

    fn callback_afi_safi(&mut self, path: &str, cb: Callback) {
        let neighbor_prefix = String::from("/routing/bgp/neighbor");
        self.callbacks.insert(neighbor_prefix + path, cb);
    }

    fn timer(&mut self, path: &str, cb: Callback) {
        let prefix = String::from("/routing/bgp/neighbor/timers");
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/routing/bgp/global/as", config_global_asn);
        self.callback_add("/routing/bgp/global/identifier", config_global_identifier);
        self.callback_peer("", config_peer);
        self.callback_peer("/peer-as", config_peer_as);
        self.callback_peer("/local-identifier", config_local_identifier);
        self.callback_peer("/transport/passive-mode", config_transport_passive);
        self.callback_peer("/afi-safi/enabled", config_afi_safi);
        self.callback_peer("/afi-safi/add-path", config_add_path);
        self.callback_peer("/afi-safi/graceful-restart/enabled", config_restart);
        self.callback_peer("/afi-safi/long-lived-graceful-restart/enabled", config_llgr);
        self.callback_peer(
            "/afi-safi/long-lived-graceful-restart/restart-time",
            config_llgr_restart_time,
        );
        // self.callback_peer("/rtc", config_rtc);

        // Timer configuration.
        self.timer("/hold-time", timer::config::hold_time);
        self.timer("/idle-hold-time", timer::config::idle_hold_time);
        self.timer("/connect-retry-time", timer::config::connect_retry_time);
        self.timer("/delay-open-time", timer::config::delay_open_time);
        self.timer("/advertisement-interval", timer::config::adv_interval);
        self.timer("/originate-interval", timer::config::orig_interval);

        self.pcallback_add("/community-list", config_com_list);
        self.pcallback_add("/community-list/seq", config_com_list_seq);
        self.pcallback_add("/community-list/seq/action", config_com_list_action);

        // Debug configuration
        self.callback_add("/routing/bgp/debug", config_debug_category);

        // Network configuration
        self.callback_add("/routing/bgp/afi-safi/network", config_network);

        // Applying policy.
        self.callback_peer("/apply-policy/out", config_policy_out);
        self.callback_peer("/prefix-set/out", config_prefix_out);

        // Route Reflector.
        self.callback_peer("/route-reflector/client", config_route_reflector);
    }
}
