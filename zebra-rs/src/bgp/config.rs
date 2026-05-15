use std::net::{IpAddr, Ipv4Addr};

use bgp_packet::*;

use crate::bgp::InOut;
use crate::config::{Args, ConfigOp};
use crate::policy;
use crate::policy::com_list::*;
use crate::rib::api::FdbEntry;

use super::auth::{AoConfig, CryptoAlgorithm, Key};
use super::peer::BgpTop;
use super::route_clean;
use super::{
    Bgp,
    inst::Callback,
    peer::{PasswordEncoding, Peer, PeerType},
    timer,
};

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
        // Go through `set_router_id` so the new value is also
        // propagated to every existing peer's `router_id` snapshot
        // — peers created before the operator typed this line would
        // otherwise keep their stale (often 0.0.0.0) value and emit
        // OPEN with the wrong BGP Identifier.
        bgp.set_router_id(router_id);
    }
    Some(())
}

fn config_global_hostname(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let hostname = args.string()?;
    if op == ConfigOp::Set {
        bgp.config_set_hostname(Some(hostname));
    } else {
        bgp.config_set_hostname(None);
    }
    Some(())
}

fn config_peer(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    if op == ConfigOp::Set {
        let peer = Peer::new(
            0, // PeerMap will assign the stable index
            bgp.asn,
            bgp.router_id,
            0u32,
            addr,
            bgp.hostname(),
            bgp.tx.clone(),
        );
        bgp.peers.insert(addr, peer);
    } else {
        let peer_idx = match bgp.peers.get(&addr) {
            Some(peer) => peer.ident,
            None => return None,
        };

        // Defensively clear any listener auth entries associated with
        // this peer before removing it, in case the per-leaf delete
        // callbacks didn't fire (e.g., whole-neighbor delete without
        // explicit tcp-md5 / tcp-ao deletions first).
        clear_peer_listener_auth(bgp, &addr);

        let mut bgp_ref = BgpTop {
            router_id: &bgp.router_id,
            local_rib: &mut bgp.local_rib,
            tx: &bgp.tx,
            rib_tx: &bgp.rib_tx,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
        };
        route_clean(peer_idx, &mut bgp_ref, &mut bgp.peers);
        bgp.peers.remove(&addr);
    }
    Some(())
}

/// Remove any TCP MD5 / TCP-AO entries for `addr` from the
/// appropriate listening socket. Best-effort: logs warnings on
/// failure but does not propagate them, since the peer is being
/// torn down either way.
fn clear_peer_listener_auth(bgp: &mut Bgp, addr: &IpAddr) {
    let fd = match addr {
        IpAddr::V4(_) => bgp.listen_fd_v4,
        IpAddr::V6(_) => bgp.listen_fd_v6,
    };
    let Some(fd) = fd else { return };

    // MD5: setsockopt with an empty key removes the entry for this
    // peer address. Only issue the call if the peer had a password
    // configured.
    let had_md5 = bgp
        .peers
        .get(addr)
        .and_then(|p| p.config.transport.md5_password.as_ref())
        .is_some();
    if had_md5 && let Err(e) = super::auth::set_tcp_md5_key(fd, *addr, &[]) {
        tracing::warn!(
            peer = %addr,
            error = %e,
            "TCP MD5 del on listener failed during peer cleanup"
        );
    }

    // TCP-AO: needs the exact (send_id, recv_id) used at install
    // time, remembered on the peer.
    if let Some(peer) = bgp.peers.get_mut(addr)
        && let Some((send_id, recv_id)) = peer.last_ao_installed.take()
        && let Err(e) = super::auth::del_tcp_ao_key(fd, *addr, send_id, recv_id)
    {
        tracing::warn!(
            peer = %addr,
            send_id,
            recv_id,
            error = %e,
            "TCP-AO del on listener failed during peer cleanup"
        );
    }
}

/// `set router bgp neighbor <addr> neighbor-group <name>` —
/// stores the reference on the peer's `PeerConfig`. No inheritance
/// resolution yet; follow-up reads this and merges fields from
/// `Bgp::neighbor_groups`.
fn config_peer_neighbor_group(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    peer.config.neighbor_group = if op == ConfigOp::Set {
        args.string()
    } else {
        None
    };
    Some(())
}

fn config_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        if let Some(addr) = args.v4addr() {
            let addr = IpAddr::V4(addr);
            let asn: u32 = args.u32()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.remote_as = asn;
                peer.peer_type = if peer.remote_as == bgp.asn {
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
                peer.remote_as = asn;
                peer.peer_type = if peer.remote_as == bgp.asn {
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

/// Drive `Register` / `Unregister` messages to Policy as a peer's
/// attachment changes. `prior` is the name the peer was bound to
/// before this call (or None on first attach), `new` is what it's
/// being bound to now (or None on detach).
///
/// - prior == new: idempotent reapply, no-op.
/// - prior present, new differs: Unregister(prior) + Register(new).
/// - new only: Register(new) (first attach).
/// - prior only: Unregister(prior) (detach).
///
/// Always-Unregister-before-Register avoids the watcher leak that
/// previously occurred when the operator switched a peer from
/// `policy in hoge` to `policy in fuga` — the "hoge"
/// watcher would otherwise stay registered forever.
fn policy_attach_msgs(
    policy_tx: &tokio::sync::mpsc::UnboundedSender<policy::Message>,
    ident: usize,
    policy_type: policy::PolicyType,
    prior: Option<String>,
    new: Option<String>,
) {
    if prior == new {
        return;
    }
    if let Some(prior_name) = prior {
        let _ = policy_tx.send(policy::Message::Unregister {
            proto: "bgp".to_string(),
            name: prior_name,
            ident,
            policy_type,
        });
    }
    if let Some(new_name) = new {
        let _ = policy_tx.send(policy::Message::Register {
            proto: "bgp".to_string(),
            name: new_name,
            ident,
            policy_type,
        });
    }
}

fn config_policy_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    let peer_ident = peer.ident;
    let config = peer.policy_list.get_mut(&InOut::Input);
    let prior = match &new_name {
        Some(n) => config.name.replace(n.clone()),
        None => config.name.take(),
    };
    policy_attach_msgs(
        &bgp.policy_tx,
        peer_ident,
        policy::PolicyType::PolicyListIn,
        prior,
        new_name,
    );
    Some(())
}

fn config_policy_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    let peer_ident = peer.ident;
    let config = peer.policy_list.get_mut(&InOut::Output);
    let prior = match &new_name {
        Some(n) => config.name.replace(n.clone()),
        None => config.name.take(),
    };
    policy_attach_msgs(
        &bgp.policy_tx,
        peer_ident,
        policy::PolicyType::PolicyListOut,
        prior,
        new_name,
    );
    Some(())
}

fn config_prefix_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    let peer_ident = peer.ident;
    let config = peer.prefix_set.get_mut(&InOut::Input);
    let prior = match &new_name {
        Some(n) => config.name.replace(n.clone()),
        None => config.name.take(),
    };
    policy_attach_msgs(
        &bgp.policy_tx,
        peer_ident,
        policy::PolicyType::PrefixSetIn,
        prior,
        new_name,
    );
    Some(())
}

fn config_prefix_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    let peer_ident = peer.ident;
    let config = peer.prefix_set.get_mut(&InOut::Output);
    let prior = match &new_name {
        Some(n) => config.name.replace(n.clone()),
        None => config.name.take(),
    };
    policy_attach_msgs(
        &bgp.policy_tx,
        peer_ident,
        policy::PolicyType::PrefixSetOut,
        prior,
        new_name,
    );
    Some(())
}

fn config_route_reflector(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let peer = bgp.peers.get_mut(&addr)?;

    peer.reflector_client = op.is_set() && flag;
    None
}

fn config_soft_reconfig_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let peer = bgp.peers.get_mut(&addr)?;

    peer.config.soft_reconfig_in = op.is_set() && flag;
    Some(())
}

fn config_afi_safi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let key: AfiSafi = args.afi_safi()?;
    let enabled: bool = args.boolean()?;

    let ipv4_unicast = key.afi == Afi::Ip && key.safi == Safi::Unicast;

    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        if enabled {
            peer.config.mp.set(key, true);
        } else {
            peer.config.mp.remove(&key);
        }
    } else {
        if ipv4_unicast {
            peer.config.mp.set(key, true);
        } else {
            peer.config.mp.remove(&key);
        }
    }
    Some(())
}

#[allow(dead_code)]
fn config_rtc(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::Rtc);
    if let Some(peer) = bgp.peers.get_mut(&addr) {
        if op.is_set() {
            peer.config.mp.set(afi_safi, true);
        } else {
            peer.config.mp.remove(&afi_safi);
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

fn config_advertise_all_vni(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    // The leaf only carries meaning for evpn; ignore on other
    // AFI/SAFIs. The YANG `advertise-all-vni` extension is augmented
    // into the global afi-safi list which spans every AF, so we have
    // to filter at the callback.
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let was_enabled = bgp.advertise_all_vni;
    let enabled = if op.is_set() { args.boolean()? } else { false };
    bgp.advertise_all_vni = enabled;

    // Replay the local FDB cache across the gate transition. The
    // false→true case fixes the cold-boot race: fib_dump's FdbAdd
    // events arrive on `rib_rx` before `config.load_config` lands the
    // advertise-all-vni Set on `cm.rx`, so on the live ingest path
    // every entry was dropped at the gate inside `evpn_originate_macip`.
    // The true→false case mirrors what an operator-driven runtime
    // toggle should do — clear the originated routes from peers.
    if !was_enabled && enabled {
        let entries: Vec<FdbEntry> = bgp.local_fdb.values().cloned().collect();
        for entry in entries {
            bgp.evpn_originate_macip(&entry);
        }
        let vxlans: Vec<(u32, std::net::IpAddr)> =
            bgp.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
        for (vni, vtep_local) in vxlans {
            bgp.evpn_originate_imet(vni, vtep_local);
        }
    } else if was_enabled && !enabled {
        let entries: Vec<FdbEntry> = bgp.local_fdb.values().cloned().collect();
        for entry in entries {
            bgp.evpn_withdraw_macip(&entry);
        }
        let vxlans: Vec<(u32, std::net::IpAddr)> =
            bgp.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
        for (vni, vtep_local) in vxlans {
            bgp.evpn_withdraw_imet(vni, vtep_local);
        }
    }
    Some(())
}

fn config_add_path(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;
    let add_path_str: String = args.string()?;
    let send_receive: AddPathSendReceive = add_path_str.parse().ok()?;

    if op.is_set() {
        let add_path = AddPathValue {
            afi: afi_safi.afi,
            safi: afi_safi.safi,
            send_receive,
        };
        peer.config.addpath.insert(afi_safi, add_path);
    } else {
        peer.config.addpath.remove(&afi_safi);
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

fn config_transport_local_address(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let peer_addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };

    let peer = bgp.peers.get_mut(&peer_addr)?;

    if op == ConfigOp::Set {
        let source = if let Some(addr) = args.v4addr() {
            IpAddr::V4(addr)
        } else if let Some(addr) = args.v6addr() {
            IpAddr::V6(addr)
        } else {
            return None;
        };
        // Address family of the source must match the peer.
        if source.is_ipv4() != peer_addr.is_ipv4() {
            return None;
        }
        peer.config.transport.update_source = Some(source);
    } else {
        peer.config.transport.update_source = None;
    }

    Some(())
}

fn config_peer_tcp_md5_password(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };

    let password_bytes: Vec<u8> = if op == ConfigOp::Set {
        let password = args.string()?;
        let bytes = password.as_bytes().to_vec();
        bgp.peers.get_mut(&addr)?.config.transport.md5_password = Some(password);
        bytes
    } else {
        bgp.peers.get_mut(&addr)?.config.transport.md5_password = None;
        Vec::new()
    };

    // Install (or remove, with an empty key) on the listener for this
    // peer's address family. The kernel requires the key to be on the
    // listener before the peer's SYN arrives — a post-accept() call
    // is too late.
    let listen_fd = match addr {
        IpAddr::V4(_) => bgp.listen_fd_v4,
        IpAddr::V6(_) => bgp.listen_fd_v6,
    };
    if let Some(fd) = listen_fd
        && let Err(e) = super::auth::set_tcp_md5_key(fd, addr, &password_bytes)
    {
        tracing::warn!(
            peer = %addr,
            error = %e,
            "TCP MD5 setsockopt on listener failed; incoming SYNs from this peer will be dropped"
        );
    }

    Some(())
}

fn config_peer_tcp_md5_encoding(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };

    let peer = bgp.peers.get_mut(&addr)?;

    if op == ConfigOp::Set {
        let encoding = args.string()?;
        peer.config.transport.md5_encoding = match encoding.as_str() {
            "clear" => PasswordEncoding::Clear,
            "encrypted" => PasswordEncoding::Encrypted,
            _ => return None,
        };
    } else {
        peer.config.transport.md5_encoding = PasswordEncoding::Clear;
    }

    Some(())
}

/// Re-resolve TCP-AO keys for every peer whose `ao_config` is set
/// and reconcile the listener state. If the previously installed
/// (send_id, recv_id) pair differs from the newly resolved one (or
/// disappears), the old entry is removed via
/// `setsockopt(TCP_AO_DEL_KEY)` before the new one is installed —
/// the kernel keys MKTs by (address, send_id, recv_id) and has no
/// wildcard delete.
///
/// Called from every TCP-AO callback (peer-side and key-chain-side)
/// after the change has been absorbed into `Bgp`.
fn apply_ao_refresh_all(bgp: &mut Bgp) {
    let fd_v4 = bgp.listen_fd_v4;
    let fd_v6 = bgp.listen_fd_v6;
    // Snapshot key_chains to release the immutable borrow before
    // iterating peers mutably.
    let key_chains = bgp.key_chains.clone();

    let addrs: Vec<IpAddr> = bgp.peers.keys().copied().collect();
    for addr in addrs {
        let Some(peer) = bgp.peers.get_mut(&addr) else {
            continue;
        };

        let fd = match addr {
            IpAddr::V4(_) => fd_v4,
            IpAddr::V6(_) => fd_v6,
        };

        let resolved = peer
            .config
            .transport
            .ao_config
            .as_ref()
            .and_then(|ao| ao.resolve(&key_chains));
        peer.config.transport.resolved_ao_key = resolved.clone();

        let new_ids = resolved.as_ref().map(|r| (r.send_id, r.recv_id));

        // Remove the stale listener entry if the resolved key now
        // disappears or uses different SendID/RecvID.
        if let (Some(prev_ids), Some(fd)) = (peer.last_ao_installed, fd)
            && new_ids != Some(prev_ids)
        {
            if let Err(e) = super::auth::del_tcp_ao_key(fd, addr, prev_ids.0, prev_ids.1) {
                tracing::warn!(
                    peer = %addr,
                    send_id = prev_ids.0,
                    recv_id = prev_ids.1,
                    error = %e,
                    "TCP-AO del on listener failed; entry may be stale",
                );
            }
            peer.last_ao_installed = None;
        }

        let Some(r) = resolved else {
            continue;
        };
        let Some(fd) = fd else {
            continue;
        };
        match super::auth::set_tcp_ao_key(
            fd,
            addr,
            r.alg_name,
            &r.key_material,
            r.send_id,
            r.recv_id,
            r.include_tcp_options,
        ) {
            Ok(()) => peer.last_ao_installed = Some((r.send_id, r.recv_id)),
            Err(e) => {
                tracing::warn!(
                    peer = %addr,
                    error = %e,
                    "TCP-AO setsockopt on listener failed; incoming SYNs from this peer will be dropped"
                );
            }
        }
    }
}

// ---------- TCP-AO per-neighbor callbacks ----------

fn config_peer_tcp_ao_key_chain(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };

    {
        let peer = bgp.peers.get_mut(&addr)?;
        if op == ConfigOp::Set {
            let chain_name = args.string()?;
            let ao = peer
                .config
                .transport
                .ao_config
                .get_or_insert_with(AoConfig::default);
            ao.key_chain = chain_name;
        } else {
            peer.config.transport.ao_config = None;
            peer.config.transport.resolved_ao_key = None;
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_peer_tcp_ao_include_tcp_options(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else if let Some(addr) = args.v6addr() {
        IpAddr::V6(addr)
    } else {
        return None;
    };

    {
        let peer = bgp.peers.get_mut(&addr)?;
        let ao = peer
            .config
            .transport
            .ao_config
            .get_or_insert_with(AoConfig::default);
        if op == ConfigOp::Set {
            ao.include_tcp_options = args.boolean()?;
        } else {
            ao.include_tcp_options = true;
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

// ---------- Key-chain callbacks ----------

fn config_key_chain(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op == ConfigOp::Set {
        bgp.key_chains.entry(name).or_default();
    } else {
        bgp.key_chains.remove(&name);
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_key_chain_description(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let chain = bgp.key_chains.get_mut(&name)?;
    chain.description = if op == ConfigOp::Set {
        Some(args.string()?)
    } else {
        None
    };
    Some(())
}

fn config_key_chain_key(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let chain_name = args.string()?;
    let key_id = args.u64()?;
    {
        let chain = bgp.key_chains.get_mut(&chain_name)?;
        if op == ConfigOp::Set {
            chain.keys.entry(key_id).or_insert_with(Key::new);
        } else {
            chain.keys.remove(&key_id);
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_key_chain_key_crypto_algorithm(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let chain_name = args.string()?;
    let key_id = args.u64()?;
    {
        let chain = bgp.key_chains.get_mut(&chain_name)?;
        let key = chain.keys.get_mut(&key_id)?;
        if op == ConfigOp::Set {
            let algo = args.string()?;
            key.crypto_algorithm = CryptoAlgorithm::from_identity(&algo);
        } else {
            key.crypto_algorithm = None;
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_key_chain_key_keystring(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let chain_name = args.string()?;
    let key_id = args.u64()?;
    {
        let chain = bgp.key_chains.get_mut(&chain_name)?;
        let key = chain.keys.get_mut(&key_id)?;
        if op == ConfigOp::Set {
            key.key_material = args.string()?.into_bytes();
        } else {
            key.key_material.clear();
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_key_chain_key_hex_string(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let chain_name = args.string()?;
    let key_id = args.u64()?;
    {
        let chain = bgp.key_chains.get_mut(&chain_name)?;
        let key = chain.keys.get_mut(&key_id)?;
        if op == ConfigOp::Set {
            let hex = args.string()?;
            let cleaned: String = hex
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':')
                .collect();
            let decoded = hex::decode(&cleaned).ok()?;
            key.key_material = decoded;
        } else {
            key.key_material.clear();
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_key_chain_key_send_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let chain_name = args.string()?;
    let key_id = args.u64()?;
    {
        let chain = bgp.key_chains.get_mut(&chain_name)?;
        let key = chain.keys.get_mut(&key_id)?;
        if op == ConfigOp::Set {
            key.send_id = Some(args.u8()?);
        } else {
            key.send_id = None;
        }
    }
    apply_ao_refresh_all(bgp);
    Some(())
}

fn config_key_chain_key_recv_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let chain_name = args.string()?;
    let key_id = args.u64()?;
    {
        let chain = bgp.key_chains.get_mut(&chain_name)?;
        let key = chain.keys.get_mut(&key_id)?;
        if op == ConfigOp::Set {
            key.recv_id = Some(args.u8()?);
        } else {
            key.recv_id = None;
        }
    }
    apply_ao_refresh_all(bgp);
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
        let prefix = String::from("/router/bgp/neighbor");
        self.callbacks.insert(prefix + path, cb);
    }

    #[allow(dead_code)]
    fn callback_afi_safi(&mut self, path: &str, cb: Callback) {
        let prefix = String::from("/router/bgp/neighbor");
        self.callbacks.insert(prefix + path, cb);
    }

    fn timer(&mut self, path: &str, cb: Callback) {
        let prefix = String::from("/router/bgp/neighbor/timers");
        self.callbacks.insert(prefix + path, cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/router/bgp/global/as", config_global_asn);
        self.callback_add("/router/bgp/global/identifier", config_global_identifier);
        self.callback_add("/router/bgp/global/hostname", config_global_hostname);
        self.callback_peer("", config_peer);
        self.callback_peer("/remote-as", config_remote_as);
        // Per-peer reference to a `neighbor-group`. Storage only —
        // resolution lands in the follow-up that adds field-level
        // override semantics.
        self.callback_peer("/neighbor-group", config_peer_neighbor_group);
        // `set router bgp neighbor-groups neighbor-group <name> [...]`.
        self.callback_add(
            "/router/bgp/neighbor-groups/neighbor-group",
            super::neighbor_group::config_neighbor_group,
        );
        self.callback_add(
            "/router/bgp/neighbor-groups/neighbor-group/remote-as",
            super::neighbor_group::config_neighbor_group_remote_as,
        );
        self.callback_peer("/local-identifier", config_local_identifier);
        self.callback_peer("/transport/passive-mode", config_transport_passive);
        self.callback_peer("/transport/local-address", config_transport_local_address);
        // FRR-style flat alias from zebra-bgp-transport.yang. Same
        // backing field (`peer.config.transport.update_source`) and
        // same `peer_connect` bind site as the IETF `local-address`
        // path above; either CLI form is accepted, both lower onto
        // the same runtime state.
        self.callback_peer("/update-source", config_transport_local_address);
        self.callback_peer("/tcp-md5/password", config_peer_tcp_md5_password);
        self.callback_peer("/tcp-md5/encoding", config_peer_tcp_md5_encoding);
        // FRR / IOS-XR flat alias from zebra-bgp-password.yang. Same
        // backing field (`peer.config.transport.md5_password`) and
        // same `setsockopt(TCP_MD5SIG)` site as the structured
        // `/tcp-md5/password` path above; either CLI form is accepted,
        // both lower onto the same runtime state.
        self.callback_peer("/password", config_peer_tcp_md5_password);
        self.callback_peer("/tcp-ao/key-chain", config_peer_tcp_ao_key_chain);
        self.callback_peer(
            "/tcp-ao/include-tcp-options",
            config_peer_tcp_ao_include_tcp_options,
        );

        // Key-chains (RFC 8177) for TCP-AO.
        self.callback_add("/key-chains/key-chain", config_key_chain);
        self.callback_add(
            "/key-chains/key-chain/description",
            config_key_chain_description,
        );
        self.callback_add("/key-chains/key-chain/key", config_key_chain_key);
        self.callback_add(
            "/key-chains/key-chain/key/crypto-algorithm",
            config_key_chain_key_crypto_algorithm,
        );
        self.callback_add(
            "/key-chains/key-chain/key/key-string/keystring",
            config_key_chain_key_keystring,
        );
        self.callback_add(
            "/key-chains/key-chain/key/key-string/hexadecimal-string",
            config_key_chain_key_hex_string,
        );
        self.callback_add(
            "/key-chains/key-chain/key/send-id",
            config_key_chain_key_send_id,
        );
        self.callback_add(
            "/key-chains/key-chain/key/recv-id",
            config_key_chain_key_recv_id,
        );
        self.callback_peer("/afi-safi/enabled", config_afi_safi);
        self.callback_peer("/afi-safi/add-path", config_add_path);
        self.callback_peer("/afi-safi/graceful-restart/enabled", config_restart);
        self.callback_peer("/afi-safi/long-lived-graceful-restart/enabled", config_llgr);
        self.callback_peer(
            "/afi-safi/long-lived-graceful-restart/restart-time",
            config_llgr_restart_time,
        );
        self.callback_peer("/rtc", config_rtc);

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
        self.callback_add("/router/bgp/debug", config_debug_category);

        // Network configuration
        self.callback_add("/router/bgp/afi-safi/network", config_network);

        // EVPN: FRR-style `advertise-all-vni` under
        // `router bgp afi-safi evpn`. Augmented in by
        // zebra-bgp-evpn.yang. Schema-only consumer for now —
        // origination from Rib::neighbors lands in a follow-up.
        self.callback_add(
            "/router/bgp/afi-safi/advertise-all-vni",
            config_advertise_all_vni,
        );

        // Applying policy.
        self.callback_peer("/policy/in", config_policy_in);
        self.callback_peer("/policy/out", config_policy_out);
        self.callback_peer("/prefix-set/in", config_prefix_in);
        self.callback_peer("/prefix-set/out", config_prefix_out);

        // Route Reflector.
        self.callback_peer("/route-reflector/client", config_route_reflector);

        // Soft-reconfiguration inbound (zebra-bgp-soft-reconfiguration.yang).
        // Stored-mode soft-in: retain pre-policy Adj-RIB-In so `clear soft in`
        // can replay locally without sending a Route Refresh.
        self.callback_peer("/soft-reconfiguration/inbound", config_soft_reconfig_in);
    }
}
