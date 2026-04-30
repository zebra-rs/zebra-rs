// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::net::{IpAddr, Ipv4Addr};

use bgp_packet::*;

use crate::bgp::InOut;
use crate::config::{Args, ConfigOp};
use crate::policy;
use crate::policy::com_list::*;

use super::auth::{AoConfig, CryptoAlgorithm, Key, KeyChain};
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
        bgp.router_id = router_id;
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
    if had_md5 {
        if let Err(e) = super::auth::set_tcp_md5_key(fd, *addr, &[]) {
            tracing::warn!(
                peer = %addr,
                error = %e,
                "TCP MD5 del on listener failed during peer cleanup"
            );
        }
    }

    // TCP-AO: needs the exact (send_id, recv_id) used at install
    // time, remembered on the peer.
    if let Some(peer) = bgp.peers.get_mut(addr)
        && let Some((send_id, recv_id)) = peer.last_ao_installed.take()
    {
        if let Err(e) = super::auth::del_tcp_ao_key(fd, *addr, send_id, recv_id) {
            tracing::warn!(
                peer = %addr,
                send_id,
                recv_id,
                error = %e,
                "TCP-AO del on listener failed during peer cleanup"
            );
        }
    }
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

fn config_policy_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    let policy_name = args.string()?;
    if op.is_set() {
        let config = peer.policy_list.get_mut(&InOut::Input);
        config.name = Some(policy_name.clone());

        let msg = policy::Message::Register {
            proto: "bgp".to_string(),
            name: policy_name,
            ident: peer.ident,
            policy_type: policy::PolicyType::PolicyListIn,
        };
        let _ = bgp.policy_tx.send(msg);
    } else {
        let config = peer.policy_list.get_mut(&InOut::Input);
        config.name = None;
    }
    Some(())
}

fn config_policy_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    let policy_name = args.string()?;
    if op.is_set() {
        let config = peer.policy_list.get_mut(&InOut::Output);
        config.name = Some(policy_name.clone());

        let msg = policy::Message::Register {
            proto: "bgp".to_string(),
            name: policy_name,
            ident: peer.ident,
            policy_type: policy::PolicyType::PolicyListOut,
        };
        // tracing::info!("{:?}", msg);
        let _ = bgp.policy_tx.send(msg);
    } else {
        let config = peer.policy_list.get_mut(&InOut::Output);
        config.name = None;
    }
    Some(())
}

fn config_prefix_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    let policy = args.string()?;
    if op.is_set() {
        let config = peer.prefix_set.get_mut(&InOut::Input);
        config.name = Some(policy.clone());

        let msg = policy::Message::Register {
            proto: "bgp".to_string(),
            name: policy,
            ident: peer.ident,
            policy_type: policy::PolicyType::PrefixSetIn,
        };
        let _ = bgp.policy_tx.send(msg);
    } else {
        let config = peer.prefix_set.get_mut(&InOut::Input);
        config.name = None;
    }
    Some(())
}

fn config_prefix_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
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
    }
    Some(())
}

fn config_route_reflector(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let peer = bgp.peers.get_mut(&addr)?;

    peer.reflector_client = op.is_set() && flag;
    None
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
    if let Some(fd) = listen_fd {
        if let Err(e) = super::auth::set_tcp_md5_key(fd, addr, &password_bytes) {
            tracing::warn!(
                peer = %addr,
                error = %e,
                "TCP MD5 setsockopt on listener failed; incoming SYNs from this peer will be dropped"
            );
        }
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
        bgp.key_chains.entry(name).or_insert_with(KeyChain::new);
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
        let prefix = String::from("/routing/bgp/neighbor");
        self.callbacks.insert(prefix + path, cb);
    }

    #[allow(dead_code)]
    fn callback_afi_safi(&mut self, path: &str, cb: Callback) {
        let prefix = String::from("/routing/bgp/neighbor");
        self.callbacks.insert(prefix + path, cb);
    }

    fn timer(&mut self, path: &str, cb: Callback) {
        let prefix = String::from("/routing/bgp/neighbor/timers");
        self.callbacks.insert(prefix + path, cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/routing/bgp/global/as", config_global_asn);
        self.callback_add("/routing/bgp/global/identifier", config_global_identifier);
        self.callback_peer("", config_peer);
        self.callback_peer("/peer-as", config_peer_as);
        self.callback_peer("/local-identifier", config_local_identifier);
        self.callback_peer("/transport/passive-mode", config_transport_passive);
        self.callback_peer("/transport/local-address", config_transport_local_address);
        self.callback_peer("/tcp-md5/password", config_peer_tcp_md5_password);
        self.callback_peer("/tcp-md5/encoding", config_peer_tcp_md5_encoding);
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
        self.callback_add("/routing/bgp/debug", config_debug_category);

        // Network configuration
        self.callback_add("/routing/bgp/afi-safi/network", config_network);

        // Applying policy.
        self.callback_peer("/apply-policy/in", config_policy_in);
        self.callback_peer("/apply-policy/out", config_policy_out);
        self.callback_peer("/prefix-set/in", config_prefix_in);
        self.callback_peer("/prefix-set/out", config_prefix_out);

        // Route Reflector.
        self.callback_peer("/route-reflector/client", config_route_reflector);
    }
}
