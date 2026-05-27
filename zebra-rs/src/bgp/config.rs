use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgp_packet::*;

use crate::bfd::inst::ClientReq;
use crate::bfd::session::{SessionKey, SessionParams};
use crate::bgp::InOut;
use crate::config::{Args, ConfigOp};
use crate::policy;
use crate::policy::com_list::*;
use crate::rib::api::FdbEntry;

use super::auth::AoConfig;
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
            bgp.ctx.clone(),
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
            rib_client: &bgp.ctx.rib,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
            interface_addrs: &bgp.interface_addrs,
            vrf_export: None,
            color_policy: Some(&bgp.color_policy),
            flex_algo_routes: Some(&bgp.flex_algo_routes),
            vrf_import: None,
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

/// `set router bgp neighbor <addr> neighbor-group <name>`.
///
/// Stores the reference on the peer's `PeerConfig` and — if the peer
/// has no explicit `remote-as` yet — pulls the group's `remote-as`
/// in via [`super::neighbor_group::group_remote_as`] and kicks
/// [`super::peer::Peer::start`]. An explicit per-peer `remote-as`
/// (signalled by `remote_as_inherited == false` and `remote_as != 0`)
/// always wins; in that case the reference is recorded but the
/// resolved value is left alone.
///
/// On Delete (or unset of the reference), peers whose `remote_as`
/// came from the group are reset to 0 and sent `Event::Stop` so the
/// FSM tears the session down; explicit-remote-as peers are left
/// alone.
fn config_peer_neighbor_group(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let new_ref = if op == ConfigOp::Set {
        args.string()
    } else {
        None
    };

    // Stash what we need to act on outside the &mut peer borrow.
    let (peer_ident, resolve_now, should_stop_inherited) = {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.neighbor_group = new_ref.clone();

        match op {
            ConfigOp::Set => {
                // Resolve only if the peer doesn't already carry an
                // explicit per-peer remote-as.
                let needs_resolve = peer.remote_as == 0 || peer.config.remote_as_inherited;
                (peer.ident, needs_resolve, false)
            }
            ConfigOp::Delete => {
                // Tear down only when the peer was relying on the
                // group's remote-as.
                let was_inherited = peer.config.remote_as_inherited && peer.remote_as != 0;
                if was_inherited {
                    peer.remote_as = 0;
                    peer.config.remote_as_inherited = false;
                    peer.active = false;
                }
                (peer.ident, false, was_inherited)
            }
            _ => (peer.ident, false, false),
        }
    };

    if resolve_now {
        // SAFE: `Set` arm above always populated `new_ref` from
        // `args.string()`; falling back to `None` here means the
        // argument was missing, in which case there is nothing to
        // resolve.
        if let Some(group_name) = new_ref.as_deref() {
            if let Some(asn) = super::neighbor_group::group_remote_as(bgp, group_name) {
                if let Some(peer) = bgp.peers.get_mut(&addr) {
                    peer.remote_as = asn;
                    peer.config.remote_as_inherited = true;
                    peer.peer_type = if asn == bgp.asn {
                        crate::bgp::peer::PeerType::IBGP
                    } else {
                        crate::bgp::peer::PeerType::EBGP
                    };
                    peer.start();
                }
            } else {
                tracing::warn!(
                    peer = %addr,
                    group = %group_name,
                    "bgp: neighbor-group reference unresolved (missing group or no remote-as); peer stays dormant",
                );
            }
        }
    }

    if should_stop_inherited {
        // FSM teardown — same mechanism `clear bgp ... hard` uses.
        let _ = bgp.tx.try_send(super::inst::Message::Event(
            peer_ident,
            super::peer::Event::Stop,
        ));
    }

    Some(())
}

fn config_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        if let Some(addr) = args.v4addr() {
            let addr = IpAddr::V4(addr);
            let asn: u32 = args.u32()?;
            if let Some(peer) = bgp.peers.get_mut(&addr) {
                peer.remote_as = asn;
                // Explicit per-peer remote-as wins over any
                // neighbor-group fallback from here on.
                peer.config.remote_as_inherited = false;
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
                peer.config.remote_as_inherited = false;
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

/// `set router bgp neighbor X bfd enable true|false` — flips the
/// BFD attachment for this neighbor. Stores the bit on
/// `peer.config.bfd.enable` and wires the same flip into a
/// `ClientReq::Subscribe` / `Unsubscribe` against the BFD instance
/// when `bgp.bfd_client_tx` is populated.
fn config_peer_bfd_enable(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let enable = args.boolean()?;
    let new_enable = op.is_set() && enable;
    // Stash data we need from the peer, then drop the borrow so we
    // can touch other Bgp fields without fighting the borrow checker.
    let local = {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.bfd.enable = new_enable;
        peer.config
            .transport
            .update_source
            .unwrap_or_else(|| unspecified_for(&addr))
    };
    let Some(client_tx) = bgp.bfd_client_tx.as_ref() else {
        if new_enable {
            tracing::debug!(
                peer = %addr,
                "bgp: bfd enable=true but bfd_client_tx is None (BFD not yet spawned)",
            );
        }
        return Some(());
    };
    let key = SessionKey {
        local,
        remote: addr,
        ifindex: 0,
        multihop: false,
    };
    let req = if new_enable {
        // Uses SessionParams::default() for every neighbor — the
        // peer's `bfd profile` reference is stored but not yet read.
        // Profile resolution against `/bfd/profile/<name>` is a
        // follow-up that needs cross-task config access (BGP would
        // need a snapshot of BFD's BfdConfig, or BFD has to resolve
        // profiles internally on Subscribe).
        ClientReq::Subscribe {
            client: "bgp".to_string(),
            key,
            params: SessionParams::default(),
            notifier: bgp.bfd_event_tx.clone(),
        }
    } else {
        ClientReq::Unsubscribe {
            client: "bgp".to_string(),
            key,
        }
    };
    let _ = client_tx.send(req);
    Some(())
}

/// Pick an unspecified local address whose family matches `remote`.
/// Used when the peer has no `update-source` set — BFD's SessionKey
/// just needs *something* in the `local` slot to demux against, and
/// 0.0.0.0 / :: are unambiguous within a single (local, remote, ifindex)
/// tuple.
fn unspecified_for(remote: &IpAddr) -> IpAddr {
    match remote {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// `set router bgp neighbor X bfd profile NAME` — selects the BFD
/// profile applied when this neighbor's BFD session is created.
/// Stored verbatim; resolution against `/bfd/profile/<name>` is
/// the responsibility of the subscribe path.
fn config_peer_bfd_profile(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let name = args.string()?;
    let peer = bgp.peers.get_mut(&addr)?;
    peer.config.bfd.profile = op.is_set().then_some(name);
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

// ---- redistribute -----------------------------------------------------
//
// Per-AFI redistribution sources (zebra-bgp-redistribute.yang). Each
// source is a presence container with modifier leaves; storage is a
// BTreeMap<(AfiSafi, Source), BgpRedistribute> on the Bgp instance.
// Storage-only today — the BGP RIB-source plumbing that consumes
// these entries lands in a follow-up.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpRedistSource {
    Connected,
    Static,
    Isis,
    Ospf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpRedistIsisLevel {
    L1,
    L2,
    L1InterArea,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpRedistOspfMatch {
    Internal,
    External1,
    External2,
    NssaExternal1,
    NssaExternal2,
}

#[derive(Debug, Default, Clone)]
pub struct BgpRedistribute {
    pub policy: Option<String>,
    pub metric: Option<u32>,
    pub multipath: bool,
    /// Populated only when source == Isis. Empty set means "no filter".
    pub isis_levels: std::collections::BTreeSet<BgpRedistIsisLevel>,
    /// Populated only when source == Ospf. Empty set means "no filter".
    pub ospf_match: std::collections::BTreeSet<BgpRedistOspfMatch>,
}

/// Only AFs BGP actually originates from are valid redistribute
/// targets. The YANG augment attaches the container to every
/// afi-safi list entry, so we filter at the callback. Returns `None`
/// for AFs we don't support — the callback in turn returns `None` and
/// libyang surfaces it as a commit failure.
fn redist_afi_valid(afi_safi: &bgp_packet::AfiSafi) -> bool {
    use bgp_packet::{Afi, Safi};
    matches!(
        (afi_safi.afi, afi_safi.safi),
        (Afi::Ip, Safi::Unicast) | (Afi::Ip6, Safi::Unicast)
    )
}

/// Map the BGP-side `AfiSafi` (afi+safi) to the wire-side `RedistAfi`
/// (afi only — SAFI is irrelevant to RIB's per-AFI table choice).
fn wire_afi(afi_safi: &bgp_packet::AfiSafi) -> crate::rib::RedistAfi {
    use bgp_packet::Afi;
    match afi_safi.afi {
        Afi::Ip => crate::rib::RedistAfi::Ipv4,
        Afi::Ip6 => crate::rib::RedistAfi::Ipv6,
        // redist_afi_valid filters everything else above, so we never
        // reach this in practice. Default keeps the fn total.
        _ => crate::rib::RedistAfi::Ipv4,
    }
}

fn wire_rtype(src: BgpRedistSource) -> crate::rib::RibType {
    match src {
        BgpRedistSource::Connected => crate::rib::RibType::Connected,
        BgpRedistSource::Static => crate::rib::RibType::Static,
        BgpRedistSource::Isis => crate::rib::RibType::Isis,
        BgpRedistSource::Ospf => crate::rib::RibType::Ospf,
    }
}

/// Translate the BGP-side subtype filters (IS-IS levels, OSPF match
/// types) into the RIB-side `RibSubType` set. Non-(IS-IS|OSPF)
/// sources have no subtype dimension so always wildcard.
///
/// Caveat for `BgpRedistIsisLevel::L1InterArea`: our `RibSubType`
/// currently models L1 as a single bucket (`IsisLevel1` +
/// `IsisIntraArea`), so the explicit "L1 inter-area" distinction
/// from IOS-XR maps to the same set as plain `L1`. Refining the
/// `RibSubType` enum to separate L1 intra vs L1 inter-area is a
/// follow-up; for now `level 1` and `level 1-inter-area` yield
/// identical filter sets.
fn wire_subtypes(
    src: BgpRedistSource,
    entry: &BgpRedistribute,
) -> std::collections::BTreeSet<crate::rib::RibSubType> {
    use crate::rib::RibSubType;
    let mut out = std::collections::BTreeSet::new();
    match src {
        BgpRedistSource::Isis => {
            if entry.isis_levels.is_empty() {
                return out; // wildcard
            }
            for lvl in &entry.isis_levels {
                match lvl {
                    BgpRedistIsisLevel::L1 | BgpRedistIsisLevel::L1InterArea => {
                        out.insert(RibSubType::IsisLevel1);
                        out.insert(RibSubType::IsisIntraArea);
                    }
                    BgpRedistIsisLevel::L2 => {
                        out.insert(RibSubType::IsisLevel2);
                    }
                }
            }
        }
        BgpRedistSource::Ospf => {
            if entry.ospf_match.is_empty() {
                return out; // wildcard
            }
            for m in &entry.ospf_match {
                match m {
                    BgpRedistOspfMatch::Internal => {
                        out.insert(RibSubType::Default);
                        out.insert(RibSubType::OspfIa);
                    }
                    BgpRedistOspfMatch::External1 => {
                        out.insert(RibSubType::OspfExternal1);
                    }
                    BgpRedistOspfMatch::External2 => {
                        out.insert(RibSubType::OspfExternal2);
                    }
                    BgpRedistOspfMatch::NssaExternal1 => {
                        out.insert(RibSubType::OspfNssa1);
                    }
                    BgpRedistOspfMatch::NssaExternal2 => {
                        out.insert(RibSubType::OspfNssa2);
                    }
                }
            }
        }
        // Connected / Static have no subtype dimension → always wildcard.
        _ => {}
    }
    out
}

/// Send the RIB the appropriate Redist message for the current state
/// of `(afi_safi, src)`. Mirrors the IS-IS helper of the same name.
fn send_redist(bgp: &Bgp, afi_safi: &bgp_packet::AfiSafi, src: BgpRedistSource, first_time: bool) {
    let afi = wire_afi(afi_safi);
    let rtype = wire_rtype(src);
    let proto = "bgp".to_string();
    let msg = match bgp.redistribute.get(&(*afi_safi, src)) {
        None => crate::rib::Message::RedistDel { proto, afi, rtype },
        Some(entry) if first_time => crate::rib::Message::RedistAdd {
            proto,
            afi,
            rtype,
            subtypes: wire_subtypes(src, entry),
        },
        Some(entry) => crate::rib::Message::RedistUpdate {
            proto,
            afi,
            rtype,
            subtypes: wire_subtypes(src, entry),
        },
    };
    let _ = bgp.ctx.rib.send(msg);
}

fn bgp_redist_set_presence(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
    src: BgpRedistSource,
) -> Option<()> {
    let afi_safi: bgp_packet::AfiSafi = args.afi_safi()?;
    if !redist_afi_valid(&afi_safi) {
        return None;
    }
    let first_time = !bgp.redistribute.contains_key(&(afi_safi, src));
    if op.is_set() {
        bgp.redistribute.entry((afi_safi, src)).or_default();
    } else {
        bgp.redistribute.remove(&(afi_safi, src));
    }
    send_redist(bgp, &afi_safi, src, first_time && op.is_set());
    Some(())
}

/// `subtype_relevant = true` means the mutation may have changed the
/// wire-level subtype set (only the `isis level` and `ospf match`
/// callbacks today), triggering a RedistUpdate to RIB. Other modifier
/// leaves (policy, metric, multipath) are consumer-side overrides
/// and don't need to flip the RIB filter.
fn bgp_redist_with<F>(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
    src: BgpRedistSource,
    subtype_relevant: bool,
    f: F,
) -> Option<()>
where
    F: FnOnce(&mut BgpRedistribute, &mut Args, ConfigOp) -> Option<()>,
{
    let afi_safi: bgp_packet::AfiSafi = args.afi_safi()?;
    if !redist_afi_valid(&afi_safi) {
        return None;
    }
    let entry = bgp.redistribute.entry((afi_safi, src)).or_default();
    f(entry, &mut args, op)?;
    if subtype_relevant {
        send_redist(bgp, &afi_safi, src, /* first_time = */ false);
    }
    Some(())
}

fn bgp_set_policy(e: &mut BgpRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    e.policy = if op.is_set() { Some(a.string()?) } else { None };
    Some(())
}
fn bgp_set_metric(e: &mut BgpRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    e.metric = if op.is_set() { Some(a.u32()?) } else { None };
    Some(())
}
fn bgp_set_multipath(e: &mut BgpRedistribute, _a: &mut Args, op: ConfigOp) -> Option<()> {
    e.multipath = op.is_set();
    Some(())
}
fn bgp_set_isis_level(e: &mut BgpRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    let v = match a.string()?.as_str() {
        "level-1" => BgpRedistIsisLevel::L1,
        "level-2" => BgpRedistIsisLevel::L2,
        "level-1-inter-area" => BgpRedistIsisLevel::L1InterArea,
        _ => return None,
    };
    if op.is_set() {
        e.isis_levels.insert(v);
    } else {
        e.isis_levels.remove(&v);
    }
    Some(())
}
fn bgp_set_ospf_match(e: &mut BgpRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    let v = match a.string()?.as_str() {
        "internal" => BgpRedistOspfMatch::Internal,
        "external-1" => BgpRedistOspfMatch::External1,
        "external-2" => BgpRedistOspfMatch::External2,
        "nssa-external-1" => BgpRedistOspfMatch::NssaExternal1,
        "nssa-external-2" => BgpRedistOspfMatch::NssaExternal2,
        _ => return None,
    };
    if op.is_set() {
        e.ospf_match.insert(v);
    } else {
        e.ospf_match.remove(&v);
    }
    Some(())
}

// Per-source presence + modifier wrappers. Mirrors the IS-IS shape.
pub(super) fn config_redistribute_connected(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    bgp_redist_set_presence(bgp, args, op, BgpRedistSource::Connected)
}
pub(super) fn config_redistribute_connected_policy(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Connected,
        false,
        bgp_set_policy,
    )
}
pub(super) fn config_redistribute_connected_metric(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Connected,
        false,
        bgp_set_metric,
    )
}
pub(super) fn config_redistribute_connected_multipath(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Connected,
        false,
        bgp_set_multipath,
    )
}

pub(super) fn config_redistribute_static(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    bgp_redist_set_presence(bgp, args, op, BgpRedistSource::Static)
}
pub(super) fn config_redistribute_static_policy(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Static,
        false,
        bgp_set_policy,
    )
}
pub(super) fn config_redistribute_static_metric(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Static,
        false,
        bgp_set_metric,
    )
}
pub(super) fn config_redistribute_static_multipath(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Static,
        false,
        bgp_set_multipath,
    )
}

pub(super) fn config_redistribute_isis(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    bgp_redist_set_presence(bgp, args, op, BgpRedistSource::Isis)
}
pub(super) fn config_redistribute_isis_policy(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(bgp, args, op, BgpRedistSource::Isis, false, bgp_set_policy)
}
pub(super) fn config_redistribute_isis_metric(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(bgp, args, op, BgpRedistSource::Isis, false, bgp_set_metric)
}
pub(super) fn config_redistribute_isis_multipath(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Isis,
        false,
        bgp_set_multipath,
    )
}
// `level <N>` flips the wire-level subtype set (BGP-from-IS-IS level
// filter); pass `subtype_relevant: true` so the callback emits a
// `RedistUpdate` to RIB.
pub(super) fn config_redistribute_isis_level(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Isis,
        true,
        bgp_set_isis_level,
    )
}

pub(super) fn config_redistribute_ospf(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    bgp_redist_set_presence(bgp, args, op, BgpRedistSource::Ospf)
}
pub(super) fn config_redistribute_ospf_policy(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(bgp, args, op, BgpRedistSource::Ospf, false, bgp_set_policy)
}
pub(super) fn config_redistribute_ospf_metric(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(bgp, args, op, BgpRedistSource::Ospf, false, bgp_set_metric)
}
pub(super) fn config_redistribute_ospf_multipath(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Ospf,
        false,
        bgp_set_multipath,
    )
}
// `match { type … }` flips the wire-level subtype set; set
// `subtype_relevant: true` so the callback emits a `RedistUpdate`.
pub(super) fn config_redistribute_ospf_match_type(
    bgp: &mut Bgp,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    bgp_redist_with(
        bgp,
        args,
        op,
        BgpRedistSource::Ospf,
        true,
        bgp_set_ospf_match,
    )
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
pub(super) fn apply_ao_refresh_all(bgp: &mut Bgp) {
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

    let (peer_ident, prior, new) = {
        let peer = bgp.peers.get_mut(&addr)?;
        let ident = peer.ident;
        let prior = peer
            .config
            .transport
            .ao_config
            .as_ref()
            .map(|ao| ao.key_chain.clone())
            .filter(|s| !s.is_empty());
        if op == ConfigOp::Set {
            let chain_name = args.string()?;
            let ao = peer
                .config
                .transport
                .ao_config
                .get_or_insert_with(AoConfig::default);
            ao.key_chain = chain_name.clone();
            (ident, prior, Some(chain_name))
        } else {
            peer.config.transport.ao_config = None;
            peer.config.transport.resolved_ao_key = None;
            (ident, prior, None)
        }
    };
    // Subscribe (or rebind) the peer's interest in the chain so the
    // policy actor pushes future `PolicyRx::KeyChain` updates for it;
    // `apply_ao_refresh_all` reconciles the live listener entries
    // using the snapshot we already have for `Set` cases and for
    // `Delete`s that need to del a stale MKT.
    policy_attach_msgs(
        &bgp.policy_tx,
        peer_ident,
        policy::PolicyType::KeyChain(policy::KeyChainScope::BgpNeighbor),
        prior,
        new,
    );
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
        // `set router bgp dynamic-neighbors …`.
        self.callback_add(
            "/router/bgp/dynamic-neighbors/listen-limit",
            super::dynamic_neighbors::config_listen_limit,
        );
        self.callback_add(
            "/router/bgp/dynamic-neighbors/listen-range",
            super::dynamic_neighbors::config_listen_range,
        );
        self.callback_add(
            "/router/bgp/dynamic-neighbors/listen-range/neighbor-group",
            super::dynamic_neighbors::config_listen_range_neighbor_group,
        );
        // `set router bgp color-policy color <N> [flex-algorithm <M>]`
        // (zebra-bgp-color-policy.yang). Storage-only on landing —
        // the consumer is the color-aware nexthop resolver that lands
        // in a follow-up PR.
        self.callback_add(
            "/router/bgp/color-policy/color",
            super::color_policy::config_color,
        );
        self.callback_add(
            "/router/bgp/color-policy/color/flex-algorithm",
            super::color_policy::config_color_flex_algorithm,
        );
        // `set router bgp vrf <name> [...]` (zebra-bgp-vrf.yang).
        // The callbacks populate `Bgp::vrfs`; the CommitEnd hook in
        // `process_cm_msg` emits a debug log per VRF entry and
        // drives per-VRF task spawn / peer materialization.
        self.callback_add("/router/bgp/vrf", super::vrf_config::config_vrf);
        self.callback_add("/router/bgp/vrf/rd", super::vrf_config::config_vrf_rd);
        self.callback_add(
            "/router/bgp/vrf/router-id",
            super::vrf_config::config_vrf_router_id,
        );
        self.callback_add(
            "/router/bgp/vrf/label-mode",
            super::vrf_config::config_vrf_label_mode,
        );
        self.callback_add(
            "/router/bgp/vrf/neighbor",
            super::vrf_config::config_vrf_neighbor,
        );
        self.callback_add(
            "/router/bgp/vrf/neighbor/remote-as",
            super::vrf_config::config_vrf_neighbor_remote_as,
        );
        self.callback_add(
            "/router/bgp/vrf/neighbor/peer-group",
            super::vrf_config::config_vrf_neighbor_peer_group,
        );
        self.callback_add(
            "/router/bgp/vrf/neighbor/description",
            super::vrf_config::config_vrf_neighbor_description,
        );
        self.callback_add(
            "/router/bgp/vrf/neighbor/enabled",
            super::vrf_config::config_vrf_neighbor_enabled,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4-unicast",
            super::vrf_config::config_vrf_afi_ipv4_unicast,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4-unicast/network",
            super::vrf_config::config_vrf_afi_ipv4_network,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6-unicast",
            super::vrf_config::config_vrf_afi_ipv6_unicast,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6-unicast/network",
            super::vrf_config::config_vrf_afi_ipv6_network,
        );

        // `set router bgp interface-neighbor <name> [...]`.
        self.callback_add(
            "/router/bgp/interface-neighbor",
            super::interface_neighbor::config_interface_neighbor,
        );
        self.callback_add(
            "/router/bgp/interface-neighbor/neighbor-group",
            super::interface_neighbor::config_interface_neighbor_neighbor_group,
        );
        self.callback_add(
            "/router/bgp/interface-neighbor/remote-as",
            super::interface_neighbor::config_interface_neighbor_remote_as,
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
        // FRR-style per-neighbor BFD attachment from
        // zebra-bgp-bfd.yang. Stores the leaves on
        // `peer.config.bfd` and wires the runtime subscribe /
        // unsubscribe path to the BFD client API.
        self.callback_peer("/bfd/enable", config_peer_bfd_enable);
        self.callback_peer("/bfd/profile", config_peer_bfd_profile);
        self.callback_peer("/tcp-ao/key-chain", config_peer_tcp_ao_key_chain);
        self.callback_peer(
            "/tcp-ao/include-tcp-options",
            config_peer_tcp_ao_include_tcp_options,
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

        // Global BGP timer configuration (zebra-bgp-timer.yang).
        // `router bgp timer adv-interval { ibgp; ebgp; }` overrides
        // the MRAI cadence used by the IPv4 / VPNv4 / EVPN adv-debounce
        // timers; defaults are 5s (iBGP) and 30s (eBGP) per RFC 4271
        // §10. The callbacks write to `Bgp::adv_interval` and re-snapshot
        // every existing peer and update-group.
        self.callback_add(
            "/router/bgp/timer/adv-interval/ibgp",
            timer::config::adv_interval_ibgp,
        );
        self.callback_add(
            "/router/bgp/timer/adv-interval/ebgp",
            timer::config::adv_interval_ebgp,
        );

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

        // Per-AFI redistribution (zebra-bgp-redistribute.yang).
        // One presence-container callback per source plus one per
        // modifier leaf, dispatched through `bgp_redist_set_presence`
        // / `bgp_redist_with`. Storage-only today.
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/connected",
            config_redistribute_connected,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/connected/policy",
            config_redistribute_connected_policy,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/connected/metric",
            config_redistribute_connected_metric,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/connected/multipath",
            config_redistribute_connected_multipath,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/static",
            config_redistribute_static,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/static/policy",
            config_redistribute_static_policy,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/static/metric",
            config_redistribute_static_metric,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/static/multipath",
            config_redistribute_static_multipath,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/isis",
            config_redistribute_isis,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/isis/policy",
            config_redistribute_isis_policy,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/isis/metric",
            config_redistribute_isis_metric,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/isis/multipath",
            config_redistribute_isis_multipath,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/isis/level",
            config_redistribute_isis_level,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/ospf",
            config_redistribute_ospf,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/ospf/policy",
            config_redistribute_ospf_policy,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/ospf/metric",
            config_redistribute_ospf_metric,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/ospf/multipath",
            config_redistribute_ospf_multipath,
        );
        self.callback_add(
            "/router/bgp/afi-safi/redistribute/ospf/match/type",
            config_redistribute_ospf_match_type,
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

#[cfg(test)]
mod bfd_wiring_tests {
    use std::collections::VecDeque;

    use tokio::sync::mpsc;

    use super::*;

    fn arg_words(parts: &[&str]) -> Args {
        Args(
            parts
                .iter()
                .map(|s| (*s).to_string())
                .collect::<VecDeque<_>>(),
        )
    }

    /// Build a parked `ProtoContext` plus its `rib_rx` half for
    /// tests. The inbound channel and the rx half are dropped after
    /// the test completes; nothing here asserts what BGP would have
    /// sent to RIB.
    fn test_ctx() -> (
        crate::context::ProtoContext,
        mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        // Leak the inbound rx so it isn't dropped — sends through the
        // client otherwise return SendError and trip BGP's unwraps.
        // Tests don't observe messages on it, but the channel must
        // stay open for the duration of the test.
        Box::leak(Box::new(_inbound_rx));
        let ctx = crate::context::ProtoContext::default_table(client);
        (ctx, rib_rx)
    }

    /// Build a minimal `RibSubscriber` for tests. Mints into a
    /// leaked rib channel — the spawn site for per-VRF subscriptions
    /// is exercised in integration / BDD tests; the BGP-config
    /// callbacks tested here never call into the subscriber.
    fn test_rib_subscriber() -> crate::config::RibSubscriber {
        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_rib_rx));
        Box::leak(Box::new(_inbound_rx));
        // ProtoId allocator starts from 1 to avoid colliding with
        // the `ProtoId::from_raw(0)` baked into `test_ctx`.
        let next_proto_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1));
        crate::config::RibSubscriber::for_test(rib_tx, rib_inbound_tx, next_proto_id)
    }

    /// Construct a Bgp with mock channels and an optional BFD
    /// client_tx. Returned alongside the BFD ClientReq receiver so
    /// the caller can assert what was sent.
    fn fresh_bgp_with_bfd() -> (Bgp, mpsc::UnboundedReceiver<ClientReq>) {
        let (ctx, rib_rx) = test_ctx();
        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        let (bfd_client_tx, bfd_client_rx) = mpsc::unbounded_channel();
        let bgp = Bgp::new(
            ctx,
            rib_rx,
            test_rib_subscriber(),
            policy_tx,
            Some(bfd_client_tx),
            None,
        );
        (bgp, bfd_client_rx)
    }

    /// `bfd enable true` on a known neighbor sends a
    /// `ClientReq::Subscribe` carrying the matching SessionKey.
    #[tokio::test]
    async fn enable_sends_subscribe() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        // Add the peer first (the callback only fires for known peers).
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        // Now flip BFD on.
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.2", "true"]), ConfigOp::Set).unwrap();

        let req = bfd_rx.try_recv().expect("BGP must send a ClientReq");
        match req {
            ClientReq::Subscribe { client, key, .. } => {
                assert_eq!(client, "bgp");
                assert_eq!(
                    key.remote,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "remote address mirrors the configured neighbor",
                );
                assert!(!key.multihop, "single-hop only");
                assert_eq!(key.ifindex, 0);
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// Flipping `bfd enable` back to false (or deleting it) sends an
    /// `Unsubscribe` for the same key.
    #[tokio::test]
    async fn disable_sends_unsubscribe() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.3"]), ConfigOp::Set).unwrap();
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.3", "true"]), ConfigOp::Set).unwrap();
        let _ = bfd_rx.try_recv().expect("subscribe arrived first");

        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.3", "true"]), ConfigOp::Delete)
            .unwrap();
        let req = bfd_rx.try_recv().expect("unsubscribe must follow");
        match req {
            ClientReq::Unsubscribe { client, key } => {
                assert_eq!(client, "bgp");
                assert_eq!(key.remote, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
            }
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
    }

    /// If `bfd_client_tx` is None (BFD not spawned at BGP start time)
    /// the callback is a no-op — peer config still flips, but no
    /// ClientReq goes out.
    #[tokio::test]
    async fn enable_without_bfd_handle_is_noop() {
        let (ctx, rib_rx) = test_ctx();
        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        let mut bgp = Bgp::new(ctx, rib_rx, test_rib_subscriber(), policy_tx, None, None);
        config_peer(&mut bgp, arg_words(&["10.0.0.4"]), ConfigOp::Set).unwrap();
        // No bfd handle to assert against; the call must not panic.
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.4", "true"]), ConfigOp::Set).unwrap();

        let peer = bgp
            .peers
            .get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)))
            .unwrap();
        assert!(peer.config.bfd.enable, "config bit still flips");
    }

    // -----------------------------------------------------------------
    // process_bfd_event teardown behaviour
    // -----------------------------------------------------------------

    use crate::bfd::inst::BfdEvent;
    use crate::bfd::session::StateChange;
    use crate::bgp::inst::Message;
    use crate::bgp::peer::Event as PeerEvent;
    use bfd_packet::{Diag, State};

    fn make_state_change(from: State, to: State) -> StateChange {
        StateChange {
            from,
            to,
            diag: Diag::None,
        }
    }

    fn make_event(remote: Ipv4Addr, from: State, to: State) -> BfdEvent {
        BfdEvent::StateChange {
            key: SessionKey {
                local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote: IpAddr::V4(remote),
                ifindex: 0,
                multihop: false,
            },
            change: make_state_change(from, to),
        }
    }

    /// BFD going Up → Down for a known peer sends `Event::Stop` to
    /// the matching peer FSM (RFC 5882 §5 path-failure response).
    #[tokio::test]
    async fn bfd_down_triggers_event_stop() {
        let (mut bgp, _bfd_rx) = fresh_bgp_with_bfd();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        config_peer(&mut bgp, arg_words(&["10.0.0.5"]), ConfigOp::Set).unwrap();
        let peer_idx = bgp.peers.get(&IpAddr::V4(addr)).unwrap().ident;

        bgp.process_bfd_event(make_event(addr, State::Up, State::Down));

        let msg = bgp.rx.try_recv().expect("Event::Stop must be queued");
        match msg {
            Message::Event(idx, ev) => {
                assert_eq!(idx, peer_idx);
                assert!(matches!(ev, PeerEvent::Stop));
            }
            other => panic!("expected Message::Event(_, Stop), got {other:?}"),
        }
    }

    /// Synthetic Down→Down events emitted by `Bfd::subscribe` (so a
    /// new subscriber can act on the current state immediately) must
    /// NOT trigger teardown — there's no transition to react to.
    #[tokio::test]
    async fn synthetic_down_to_down_is_ignored() {
        let (mut bgp, _bfd_rx) = fresh_bgp_with_bfd();
        let addr = Ipv4Addr::new(10, 0, 0, 6);
        config_peer(&mut bgp, arg_words(&["10.0.0.6"]), ConfigOp::Set).unwrap();

        bgp.process_bfd_event(make_event(addr, State::Down, State::Down));
        assert!(
            bgp.rx.try_recv().is_err(),
            "synthetic Down→Down must not enqueue any message",
        );
    }

    /// BFD coming Up is informational — BGP doesn't need to do
    /// anything in particular (its own FSM is already running).
    #[tokio::test]
    async fn bfd_up_does_not_tear_down() {
        let (mut bgp, _bfd_rx) = fresh_bgp_with_bfd();
        let addr = Ipv4Addr::new(10, 0, 0, 7);
        config_peer(&mut bgp, arg_words(&["10.0.0.7"]), ConfigOp::Set).unwrap();

        bgp.process_bfd_event(make_event(addr, State::Init, State::Up));
        assert!(
            bgp.rx.try_recv().is_err(),
            "BFD Up must not enqueue any message",
        );
    }

    /// A Down event for a peer that no longer exists (raced against
    /// neighbor deletion) is logged but otherwise ignored — no
    /// panic, no spurious Event::Stop.
    #[tokio::test]
    async fn bfd_down_for_unknown_peer_is_noop() {
        let (mut bgp, _bfd_rx) = fresh_bgp_with_bfd();
        bgp.process_bfd_event(make_event(
            Ipv4Addr::new(10, 99, 99, 99),
            State::Up,
            State::Down,
        ));
        assert!(bgp.rx.try_recv().is_err());
    }
}

#[cfg(test)]
mod neighbor_group_wiring_tests {
    //! End-to-end exercise of the neighbor-group inheritance callback
    //! paths landed across PR #758 (static-peer resolver), PR #760
    //! (reactive sweep on group remote-as Set/Delete), and PR #762
    //! (group-level delete cascade). Asserts the user-observable
    //! state after each callback rather than the internal sweep
    //! decision — the decision matrix itself is unit-tested in
    //! `neighbor_group::tests`.

    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;

    use super::super::neighbor_group::{config_neighbor_group, config_neighbor_group_remote_as};
    use super::*;

    fn arg_words(parts: &[&str]) -> Args {
        Args(
            parts
                .iter()
                .map(|s| (*s).to_string())
                .collect::<VecDeque<_>>(),
        )
    }

    /// Parked `ProtoContext` plus its `rib_rx` half. Mirror of the
    /// helper in `bfd_wiring_tests` — duplicated here so the two
    /// test modules stay independent.
    fn test_ctx() -> (
        crate::context::ProtoContext,
        mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        Box::leak(Box::new(_inbound_rx));
        let ctx = crate::context::ProtoContext::default_table(client);
        (ctx, rib_rx)
    }

    fn test_rib_subscriber() -> crate::config::RibSubscriber {
        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_rib_rx));
        Box::leak(Box::new(_inbound_rx));
        let next_proto_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1));
        crate::config::RibSubscriber::for_test(rib_tx, rib_inbound_tx, next_proto_id)
    }

    fn fresh_bgp() -> Bgp {
        let (ctx, rib_rx) = test_ctx();
        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_policy_rx));
        Bgp::new(ctx, rib_rx, test_rib_subscriber(), policy_tx, None, None)
    }

    fn peer_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    /// Drain `bgp.rx`, returning the peer-ident of every queued
    /// `Event::Stop`. Other event variants are ignored.
    fn drain_stop_events(bgp: &mut Bgp) -> Vec<usize> {
        use crate::bgp::inst::Message;
        use crate::bgp::peer::Event;
        let mut out = Vec::new();
        while let Ok(msg) = bgp.rx.try_recv() {
            if let Message::Event(ident, Event::Stop) = msg {
                out.push(ident);
            }
        }
        out
    }

    /// Group defined first, then peer attaches to it: the resolver
    /// pulls the asn off the group, marks inheritance, and starts
    /// the peer.
    #[tokio::test]
    async fn group_first_then_peer_resolves_and_starts() {
        let mut bgp = fresh_bgp();
        config_neighbor_group(&mut bgp, arg_words(&["RR"]), ConfigOp::Set).unwrap();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["RR", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "RR"]), ConfigOp::Set)
            .unwrap();

        let peer = bgp.peers.get(&peer_addr()).expect("peer exists");
        assert_eq!(peer.remote_as, 65000);
        assert!(peer.config.remote_as_inherited);
        assert!(peer.active, "peer.start() must have fired");
    }

    /// Peer references the group before any remote-as is configured
    /// on it: the peer stays dormant until the group gets its asn,
    /// at which point the reactive sweep adopts and starts.
    #[tokio::test]
    async fn peer_first_then_group_adopts_via_sweep() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        // Group doesn't exist yet — reference is recorded; peer dormant.
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "RR"]), ConfigOp::Set)
            .unwrap();
        {
            let peer = bgp.peers.get(&peer_addr()).unwrap();
            assert_eq!(peer.remote_as, 0);
            assert!(!peer.active);
        }
        // Group's remote-as lands — reactive sweep should adopt.
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["RR", "65000"]), ConfigOp::Set)
            .unwrap();
        let peer = bgp.peers.get(&peer_addr()).unwrap();
        assert_eq!(peer.remote_as, 65000);
        assert!(peer.config.remote_as_inherited);
        assert!(peer.active);
    }

    /// Explicit per-peer remote-as always wins, even if the group
    /// reference is added afterwards.
    #[tokio::test]
    async fn explicit_remote_as_overrides_group() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["RR", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        // Explicit remote-as first.
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        // Now attach the group — must NOT clobber the explicit value.
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "RR"]), ConfigOp::Set)
            .unwrap();
        let peer = bgp.peers.get(&peer_addr()).unwrap();
        assert_eq!(peer.remote_as, 65001, "explicit asn must win");
        assert!(!peer.config.remote_as_inherited);
    }

    /// Deleting the whole group cascades through `sweep_peers_for_group`
    /// and tears inherited peers down. Verified by asserting the
    /// peer's post-state and that `Event::Stop` was enqueued.
    #[tokio::test]
    async fn group_delete_cascades_to_inherited_peers() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["RR", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "RR"]), ConfigOp::Set)
            .unwrap();
        let peer_ident = bgp.peers.get(&peer_addr()).unwrap().ident;
        // Drain the no-op channel state before the delete.
        let _ = drain_stop_events(&mut bgp);

        config_neighbor_group(&mut bgp, arg_words(&["RR"]), ConfigOp::Delete).unwrap();

        let peer = bgp.peers.get(&peer_addr()).unwrap();
        assert_eq!(peer.remote_as, 0);
        assert!(!peer.config.remote_as_inherited);
        assert!(!peer.active);
        assert!(
            drain_stop_events(&mut bgp).contains(&peer_ident),
            "Event::Stop must have been enqueued",
        );
        assert!(
            !bgp.neighbor_groups.contains_key("RR"),
            "group entry removed after cascade",
        );
    }

    /// Changing the group's remote-as while a peer is actively
    /// inheriting bounces the peer (resets `active`, enqueues
    /// `Event::Stop`) so the FSM renegotiates with the new asn.
    #[tokio::test]
    async fn group_remote_as_change_rebounces_active_peer() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["RR", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "RR"]), ConfigOp::Set)
            .unwrap();
        let peer_ident = bgp.peers.get(&peer_addr()).unwrap().ident;
        assert!(bgp.peers.get(&peer_addr()).unwrap().active);
        let _ = drain_stop_events(&mut bgp);

        config_neighbor_group_remote_as(&mut bgp, arg_words(&["RR", "65001"]), ConfigOp::Set)
            .unwrap();

        let peer = bgp.peers.get(&peer_addr()).unwrap();
        assert_eq!(peer.remote_as, 65001, "new asn applied");
        assert!(peer.config.remote_as_inherited);
        assert!(!peer.active, "active cleared in preparation for FSM bounce");
        assert!(
            drain_stop_events(&mut bgp).contains(&peer_ident),
            "Event::Stop must have been enqueued",
        );
    }
}
