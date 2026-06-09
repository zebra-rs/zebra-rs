use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgp_packet::*;

use crate::bfd::inst::ClientReq;
use crate::bfd::session::{EchoMode, SessionKey, SessionParams};
use crate::bfd::socket::{BFD_MULTI_HOP_PORT, BFD_MULTIHOP_DEFAULT_MIN_TTL, BFD_SINGLE_HOP_PORT};
use crate::bgp::InOut;
use crate::bgp_bfd_trace;
use crate::config::{Args, ConfigOp};
use crate::policy;
use crate::policy::com_list::*;
use crate::rib::api::FdbEntry;

use super::auth::AoConfig;
use super::peer::{AfiSafiEncapType, BgpTop};
use super::route_clean;
use super::{
    Bgp,
    inst::Callback,
    peer::{
        ALLOWAS_IN_DEFAULT_COUNT, AllowAsIn, PasswordEncoding, Peer, PeerType, RemovePrivateAs,
    },
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

/// `set router bgp global no-fib-install <true|false>` — route reflector
/// mode. When enabled, the instance's RIB client drops every forwarding
/// install so selected routes stay out of the kernel FIB while the
/// Loc-RIB and peer advertisement keep running. Flips the shared
/// `RibClient` gate (observed by every FSM / listen / timer clone of
/// `ctx.rib`) and mirrors the value on `Bgp` for `show`.
fn config_global_no_fib_install(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let flag = args.boolean()?;
    let enabled = op.is_set() && flag;
    bgp.no_fib_install = enabled;
    bgp.ctx.rib.set_suppress_install(enabled);
    Some(())
}

/// `set router bgp segment-routing srv6 locator <name>` — names the
/// SRv6 locator BGP carves per-VRF End.DT46 service SIDs from for
/// L3VPN over SRv6 (RFC 9252). Mirrors `router isis / segment-routing
/// / srv6 / locator`; BGP has no SR-MPLS knob, so there is no `mpls`
/// sibling. Drives the RIB locator watch (`set_srv6_locator`), which
/// in turn reconciles every `encapsulation srv6` VRF's service SID.
fn config_srv6_locator(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        let name = args.string()?;
        bgp.set_srv6_locator(Some(name));
    } else {
        bgp.set_srv6_locator(None);
    }
    Some(())
}

fn config_peer(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    if op == ConfigOp::Set {
        let mut peer = Peer::new(
            0, // PeerMap will assign the stable index
            bgp.asn,
            bgp.router_id,
            0u32,
            addr,
            bgp.hostname(),
            bgp.tx.clone(),
            bgp.ctx.clone(),
        );
        // Seed the per-peer snapshot of the instance tracing config so
        // the additive (instance ∪ per-neighbor) checks work from the
        // start; later instance-config changes refresh it via
        // `propagate_instance_tracing`.
        peer.tracing_instance = bgp.tracing.clone();
        bgp.peers.insert(addr, peer);
        // Seed `shared_network` from interface addresses learned so far so
        // the eBGP connected check is accurate on this peer's first dial
        // (interfaces are dumped at startup, before config). No peer is
        // dialing yet, so no kick fires here.
        bgp.refresh_connected();
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
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            lu_labels: None,
        };
        route_clean(peer_idx, &mut bgp_ref, &mut bgp.peers);
        bgp.peers.remove(&addr);
    }
    // Keep the shared listener's TCP MSS minimum in step with the peer
    // set: a whole-neighbor delete may drop the peer that owned the
    // current minimum without the per-leaf `/tcp-mss` delete firing (the
    // same gap `clear_peer_listener_auth` covers for MD5/AO).
    apply_tcp_mss_refresh_all(bgp);
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

/// `set router bgp neighbor X flowspec validation true|false` — per
/// RFC 9117, toggle whether flow specs received from this neighbor are
/// validated against the unicast RIB before re-advertising. Defaults to
/// enabled; `delete` (or no config) restores the default.
fn config_flowspec_validation(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let peer = bgp.peers.get_mut(&addr)?;

    peer.config.flowspec_validation = if op.is_set() { flag } else { true };
    Some(())
}

/// `set router bgp neighbor X allowas-in` — the presence container
/// (zebra-bgp-allowas-in.yang). The bare form enables loop relaxation
/// with the default occurrence budget; `delete` disables it.
///
/// `count` / `origin` ride their own callbacks. All three are
/// order-independent within a commit: this handler uses `get_or_insert`
/// so it never clobbers a `count`/`origin` that landed first, and the
/// child handlers overwrite the default this one seeds.
fn config_allowas_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        peer.config
            .allowas_in
            .get_or_insert(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
    } else {
        peer.config.allowas_in = None;
    }
    Some(())
}

/// `set router bgp neighbor X allowas-in count <1-10>`. Deleting just
/// the count reverts to the default budget while the container stays
/// enabled; full removal goes through [`config_allowas_in`].
fn config_allowas_in_count(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;

    if op.is_set() {
        let count = args.u8()?;
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.allowas_in = Some(AllowAsIn::Count(count));
    } else {
        let peer = bgp.peers.get_mut(&addr)?;
        if matches!(peer.config.allowas_in, Some(AllowAsIn::Count(_))) {
            peer.config.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
        }
    }
    Some(())
}

/// `set router bgp neighbor X allowas-in origin`. Deleting `origin`
/// reverts to the default count budget while the container stays
/// enabled; full removal goes through [`config_allowas_in`].
fn config_allowas_in_origin(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        peer.config.allowas_in = Some(AllowAsIn::Origin);
    } else if matches!(peer.config.allowas_in, Some(AllowAsIn::Origin)) {
        peer.config.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
    }
    Some(())
}

/// `set router bgp neighbor X as-override` — the presence container
/// (zebra-bgp-as-override.yang). Enables egress AS_PATH override toward
/// this neighbor (the peer's own AS is swapped for the local AS before
/// the local-AS prepend, on every outbound eBGP UPDATE); `delete`
/// disables it. The flag is a no-op for iBGP peers, which never prepend.
fn config_as_override(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    peer.config.as_override = op.is_set();
    Some(())
}

/// `set router bgp neighbor X remove-private-as` — the presence
/// container (zebra-bgp-remove-private-as.yang). Enables egress
/// private-AS stripping toward this neighbor with both modifiers off
/// (FRR's bare form: strip only when the whole AS_PATH is private);
/// `delete` disables the feature entirely.
///
/// The `all` / `replace-as` modifiers ride their own callbacks. All
/// three are order-independent within a commit: this handler uses
/// `get_or_insert_with` so it never clobbers a modifier that landed
/// first, and the child handlers seed the container if they arrive
/// first.
fn config_remove_private_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        peer.config
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default);
    } else {
        peer.config.remove_private_as = None;
    }
    Some(())
}

/// `set router bgp neighbor X remove-private-as all`. Act on a mixed
/// public/private AS_PATH, not only an all-private one. Deleting just
/// `all` reverts to the conditional (all-private-only) behaviour while
/// the container stays enabled; full removal goes through
/// [`config_remove_private_as`].
fn config_remove_private_as_all(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        peer.config
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default)
            .all = true;
    } else if let Some(rpa) = peer.config.remove_private_as.as_mut() {
        rpa.all = false;
    }
    Some(())
}

/// `set router bgp neighbor X remove-private-as replace-as`. Rewrite
/// each stripped private AS to the local AS instead of dropping it.
/// Deleting just `replace-as` reverts to dropping while the container
/// stays enabled; full removal goes through [`config_remove_private_as`].
fn config_remove_private_as_replace_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        peer.config
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default)
            .replace_as = true;
    } else if let Some(rpa) = peer.config.remove_private_as.as_mut() {
        rpa.replace_as = false;
    }
    Some(())
}

/// `set router bgp neighbor X enforce-first-as` — the presence container
/// (zebra-bgp-enforce-first-as.yang). Enables the inbound first-AS check
/// for this neighbor (drop an eBGP UPDATE whose AS_PATH does not begin
/// with the neighbor's own AS); `delete` disables it. The flag is a no-op
/// for iBGP peers, which never prepend.
fn config_enforce_first_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    peer.config.enforce_first_as = op.is_set();
    Some(())
}

/// `set router bgp neighbor X bfd enable true|false` — flips the
/// Reconcile this neighbor's live BFD subscription with its current
/// `peer.config.bfd` state. Idempotent and order-independent: every
/// `/bfd/*` callback funnels through here, so whichever leaf lands last
/// in a commit leaves the correct session subscribed regardless of the
/// order `enable` / `multihop` / `minimum-ttl` arrive.
///
/// The desired key is recomputed from scratch (local source, hop mode,
/// remote). It's compared against `peer.bfd_session_key` — the key we
/// actually subscribed last time — so a changed key (hop-mode flip,
/// update-source change) unsubscribes the stale session before
/// subscribing the new one. No leak, no duplicate.
///
/// `minimum-ttl` is not part of the key; changing it on an already-up
/// session needs a bounce (BFD applies params only at session
/// creation), consistent with how intervals / profile behave.
fn bfd_apply(bgp: &mut Bgp, addr: IpAddr) -> Option<()> {
    let (enable, desired_key, params) = {
        let peer = bgp.peers.get(&addr)?;
        // Effective enable + Echo = the per-neighbor `bfd {}` merged over the
        // instance-level `router bgp { bfd {} }` default (blanket enable +
        // per-neighbor override). Hop-mode / min-ttl stay per-neighbor.
        let eff = peer.config.bfd.resolve(&bgp.bfd);
        let enable = eff.enable;
        let local = peer
            .config
            .transport
            .update_source
            .unwrap_or_else(|| unspecified_for(&addr));
        let multihop = peer.bfd_multihop();
        let min_ttl = if multihop {
            peer.config
                .bfd
                .minimum_ttl
                .unwrap_or(BFD_MULTIHOP_DEFAULT_MIN_TTL)
        } else {
            255 // GTSM (RFC 5881 §5): single-hop accepts only TTL 255.
        };
        let key = SessionKey {
            local,
            remote: addr,
            ifindex: 0,
            multihop,
        };
        // Echo is single-hop only (RFC 5883 multihop has no Echo), so it's
        // requested only for non-multihop neighbors; the BFD instance gates it
        // further to IPv4 with a live reflector.
        let (echo_mode, echo_rx_us, echo_tx_us) = match eff.echo_mode {
            Some(mode) if !multihop => (
                mode,
                eff.echo_receive_ms.saturating_mul(1000),
                eff.echo_transmit_ms.saturating_mul(1000),
            ),
            _ => (crate::bfd::session::EchoMode::Off, 0, 0),
        };
        let params = SessionParams {
            dst_port: if multihop {
                BFD_MULTI_HOP_PORT
            } else {
                BFD_SINGLE_HOP_PORT
            },
            min_ttl,
            echo_mode,
            required_min_echo_rx_us: echo_rx_us,
            echo_transmit_us: echo_tx_us,
            // Detect-mult still comes from the defaults; the peer's `bfd
            // profile` is stored but not yet resolved (a separate follow-up
            // needing cross-task BfdConfig access).
            ..SessionParams::default()
        };
        (enable, key, params)
    };

    let current = bgp.peers.get(&addr).and_then(|p| p.bfd_session_key);
    let want = enable.then_some(desired_key);
    if want == current {
        return Some(()); // Already in the desired state — no churn.
    }

    let Some(client_tx) = bgp.bfd_client_tx.as_ref() else {
        if enable {
            bgp_bfd_trace!(
                bgp.tracing,
                peer = %addr,
                "bgp: bfd enabled but bfd_client_tx is None (BFD not yet spawned)",
            );
        }
        return Some(());
    };

    // Drop a stale subscription (key changed, or BFD turned off) before
    // adding the new one.
    if let Some(old) = current {
        let _ = client_tx.send(ClientReq::Unsubscribe {
            client: "bgp".to_string(),
            key: old,
        });
    }
    if enable {
        let _ = client_tx.send(ClientReq::Subscribe {
            client: "bgp".to_string(),
            key: desired_key,
            params,
            notifier: bgp.bfd_event_tx.clone(),
        });
    }

    if let Some(peer) = bgp.peers.get_mut(&addr) {
        peer.bfd_session_key = want;
    }
    Some(())
}

/// BFD attachment for this neighbor. Stores the bit on
/// `peer.config.bfd.enable`, then reconciles the live subscription.
fn config_peer_bfd_enable(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let enable = args.boolean()?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        // `None` ⇒ inherit `router bgp { bfd { enable } }`; `Some(false)` opts
        // this neighbor out of a blanket instance enable.
        peer.config.bfd.enable = op.is_set().then_some(enable);
    }
    bfd_apply(bgp, addr)
}

/// `set router bgp neighbor X bfd multihop <bool>` — explicit hop-mode
/// override. Cleared (back to `is_ibgp()`-inference) on delete.
fn config_peer_bfd_multihop(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let multihop = args.boolean()?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.bfd.multihop = op.is_set().then_some(multihop);
    }
    bfd_apply(bgp, addr)
}

/// `set router bgp neighbor X bfd minimum-ttl <1-254>` — multihop
/// received-TTL floor (RFC 5883). Ignored for single-hop sessions.
fn config_peer_bfd_min_ttl(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let ttl = args.u8()?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.bfd.minimum_ttl = op.is_set().then_some(ttl);
    }
    bfd_apply(bgp, addr)
}

/// Parse the `{transmit|receive|both}` echo-mode enum (set) → `Some(mode)`, or
/// `None` on delete. `None`/parse-failure on a malformed value.
fn parse_bfd_echo_mode(value: &str, op: ConfigOp) -> Option<Option<EchoMode>> {
    if !op.is_set() {
        return Some(None);
    }
    match value {
        "transmit" => Some(Some(EchoMode::Transmit)),
        "receive" => Some(Some(EchoMode::Receive)),
        "both" => Some(Some(EchoMode::Both)),
        _ => None,
    }
}

/// `set router bgp neighbor X bfd echo-mode <transmit|receive|both>` —
/// per-neighbor Echo role. Single-hop only (inert on multihop sessions).
fn config_peer_bfd_echo_mode(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let value = args.string()?;
    let mode = parse_bfd_echo_mode(&value, op)?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.bfd.echo_mode = mode;
    }
    bfd_apply(bgp, addr)
}

/// `set router bgp neighbor X bfd echo-transmit-interval <ms>`.
fn config_peer_bfd_echo_tx(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let interval = args.u32()?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.bfd.echo_transmit_ms = op.is_set().then_some(interval);
    }
    bfd_apply(bgp, addr)
}

/// `set router bgp neighbor X bfd echo-receive-interval <ms>`.
fn config_peer_bfd_echo_rx(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let interval = args.u32()?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.bfd.echo_receive_ms = op.is_set().then_some(interval);
    }
    bfd_apply(bgp, addr)
}

/// Re-reconcile BFD for every neighbor — used by the instance-level
/// `router bgp { bfd {} }` callbacks, whose defaults (notably a blanket
/// `enable`) affect neighbors that set nothing of their own. `bfd_apply` is a
/// per-neighbor reconcile that diffs against the recorded session key, so this
/// is just a fan-out.
fn bfd_reconcile_all(bgp: &mut Bgp) {
    let addrs: Vec<IpAddr> = bgp.peers.keys().copied().collect();
    for addr in addrs {
        bfd_apply(bgp, addr);
    }
}

// ---- instance-level `router bgp { bfd { ... } }` defaults -------------------

/// `router bgp bfd enable <bool>` — blanket-enable BFD on every neighbor
/// (a per-neighbor `bfd { enable false }` opts one out).
fn config_bgp_bfd_enable(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let enable = args.boolean()?;
    bgp.bfd.enable = op.is_set().then_some(enable);
    bfd_reconcile_all(bgp);
    Some(())
}

/// `router bgp bfd echo-mode <transmit|receive|both>` — instance default.
fn config_bgp_bfd_echo_mode(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = args.string()?;
    bgp.bfd.echo_mode = parse_bfd_echo_mode(&value, op)?;
    bfd_reconcile_all(bgp);
    Some(())
}

/// `router bgp bfd echo-transmit-interval <ms>` — instance default.
fn config_bgp_bfd_echo_tx(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let interval = args.u32()?;
    bgp.bfd.echo_transmit_ms = op.is_set().then_some(interval);
    Some(())
}

/// `router bgp bfd echo-receive-interval <ms>` — instance default.
fn config_bgp_bfd_echo_rx(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let interval = args.u32()?;
    bgp.bfd.echo_receive_ms = op.is_set().then_some(interval);
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

fn config_afi_safi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let key: AfiSafi = args.afi_safi()?;
    let enabled: bool = args.boolean()?;

    let ipv4_unicast = key.afi == Afi::Ip && key.safi == Safi::Unicast;
    // Enabling a Labeled-Unicast family means we may re-advertise routes
    // with next-hop-self and need per-prefix local labels; request a
    // dynamic label block eagerly so one is granted before routes arrive.
    let lu_enabled = key.safi == Safi::MplsLabel && op.is_set() && enabled;

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
    if lu_enabled {
        bgp.request_label_block();
    }
    Some(())
}

fn config_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    // The `network` key is a union of ipv4-prefix / ipv6-prefix; parse it
    // as the address family the afi-safi selects. An ipv6-prefix under a
    // v4 family (or vice versa) fails to parse and the command is
    // rejected, which is the desired behavior.
    match (afi_safi.afi, afi_safi.safi) {
        (Afi::Ip, Safi::Unicast) => {
            let network = args.v4net()?;
            if op.is_set() {
                bgp.route_add(network);
            } else {
                bgp.route_del(network);
            }
        }
        (Afi::Ip6, Safi::Unicast) => {
            let network = args.v6net()?;
            if op.is_set() {
                bgp.route_add_v6(network);
            } else {
                bgp.route_del_v6(network);
            }
        }
        (Afi::Ip, Safi::MplsLabel) => {
            let network = args.v4net()?;
            if op.is_set() {
                bgp.route_add_label_v4(network);
            } else {
                bgp.route_del_label_v4(network);
            }
        }
        (Afi::Ip6, Safi::MplsLabel) => {
            let network = args.v6net()?;
            if op.is_set() {
                bgp.route_add_label_v6(network);
            } else {
                bgp.route_del_label_v6(network);
            }
        }
        _ => return None,
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
        (Afi::Ip, Safi::Unicast)
            | (Afi::Ip6, Safi::Unicast)
            | (Afi::Ip, Safi::MplsLabel)
            | (Afi::Ip6, Safi::MplsLabel)
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

/// `set/delete router bgp neighbor <addr> afi-safi <name> encapsulation-type
/// <srv6|srv6-relax>`. Records the per-neighbor, per-AFI/SAFI SRv6
/// encapsulation mode on the peer's [`PeerSubConfig`]. The YANG `when`
/// guard restricts the leaf to `afi-safi ipv6`, so in practice `afi_safi`
/// is always IPv6 unicast here. Config-only for now — see
/// [`AfiSafiEncapType`] for the deferred advertise/accept filtering.
fn config_encapsulation_type(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        let encap = AfiSafiEncapType::parse(&args.string()?)?;
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.encapsulation_type = Some(encap);
    } else {
        let config = peer.config.sub.entry(afi_safi).or_default();
        config.encapsulation_type = None;
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

    // IOS-XR semantics: an async BFD session inherits the neighbor's
    // update-source as its local address (see `bfd_apply`, which reads
    // `transport.update_source`). Reconcile here so changing or clearing
    // update-source on a peer that already has BFD enabled rebuilds the
    // session with the new local address instead of leaving it stale at
    // the wildcard (0.0.0.0 / ::) until the next `/bfd/*` leaf change.
    // Order-independent, mirroring the `/bfd/*` callbacks; a no-op when
    // BFD isn't enabled, since `bfd_apply` diffs against the recorded
    // session key.
    bfd_apply(bgp, peer_addr)
}

/// `[no] router bgp neighbor <addr> ttl-security` — enable GTSM (RFC
/// 5082) for a directly-connected peer. The leaf is `type empty`, so
/// presence (Set) turns it on and Delete turns it off; no value is
/// read. The socket options themselves are installed when the TCP
/// session is set up (`fsm_connected`), so a change to an already
/// running session is bounced with `Event::Stop` — the same teardown
/// `clear bgp ... hard` uses — to force a reconnect under the new TTL
/// policy. A peer still Idle is left to pick the option up on its first
/// connect.
fn config_ttl_security(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let want = op.is_set();
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Mutually exclusive with ebgp-multihop: GTSM pins the TTL to 255
        // and filters the received TTL, while ebgp-multihop permits a
        // decremented TTL. Refuse to enable GTSM on a peer that already
        // has ebgp-multihop — the existing setting wins; the operator
        // must remove ebgp-multihop first.
        if want && peer.config.transport.ebgp_multihop.is_some() {
            tracing::warn!(
                peer = %addr,
                "bgp: ttl-security and ebgp-multihop are mutually exclusive; ignoring ttl-security (remove ebgp-multihop on this neighbor first)",
            );
            return Some(());
        }
        if peer.config.transport.ttl_security == want {
            // No actual change — don't disturb a live session.
            return Some(());
        }
        peer.config.transport.ttl_security = want;
        peer.start();
        // Only an established / in-progress session needs an explicit
        // bounce; bouncing an Idle peer here could race the idle-hold
        // timer `start()` just armed and strand it.
        (peer.ident, !matches!(peer.state, super::peer::State::Idle))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// `[no] router bgp neighbor <addr> ebgp-multihop <1-255>` — raise the
/// egress TTL for an eBGP session so a peer up to N hops away is
/// reachable (RFC 4271 operational practice). The value is resolved
/// into the session TTL by [`super::peer::Peer::session_ttl`] (ignored
/// for iBGP) and applied at connect / `fsm_connected`. Mutually
/// exclusive with ttl-security: setting it on a GTSM peer is refused
/// with a warning. A change to a live session is bounced (`Event::Stop`,
/// like `clear bgp ... hard`) so the new TTL takes effect on reconnect;
/// an Idle peer picks it up on its first connect.
fn config_ebgp_multihop(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    // On delete the value (if echoed in the path) is irrelevant — clear
    // unconditionally. On set, read the 1..255 hop count.
    let want = if op.is_set() { Some(args.u8()?) } else { None };
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Mutually exclusive with ttl-security (see `config_ttl_security`).
        // Refuse to set ebgp-multihop on a peer that already has GTSM —
        // the existing setting wins; remove ttl-security first.
        if want.is_some() && peer.config.transport.ttl_security {
            tracing::warn!(
                peer = %addr,
                "bgp: ebgp-multihop and ttl-security are mutually exclusive; ignoring ebgp-multihop (remove ttl-security on this neighbor first)",
            );
            return Some(());
        }
        if peer.config.transport.ebgp_multihop == want {
            return Some(());
        }
        peer.config.transport.ebgp_multihop = want;
        peer.start();
        (peer.ident, !matches!(peer.state, super::peer::State::Idle))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// `[no] router bgp neighbor <addr> tcp-mss <1-65535>` — cap the TCP
/// Maximum Segment Size for this neighbor's connection. Stored on the
/// peer (read at connect time by `peer_connect` for the active socket)
/// and reconciled onto the shared listener via
/// [`apply_tcp_mss_refresh_all`] so passively-accepted connections
/// inherit the clamp. Both apply before the TCP handshake — see
/// [`super::mss`].
///
/// Unlike ttl-security / ebgp-multihop, a change does **not** bounce a
/// live session: matching FRR, the new MSS takes effect on the next
/// connect, so `show bgp neighbor` may report a configured value that
/// differs from the synced one until the operator resets the session
/// (`clear bgp <peer>`). `peer.start()` covers the first-config case
/// (a freshly created, still-Idle peer begins connecting).
fn config_tcp_mss(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    // On delete the echoed value (if any) is irrelevant — clear it.
    let want = if op.is_set() { Some(args.u16()?) } else { None };
    {
        let peer = bgp.peers.get_mut(&addr)?;
        if peer.config.transport.tcp_mss == want {
            // No actual change — leave the live session and listener alone.
            return Some(());
        }
        peer.config.transport.tcp_mss = want;
        peer.start();
    }
    apply_tcp_mss_refresh_all(bgp);
    Some(())
}

/// Reconcile the shared BGP listener's TCP MSS. A listening socket
/// carries a single `TCP_MAXSEG` that every passively-accepted child
/// inherits on its SYN-ACK, so — like FRR's `bgp_tcp_mss_set` — install
/// the **minimum** configured `tcp-mss` across this address family's
/// peers; `0` clears it back to the kernel (path-MTU) default when no
/// peer of that family sets one. The active connect path applies each
/// peer's own value precisely in `peer_connect`, so only the passive
/// path needs this shared approximation. Safe to call repeatedly; silent
/// when a listener fd is not bound yet — `listen()` re-runs it once the
/// bind completes.
pub(super) fn apply_tcp_mss_refresh_all(bgp: &mut Bgp) {
    let mut min_v4: Option<u16> = None;
    let mut min_v6: Option<u16> = None;
    let addrs: Vec<IpAddr> = bgp.peers.keys().copied().collect();
    for addr in &addrs {
        let Some(mss) = bgp.peers.get(addr).and_then(|p| p.config.transport.tcp_mss) else {
            continue;
        };
        let slot = if addr.is_ipv4() {
            &mut min_v4
        } else {
            &mut min_v6
        };
        *slot = Some(slot.map_or(mss, |cur| cur.min(mss)));
    }
    for (fd, min) in [(bgp.listen_fd_v4, min_v4), (bgp.listen_fd_v6, min_v6)] {
        let Some(fd) = fd else { continue };
        // 0 resets the user MSS to the kernel default.
        let value = min.unwrap_or(0);
        if let Err(e) = super::mss::set_tcp_mss(fd, value) {
            tracing::warn!(
                error = %e,
                mss = value,
                "bgp: failed to set TCP MSS on BGP listener",
            );
        }
    }
}

/// `[no] router bgp neighbor <addr> disable-connected-check` — exempt a
/// single-hop eBGP neighbor from the directly-connected-network check, so
/// a session toward a non-connected address (typically a loopback one L2
/// hop away) is dialed while the egress TTL stays at 1. No-op for iBGP and
/// for multihop / GTSM sessions (the check never applies there). The flag
/// is consulted by [`super::peer::Peer::connected_check_ok`] at
/// connect-initiation time. Like the sibling TTL knobs, a change on a live
/// session bounces it (`Event::Stop`, as `clear bgp ... hard` does): on
/// enable a peer held by the check reconnects on the next start; on
/// disable an established but non-connected session is reset (FRR's
/// `peer_change_reset`). An Idle peer just picks it up on its first connect.
fn config_disable_connected_check(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let want = op.is_set();
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        if peer.config.transport.disable_connected_check == want {
            // No actual change — don't disturb a live session.
            return Some(());
        }
        peer.config.transport.disable_connected_check = want;
        peer.start();
        // Only an established / in-progress session needs an explicit
        // bounce; bouncing an Idle peer here could race the idle-hold
        // timer `start()` just armed and strand it. A held (Active) peer
        // is bounced too, so it leaves Active and re-dials on the next
        // idle-hold rather than waiting out the connect-retry backstop.
        (peer.ident, !matches!(peer.state, super::peer::State::Idle))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
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

    // Store the password on the peer if it exists. The peer may not
    // be in the map yet if the per-leaf callbacks fire in deeper-first
    // order (`/password` before `/neighbor`); in that case we just
    // skip the field-store — the peer will be created momentarily and
    // a follow-up `apply_md5_refresh_all` will catch up. The earlier
    // `?` short-circuit also skipped the listener install, which is
    // the actual bug that left passive peers unauthenticated.
    if op == ConfigOp::Set {
        let password = args.string()?;
        if let Some(peer) = bgp.peers.get_mut(&addr) {
            peer.config.transport.md5_password = Some(password);
        }
    } else if let Some(peer) = bgp.peers.get_mut(&addr) {
        peer.config.transport.md5_password = None;
    }

    // Reconcile the listener state for this peer regardless of
    // whether the field-store branch fired. The reconciler reads from
    // peer.config.transport.md5_password, so callers later in the
    // commit can still get the install when the peer materializes
    // (we run apply_md5_refresh_all from config_peer too).
    apply_md5_refresh_for(bgp, addr);

    Some(())
}

/// Reconcile the listener TCP MD5 key for a single peer. Reads
/// `peer.config.transport.md5_password` and installs (or removes,
/// with an empty key) on the appropriate listening socket. Silent
/// when there is no listener fd yet — `apply_md5_refresh_all` from
/// `listen()` will fill in once the bind completes.
fn apply_md5_refresh_for(bgp: &mut Bgp, addr: IpAddr) {
    let listen_fd = match addr {
        IpAddr::V4(_) => bgp.listen_fd_v4,
        IpAddr::V6(_) => bgp.listen_fd_v6,
    };
    let Some(fd) = listen_fd else {
        // Listener not bound yet. The startup reconciler in `listen()`
        // will install the key once the fd is captured.
        return;
    };

    // Empty key removes the entry. Either the peer has no password
    // set, or the peer doesn't exist in the map (delete path).
    let password_bytes: Vec<u8> = bgp
        .peers
        .get(&addr)
        .and_then(|p| p.config.transport.md5_password.as_ref())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();

    match super::auth::set_tcp_md5_key(fd, addr, &password_bytes) {
        Ok(()) => {
            if !password_bytes.is_empty() {
                tracing::debug!(
                    peer = %addr,
                    keylen = password_bytes.len(),
                    "bgp: TCP MD5 installed on listener for peer",
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                peer = %addr,
                error = %e,
                "TCP MD5 setsockopt on listener failed; incoming SYNs from this peer will be dropped"
            );
        }
    }
}

/// Iterate every peer with an MD5 password configured and install its
/// key on the matching listener fd. Mirrors `apply_ao_refresh_all`.
/// Safe to call repeatedly — `setsockopt(TCP_MD5SIG)` is idempotent
/// for the same (addr, key) tuple.
pub(super) fn apply_md5_refresh_all(bgp: &mut Bgp) {
    let addrs: Vec<IpAddr> = bgp.peers.keys().copied().collect();
    for addr in addrs {
        apply_md5_refresh_for(bgp, addr);
    }
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
        self.callback_add(
            "/router/bgp/global/no-fib-install",
            config_global_no_fib_install,
        );
        self.callback_add(
            "/router/bgp/segment-routing/srv6/locator",
            config_srv6_locator,
        );
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
        // `set router bgp sr-policy policy <NAME> [...]`
        // (zebra-bgp-sr-policy.yang). Locally-originated SR Policies,
        // advertised as SAFI 73; callbacks stage onto
        // `Bgp::local_rib.sr_policy_local` and re-advertise.
        self.callback_add(
            "/router/bgp/sr-policy/policy",
            super::sr_policy::config_srp_policy,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/color",
            super::sr_policy::config_srp_color,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/endpoint",
            super::sr_policy::config_srp_endpoint,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/preference",
            super::sr_policy::config_srp_preference,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/binding-sid-label",
            super::sr_policy::config_srp_binding_sid_label,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/binding-sid-sid",
            super::sr_policy::config_srp_binding_sid_sid,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/route-target",
            super::sr_policy::config_srp_route_target,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/segment",
            super::sr_policy::config_srp_segment,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/segment/mpls-label",
            super::sr_policy::config_srp_segment_mpls_label,
        );
        self.callback_add(
            "/router/bgp/sr-policy/policy/segment/srv6-sid",
            super::sr_policy::config_srp_segment_srv6_sid,
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
            "/router/bgp/vrf/encapsulation",
            super::vrf_config::config_vrf_encapsulation,
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
            "/router/bgp/vrf/afi-safi/ipv4",
            super::vrf_config::config_vrf_afi_ipv4,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4/network",
            super::vrf_config::config_vrf_afi_ipv4_network,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6",
            super::vrf_config::config_vrf_afi_ipv6,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6/network",
            super::vrf_config::config_vrf_afi_ipv6_network,
        );
        self.callback_add(
            "/router/bgp/vrf/evpn/advertise-ipv4",
            super::vrf_config::config_vrf_evpn_advertise_ipv4,
        );
        self.callback_add(
            "/router/bgp/vrf/evpn/advertise-ipv6",
            super::vrf_config::config_vrf_evpn_advertise_ipv6,
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
        // FRR-style `neighbor X ttl-security` (GTSM, RFC 5082) from
        // zebra-bgp-transport.yang. `type empty` flag — directly
        // connected only, TTL pinned to 255. Lowered onto the session
        // socket in `fsm_connected`.
        self.callback_peer("/ttl-security", config_ttl_security);
        // FRR-style `neighbor X ebgp-multihop <1-255>` from
        // zebra-bgp-transport.yang. Raises the eBGP egress TTL; resolved
        // by Peer::session_ttl and applied at connect / fsm_connected.
        self.callback_peer("/ebgp-multihop", config_ebgp_multihop);
        self.callback_peer("/tcp-mss", config_tcp_mss);
        // FRR-style `neighbor X disable-connected-check` from
        // zebra-bgp-transport.yang. Exempts a single-hop eBGP neighbor from
        // the directly-connected-network check (Peer::connected_check_ok).
        self.callback_peer("/disable-connected-check", config_disable_connected_check);
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
        self.callback_peer("/bfd/multihop", config_peer_bfd_multihop);
        self.callback_peer("/bfd/minimum-ttl", config_peer_bfd_min_ttl);
        self.callback_peer("/bfd/echo-mode", config_peer_bfd_echo_mode);
        self.callback_peer("/bfd/echo-transmit-interval", config_peer_bfd_echo_tx);
        self.callback_peer("/bfd/echo-receive-interval", config_peer_bfd_echo_rx);
        // Instance-level `router bgp { bfd { ... } }` defaults.
        self.callback_add("/router/bgp/bfd/enable", config_bgp_bfd_enable);
        self.callback_add("/router/bgp/bfd/echo-mode", config_bgp_bfd_echo_mode);
        self.callback_add(
            "/router/bgp/bfd/echo-transmit-interval",
            config_bgp_bfd_echo_tx,
        );
        self.callback_add(
            "/router/bgp/bfd/echo-receive-interval",
            config_bgp_bfd_echo_rx,
        );
        self.callback_peer("/tcp-ao/key-chain", config_peer_tcp_ao_key_chain);
        self.callback_peer(
            "/tcp-ao/include-tcp-options",
            config_peer_tcp_ao_include_tcp_options,
        );

        self.callback_peer("/afi-safi/enabled", config_afi_safi);
        self.callback_peer("/afi-safi/add-path", config_add_path);
        self.callback_peer("/afi-safi/encapsulation-type", config_encapsulation_type);
        self.callback_peer("/afi-safi/graceful-restart/enabled", config_restart);
        self.callback_peer("/afi-safi/long-lived-graceful-restart/enabled", config_llgr);
        self.callback_peer(
            "/afi-safi/long-lived-graceful-restart/restart-time",
            config_llgr_restart_time,
        );

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

        // Per-neighbor Flowspec validation toggle (zebra-bgp-flowspec.yang).
        self.callback_peer("/flowspec/validation", config_flowspec_validation);

        // Per-neighbor allowas-in (zebra-bgp-allowas-in.yang). The
        // presence container relaxes the inbound AS_PATH loop check;
        // `count` caps occurrences (default 3) and `origin` accepts the
        // local AS only at the origin. `count`/`origin` are mutually
        // exclusive via the YANG `choice`.
        self.callback_peer("/allowas-in", config_allowas_in);
        self.callback_peer("/allowas-in/count", config_allowas_in_count);
        self.callback_peer("/allowas-in/origin", config_allowas_in_origin);

        // Per-neighbor as-override (zebra-bgp-as-override.yang). On the
        // egress path toward this neighbor, replace its own AS with the
        // local AS in the AS_PATH so its RFC 4271 loop check accepts
        // routes that transited its AS (eBGP only).
        self.callback_peer("/as-override", config_as_override);

        // Per-neighbor remove-private-as (zebra-bgp-remove-private-as.yang).
        // Strip (or, with `replace-as`, rewrite to the local AS) private
        // ASNs from the egress AS_PATH toward this neighbor; the `all`
        // modifier widens it from all-private-only to any path (eBGP only).
        self.callback_peer("/remove-private-as", config_remove_private_as);
        self.callback_peer("/remove-private-as/all", config_remove_private_as_all);
        self.callback_peer(
            "/remove-private-as/replace-as",
            config_remove_private_as_replace_as,
        );

        // Per-neighbor enforce-first-as (zebra-bgp-enforce-first-as.yang).
        // The presence container drops an inbound eBGP UPDATE unless the
        // left-most AS_PATH segment begins with the neighbor's own AS
        // (eBGP only).
        self.callback_peer("/enforce-first-as", config_enforce_first_as);
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
            tokio::sync::mpsc::channel(1).0,
        );
        (bgp, bfd_client_rx)
    }

    /// `bfd enable true` on a known iBGP neighbor (the default peer
    /// type) auto-infers multihop and subscribes on the 4784 port.
    #[tokio::test]
    async fn enable_sends_subscribe() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        // Add the peer first (the callback only fires for known peers).
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        // Now flip BFD on.
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.2", "true"]), ConfigOp::Set).unwrap();

        let req = bfd_rx.try_recv().expect("BGP must send a ClientReq");
        match req {
            ClientReq::Subscribe {
                client,
                key,
                params,
                ..
            } => {
                assert_eq!(client, "bgp");
                assert_eq!(
                    key.remote,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    "remote address mirrors the configured neighbor",
                );
                assert!(key.multihop, "iBGP default infers multihop (FRR-style)");
                assert_eq!(params.dst_port, BFD_MULTI_HOP_PORT);
                assert_eq!(params.min_ttl, BFD_MULTIHOP_DEFAULT_MIN_TTL);
                assert_eq!(key.ifindex, 0);
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// An eBGP neighbor with no override defaults to single-hop
    /// (port 3784, GTSM TTL floor of 255).
    #[tokio::test]
    async fn enable_ebgp_is_single_hop() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.5"]), ConfigOp::Set).unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        bgp.peers.get_mut(&addr).unwrap().peer_type = PeerType::EBGP;

        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.5", "true"]), ConfigOp::Set).unwrap();
        match bfd_rx.try_recv().expect("subscribe") {
            ClientReq::Subscribe { key, params, .. } => {
                assert!(!key.multihop, "eBGP without override is single-hop");
                assert_eq!(params.dst_port, BFD_SINGLE_HOP_PORT);
                assert_eq!(params.min_ttl, 255);
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// IOS-XR semantics: an async BFD session inherits the neighbor's
    /// `update-source` as its local address — order-independently, so
    /// setting update-source AFTER `bfd enable` rebuilds the session
    /// with the new local instead of leaving it stale at the wildcard.
    /// Regression: the update-source callback now re-runs `bfd_apply`.
    #[tokio::test]
    async fn bfd_inherits_update_source_after_enable() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.5"]), ConfigOp::Set).unwrap();

        // Enable BFD first → subscribe with the wildcard local.
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.5", "true"]), ConfigOp::Set).unwrap();
        let first_key = match bfd_rx.try_recv().expect("initial subscribe") {
            ClientReq::Subscribe { key, .. } => {
                assert_eq!(
                    key.local,
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    "no update-source ⇒ wildcard local",
                );
                key
            }
            other => panic!("expected Subscribe, got {other:?}"),
        };

        // Set update-source AFTER bfd is already enabled.
        config_transport_local_address(
            &mut bgp,
            arg_words(&["10.0.0.5", "10.0.0.100"]),
            ConfigOp::Set,
        )
        .unwrap();

        // The stale wildcard-local session is dropped …
        match bfd_rx.try_recv().expect("unsubscribe stale key") {
            ClientReq::Unsubscribe { key, .. } => {
                assert_eq!(key, first_key, "old wildcard-local session removed");
            }
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
        // … and re-created with the update-source as the local address.
        match bfd_rx.try_recv().expect("resubscribe with update-source") {
            ClientReq::Subscribe { key, .. } => {
                assert_eq!(
                    key.local,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
                    "BFD local inherits update-source",
                );
                assert_eq!(key.remote, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// Clearing update-source on a BFD-enabled peer reverts the local
    /// address to the wildcard (the kernel then picks the source).
    #[tokio::test]
    async fn bfd_update_source_cleared_reverts_to_wildcard() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.5"]), ConfigOp::Set).unwrap();
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.5", "true"]), ConfigOp::Set).unwrap();
        let _ = bfd_rx.try_recv().expect("initial wildcard subscribe");

        config_transport_local_address(
            &mut bgp,
            arg_words(&["10.0.0.5", "10.0.0.100"]),
            ConfigOp::Set,
        )
        .unwrap();
        let _ = bfd_rx.try_recv().expect("unsubscribe wildcard");
        let _ = bfd_rx.try_recv().expect("subscribe 10.0.0.100");

        // Delete update-source → session rebuilt with the wildcard local.
        config_transport_local_address(
            &mut bgp,
            arg_words(&["10.0.0.5", "10.0.0.100"]),
            ConfigOp::Delete,
        )
        .unwrap();
        match bfd_rx.try_recv().expect("unsubscribe 10.0.0.100") {
            ClientReq::Unsubscribe { key, .. } => {
                assert_eq!(key.local, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)));
            }
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
        match bfd_rx.try_recv().expect("resubscribe wildcard") {
            ClientReq::Subscribe { key, .. } => {
                assert_eq!(
                    key.local,
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    "cleared update-source ⇒ wildcard local again",
                );
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// `bfd multihop true` forces multihop even on an eBGP neighbor,
    /// regardless of the order the leaves arrive within the commit
    /// (enable lands first, then the override) — the stale single-hop
    /// session is unsubscribed and replaced.
    #[tokio::test]
    async fn multihop_override_replaces_single_hop() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.6"]), ConfigOp::Set).unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        bgp.peers.get_mut(&addr).unwrap().peer_type = PeerType::EBGP;

        // enable first → transient single-hop subscribe.
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.6", "true"]), ConfigOp::Set).unwrap();
        match bfd_rx.try_recv().expect("initial subscribe") {
            ClientReq::Subscribe { key, .. } => assert!(!key.multihop),
            other => panic!("expected Subscribe, got {other:?}"),
        }

        // override arrives → unsubscribe single-hop, subscribe multihop.
        config_peer_bfd_multihop(&mut bgp, arg_words(&["10.0.0.6", "true"]), ConfigOp::Set)
            .unwrap();
        match bfd_rx.try_recv().expect("unsubscribe stale key") {
            ClientReq::Unsubscribe { key, .. } => assert!(!key.multihop),
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
        match bfd_rx.try_recv().expect("resubscribe multihop") {
            ClientReq::Subscribe { key, params, .. } => {
                assert!(key.multihop);
                assert_eq!(params.dst_port, BFD_MULTI_HOP_PORT);
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
        let mut bgp = Bgp::new(
            ctx,
            rib_rx,
            test_rib_subscriber(),
            policy_tx,
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
        );
        config_peer(&mut bgp, arg_words(&["10.0.0.4"]), ConfigOp::Set).unwrap();
        // No bfd handle to assert against; the call must not panic.
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.4", "true"]), ConfigOp::Set).unwrap();

        let peer = bgp
            .peers
            .get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)))
            .unwrap();
        assert_eq!(peer.config.bfd.enable, Some(true), "config bit still flips");
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

    fn peer_allowas_in(bgp: &Bgp, addr: &str) -> Option<AllowAsIn> {
        bgp.peers
            .get(&addr.parse().unwrap())
            .unwrap()
            .config
            .allowas_in
    }

    /// Bare `allowas-in` (presence container, no child) enables the
    /// relaxation with the default occurrence budget of 3.
    #[tokio::test]
    async fn allowas_in_bare_defaults_to_three() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_allowas_in(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert_eq!(peer_allowas_in(&bgp, "10.0.0.2"), Some(AllowAsIn::Count(3)));
    }

    /// `allowas-in count <n>` overrides the budget; `delete` reverts to
    /// the default while the container stays enabled.
    #[tokio::test]
    async fn allowas_in_count_sets_and_reverts() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_allowas_in_count(&mut bgp, arg_words(&["10.0.0.2", "5"]), ConfigOp::Set).unwrap();
        assert_eq!(peer_allowas_in(&bgp, "10.0.0.2"), Some(AllowAsIn::Count(5)));
        config_allowas_in_count(&mut bgp, arg_words(&["10.0.0.2", "5"]), ConfigOp::Delete).unwrap();
        assert_eq!(peer_allowas_in(&bgp, "10.0.0.2"), Some(AllowAsIn::Count(3)));
    }

    /// `allowas-in origin` selects origin-only mode.
    #[tokio::test]
    async fn allowas_in_origin_mode() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_allowas_in_origin(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert_eq!(peer_allowas_in(&bgp, "10.0.0.2"), Some(AllowAsIn::Origin));
    }

    /// Deleting the presence container disables allowas-in entirely.
    #[tokio::test]
    async fn allowas_in_delete_disables() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_allowas_in(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_allowas_in(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete).unwrap();
        assert_eq!(peer_allowas_in(&bgp, "10.0.0.2"), None);
    }

    /// The presence callback must not clobber a `count`/`origin` that
    /// landed first in the same commit (callbacks are order-independent).
    #[tokio::test]
    async fn allowas_in_presence_does_not_clobber_count() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        // Child leaf fires before the presence container.
        config_allowas_in_count(&mut bgp, arg_words(&["10.0.0.2", "7"]), ConfigOp::Set).unwrap();
        config_allowas_in(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert_eq!(peer_allowas_in(&bgp, "10.0.0.2"), Some(AllowAsIn::Count(7)));
    }

    fn peer_as_override(bgp: &Bgp, addr: &str) -> bool {
        bgp.peers
            .get(&addr.parse().unwrap())
            .unwrap()
            .config
            .as_override
    }

    /// `as-override` defaults off and the presence container turns it on.
    #[tokio::test]
    async fn as_override_set_enables() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert!(!peer_as_override(&bgp, "10.0.0.2"));
        config_as_override(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert!(peer_as_override(&bgp, "10.0.0.2"));
    }

    /// Deleting the presence container turns `as-override` back off.
    #[tokio::test]
    async fn as_override_delete_disables() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_as_override(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_as_override(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete).unwrap();
        assert!(!peer_as_override(&bgp, "10.0.0.2"));
    }

    fn peer_remove_private_as(bgp: &Bgp, addr: &str) -> Option<RemovePrivateAs> {
        bgp.peers
            .get(&addr.parse().unwrap())
            .unwrap()
            .config
            .remove_private_as
    }

    /// The bare presence container enables the feature with both
    /// modifiers off (FRR's plain `remove-private-AS`).
    #[tokio::test]
    async fn remove_private_as_set_enables_bare() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert_eq!(peer_remove_private_as(&bgp, "10.0.0.2"), None);
        config_remove_private_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert_eq!(
            peer_remove_private_as(&bgp, "10.0.0.2"),
            Some(RemovePrivateAs {
                all: false,
                replace_as: false
            })
        );
    }

    /// `all` and `replace-as` arriving in either order both land, and
    /// neither child clobbers the other or the container. Mirrors the
    /// order-independence the BGP commit pipeline relies on.
    #[tokio::test]
    async fn remove_private_as_modifiers_compose_order_independent() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        // Child callbacks arrive before the container set — `get_or_insert`
        // must seed it rather than no-op.
        config_remove_private_as_replace_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set)
            .unwrap();
        config_remove_private_as_all(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_remove_private_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert_eq!(
            peer_remove_private_as(&bgp, "10.0.0.2"),
            Some(RemovePrivateAs {
                all: true,
                replace_as: true
            })
        );
    }

    /// Deleting a single modifier reverts just that modifier; deleting
    /// the container disables the whole feature.
    #[tokio::test]
    async fn remove_private_as_partial_then_full_delete() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_remove_private_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_remove_private_as_all(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_remove_private_as_replace_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set)
            .unwrap();

        // Drop just `all`; the container and `replace-as` stay.
        config_remove_private_as_all(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            peer_remove_private_as(&bgp, "10.0.0.2"),
            Some(RemovePrivateAs {
                all: false,
                replace_as: true
            })
        );

        // Drop the whole container.
        config_remove_private_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete).unwrap();
        assert_eq!(peer_remove_private_as(&bgp, "10.0.0.2"), None);
    }

    fn peer_enforce_first_as(bgp: &Bgp, addr: &str) -> bool {
        bgp.peers
            .get(&addr.parse().unwrap())
            .unwrap()
            .config
            .enforce_first_as
    }

    /// `enforce-first-as` defaults off and the presence container turns
    /// it on.
    #[tokio::test]
    async fn enforce_first_as_set_enables() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert!(!peer_enforce_first_as(&bgp, "10.0.0.2"));
        config_enforce_first_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert!(peer_enforce_first_as(&bgp, "10.0.0.2"));
    }

    /// Deleting the presence container turns `enforce-first-as` back off.
    #[tokio::test]
    async fn enforce_first_as_delete_disables() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_enforce_first_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        config_enforce_first_as(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete).unwrap();
        assert!(!peer_enforce_first_as(&bgp, "10.0.0.2"));
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
        Bgp::new(
            ctx,
            rib_rx,
            test_rib_subscriber(),
            policy_tx,
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
        )
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

    /// `ttl-security` is a `type empty` flag: Set turns it on, Delete
    /// turns it off, and a change to an already-established session is
    /// bounced (`Event::Stop`) so the new TTL policy applies on the
    /// reconnect. A no-op Set must not bounce.
    #[tokio::test]
    async fn ttl_security_toggles_field_and_bounces_live_session() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        // Pretend the session is established so a toggle must bounce.
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        // Enable: field set + one Event::Stop queued.
        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ttl_security,
            "set must enable the flag",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "enabling on a live session must bounce it",
        );

        // The bounce is modeled only as a queued event in the unit
        // harness, so the state is still Established. Idempotent set:
        // no change, no bounce.
        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a no-op set must not bounce the session",
        );

        // Disable: field cleared + one Event::Stop queued.
        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert!(
            !bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ttl_security,
            "delete must clear the flag",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "disabling on a live session must bounce it",
        );
    }

    /// A peer still Idle (never connected) must not be bounced when
    /// ttl-security is set during initial config — the flag is stored
    /// and the first connect picks it up.
    #[tokio::test]
    async fn ttl_security_on_idle_peer_does_not_bounce() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ttl_security,
            "flag must still be stored on an Idle peer",
        );
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "an Idle peer must not be bounced",
        );
    }

    /// Build a `LinkAddr` for an interface prefix (e.g. `"10.0.0.1/24"`).
    fn link_addr(cidr: &str) -> crate::rib::link::LinkAddr {
        crate::rib::link::LinkAddr {
            addr: cidr.parse().unwrap(),
            ifindex: 2,
            secondary: false,
            config: false,
            fib: true,
        }
    }

    /// `disable-connected-check` is a `type empty` flag: Set/Delete toggle
    /// it and a change to a live session is bounced (FRR resets the peer
    /// on this flag); a no-op set does not bounce, an Idle peer is not
    /// bounced.
    #[tokio::test]
    async fn disable_connected_check_toggles_field_and_bounces_live_session() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_disable_connected_check(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .disable_connected_check,
            "set must enable the flag",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "enabling on a live session must bounce it",
        );

        config_disable_connected_check(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a no-op set must not bounce the session",
        );

        config_disable_connected_check(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete)
            .unwrap();
        assert!(
            !bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .disable_connected_check,
            "delete must clear the flag",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "disabling on a live session must bounce it",
        );
    }

    /// A single-hop eBGP peer whose address is not on a connected subnet
    /// is gated by the connected check; learning the link does not help
    /// (the peer's loopback is off-subnet) but `disable-connected-check`
    /// lifts the gate. With no interface knowledge the check fails open.
    #[tokio::test]
    async fn connected_check_gates_unconnected_single_hop_ebgp() {
        let mut bgp = fresh_bgp();
        bgp.asn = 65000;
        // eBGP peer reachable only via its loopback (10.255.0.2).
        let loop_peer = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 2));
        config_peer(&mut bgp, arg_words(&["10.255.0.2"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.255.0.2", "65001"]), ConfigOp::Set).unwrap();

        // No interface knowledge yet → fail open.
        assert!(
            bgp.peers.get(&loop_peer).unwrap().connected_check_ok(),
            "with no connected-subnet knowledge the check fails open",
        );

        // Learn the directly-connected /24; the loopback peer is not in it.
        bgp.connected_subnets.record(&link_addr("10.0.0.1/24"));
        bgp.refresh_connected();
        let peer = bgp.peers.get(&loop_peer).unwrap();
        assert!(peer.is_ebgp());
        assert!(
            !peer.shared_network,
            "loopback peer is not on the connected /24"
        );
        assert!(
            !peer.connected_check_ok(),
            "a single-hop eBGP peer off every connected subnet must be gated",
        );

        // The override lifts the gate.
        config_disable_connected_check(&mut bgp, arg_words(&["10.255.0.2"]), ConfigOp::Set)
            .unwrap();
        assert!(
            bgp.peers.get(&loop_peer).unwrap().connected_check_ok(),
            "disable-connected-check exempts the peer",
        );

        // So does learning a subnet that actually covers the peer.
        config_disable_connected_check(&mut bgp, arg_words(&["10.255.0.2"]), ConfigOp::Delete)
            .unwrap();
        bgp.connected_subnets.record(&link_addr("10.255.0.1/24"));
        bgp.refresh_connected();
        assert!(
            bgp.peers.get(&loop_peer).unwrap().connected_check_ok(),
            "once the peer is on a connected subnet the check passes",
        );
    }

    /// The connected check never applies to iBGP, multihop or GTSM peers,
    /// even when they are off every connected subnet.
    #[tokio::test]
    async fn connected_check_never_gates_ibgp_or_multihop() {
        let mut bgp = fresh_bgp();
        bgp.asn = 65000;
        // Only a /24 link is connected; both peers below are off-subnet.
        bgp.connected_subnets.record(&link_addr("10.0.0.1/24"));

        // iBGP peer (remote-as == local) — never gated.
        let ibgp = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 9));
        config_peer(&mut bgp, arg_words(&["10.255.0.9"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.255.0.9", "65000"]), ConfigOp::Set).unwrap();

        // eBGP peer with ebgp-multihop — never gated.
        let mh = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 8));
        config_peer(&mut bgp, arg_words(&["10.255.0.8"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.255.0.8", "65001"]), ConfigOp::Set).unwrap();
        config_ebgp_multihop(&mut bgp, arg_words(&["10.255.0.8", "5"]), ConfigOp::Set).unwrap();

        bgp.refresh_connected();
        assert!(
            !bgp.peers.get(&ibgp).unwrap().shared_network,
            "iBGP peer is off-subnet",
        );
        assert!(
            bgp.peers.get(&ibgp).unwrap().connected_check_ok(),
            "iBGP is never subject to the connected check",
        );
        assert!(
            bgp.peers.get(&mh).unwrap().connected_check_ok(),
            "a multihop eBGP peer is never subject to the connected check",
        );
    }

    /// `Peer::session_ttl` resolution: a directly-connected eBGP peer
    /// defaults to TTL 1, `ebgp-multihop N` raises it to N, and
    /// `ttl-security` overrides both with 255.
    #[tokio::test]
    async fn session_ttl_ebgp_default_multihop_and_ttl_security() {
        let mut bgp = fresh_bgp(); // local asn 0
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        // remote-as 65001 != local 0 ⇒ eBGP.
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().session_ttl(),
            1,
            "directly-connected eBGP must default to TTL 1",
        );

        // ebgp-multihop raises the egress TTL.
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "10"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().session_ttl(),
            10,
            "ebgp-multihop N must set the egress TTL to N",
        );

        // Clearing ebgp-multihop returns to the eBGP default.
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "10"]), ConfigOp::Delete).unwrap();
        assert_eq!(bgp.peers.get(&peer_addr()).unwrap().session_ttl(), 1);

        // ttl-security alone ⇒ 255 (the two options are mutually
        // exclusive at config time, so they are set separately here).
        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().session_ttl(),
            255,
            "ttl-security ⇒ 255",
        );

        // Defensive precedence inside session_ttl: even if both fields
        // somehow coexisted (the callbacks reject this — see the
        // mutual-exclusion tests), ttl-security wins. Set the field
        // directly to exercise that fallback branch.
        bgp.peers
            .get_mut(&peer_addr())
            .unwrap()
            .config
            .transport
            .ebgp_multihop = Some(10);
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().session_ttl(),
            255,
            "ttl-security must win over a coexisting ebgp-multihop",
        );
    }

    /// An iBGP peer always uses TTL 255, and `ebgp-multihop` is ignored
    /// on it (mirroring FRR).
    #[tokio::test]
    async fn session_ttl_ibgp_is_255_and_ignores_multihop() {
        let mut bgp = fresh_bgp();
        bgp.asn = 65000;
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        // remote-as == local asn ⇒ iBGP.
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65000"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().session_ttl(),
            255,
            "iBGP must use TTL 255",
        );

        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "5"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().session_ttl(),
            255,
            "ebgp-multihop must be ignored on an iBGP peer",
        );
    }

    /// `ebgp-multihop` stores the hop count, is idempotent on a no-op
    /// set, bounces an established session on change, and clears on
    /// delete.
    #[tokio::test]
    async fn ebgp_multihop_sets_value_and_bounces_live_session() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        // Set 5 → stored + one bounce.
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "5"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ebgp_multihop,
            Some(5),
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "changing ebgp-multihop on a live session must bounce it",
        );

        // Same value again → no-op, no bounce.
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "5"]), ConfigOp::Set).unwrap();
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "re-setting the same hop count must not bounce",
        );

        // Delete → cleared + bounce.
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ebgp_multihop,
            None,
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "deleting ebgp-multihop on a live session must bounce it",
        );
    }

    /// ttl-security and ebgp-multihop are mutually exclusive: with
    /// ebgp-multihop already set, a `set ... ttl-security` is refused
    /// (the existing setting wins) and does not bounce the session.
    #[tokio::test]
    async fn ttl_security_refused_when_ebgp_multihop_set() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "5"]), ConfigOp::Set).unwrap();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = crate::bgp::peer::State::Established;
        let _ = drain_stop_events(&mut bgp);

        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();

        let p = bgp.peers.get(&peer_addr()).unwrap();
        assert!(
            !p.config.transport.ttl_security,
            "ttl-security must be refused while ebgp-multihop is set",
        );
        assert_eq!(
            p.config.transport.ebgp_multihop,
            Some(5),
            "the existing ebgp-multihop must be left untouched",
        );
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a refused config must not bounce the session",
        );
    }

    /// The symmetric direction: with ttl-security already set, a
    /// `set ... ebgp-multihop N` is refused.
    #[tokio::test]
    async fn ebgp_multihop_refused_when_ttl_security_set() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = crate::bgp::peer::State::Established;
        let _ = drain_stop_events(&mut bgp);

        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "5"]), ConfigOp::Set).unwrap();

        let p = bgp.peers.get(&peer_addr()).unwrap();
        assert_eq!(
            p.config.transport.ebgp_multihop, None,
            "ebgp-multihop must be refused while ttl-security is set",
        );
        assert!(
            p.config.transport.ttl_security,
            "the existing ttl-security must be left untouched",
        );
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a refused config must not bounce the session",
        );
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
