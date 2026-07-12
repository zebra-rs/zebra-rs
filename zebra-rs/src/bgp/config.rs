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
    AssistedReplicationRole, BGP_PORT, Bgp, EvpnBumTunnel,
    inst::Callback,
    peer::{
        ALLOWAS_IN_DEFAULT_COUNT, AllowAsIn, LocalAs, PasswordEncoding, Peer, PeerType,
        RemovePrivateAs,
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

fn config_global_router_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Set {
        bgp.router_id_config = Some(args.v4addr()?);
    } else {
        // Delete falls back to the RIB-derived value (or 0.0.0.0 if
        // none was ever learned) instead of silently keeping the old
        // identifier.
        bgp.router_id_config = None;
    }
    // `refresh_router_id` resolves configured-vs-RIB precedence and
    // goes through `set_router_id`, so the result is also propagated
    // to every existing peer's `router_id` snapshot — peers created
    // before the operator typed this line would otherwise keep their
    // stale (often 0.0.0.0) value and emit OPEN with the wrong BGP
    // Identifier.
    bgp.refresh_router_id();
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

/// `set router bgp global fast-external-failover <true|false>` —
/// IOS-XR `bgp fast-external-fallover` parity, on by default: reset
/// directly connected eBGP sessions immediately on interface down
/// (`Bgp::link_down_failover`) instead of waiting for hold-timer
/// expiry. Unlike `no-fib-install` this knob defaults *true*, so
/// Delete restores `true`; and a missing value token must not
/// early-return into stale state. Flipping the knob never bounces
/// sessions — it only changes how a future link-down is handled.
fn config_global_fast_external_failover(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let flag = args.boolean().unwrap_or(true);
    bgp.fast_external_failover = !op.is_set() || flag;
    Some(())
}

/// `set router bgp as-sets-withdraw <true|false>` — RFC 9774 global
/// toggle (zebra-bgp-as-sets-withdraw.yang). On by default: received
/// UPDATEs whose AS_PATH or AS4_PATH carry AS_SET / AS_CONFED_SET are
/// treat-as-withdraw, and such segments are not originated on egress.
/// Set `false` to opt out during a transition period. Delete restores
/// the default (`true`).
fn config_as_sets_withdraw(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let flag = args.boolean().unwrap_or(true);
    bgp.as_sets_withdraw = !op.is_set() || flag;
    Some(())
}

/// `set router bgp lua-script <name> source-path <path>` — load a named
/// Lua script from a file into the global script registry. With the `lua`
/// build feature off the registry is still populated (so a config
/// round-trips) but never executed. A read error logs and clears that
/// script rather than failing the commit.
fn config_lua_script_source_path(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let path = args.string()?;
        match std::fs::read_to_string(&path) {
            Ok(src) => crate::script::set_source(&name, Some(src)),
            Err(e) => {
                tracing::warn!("lua: cannot read script '{name}' from '{path}': {e}");
                crate::script::set_source(&name, None);
            }
        }
    } else {
        crate::script::set_source(&name, None);
    }
    Some(())
}

/// `delete router bgp lua-script <name>` — drop the named script. The
/// `set` of the list node itself carries no data (the `source-path` leaf
/// installs it), so only delete acts here.
fn config_lua_script(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Delete {
        let name = args.string()?;
        crate::script::set_source(&name, None);
    }
    Some(())
}

/// `set router bgp loc-rib-hook ipv4-unicast import <name>` — bind a
/// script to the IPv4-unicast Adj-RIB-In → Loc-RIB import hook; delete
/// unbinds.
fn config_loc_rib_hook_import_v4(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        crate::script::set_import_binding_v4(Some(name));
    } else {
        crate::script::set_import_binding_v4(None);
    }
    Some(())
}

/// `set router bgp loc-rib-hook ipv4-unicast withdraw <name>` — bind a
/// script to the IPv4-unicast Loc-RIB withdraw hook; delete unbinds.
fn config_loc_rib_hook_withdraw_v4(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        crate::script::set_withdraw_binding_v4(Some(name));
    } else {
        crate::script::set_withdraw_binding_v4(None);
    }
    Some(())
}

/// `set router bgp loc-rib-hook l2vpn-evpn import <name>` — bind a script
/// to the EVPN Adj-RIB-In → Loc-RIB import hook; delete unbinds.
fn config_loc_rib_hook_import_evpn(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        crate::script::set_import_binding_evpn(Some(name));
    } else {
        crate::script::set_import_binding_evpn(None);
    }
    Some(())
}

/// `set router bgp loc-rib-hook l2vpn-evpn withdraw <name>` — bind a
/// script to the EVPN Loc-RIB withdraw hook; delete unbinds.
fn config_loc_rib_hook_withdraw_evpn(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        crate::script::set_withdraw_binding_evpn(Some(name));
    } else {
        crate::script::set_withdraw_binding_evpn(None);
    }
    Some(())
}

/// Re-evaluate every established peer's update-group membership
/// (detach + attach, which recompute `signature_of`). Needed after an
/// egress-script binding change: a bound egress script must move each
/// scripted peer into its own singleton group (Model B) *before* the
/// transform runs, or the canonical-member encode would replicate one
/// peer's rewritten bytes to another.
fn reassign_all_update_groups(bgp: &mut Bgp) {
    let router_id = bgp.router_id;
    let idents: Vec<usize> = bgp
        .peers
        .iter_all()
        .filter(|(_, peer)| peer.state.is_established())
        .map(|(_, peer)| peer.ident)
        .collect();
    for ident in idents {
        super::update_group::detach(&mut bgp.update_groups, &mut bgp.peers, ident);
        super::update_group::attach(
            &mut bgp.update_groups,
            &mut bgp.peers,
            ident,
            router_id,
            bgp.as_sets_withdraw,
        );
    }
}

/// `set router bgp adj-rib-out-hook ipv4-unicast export <name>` — bind a
/// script to the IPv4-unicast egress (Adj-RIB-Out) hook; delete unbinds.
/// A change re-forms the update-groups (see [`reassign_all_update_groups`]).
fn config_adj_rib_out_hook_export_v4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        crate::script::set_egress_binding_v4(Some(name));
    } else {
        crate::script::set_egress_binding_v4(None);
    }
    reassign_all_update_groups(bgp);
    Some(())
}

/// `set router bgp adj-rib-out-hook l2vpn-evpn export <name>` — bind a
/// script to the EVPN egress hook; delete unbinds. Re-forms the
/// update-groups (the EVPN sig branch already keys on the egress script).
fn config_adj_rib_out_hook_export_evpn(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        crate::script::set_egress_binding_evpn(Some(name));
    } else {
        crate::script::set_egress_binding_evpn(None);
    }
    reassign_all_update_groups(bgp);
    Some(())
}

/// Parse a flat JSON object (`{"key": "value", ...}`) into a string→string
/// map for `map.get`. Non-string JSON values (numbers, bools) are taken as
/// their JSON text (so `{"aa:..": 100}` yields `"100"`); a parse failure
/// yields an empty map.
fn parse_lua_map(content: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    if let Ok(obj) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(content) {
        for (key, value) in obj {
            let value = match value {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            out.insert(key, value);
        }
    }
    out
}

/// `set router bgp lua-map <ns> source-path <path>` — load a JSON lookup
/// table into the `map.get` namespace `<ns>`. A read error logs and clears
/// the namespace rather than failing the commit.
fn config_lua_map_source_path(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let namespace = args.string()?;
    if op.is_set() {
        let path = args.string()?;
        match std::fs::read_to_string(&path) {
            Ok(content) => crate::script::map_set_namespace(&namespace, parse_lua_map(&content)),
            Err(e) => {
                tracing::warn!("lua: cannot read map '{namespace}' from '{path}': {e}");
                crate::script::map_clear_namespace(&namespace);
            }
        }
    } else {
        crate::script::map_clear_namespace(&namespace);
    }
    Some(())
}

/// `delete router bgp lua-map <ns>` — drop the namespace.
fn config_lua_map(_bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    if op == ConfigOp::Delete {
        let namespace = args.string()?;
        crate::script::map_clear_namespace(&namespace);
    }
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

/// `set/delete router bgp segment-routing srv6 ipv6-unicast` — the
/// presence container that enables SRv6 End.DT6 SID origination for the
/// global IPv6 unicast table. Toggling it (re)allocates or withdraws the
/// instance End.DT6 SID via `set_srv6_ipv6_unicast`.
fn config_srv6_ipv6_unicast(bgp: &mut Bgp, _args: Args, op: ConfigOp) -> Option<()> {
    bgp.set_srv6_ipv6_unicast(op == ConfigOp::Set);
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
        let peer_idx = {
            let peer = bgp.peers.get(&addr)?;
            peer.ident
        };

        // Defensively clear any listener auth entries associated with
        // this peer before removing it, in case the per-leaf delete
        // callbacks didn't fire (e.g., whole-neighbor delete without
        // explicit tcp-md5 / tcp-ao deletions first).
        clear_peer_listener_auth(bgp, &addr);

        let mut bgp_ref = BgpTop {
            router_id: &bgp.router_id,
            srv6_ipv6_export: bgp.srv6_ipv6_export.as_ref(),
            local_rib: &mut bgp.local_rib,
            shard: &mut bgp.shard,
            tx: &bgp.tx,
            rib_client: &bgp.ctx.rib,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
            interface_addrs: &bgp.interface_addrs,
            vrf_export: None,
            color_policy: Some(&bgp.color_policy),
            flex_algo_routes: Some(&bgp.flex_algo_routes),
            flex_algo_srv6_routes: Some(&bgp.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: bgp.as_sets_withdraw,
        };
        route_clean(peer_idx, &mut bgp_ref, &mut bgp.peers, bgp.shards.as_ref());
        // Update-groups live outside `PeerMap`: removal below purges
        // the membership index by construction, but the group member
        // sets must be detached explicitly or the freed ident lingers
        // and a future slot reuse inherits the group.
        super::update_group::detach(&mut bgp.update_groups, &mut bgp.peers, peer_idx);
        bgp.peers.remove(&addr);
    }
    // Keep the shared listener's TCP MSS minimum in step with the peer
    // set: a whole-neighbor delete may drop the peer that owned the
    // current minimum without the per-leaf `/tcp-mss` delete firing (the
    // same gap `clear_peer_listener_auth` covers for MD5/AO).
    apply_tcp_mss_refresh_all(bgp);
    // Same reconciliation for the listener IP_TRANSPARENT union — the
    // deleted peer may have been the last one holding the flag.
    apply_ip_transparent_refresh_all(bgp);
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
/// Stores the reference on the peer's `PeerConfig`, re-resolves the
/// effective MP family set against the group's afi-safi opinions, and
/// — if the peer has no explicit `remote-as` yet — pulls the group's
/// `remote-as` in via [`super::neighbor_group::group_remote_as`] and
/// kicks [`super::peer::Peer::start`]. An explicit per-peer `remote-as`
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
    let (peer_ident, resolve_now, should_stop_inherited, outcome) = {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.neighbor_group = new_ref.clone();
        // Re-resolve everything the group supplies against the new
        // reference — Set adopts the group's opinions underneath any
        // explicit per-peer statements; Delete falls back to
        // defaults + explicit. A knob whose effective value changed
        // on a live session asks for a bounce; the listener/BFD jobs
        // run after the peer borrow ends.
        let outcome =
            super::neighbor_group::apply_inherited(&bgp.neighbor_groups, &bgp.policy_tx, peer);

        match op {
            ConfigOp::Set => {
                // Resolve only if the peer doesn't already carry an
                // explicit per-peer remote-as.
                let needs_resolve = peer.remote_as == 0 || peer.config.remote_as_inherited;
                (peer.ident, needs_resolve, false, outcome)
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
                (peer.ident, false, was_inherited, outcome)
            }
            _ => (peer.ident, false, false, outcome),
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

    if should_stop_inherited || outcome.bounce {
        // FSM teardown — same mechanism `clear bgp ... hard` uses.
        // Either the inherited remote-as went away or some inherited
        // knob needs the session to reconnect under its new value.
        let _ = bgp.tx.try_send(super::inst::Message::Event(
            peer_ident,
            super::peer::Event::Stop,
        ));
    }

    // Cross-borrow jobs the inherited-knob pass asked for.
    if outcome.mss_refresh {
        apply_tcp_mss_refresh_all(bgp);
    }
    if outcome.md5_refresh {
        apply_md5_refresh_for(bgp, addr);
    }
    if outcome.bfd_reapply {
        let _ = bfd_apply(bgp, addr);
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

/// Bind a resolved policy / prefix-set name to one direction of the
/// peer-wide fallback slot and (un)register it with the policy actor.
/// The actor's `PolicyRx` reply resolves the name into the actual
/// object and soft-replays the direction. Diff-gated inside
/// [`policy_attach_msgs`] (prior == new sends nothing), so group
/// sweeps may call this freely. The peer-wide `neighbor X policy
/// {in,out}` CLI was retired, so the only caller is now the
/// neighbor-group inheritance sweep ([`super::neighbor_group::apply_inherited`]);
/// per-family bindings go through [`apply_peer_afi_policy_ref`].
pub(super) fn apply_peer_policy_ref(
    policy_tx: &tokio::sync::mpsc::UnboundedSender<policy::Message>,
    peer: &mut Peer,
    policy_type: policy::PolicyType,
    want: Option<String>,
) {
    // The legacy peer-wide binding registers with a family-less ident.
    let ident = peer_policy_ident(peer.ident, None);
    let slot = match policy_type {
        policy::PolicyType::PolicyListIn => {
            &mut peer.policy_list_legacy.get_mut(&InOut::Input).name
        }
        policy::PolicyType::PolicyListOut => {
            &mut peer.policy_list_legacy.get_mut(&InOut::Output).name
        }
        policy::PolicyType::PrefixSetIn => &mut peer.prefix_set_legacy.get_mut(&InOut::Input).name,
        policy::PolicyType::PrefixSetOut => {
            &mut peer.prefix_set_legacy.get_mut(&InOut::Output).name
        }
        // Key-chain subscriptions ride a different registry, and
        // table-map subscriptions are AFI-scoped rather than
        // peer-scoped; neither reaches this helper.
        policy::PolicyType::KeyChain(_) | policy::PolicyType::TableMap => return,
    };
    let prior = match &want {
        Some(n) => slot.replace(n.clone()),
        None => slot.take(),
    };
    policy_attach_msgs(policy_tx, ident, policy_type, prior, want);
}

/// Per-AFI sibling of [`apply_peer_policy_ref`]: bind a resolved policy
/// / prefix-set name to one direction slot of one address family and
/// (un)register it with the policy actor under a family-tagged ident so
/// the resolve reply lands back on the same per-AFI slot. Used by the
/// `neighbor X afi-safi <name> {policy,prefix-set} {in,out}` callbacks.
pub(super) fn apply_peer_afi_policy_ref(
    policy_tx: &tokio::sync::mpsc::UnboundedSender<policy::Message>,
    peer: &mut Peer,
    afi_safi: AfiSafi,
    policy_type: policy::PolicyType,
    want: Option<String>,
) {
    let ident = peer_policy_ident(peer.ident, Some(afi_safi));
    let slot = match policy_type {
        policy::PolicyType::PolicyListIn => &mut peer.policy_list_slot(afi_safi, InOut::Input).name,
        policy::PolicyType::PolicyListOut => {
            &mut peer.policy_list_slot(afi_safi, InOut::Output).name
        }
        policy::PolicyType::PrefixSetIn => &mut peer.prefix_set_slot(afi_safi, InOut::Input).name,
        policy::PolicyType::PrefixSetOut => &mut peer.prefix_set_slot(afi_safi, InOut::Output).name,
        policy::PolicyType::KeyChain(_) | policy::PolicyType::TableMap => return,
    };
    let prior = match &want {
        Some(n) => slot.replace(n.clone()),
        None => slot.take(),
    };
    policy_attach_msgs(policy_tx, ident, policy_type, prior, want);
}

/// `neighbor X afi-safi <name> policy {in,out} <ref>` — the per-family
/// route-policy binding, and the only per-neighbor route-policy binding
/// (the peer-wide `neighbor X policy {in,out}` was retired). For a family
/// with no per-AFI binding, [`Peer::policy_list_at`] falls back to the
/// peer-wide slot, which only a neighbor-group can populate. No per-AFI
/// neighbor-group inheritance layer (the group's policy is peer-wide), so
/// the explicit name is bound directly.
fn config_afi_safi_policy_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    apply_peer_afi_policy_ref(
        &bgp.policy_tx,
        peer,
        afi_safi,
        policy::PolicyType::PolicyListIn,
        new_name,
    );
    Some(())
}

fn config_afi_safi_policy_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    apply_peer_afi_policy_ref(
        &bgp.policy_tx,
        peer,
        afi_safi,
        policy::PolicyType::PolicyListOut,
        new_name,
    );
    Some(())
}

/// `neighbor X afi-safi <name> prefix-set {in,out} <ref>` — the per-family
/// prefix-set binding. There is no legacy top-level neighbor `prefix-set`
/// (it was removed when this moved under afi-safi); inheritance through a
/// neighbor-group still feeds the per-family fallback.
fn config_afi_safi_prefix_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    apply_peer_afi_policy_ref(
        &bgp.policy_tx,
        peer,
        afi_safi,
        policy::PolicyType::PrefixSetIn,
        new_name,
    );
    Some(())
}

fn config_afi_safi_prefix_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let new_name = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let peer = bgp.peers.get_mut(&addr)?;
    apply_peer_afi_policy_ref(
        &bgp.policy_tx,
        peer,
        afi_safi,
        policy::PolicyType::PrefixSetOut,
        new_name,
    );
    Some(())
}

fn config_route_reflector(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let peer = bgp.peers.get_mut(&addr)?;

    // Record the verbatim statement (the `client` boolean leaf): Set
    // carries the value, Delete forgets the statement. Then resolve
    // through the neighbor-group precedence: the explicit statement
    // wins, a Delete falls back to the group's opinion (or the off
    // default).
    peer.config.knobs_explicit.route_reflector_client = op.is_set().then_some(flag);
    let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
        k.route_reflector_client
    })
    .unwrap_or(false);
    apply_route_reflector_client(peer, want);
    Some(())
}

/// Write a resolved `route-reflector client` value onto the peer.
/// Note the field lives on [`Peer`] directly (`peer.reflector_client`),
/// not on [`super::peer::PeerConfig`]. Storage-only effective state — no
/// FSM ritual: like the per-neighbor knob the new role applies to route
/// reflection performed after the change. Shared by the per-neighbor
/// callback and the neighbor-group sweep.
pub(super) fn apply_route_reflector_client(peer: &mut Peer, want: bool) -> bool {
    peer.reflector_client = want;
    false
}

fn config_soft_reconfig_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let flag = args.boolean()?;

    let peer = bgp.peers.get_mut(&addr)?;

    peer.config.soft_reconfig_in = op.is_set() && flag;
    Some(())
}

/// `/router/bgp/neighbor/<addr>/pic-retention` — presence container, so
/// presence means "on". Opt-in NHT-gated route retention on session-down.
fn config_pic_retention(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    peer.config.pic_retention = op.is_set();
    Some(())
}

/// `set router bgp neighbor X description <TEXT>` — free-form operator
/// note stored on the peer and echoed under the header line of
/// `show bgp neighbors`.
fn config_peer_description(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;
    match op {
        ConfigOp::Set => peer.config.description = Some(args.string()?),
        ConfigOp::Delete => peer.config.description = None,
        _ => {}
    }
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

    // The verbatim statement now rides `knobs_explicit`; the effective
    // value (explicit-wins over the group opinion) is written below.
    if op.is_set() {
        peer.config
            .knobs_explicit
            .allowas_in
            .get_or_insert(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
    } else {
        peer.config.knobs_explicit.allowas_in = None;
    }
    let want =
        super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.allowas_in);
    apply_allowas_in(peer, want);
    Some(())
}

/// Write a resolved `allowas-in` value onto the peer. Storage-only
/// effective state — no FSM ritual: like the per-neighbor knob the new
/// budget applies to inbound UPDATEs processed after the change.
/// Shared by the per-neighbor callbacks and the neighbor-group sweep.
pub(super) fn apply_allowas_in(peer: &mut Peer, want: Option<AllowAsIn>) -> bool {
    peer.config.allowas_in = want;
    false
}

/// `set router bgp neighbor X allowas-in count <1-10>`. Deleting just
/// the count reverts to the default budget while the container stays
/// enabled; full removal goes through [`config_allowas_in`].
fn config_allowas_in_count(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;

    if op.is_set() {
        let count = args.u8()?;
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.knobs_explicit.allowas_in = Some(AllowAsIn::Count(count));
    } else {
        let peer = bgp.peers.get_mut(&addr)?;
        if matches!(
            peer.config.knobs_explicit.allowas_in,
            Some(AllowAsIn::Count(_))
        ) {
            peer.config.knobs_explicit.allowas_in =
                Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
        }
    }
    let peer = bgp.peers.get_mut(&addr)?;
    let want =
        super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.allowas_in);
    apply_allowas_in(peer, want);
    Some(())
}

/// `set router bgp neighbor X allowas-in origin`. Deleting `origin`
/// reverts to the default count budget while the container stays
/// enabled; full removal goes through [`config_allowas_in`].
fn config_allowas_in_origin(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let peer = bgp.peers.get_mut(&addr)?;

    if op.is_set() {
        peer.config.knobs_explicit.allowas_in = Some(AllowAsIn::Origin);
    } else if matches!(
        peer.config.knobs_explicit.allowas_in,
        Some(AllowAsIn::Origin)
    ) {
        peer.config.knobs_explicit.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
    }
    let want =
        super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.allowas_in);
    apply_allowas_in(peer, want);
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
    // Record the verbatim statement (a presence container: presence
    // means "on"), then resolve through the neighbor-group precedence:
    // the explicit statement wins, a Delete falls back to the group's
    // opinion (or the off default).
    peer.config.knobs_explicit.as_override = op.is_set().then_some(true);
    let want =
        super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.as_override)
            .unwrap_or(false);
    apply_as_override(peer, want);
    Some(())
}

/// Write a resolved `as-override` value onto the peer. Storage-only
/// effective state — no FSM ritual: like the per-neighbor knob the new
/// value applies to UPDATEs advertised after the change. Shared by the
/// per-neighbor callback and the neighbor-group sweep.
pub(super) fn apply_as_override(peer: &mut Peer, want: bool) -> bool {
    peer.config.as_override = want;
    false
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

    // The verbatim statement now rides `knobs_explicit`; the effective
    // value (explicit-wins over the group opinion) is written below.
    if op.is_set() {
        peer.config
            .knobs_explicit
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default);
    } else {
        peer.config.knobs_explicit.remove_private_as = None;
    }
    let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
        k.remove_private_as
    });
    apply_remove_private_as(peer, want);
    Some(())
}

/// Write a resolved `remove-private-as` value onto the peer.
/// Storage-only effective state — no FSM ritual: like the per-neighbor
/// knob the new policy applies to UPDATEs advertised after the change.
/// Shared by the per-neighbor callbacks and the neighbor-group sweep.
pub(super) fn apply_remove_private_as(peer: &mut Peer, want: Option<RemovePrivateAs>) -> bool {
    peer.config.remove_private_as = want;
    false
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
            .knobs_explicit
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default)
            .all = true;
    } else if let Some(rpa) = peer.config.knobs_explicit.remove_private_as.as_mut() {
        rpa.all = false;
    }
    let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
        k.remove_private_as
    });
    apply_remove_private_as(peer, want);
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
            .knobs_explicit
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default)
            .replace_as = true;
    } else if let Some(rpa) = peer.config.knobs_explicit.remove_private_as.as_mut() {
        rpa.replace_as = false;
    }
    let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
        k.remove_private_as
    });
    apply_remove_private_as(peer, want);
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
    // Record the verbatim statement (a presence container: presence
    // means "on"), then resolve through the neighbor-group precedence:
    // the explicit statement wins, a Delete falls back to the group's
    // opinion (or the off default).
    peer.config.knobs_explicit.enforce_first_as = op.is_set().then_some(true);
    let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
        k.enforce_first_as
    })
    .unwrap_or(false);
    apply_enforce_first_as(peer, want);
    Some(())
}

/// Write a resolved `enforce-first-as` value onto the peer.
/// Storage-only effective state — no FSM ritual: like the per-neighbor
/// knob the new check applies to inbound UPDATEs processed after the
/// change. Shared by the per-neighbor callback and the neighbor-group
/// sweep.
pub(super) fn apply_enforce_first_as(peer: &mut Peer, want: bool) -> bool {
    peer.config.enforce_first_as = want;
    false
}

/// Parse the compact `attach-unknown-attribute` spec
/// `<type>:<flags>:<value-hex>` into a [`UnknownAttr`].
///
/// * `<type>`  — Attribute Type Code, decimal 0–255.
/// * `<flags>` — Attribute Flags octet, decimal 0–255 (e.g. 192 =
///   Optional|Transitive, 128 = Optional only). The Extended-Length bit
///   is ignored here and re-derived from the value length at emit time.
/// * `<value-hex>` — attribute Value as an even-length hex string; may be
///   empty for a zero-length attribute (`250:192:`).
///
/// Returns `None` on any malformed field so the config callback rejects
/// the statement rather than attaching a half-built attribute.
fn parse_attach_unknown_attr(spec: &str) -> Option<UnknownAttr> {
    let mut parts = spec.splitn(3, ':');
    let type_code: u8 = parts.next()?.trim().parse().ok()?;
    let flags: u8 = parts.next()?.trim().parse().ok()?;
    let value_hex = parts.next()?.trim();
    if value_hex.len() % 2 != 0 {
        return None;
    }
    let mut value = Vec::with_capacity(value_hex.len() / 2);
    for i in (0..value_hex.len()).step_by(2) {
        value.push(u8::from_str_radix(&value_hex[i..i + 2], 16).ok()?);
    }
    Some(UnknownAttr::new(flags, type_code, value))
}

/// `set router bgp neighbor X attach-unknown-attribute "<type>:<flags>:<hex>"`
/// (zebra-bgp-unknown-attr.yang). Debug/test knob: stamp a synthetic
/// unrecognized path attribute onto every IPv4-unicast route advertised
/// to this neighbor so a downstream speaker's RFC 4271 §9 handling can be
/// driven from config. `delete` clears it.
fn config_attach_unknown_attribute(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    if op.is_set() {
        let spec = args.string()?;
        let attr = parse_attach_unknown_attr(&spec)?;
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.attach_unknown_attr = Some(attr);
    } else {
        let peer = bgp.peers.get_mut(&addr)?;
        peer.config.attach_unknown_attr = None;
    }
    Some(())
}

/// Resolve the `local-as` entry the callbacks below may write to,
/// enforcing the two commit-time rules from zebra-bgp-local-as.yang:
/// the substitute must differ from the router's global AS (FRR's
/// "Cannot have local-as same as BGP AS number"), and the list is
/// single-instance — the YANG `max-elements 1` is not engine-enforced,
/// so a second key is refused here with a warning and the
/// first-configured entry wins (delete it before setting another).
/// Returns the entry, seeded with all modifiers off when new, so the
/// list-node and flag callbacks stay order-independent within a
/// commit.
fn local_as_entry(bgp_asn: u32, peer: &mut Peer, key: u32) -> Option<&mut LocalAs> {
    if key == bgp_asn {
        tracing::warn!(
            peer = %peer.display_name(),
            "bgp: cannot have local-as {key} same as the BGP AS number; ignoring",
        );
        return None;
    }
    if let Some(existing) = &peer.config.local_as
        && existing.as_number != key
    {
        tracing::warn!(
            peer = %peer.display_name(),
            "bgp: local-as is single-instance (already {}); delete it before setting {key}",
            existing.as_number,
        );
        return None;
    }
    Some(peer.config.local_as.get_or_insert(LocalAs {
        as_number: key,
        no_prepend: false,
        replace_as: false,
        dual_as: false,
    }))
}

/// `set router bgp neighbor X local-as <ASN>` — the list node
/// (zebra-bgp-local-as.yang): present the substitute AS to this
/// neighbor. Creating or removing the entry changes the OPEN's My-AS
/// field, so an already-running session is bounced with `Event::Stop`
/// (the `clear ... hard` teardown) to renegotiate under the new AS; a
/// peer still Idle picks it up on its first connect. The modifier
/// leaves ride their own callbacks and do not bounce.
fn config_local_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let key = args.u32();
    let bgp_asn = bgp.asn;
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        let changed = if op.is_set() {
            let key = key?;
            let before = peer.config.local_as;
            local_as_entry(bgp_asn, peer, key)?;
            peer.config.local_as != before
        } else {
            // Be liberal about the delete spelling: a keyed delete only
            // removes the matching entry, an unkeyed one clears the lot
            // (there is at most one).
            match (key, peer.config.local_as) {
                (Some(k), Some(existing)) if existing.as_number != k => false,
                _ => peer.config.local_as.take().is_some(),
            }
        };
        if !changed {
            return Some(());
        }
        // The substitute the session presents changed — restart the
        // dual-as retry state from the configured side.
        peer.local_as_dual_fallback = false;
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

/// Shared body for the three `local-as` modifier leaves
/// (`no-prepend` / `replace-as` / `dual-as`): boolean, default false,
/// keyed by the list's AS number. A Set writes the flag (seeding the
/// entry when the flag line lands before the list node within a
/// commit); a Delete reverts it to false. No session bounce — the
/// modifiers steer route processing and the retry policy, not the
/// OPEN itself.
fn config_local_as_flag(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
    write: impl Fn(&mut LocalAs, bool),
) -> Option<()> {
    let addr = args.addr()?;
    let key = args.u32()?;
    let bgp_asn = bgp.asn;
    let peer = bgp.peers.get_mut(&addr)?;
    if op.is_set() {
        let flag = args.boolean()?;
        let entry = local_as_entry(bgp_asn, peer, key)?;
        write(entry, flag);
    } else {
        // Revert to the default without seeding: a flag delete must
        // not resurrect an entry the same commit already removed.
        let entry = peer
            .config
            .local_as
            .as_mut()
            .filter(|la| la.as_number == key)?;
        write(entry, false);
    }
    // Any local-as edit restarts the dual-as retry from the
    // configured side.
    peer.local_as_dual_fallback = false;
    Some(())
}

fn config_local_as_no_prepend(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_local_as_flag(bgp, args, op, |la, v| la.no_prepend = v)
}

fn config_local_as_replace_as(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_local_as_flag(bgp, args, op, |la, v| la.replace_as = v)
}

fn config_local_as_dual_as(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_local_as_flag(bgp, args, op, |la, v| la.dual_as = v)
}

/// `set router bgp neighbor X bfd enabled true|false` — flips the
/// Reconcile this neighbor's live BFD subscription with its current
/// `peer.config.bfd` state. Idempotent and order-independent: every
/// `/bfd/*` callback funnels through here, so whichever leaf lands last
/// in a commit leaves the correct session subscribed regardless of the
/// order `enabled` / `multihop` / `minimum-ttl` arrive.
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
/// Addressed-neighbor entry point: resolve the address to its stable
/// ident and reconcile. Used by the per-`neighbor <addr>` config
/// callbacks. Interface-keyed (unnumbered) peers reach the same core
/// via [`bfd_apply_ident`] — they cannot be found by `get(&addr)`,
/// since their map key is the ifindex, not the link-local.
pub(super) fn bfd_apply(bgp: &mut Bgp, addr: IpAddr) -> Option<()> {
    let ident = bgp.peers.get(&addr)?.ident;
    bfd_apply_ident(bgp, ident)
}

/// Reconcile the BFD session for one peer by its stable ident. The
/// BFD remote / session key derive from `peer.address` read here, so
/// this also works for an interface-keyed peer whose link-local is not
/// a map key.
pub(super) fn bfd_apply_ident(bgp: &mut Bgp, ident: usize) -> Option<()> {
    let addr = bgp.peers.get_by_idx(ident)?.address;
    let (enable, desired_key, params) = {
        let peer = bgp.peers.get_by_idx(ident)?;
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
        // Key single-hop sessions by the connected interface when we know it
        // (from `RibRx::AddrAdd`): the per-interface XDP helper — the Echo
        // reflector and the expiration watchdog — attaches by ifindex, so an
        // ifindex-0 key can never bring it up. Unknown (no address info yet,
        // or a v6 link-local peer) falls back to 0 — the session still works,
        // helper-backed features stay off; the `RibRx::AddrAdd` hook
        // re-reconciles once the interface is learned. Multihop has no single
        // egress interface.
        let ifindex = if multihop {
            0
        } else {
            bgp.connected_subnets.ifindex_for(addr).unwrap_or(0)
        };
        let key = SessionKey {
            local,
            remote: addr,
            ifindex,
            multihop,
        };
        // Echo is single-hop only (RFC 5883 multihop has no Echo), so it's
        // requested only for non-multihop neighbors; the BFD instance gates it
        // further to a live reflector (both address families work).
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
            // Like Echo, the expiration watchdog is single-hop only (the XDP
            // helper attaches per interface) — keep the params honest rather
            // than relying on the BFD instance's own multihop gate.
            detect_offload: eff.detect_offload && !multihop,
            // Detect-mult still comes from the defaults; the peer's `bfd
            // profile` is stored but not yet resolved (a separate follow-up
            // needing cross-task BfdConfig access).
            ..SessionParams::default()
        };
        (enable, key, params)
    };

    let (current, current_params) = bgp
        .peers
        .get_by_idx(ident)
        .map(|p| (p.bfd_session_key, p.bfd_session_params))
        .unwrap_or((None, None));
    let want = enable.then_some(desired_key);
    let want_params = enable.then_some(params);
    if want == current && want_params == current_params {
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

    // Drop a stale subscription before adding the new one — only when the
    // *key* changed (hop-mode flip, update-source change) or BFD turned
    // off. A params-only change must not unsubscribe: that could tear the
    // session down if we were its last subscriber. Re-sending `Subscribe`
    // on the same key applies the new Echo params to the live session
    // (`Bfd::update_echo_params`).
    if let Some(old) = current
        && want != current
    {
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

    if let Some(peer) = bgp.peers.get_mut_by_idx(ident) {
        peer.bfd_session_key = want;
        peer.bfd_session_params = want_params;
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
        // `None` ⇒ inherit `router bgp { bfd { enabled } }`; `Some(false)` opts
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

/// `set router bgp neighbor X bfd detect-offload <bool>` — offload
/// control-packet expiration detection (RFC 5880 §6.8.4) to the
/// per-interface XDP helper once the session is Up. Single-hop only
/// (inert on multihop sessions).
fn config_peer_bfd_detect_offload(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let offload = args.boolean()?;
    {
        let peer = bgp.peers.get_mut(&addr)?;
        // `None` ⇒ inherit `router bgp { bfd { detect-offload } }`;
        // `Some(false)` explicitly opts this neighbor out.
        peer.config.bfd.detect_offload = op.is_set().then_some(offload);
    }
    bfd_apply(bgp, addr)
}

/// Re-reconcile BFD for every neighbor — used by the instance-level
/// `router bgp { bfd {} }` callbacks, whose defaults (notably a blanket
/// `enabled`) affect neighbors that set nothing of their own, and by the
/// `RibRx::AddrAdd`/`AddrDel` handlers, whose connected-interface knowledge
/// feeds the single-hop session key's ifindex. `bfd_apply` is a per-neighbor
/// reconcile that diffs against the recorded session key, so this is just a
/// fan-out (a no-op per neighbor when nothing changed).
pub(super) fn bfd_reconcile_all(bgp: &mut Bgp) {
    for ident in bgp.peers.idents() {
        bfd_apply_ident(bgp, ident);
    }
}

// ---- instance-level `router bgp { bfd { ... } }` defaults -------------------

/// `router bgp bfd enable <bool>` — blanket-enable BFD on every neighbor
/// (a per-neighbor `bfd { enabled false }` opts one out).
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

/// `router bgp bfd detect-offload <bool>` — instance default for offloading
/// expiration detection to the XDP helper (overridable per neighbor).
fn config_bgp_bfd_detect_offload(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let offload = args.boolean()?;
    bgp.bfd.detect_offload = op.is_set().then_some(offload);
    bfd_reconcile_all(bgp);
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
    let enabled = args.boolean();

    // Enabling a Labeled-Unicast or VPN family means we may re-advertise
    // routes with next-hop-self and need per-prefix local labels (the
    // Inter-AS Option B/C transit case); request a dynamic label block
    // eagerly so one is granted before routes arrive. A PE with a VRF
    // already requests the block on VRF config — this also covers a
    // transit ASBR that runs VPNv4 with no VRF of its own.
    let label_block_needed = matches!(key.safi, Safi::MplsLabel | Safi::MplsVpn)
        && op.is_set()
        && enabled.unwrap_or(false);

    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;

        // Snapshot the effective MP family set so we can tell whether this
        // statement actually changes it (a redundant set must not bounce).
        let before: std::collections::BTreeSet<AfiSafi> =
            peer.config.mp.0.keys().copied().collect();

        // Record the verbatim statement, then re-resolve the effective MP
        // set through the default < group < explicit precedence. A Delete
        // simply forgets the statement: IPv4 unicast falls back to the
        // built-in default (or the group's opinion), other families to
        // off (or the group's opinion). The `mup` name expands to
        // both the IPv4 and IPv6 MUP families (draft-ietf-bess-mup-safi).
        if op.is_set() {
            let enabled = enabled?;
            for fam in super::neighbor_group::mp_family_expand(key) {
                peer.config.mp_explicit.insert(fam, enabled);
            }
        } else {
            for fam in super::neighbor_group::mp_family_expand(key) {
                peer.config.mp_explicit.remove(&fam);
            }
        }
        super::neighbor_group::recompute_peer_mp(&bgp.neighbor_groups, &mut peer.config);

        // An AFI/SAFI is a Multiprotocol *capability*, advertised once in
        // the OPEN — the negotiated set is fixed for the life of the
        // session. So changing the family set on an already-Established
        // peer has no effect until the session renegotiates: bounce it with
        // `Event::Stop` (the `clear bgp ... hard` teardown) to force a
        // reconnect that carries the new capability set. A peer still coming
        // up includes the new family in its first OPEN, so startup config —
        // applied before the session establishes — never bounces.
        let after: std::collections::BTreeSet<AfiSafi> = peer.config.mp.0.keys().copied().collect();
        let bounce = before != after && matches!(peer.state, super::peer::State::Established);
        (peer.ident, bounce)
    };

    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    if label_block_needed {
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

/// `router bgp afi-safi evpn encapsulation {vxlan|srv6}` (RFC 9252).
/// With `srv6`, Type-2 routes carry a per-VNI End.DT2U SID and Type-3
/// IMETs an End.DT2M SID (SRv6 L2 Service TLVs), both carved from the
/// BGP SRv6 locator; received MACs install against the peer's SIDs.
/// Toggling re-originates the local FDB and IMETs so the SIDs are
/// attached/dropped in place.
fn config_evpn_encapsulation(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let srv6 = if op.is_set() {
        args.string()?.as_str() == "srv6"
    } else {
        false
    };
    if bgp.evpn_encap_srv6 == srv6 {
        return Some(());
    }
    bgp.evpn_encap_srv6 = srv6;
    // Re-originate under the new encapsulation (no-op when
    // advertise-all-vni is off; the config-load gate replay covers
    // cold boot, where this leaf lands before the FdbAdds arrive).
    if bgp.advertise_all_vni {
        let entries: Vec<FdbEntry> = bgp.local_fdb.values().cloned().collect();
        for entry in entries {
            bgp.evpn_originate_macip(&entry);
        }
    }
    reoriginate_all_imet(bgp);
    Some(())
}

/// `router bgp afi-safi evpn igmp-mld-proxy <bool>` (RFC 9251 §6).
/// When enabled, the Multicast Flags Extended Community (IGMP + MLD
/// proxy capability) is attached to every originated Type-3 IMET
/// route. Toggling re-originates all IMET so the EC is added/removed;
/// `evpn_originate_imet` replaces the Originated path in place.
fn config_igmp_mld_proxy(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let enabled = if op.is_set() { args.boolean()? } else { false };
    if bgp.igmp_mld_proxy == enabled {
        return Some(());
    }
    bgp.igmp_mld_proxy = enabled;
    // Re-originate IMET (the Multicast Flags EC rides it), then replay
    // the snooped-membership cache across the gate transition: on
    // enable, originate a SMET per cached (*,G)/(S,G); on disable,
    // withdraw them all.
    reoriginate_all_imet(bgp);
    let memberships: Vec<(u32, IpAddr, Option<IpAddr>, IpAddr)> = bgp
        .local_smet
        .iter()
        .map(|((vni, group, source), vtep)| (*vni, *group, *source, *vtep))
        .collect();
    for (vni, group, source, vtep_local) in memberships {
        if enabled {
            bgp.evpn_originate_smet(vni, vtep_local, group, source);
            // A selective S-PMSI rides the same snoop membership when
            // segmentation is on (the originate is a no-op otherwise).
            bgp.evpn_originate_spmsi(vni, vtep_local, group, source);
        } else {
            bgp.evpn_withdraw_smet(vni, vtep_local, group, source);
            bgp.evpn_withdraw_spmsi(vni, vtep_local, group, source);
        }
    }
    Some(())
}

/// `router bgp afi-safi evpn ethernet-segment <name>` (RFC 7432) — create or
/// delete a locally-configured Ethernet Segment. Deleting an ES that had an
/// ESI withdraws its Type-4 route.
fn config_ethernet_segment(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.ethernet_segments.entry(name).or_default();
        }
        ConfigOp::Delete => {
            let vtep = IpAddr::V4(bgp.router_id);
            if let Some(esi) = bgp.ethernet_segments.get(&name).and_then(|es| es.esi) {
                bgp.evpn_withdraw_es_routes(esi, vtep);
            }
            bgp.ethernet_segments.remove(&name);
        }
        _ => {}
    }
    Some(())
}

/// `router bgp afi-safi evpn ethernet-segment <name> esi <value>` — the
/// 10-octet ESI (colon-hex or 20 hex digits). A malformed value is rejected.
/// Setting the ESI originates the ES routes (Type-4 + per-ES Type-1 A-D);
/// changing or clearing it withdraws the previous ones first.
fn config_ethernet_segment_esi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    let new_esi = if op.is_set() {
        Some(bgp_packet::esi_from_str(&args.string()?)?)
    } else {
        None
    };
    let vtep = IpAddr::V4(bgp.router_id);
    // Withdraw the ES routes for the previously-configured ESI (if any), then
    // set the new one and originate under it.
    if let Some(old) = bgp.ethernet_segments.get(&name).and_then(|es| es.esi) {
        bgp.evpn_withdraw_es_routes(old, vtep);
    }
    let single_active = {
        let es = bgp.ethernet_segments.entry(name).or_default();
        es.esi = new_esi;
        es.redundancy_mode.single_active()
    };
    if let Some(esi) = new_esi {
        bgp.evpn_originate_es_routes(esi, vtep, single_active);
    }
    Some(())
}

/// `router bgp afi-safi evpn ethernet-segment <name> redundancy-mode
/// <all-active|single-active>` (default all-active).
fn config_ethernet_segment_redundancy_mode(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    let mode = if op.is_set() {
        super::ethernet_segment::EsRedundancyMode::from_keyword(&args.string()?)
    } else {
        super::ethernet_segment::EsRedundancyMode::default()
    };
    let esi = {
        let es = bgp.ethernet_segments.entry(name).or_default();
        es.redundancy_mode = mode;
        es.esi
    };
    // The redundancy mode rides the per-ES A-D's ESI Label EC flag, so
    // re-originate the ES routes with the new mode (a no-op for the Type-4,
    // an in-place update for the per-ES A-D).
    if let Some(esi) = esi {
        let vtep = IpAddr::V4(bgp.router_id);
        bgp.evpn_originate_es_routes(esi, vtep, mode.single_active());
    }
    Some(())
}

/// `router bgp afi-safi evpn ethernet-segment <name> interface <name>` — the
/// CE-facing access port bound to this ES.
fn config_ethernet_segment_interface(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    let interface = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    bgp.ethernet_segments.entry(name).or_default().interface = interface;
    Some(())
}

/// `router bgp afi-safi evpn vpws <name>` (RFC 8214) — create or delete a
/// VPWS E-Line service. Deleting withdraws its Type-1, unbinds the AC
/// cross-connect, and releases its End.DX2 SID.
fn config_vpws(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.local_rib.evpn_vpws.services.entry(name).or_default();
        }
        ConfigOp::Delete => {
            bgp.vpws_teardown(&name);
            bgp.local_rib.evpn_vpws.services.remove(&name);
        }
        _ => {}
    }
    Some(())
}

/// Shared body for the VPWS leaf handlers: mutate one field, then
/// reconcile the service (withdraw + re-originate + re-push the AC
/// cross-connect as needed). Two invariants ride here so every leaf gets
/// them: a live binding whose `(vid, VLAN-table)` scoping changed (vlan
/// or evi edits) is unbound under its OLD pair first — the reconcile's
/// re-add can't reach the stale cradle entry — and a vlan-presence flip
/// releases the End.DX2/DX2V SID so the re-originate allocates one with
/// the right behavior.
fn config_vpws_leaf(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
    set: impl FnOnce(&mut super::vpws::VpwsService, Option<u32>),
    parse_u32: bool,
) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    let value = if op.is_set() && parse_u32 {
        Some(args.u32()?)
    } else {
        None
    };
    let svc = bgp
        .local_rib
        .evpn_vpws
        .services
        .entry(name.clone())
        .or_default();
    let old_bound = svc.remote_sid.is_some().then(|| svc.interface.clone());
    let old_vt = svc.vid_table();
    let old_vlan_set = svc.vlan.is_some();
    set(svc, value);
    let new_vt = svc.vid_table();
    let vlan_flipped = svc.vlan.is_some() != old_vlan_set;
    if old_vt != new_vt
        && let Some(Some(ifname)) = old_bound
    {
        let local_sid = bgp.local_rib.evpn_vpws.sids.get(&name).map(|(a, _)| *a);
        let _ = bgp.ctx.rib.send(crate::rib::Message::XconnectDel {
            ifname,
            local_sid,
            vid: old_vt.0,
            table: old_vt.1,
        });
    }
    if vlan_flipped {
        bgp.free_vpws_dx2_sid(&name);
    }
    bgp.vpws_reconcile(&name);
    Some(())
}

/// `router bgp afi-safi evpn vpws <name> evi <1..16777215>`.
fn config_vpws_evi(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_vpws_leaf(bgp, args, op, |svc, v| svc.evi = v, true)
}

/// `router bgp afi-safi evpn vpws <name> local-service-id <id>` — the
/// Ethernet Tag of our Type-1.
fn config_vpws_local_service_id(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_vpws_leaf(bgp, args, op, |svc, v| svc.local_service_id = v, true)
}

/// `router bgp afi-safi evpn vpws <name> remote-service-id <id>` — the
/// Ethernet Tag expected on the remote PE's Type-1.
fn config_vpws_remote_service_id(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_vpws_leaf(bgp, args, op, |svc, v| svc.remote_service_id = v, true)
}

/// `router bgp afi-safi evpn vpws <name> mtu <0..65535>` — the L2 MTU
/// signalled in the Type-1's Layer-2 Attributes EC (RFC 8214 §3.1);
/// 0 (or unset) disables the MTU check.
fn config_vpws_mtu(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_vpws_leaf(bgp, args, op, |svc, v| svc.mtu = v.map(|m| m as u16), true)
}

/// `router bgp afi-safi evpn vpws <name> vlan <1..4094>` — scope the AC to
/// one 802.1Q VID (RFC 8214 VLAN-based E-Line, End.DX2V). The shared leaf
/// body unbinds the old scoping and re-allocates the SID on a flip.
fn config_vpws_vlan(bgp: &mut Bgp, args: Args, op: ConfigOp) -> Option<()> {
    config_vpws_leaf(bgp, args, op, |svc, v| svc.vlan = v.map(|x| x as u16), true)
}

/// `router bgp afi-safi evpn vpws <name> interface <name>` — the
/// attachment circuit. Changing (or clearing) it unbinds the old AC's
/// cross-connect first.
fn config_vpws_interface(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let name = args.string()?;
    let interface = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    let svc = bgp
        .local_rib
        .evpn_vpws
        .services
        .entry(name.clone())
        .or_default();
    let old = std::mem::replace(&mut svc.interface, interface);
    let (vid, table) = svc.vid_table();
    if old != svc.interface
        && svc.remote_sid.is_some()
        && let Some(old_ifname) = old
    {
        let local_sid = bgp.local_rib.evpn_vpws.sids.get(&name).map(|(a, _)| *a);
        let _ = bgp.ctx.rib.send(crate::rib::Message::XconnectDel {
            ifname: old_ifname,
            local_sid,
            vid,
            table,
        });
    }
    bgp.vpws_reconcile(&name);
    Some(())
}

/// `router bgp afi-safi evpn segmentation <bool>` (RFC 9572 §8). When
/// enabled, the Multicast Flags Extended Community's segmentation-support
/// bit (bit 8) is attached to every originated Type-3 IMET route, telling
/// peers / Regional Border Routers that this PE supports BUM tunnel
/// segmentation. Toggling re-originates all IMET so the bit is added/removed.
fn config_segmentation(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let enabled = if op.is_set() { args.boolean()? } else { false };
    if bgp.segmentation == enabled {
        return Some(());
    }
    bgp.segmentation = enabled;
    reoriginate_all_imet(bgp);
    // Replay snooped memberships so existing flows gain/lose their selective
    // S-PMSI (Type-10) tunnel on the segmentation toggle.
    let memberships: Vec<(u32, IpAddr, Option<IpAddr>, IpAddr)> = bgp
        .local_smet
        .iter()
        .map(|((vni, group, source), vtep)| (*vni, *group, *source, *vtep))
        .collect();
    for (vni, group, source, vtep_local) in memberships {
        if enabled {
            bgp.evpn_originate_spmsi(vni, vtep_local, group, source);
        } else {
            bgp.evpn_withdraw_spmsi(vni, vtep_local, group, source);
        }
    }
    Some(())
}

// --- MUP controller config (router bgp mup-c) ---------------
//
// `router bgp mup-c { enable; controller-address;
// pfcp { node-id; listen-address; port }; srv6 { locator }; architecture }`
// (augmented in by zebra-bgp-mup-controller.yang, directly under the BGP
// instance — no `afi-safi` wrapper). Every callback mutates the staged
// `mup_c_config`, marking it dirty. The spawn / teardown / reconfigure of
// the controller task happens at CommitEnd in
// `Bgp::apply_mup_c_commit_diff` — these only stage config.

/// `… mup-c enable <bool>` — the controller master switch.
fn config_mup_c_enable(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let enabled = if op.is_set() { args.boolean()? } else { false };
    bgp.mup_c_config.enable = enabled;
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c controller-address <ipv6>` — next-hop on originated ST routes.
fn config_mup_c_controller_address(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.controller_address = if op.is_set() {
        Some(args.v6addr()?)
    } else {
        None
    };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c upf-address <ip>` — Core (N6) endpoint for ST2 routes when the
/// session carries no core-side GTP tunnel.
fn config_mup_c_upf_address(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.upf_address = if op.is_set() {
        Some(args.addr()?)
    } else {
        None
    };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c upf-teid <u32>` — Core (N6) TEID paired with `upf-address` for ST2
/// routes when the session carries no core-side F-TEID.
fn config_mup_c_upf_teid(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.upf_teid = if op.is_set() { Some(args.u32()?) } else { None };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c pfcp node-id <ip>` — our PFCP Node ID for responses.
fn config_mup_c_pfcp_node_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.node_id = if op.is_set() {
        Some(args.addr()?)
    } else {
        None
    };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c pfcp listen-address <ip>` — PFCP bind address (default `::`).
fn config_mup_c_pfcp_listen_address(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.listen_address = if op.is_set() {
        Some(args.addr()?)
    } else {
        None
    };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c pfcp port <0-65535>` — PFCP bind port (default 8805).
fn config_mup_c_pfcp_port(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.port = if op.is_set() { Some(args.u16()?) } else { None };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c srv6 locator <name>` — locator SIDs are drawn from (route phase).
fn config_mup_c_srv6_locator(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.locator = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    bgp.mup_c_dirty = true;
    Some(())
}

/// `… mup-c architecture <enum>` — mobile architecture (informational).
fn config_mup_c_architecture(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    bgp.mup_c_config.architecture = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    bgp.mup_c_dirty = true;
    Some(())
}

/// Re-originate every per-VNI Type-3 IMET route so a changed Assisted
/// Replication role / AR-IP is reflected in the PMSI Tunnel attribute and
/// next hop. `evpn_originate_imet` replaces the existing Originated path
/// in place (the prefix key is the local VTEP, which does not change) and
/// re-advertises to peers. No-op unless `advertise-all-vni` is on.
pub(super) fn reoriginate_all_imet(bgp: &mut Bgp) {
    if !bgp.advertise_all_vni {
        return;
    }
    let vxlans: Vec<(u32, IpAddr)> = bgp.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
    for (vni, vtep_local) in vxlans {
        bgp.evpn_originate_imet(vni, vtep_local);
    }
}

/// `router bgp afi-safi evpn assisted-replication role {none|replicator|leaf}`
/// (RFC 9574). Stored on `LocalRib.evpn_flood`; drives both IMET origination
/// (`evpn_originate_imet`) and the BUM flood-list reconcile.
fn config_assisted_replication_role(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let role = if op.is_set() {
        match args.string()?.as_str() {
            "replicator" => AssistedReplicationRole::Replicator,
            "leaf" => AssistedReplicationRole::Leaf,
            _ => AssistedReplicationRole::None,
        }
    } else {
        AssistedReplicationRole::None
    };
    if bgp.local_rib.evpn_flood.role == role {
        return Some(());
    }
    bgp.local_rib.evpn_flood.role = role;
    reoriginate_all_imet(bgp);
    bgp.evpn_reconcile_all_flood();
    Some(())
}

/// `router bgp afi-safi evpn assisted-replication replicator-ip <ip>` —
/// the AR-IP advertised in the Replicator-AR route's next hop (RFC 9574).
fn config_assisted_replication_ip(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let ip = if op.is_set() {
        Some(args.addr()?)
    } else {
        None
    };
    if bgp.local_rib.evpn_flood.ar_ip == ip {
        return Some(());
    }
    bgp.local_rib.evpn_flood.ar_ip = ip;
    reoriginate_all_imet(bgp);
    Some(())
}

/// `router bgp afi-safi evpn assisted-replication selective <bool>` (RFC
/// 9574). Toggles the L flag in our Replicator-AR route (selective mode);
/// re-originates the IMET so the flag change reaches peers.
fn config_assisted_replication_selective(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let on = if op.is_set() { args.boolean()? } else { false };
    if bgp.local_rib.evpn_flood.selective == on {
        return Some(());
    }
    bgp.local_rib.evpn_flood.selective = on;
    reoriginate_all_imet(bgp);
    Some(())
}

/// `router bgp afi-safi evpn pruned-flood-list broadcast-multicast <bool>`
/// (RFC 9574). Sets the BM flag in this node's own Type-3 IMET to ask peers
/// to prune it from the broadcast/multicast flood list.
fn config_pruned_flood_bm(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let on = if op.is_set() { args.boolean()? } else { false };
    if bgp.local_rib.evpn_flood.prune_bm == on {
        return Some(());
    }
    bgp.local_rib.evpn_flood.prune_bm = on;
    reoriginate_all_imet(bgp);
    Some(())
}

/// `router bgp afi-safi evpn pruned-flood-list unknown-unicast <bool>`
/// (RFC 9574). Sets the U flag in this node's own Type-3 IMET.
fn config_pruned_flood_unknown(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let on = if op.is_set() { args.boolean()? } else { false };
    if bgp.local_rib.evpn_flood.prune_unknown == on {
        return Some(());
    }
    bgp.local_rib.evpn_flood.prune_unknown = on;
    reoriginate_all_imet(bgp);
    Some(())
}

/// `router bgp afi-safi evpn bum-tunnel-type <ingress-replication|
/// sr-mpls-p2mp|srv6-p2mp>` — the inclusive BUM P-tunnel advertised in the
/// Type-3 IMET PMSI. The SR P2MP modes bind BUM delivery to an RFC 9524
/// replication tree (draft-ietf-bess-mvpn-evpn-sr-p2mp).
fn config_evpn_bum_tunnel_type(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if afi_safi.afi != Afi::L2vpn || afi_safi.safi != Safi::Evpn {
        return None;
    }
    let bum = if op.is_set() {
        match args.string()?.as_str() {
            "sr-mpls-p2mp" => EvpnBumTunnel::SrMplsP2mp,
            "srv6-p2mp" => EvpnBumTunnel::SrV6P2mp,
            _ => EvpnBumTunnel::IngressReplication,
        }
    } else {
        EvpnBumTunnel::IngressReplication
    };
    if bgp.local_rib.evpn_flood.bum_tunnel == bum {
        return Some(());
    }
    bgp.local_rib.evpn_flood.bum_tunnel = bum;
    reoriginate_all_imet(bgp);
    // The flood model is mode-dependent: SR P2MP suppresses the VXLAN
    // head-end FDB and programs a replication segment instead, so a mode
    // change must reconcile every VNI's dataplane (withdraw stale VXLAN IR
    // entries / emit or withdraw the ReplSeg).
    bgp.evpn_reconcile_all_flood();
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

/// Families `table-map` accepts today. The YANG augment attaches the
/// leaf to every afi-safi list entry, so filter at the callback —
/// returning `None` surfaces as a commit failure. v4 + v6 unicast;
/// the labeled / VPN / EVPN families install through their own paths
/// and have no table-map hook.
fn table_map_afi_valid(afi_safi: &AfiSafi) -> bool {
    matches!(
        (afi_safi.afi, afi_safi.safi),
        (Afi::Ip, Safi::Unicast) | (Afi::Ip6, Safi::Unicast)
    )
}

/// `ident` slot a table-map binding uses on the policy watch
/// registry: there's no peer behind it, so the AFI/SAFI itself is
/// encoded. The codec already spans v6 for the follow-up.
pub(super) fn table_map_ident(afi_safi: &AfiSafi) -> Option<usize> {
    match (afi_safi.afi, afi_safi.safi) {
        (Afi::Ip, Safi::Unicast) => Some(0),
        (Afi::Ip6, Safi::Unicast) => Some(1),
        _ => None,
    }
}

pub(super) fn table_map_ident_decode(ident: usize) -> Option<AfiSafi> {
    match ident {
        0 => Some(AfiSafi::new(Afi::Ip, Safi::Unicast)),
        1 => Some(AfiSafi::new(Afi::Ip6, Safi::Unicast)),
        _ => None,
    }
}

/// Low bits of a per-neighbor policy `ident` carry the AFI/SAFI the
/// binding belongs to; the high bits carry the peer index. The policy
/// watch registry treats `ident` as an opaque token and echoes it back
/// on resolve, so [`process_policy_msg`](super::Bgp::process_policy_msg)
/// recovers both halves. Tag `0` means the legacy peer-wide binding
/// (top-level `policy {in,out}` / neighbor-group inheritance), which has
/// no family of its own. A real family's code is `(afi << 8) | safi`,
/// always ≥ 257, so it never collides with the legacy tag.
const POLICY_AFI_BITS: u32 = 24;
const POLICY_AFI_MASK: usize = (1 << POLICY_AFI_BITS) - 1;

fn policy_afi_code(afi_safi: AfiSafi) -> usize {
    ((u16::from(afi_safi.afi) as usize) << 8) | (u8::from(afi_safi.safi) as usize)
}

/// Encode `(peer_idx, family)` into a policy-watch `ident`. `family ==
/// None` ⇒ the legacy peer-wide slot.
pub(super) fn peer_policy_ident(peer_idx: usize, afi_safi: Option<AfiSafi>) -> usize {
    debug_assert!(peer_idx < (1 << (usize::BITS - POLICY_AFI_BITS)));
    (peer_idx << POLICY_AFI_BITS) | afi_safi.map(policy_afi_code).unwrap_or(0)
}

/// Inverse of [`peer_policy_ident`]. Returns the peer index and the
/// family the binding targets (`None` ⇒ the legacy peer-wide slot).
pub(super) fn peer_policy_ident_decode(ident: usize) -> (usize, Option<AfiSafi>) {
    let code = ident & POLICY_AFI_MASK;
    let peer_idx = ident >> POLICY_AFI_BITS;
    let afi_safi = if code == 0 {
        None
    } else {
        Some(AfiSafi::new(
            Afi::from((code >> 8) as u16),
            Safi::from((code & 0xff) as u8),
        ))
    };
    (peer_idx, afi_safi)
}

/// `router bgp afi-safi <af> table-map <policy>`
/// (zebra-bgp-table-map.yang). Stores the binding on
/// `local_rib.table_map`, (un)registers the policy watch via
/// [`policy_attach_msgs`], and reconciles the FIB. Set defers the
/// resync to the `PolicyRx` reply — always sent for
/// `PolicyType::TableMap`, even when the name doesn't resolve — so
/// the FIB flips exactly once, on the definitive answer. Delete
/// resyncs immediately (nothing will reply).
pub(super) fn config_table_map(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi_safi: AfiSafi = args.afi_safi()?;
    if !table_map_afi_valid(&afi_safi) {
        return None;
    }
    let ident = table_map_ident(&afi_safi)?;
    if op.is_set() {
        let new = args.string()?;
        let tm = bgp.local_rib.table_map.entry(afi_safi).or_default();
        let prior = tm.name.replace(new.clone());
        policy_attach_msgs(
            &bgp.policy_tx,
            ident,
            policy::PolicyType::TableMap,
            prior,
            Some(new),
        );
    } else {
        let Some(tm) = bgp.local_rib.table_map.remove(&afi_safi) else {
            return Some(());
        };
        policy_attach_msgs(
            &bgp.policy_tx,
            ident,
            policy::PolicyType::TableMap,
            tm.name,
            None,
        );
        bgp.table_map_resync(afi_safi);
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

/// `set/delete router bgp neighbor <addr> afi-safi <name> encapsulation-type
/// <srv6|srv6-relax>`. Records the per-neighbor, per-AFI/SAFI SRv6
/// encapsulation mode on the peer's [`PeerSubConfig`]. The YANG `when`
/// guard restricts the leaf to `afi-safi ipv6`, so in practice `afi_safi`
/// is always IPv6 unicast here. The mode is enforced on the advertise /
/// accept paths — see [`AfiSafiEncapType`].
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

/// `set/delete router bgp neighbor <addr> afi-safi <name> next-hop-self
/// <true|false>`. Records the per-neighbor, per-AFI/SAFI next-hop-self
/// flag on the peer's [`PeerSubConfig`]. Honored on the Labeled-Unicast
/// advertise paths ([`route_update_labelv4`](super::route::route_update_labelv4)
/// / `…v6`) and on the VPNv4 advertise path
/// ([`route_update_ipv4`](super::route::route_update_ipv4)): an Inter-AS
/// Option C ASBR sets it on the iBGP-LU session to its PE so re-advertised
/// eBGP-LU routes carry the ASBR as next-hop; an Option B ASBR sets it on
/// the iBGP-VPNv4 session for the same reason (the re-advertised route also
/// gets a fresh local label + swap ILM).
fn config_next_hop_self(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;

    // Record the verbatim statement, then resolve through the
    // neighbor-group precedence — a Delete falls back to the group's
    // per-family opinion (or the off default).
    if op.is_set() {
        let value = args.boolean()?;
        peer.config.nhs_explicit.insert(afi_safi, value);
    } else {
        peer.config.nhs_explicit.remove(&afi_safi);
    }
    let value =
        super::neighbor_group::resolve_next_hop_self(&bgp.neighbor_groups, &peer.config, afi_safi);
    peer.config.sub.entry(afi_safi).or_default().next_hop_self = value;
    Some(())
}

fn config_next_hop_unchanged(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let peer = bgp.peers.get_mut(&addr)?;

    let value = op.is_set() && args.boolean()?;
    peer.config
        .sub
        .entry(afi_safi)
        .or_default()
        .next_hop_unchanged = value;
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
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else {
        let addr = args.v6addr()?;
        IpAddr::V6(addr)
    };
    let identifier = if op == ConfigOp::Set {
        Some(args.v4addr()?)
    } else {
        // Delete reverts the peer to the instance identifier instead
        // of keeping the per-peer override forever.
        None
    };
    if let Some(peer) = bgp.peers.get_mut(&addr) {
        peer.local_identifier = identifier;
        peer.start();
    }
    Some(())
}

fn config_transport_passive(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    // Per-neighbor `transport passive-mode` is a boolean leaf: Set
    // carries the value, Delete forgets the statement.
    let passive = if op.is_set() {
        Some(args.boolean()?)
    } else {
        None
    };

    if let Some(peer) = bgp.peers.get_mut(&addr) {
        // Record the verbatim statement, then resolve through the
        // neighbor-group precedence: the explicit statement wins, a
        // Delete falls back to the group's opinion (or the off
        // default).
        peer.config.knobs_explicit.passive = passive;
        let want =
            super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.passive)
                .unwrap_or(false);
        apply_passive(peer, want);
    }

    Some(())
}

/// Write a resolved `passive` value onto the peer, preserving the
/// per-neighbor ritual. Never bounces (returns `false`): a passive
/// flip changes only which side dials, applied live by re-running the
/// timer reconciler. Shared by the per-neighbor callback and the
/// neighbor-group sweep.
///
/// Dynamic (listen-range) members are ALWAYS passive — they only exist
/// because an inbound connection matched a range and must never dial
/// back out (see `try_dynamic_accept`, which forces it at
/// materialization). The resolved opinion is clamped to `true` for such
/// peers regardless of the group's value.
///
/// Make the flag effective now, not at the next idle-hold tick. A
/// started peer parked in Idle has an idle-hold timer armed toward its
/// first dial (commonly because `remote-as` in the same commit fired
/// `start()` a moment before this leaf): re-running the timer
/// reconciler flips it straight to Active — listening, never dialing.
/// Without this, an inbound connection landing in that ≤5s Idle window
/// is dropped by `handle_peer_connection` (Idle refuses connections)
/// and the remote parks on its 120s connect-retry timer.
pub(super) fn apply_passive(peer: &mut Peer, want: bool) -> bool {
    // Dynamic listen-range peers are passive-only, no matter the group.
    let want = want || matches!(peer.origin, super::peer_key::PeerOrigin::Dynamic { .. });
    peer.config.transport.passive = want;
    if peer.config.transport.passive
        && peer.active
        && matches!(peer.state, super::peer::State::Idle)
    {
        timer::update_timers(peer);
    }
    false
}

fn config_transport_local_address(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let peer_addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else {
        let addr = args.v6addr()?;
        IpAddr::V6(addr)
    };

    {
        let peer = bgp.peers.get_mut(&peer_addr)?;

        // Record the verbatim statement, then resolve through the
        // neighbor-group precedence — a Delete falls back to the
        // group's source (or none).
        if op == ConfigOp::Set {
            let source = if let Some(addr) = args.v4addr() {
                IpAddr::V4(addr)
            } else {
                let addr = args.v6addr()?;
                IpAddr::V6(addr)
            };
            // Address family of the source must match the peer; an
            // invalid statement is refused outright (not recorded).
            if source.is_ipv4() != peer_addr.is_ipv4() {
                return None;
            }
            peer.config.knobs_explicit.update_source = Some(source);
        } else {
            peer.config.knobs_explicit.update_source = None;
        }
        let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
            k.update_source
        });
        apply_update_source(peer, want);
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

/// Write a resolved `update-source` onto the peer. The connect path
/// reads it at dial time, so no bounce — parity with the per-neighbor
/// callback, which has never bounced on a source change. A source
/// whose address family doesn't match the peer is skipped with a
/// warning: a group serves IPv4 and IPv6 members alike, so a v4
/// `update-source` simply doesn't apply to a v6 member
/// (interface-keyed link-local peers included). Returns `true` when
/// the stored value changed — the caller owes a `bfd_apply`
/// reconcile.
pub(super) fn apply_update_source(peer: &mut Peer, want: Option<IpAddr>) -> bool {
    if let Some(source) = want
        && source.is_ipv4() != peer.address.is_ipv4()
    {
        tracing::warn!(
            peer = %peer.display_name(),
            source = %source,
            "bgp: update-source address family does not match the peer; not applied to this member",
        );
        return false;
    }
    if peer.config.transport.update_source == want {
        return false;
    }
    peer.config.transport.update_source = want;
    true
}

/// `[no] router bgp neighbor <addr> ttl-security` — enable GTSM (RFC
/// 5082) for a directly-connected peer. The node is a presence container, so
/// presence (Set) turns it on and Delete turns it off; no value is
/// read. The socket options themselves are installed when the TCP
/// session is set up (`fsm_connected`), so a change to an already
/// running session is bounced with `Event::Stop` — the same teardown
/// `clear bgp ... hard` uses — to force a reconnect under the new TTL
/// policy. A peer still Idle is left to pick the option up on its first
/// connect.
fn config_ttl_security(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Record the verbatim statement, then resolve through the
        // neighbor-group precedence: the explicit statement wins, a
        // Delete falls back to the group's opinion (or the off
        // default).
        peer.config.knobs_explicit.ttl_security = op.is_set().then_some(true);
        let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
            k.ttl_security
        })
        .unwrap_or(false);
        (peer.ident, apply_ttl_security(peer, want))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// Write a resolved `ttl-security` value onto the peer, preserving the
/// per-neighbor ritual: the ebgp-multihop mutual-exclusion guard, the
/// no-change diff-gate, `start()` for a dormant peer, and the
/// bounce-if-live decision (returned to the caller, which owns the
/// `Event::Stop` send — only an established / in-progress session
/// needs the explicit bounce; bouncing an Idle peer here could race
/// the idle-hold timer `start()` just armed and strand it). Shared by
/// the per-neighbor callback and the neighbor-group sweep.
///
/// GTSM pins the TTL to 255 and filters the received TTL, while
/// ebgp-multihop permits a decremented TTL — refusing to enable GTSM
/// on a peer that already has ebgp-multihop keeps the existing
/// setting; the operator must remove ebgp-multihop first.
pub(super) fn apply_ttl_security(peer: &mut Peer, want: bool) -> bool {
    if want && peer.config.transport.ebgp_multihop.is_some() {
        tracing::warn!(
            peer = %peer.display_name(),
            "bgp: ttl-security and ebgp-multihop are mutually exclusive; ignoring ttl-security (remove ebgp-multihop on this neighbor first)",
        );
        return false;
    }
    if peer.config.transport.ttl_security == want {
        // No actual change — don't disturb a live session.
        return false;
    }
    peer.config.transport.ttl_security = want;
    peer.start();
    !matches!(peer.state, super::peer::State::Idle)
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
        // Record the verbatim statement, then resolve through the
        // neighbor-group precedence: the explicit statement wins, a
        // Delete falls back to the group's opinion (or off — `None`).
        peer.config.knobs_explicit.ebgp_multihop = want;
        let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
            k.ebgp_multihop
        });
        (peer.ident, apply_ebgp_multihop(peer, want))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// Write a resolved `ebgp-multihop` value onto the peer, preserving the
/// per-neighbor ritual: the ttl-security mutual-exclusion guard, the
/// no-change diff-gate, `start()` for a dormant peer, and the
/// bounce-if-live decision (returned to the caller, which owns the
/// `Event::Stop` send — only an established / in-progress session needs
/// the explicit bounce; bouncing an Idle peer here could race the
/// idle-hold timer `start()` just armed and strand it). Shared by the
/// per-neighbor callback and the neighbor-group sweep.
///
/// Mutually exclusive with ttl-security (GTSM pins the TTL to 255 while
/// ebgp-multihop permits a decremented TTL): refusing to raise the TTL
/// on a peer that already has GTSM keeps the existing setting; the
/// operator must remove ttl-security first.
pub(super) fn apply_ebgp_multihop(peer: &mut Peer, want: Option<u8>) -> bool {
    if want.is_some() && peer.config.transport.ttl_security {
        tracing::warn!(
            peer = %peer.display_name(),
            "bgp: ebgp-multihop and ttl-security are mutually exclusive; ignoring ebgp-multihop (remove ttl-security on this neighbor first)",
        );
        return false;
    }
    if peer.config.transport.ebgp_multihop == want {
        return false;
    }
    peer.config.transport.ebgp_multihop = want;
    peer.start();
    !matches!(peer.state, super::peer::State::Idle)
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
    let changed = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Record the verbatim statement, then resolve through the
        // neighbor-group precedence — a Delete falls back to the
        // group's clamp (or none).
        peer.config.knobs_explicit.tcp_mss = if op.is_set() { Some(args.u16()?) } else { None };
        let want =
            super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.tcp_mss);
        apply_tcp_mss(peer, want)
    };
    if changed {
        apply_tcp_mss_refresh_all(bgp);
    }
    Some(())
}

/// Write a resolved `tcp-mss` onto the peer, preserving the
/// per-neighbor ritual: the no-change diff-gate and `start()` for a
/// dormant peer. Never bounces — the clamp is read at connect time;
/// the operator clears the session for immediate effect. Returns
/// `true` when the value changed, in which case the caller owes one
/// [`apply_tcp_mss_refresh_all`] so the shared listener re-derives
/// its per-AF minimum.
pub(super) fn apply_tcp_mss(peer: &mut Peer, want: Option<u16>) -> bool {
    if peer.config.transport.tcp_mss == want {
        // No actual change — leave the live session and listener alone.
        return false;
    }
    peer.config.transport.tcp_mss = want;
    peer.start();
    true
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
    // Every peer regardless of key variant: an interface-keyed
    // (unnumbered) peer's configured `tcp-mss` must fold into the
    // listener-wide minimum like any other. The session family comes
    // from `peer.address` (a v6 link-local for unnumbered peers).
    for ident in bgp.peers.idents() {
        let Some(peer) = bgp.peers.get_by_idx(ident) else {
            continue;
        };
        let Some(mss) = peer.config.transport.tcp_mss else {
            continue;
        };
        let slot = if peer.address.is_ipv4() {
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

/// `[no] router bgp neighbor <addr> port <1-65535>` — TCP destination
/// port used when this router actively dials the neighbor; deleting the
/// leaf returns to the IANA default 179 ([`BGP_PORT`]). The value is
/// read by `peer_start_connection` when the connect task is spawned.
/// Inbound connections are matched by source address only, so the
/// local listener is unaffected (that side moves with the
/// instance-level `router bgp port`). Like FRR (`PEER_FLAG_PORT` is a
/// `peer_change_reset` flag), a change on a live session bounces it
/// (`Event::Stop`, the `clear bgp ... hard` teardown) so the session
/// re-establishes on the new port immediately; an Idle peer just picks
/// the port up on its first connect.
fn config_peer_port(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    // On delete the echoed value (if any) is irrelevant — back to 179.
    let want = if op.is_set() { Some(args.u16()?) } else { None };
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Record the verbatim statement, then resolve through the
        // neighbor-group precedence: the explicit statement wins, a
        // Delete falls back to the group's opinion (or the 179
        // default — `None`).
        peer.config.knobs_explicit.port = want;
        let want =
            super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| k.port);
        (peer.ident, apply_port(peer, want))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// Write a resolved `port` onto the peer, preserving the per-neighbor
/// ritual: the no-change diff-gate, `start()` for a dormant peer, and
/// the bounce-if-live decision (returned to the caller, which owns the
/// `Event::Stop` send — only an established / in-progress session needs
/// the explicit bounce; bouncing an Idle peer here could race the
/// idle-hold timer `start()` just armed and strand it). Shared by the
/// per-neighbor callback and the neighbor-group sweep.
pub(super) fn apply_port(peer: &mut Peer, want: Option<u16>) -> bool {
    if peer.config.transport.port == want {
        // No actual change — don't disturb a live session.
        return false;
    }
    peer.config.transport.port = want;
    peer.start();
    !matches!(peer.state, super::peer::State::Idle)
}

/// `[no] router bgp port <0-65535>` — TCP port the BGP listener binds;
/// 0 disables listening entirely and deleting the leaf returns to the
/// IANA default 179 ([`BGP_PORT`]). The bind itself is async while
/// config callbacks are sync, so the callback only records the value
/// and queues [`super::inst::Message::Relisten`]; the event loop then
/// closes the current listeners and reopens them on the new port (or
/// leaves them closed for 0) in [`Bgp::relisten`]. Established
/// sessions are not touched — only the server socket cycles. FRR
/// exposes this as the `-p/--bgp_port` startup option only; here it
/// is runtime-changeable.
fn config_global_port(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let want = if op.is_set() { args.u16()? } else { BGP_PORT };
    if bgp.port == want {
        // No actual change — don't cycle a healthy listener.
        return Some(());
    }
    bgp.port = want;
    let _ = bgp.tx.try_send(super::inst::Message::Relisten);
    Some(())
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
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Record the verbatim statement (a presence flag: presence
        // means "on"), then resolve through the neighbor-group
        // precedence: the explicit statement wins, a Delete falls back
        // to the group's opinion (or the off default).
        peer.config.knobs_explicit.disable_connected_check = op.is_set().then_some(true);
        let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
            k.disable_connected_check
        })
        .unwrap_or(false);
        (peer.ident, apply_disable_connected_check(peer, want))
    };
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// Write a resolved `disable-connected-check` value onto the peer,
/// preserving the per-neighbor ritual: the no-change diff-gate,
/// `start()` for a dormant peer, and the bounce-if-live decision
/// (returned to the caller, which owns the `Event::Stop` send — only an
/// established / in-progress session needs the explicit bounce;
/// bouncing an Idle peer here could race the idle-hold timer `start()`
/// just armed and strand it. A held (Active) peer is bounced too, so it
/// leaves Active and re-dials on the next idle-hold rather than waiting
/// out the connect-retry backstop). Shared by the per-neighbor callback
/// and the neighbor-group sweep.
pub(super) fn apply_disable_connected_check(peer: &mut Peer, want: bool) -> bool {
    if peer.config.transport.disable_connected_check == want {
        // No actual change — don't disturb a live session.
        return false;
    }
    peer.config.transport.disable_connected_check = want;
    peer.start();
    !matches!(peer.state, super::peer::State::Idle)
}

/// `[no] router bgp neighbor <addr> ip-transparent` (presence container,
/// FRR 10.4) — set IP_TRANSPARENT / IPV6_TRANSPARENT on this
/// neighbor's TCP socket so the session can use a local address the
/// host does not own (the address itself comes from `update-source`;
/// the two are used together). Consumed at connect time by
/// `peer_connect` (before bind, gated on update-source — FRR's
/// both-flags gate) and reconciled onto the shared listeners by
/// [`apply_ip_transparent_refresh_all`] so a TPROXY-steered passive
/// session to a non-local address can be answered. Like the sibling
/// TTL knobs, a change on a live session bounces it (`Event::Stop`,
/// FRR `peer_change_reset`): the option must be on the socket before
/// bind()/connect(), so only a reconnect can apply it. An Idle peer
/// picks it up on its first connect.
fn config_ip_transparent(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = args.addr()?;
    let (ident, bounce) = {
        let peer = bgp.peers.get_mut(&addr)?;
        // Record the verbatim statement (a presence flag: presence
        // means "on"), then resolve through the neighbor-group
        // precedence: the explicit statement wins, a Delete falls back
        // to the group's opinion (or the off default).
        peer.config.knobs_explicit.ip_transparent = op.is_set().then_some(true);
        let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
            k.ip_transparent
        })
        .unwrap_or(false);
        (peer.ident, apply_ip_transparent(peer, want))
    };
    // Reconcile the listeners unconditionally — cheap, idempotent, and
    // immune to the diff-gate (the per-AF union may change even when
    // this peer's resolved value did not, e.g. a redundant statement
    // after a group flip).
    apply_ip_transparent_refresh_all(bgp);
    if bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    Some(())
}

/// Write a resolved `ip-transparent` value onto the peer, preserving
/// the per-neighbor ritual: the no-change diff-gate, `start()` for a
/// dormant peer, and the bounce-if-live decision (returned to the
/// caller, which owns the `Event::Stop` send — only an established /
/// in-progress session needs the explicit bounce; bouncing an Idle peer
/// here could race the idle-hold timer `start()` just armed and strand
/// it). Shared by the per-neighbor callback and the neighbor-group
/// sweep.
pub(super) fn apply_ip_transparent(peer: &mut Peer, want: bool) -> bool {
    if peer.config.transport.ip_transparent == want {
        // No actual change — don't disturb a live session.
        return false;
    }
    peer.config.transport.ip_transparent = want;
    peer.start();
    !matches!(peer.state, super::peer::State::Idle)
}

/// Reconcile IP_TRANSPARENT / IPV6_TRANSPARENT on the shared BGP
/// listeners: set while any neighbor of the address family resolves
/// `ip-transparent` on, cleared when none does. A listening socket
/// carries one flag for all peers, so this is the per-AF union — the
/// option is inert for ordinary inbound connections, it only also
/// permits TPROXY-steered connections destined to non-local addresses
/// to be accepted and answered. A neighbor-group opinion counts toward
/// both families: a dynamic (listen-range) member inherits it and must
/// find the flag on the listener *before* its SYN arrives — i.e.
/// before any member peer exists. Safe to call repeatedly; silent when
/// a listener fd is not bound yet — `listen()` re-runs it once the
/// bind completes.
pub(super) fn apply_ip_transparent_refresh_all(bgp: &mut Bgp) {
    let mut want_v4 = false;
    let mut want_v6 = false;
    for (_, peer) in bgp.peers.iter_all() {
        if peer.config.transport.ip_transparent {
            if peer.address.is_ipv4() {
                want_v4 = true;
            } else {
                want_v6 = true;
            }
        }
    }
    if bgp
        .neighbor_groups
        .values()
        .any(|g| g.knobs.ip_transparent == Some(true))
    {
        want_v4 = true;
        want_v6 = true;
    }
    for (fd, is_v4, want) in [
        (bgp.listen_fd_v4, true, want_v4),
        (bgp.listen_fd_v6, false, want_v6),
    ] {
        let Some(fd) = fd else { continue };
        if let Err(e) = super::transparent::set_ip_transparent(fd, is_v4, want) {
            tracing::warn!(
                error = %e,
                want,
                "bgp: failed to set IP_TRANSPARENT on BGP listener (CAP_NET_ADMIN required)",
            );
        }
    }
}

fn config_peer_tcp_md5_password(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else {
        let addr = args.v6addr()?;
        IpAddr::V6(addr)
    };

    // Record the verbatim statement on the peer if it exists, then
    // resolve through the neighbor-group precedence — a Delete falls
    // back to the group's password (or none). The peer may not be in
    // the map yet if the per-leaf callbacks fire in deeper-first
    // order (`/password` before `/neighbor`); in that case we just
    // skip the record — the peer will be created momentarily and a
    // follow-up `apply_md5_refresh_all` will catch up. The earlier
    // `?` short-circuit also skipped the listener install, which is
    // the actual bug that left passive peers unauthenticated.
    let explicit = if op == ConfigOp::Set {
        Some(args.string()?)
    } else {
        None
    };
    let mut bounce_ident = None;
    if let Some(peer) = bgp.peers.get_mut(&addr) {
        peer.config.knobs_explicit.password = explicit;
        let want = super::neighbor_group::resolve_knob(&bgp.neighbor_groups, &peer.config, |k| {
            k.password.clone()
        });
        // A password change resets the session (FRR's `peer_change_reset`):
        // the listener / connect-socket key only takes effect on a fresh
        // connection, so a session authenticated under the old key would
        // otherwise survive a new, removed, or mismatched password until
        // the hold timer eventually expires. Bounce a live session with
        // `Event::Stop` (the `clear … hard` teardown); an Idle peer picks
        // the new key up on its first connect.
        if apply_md5_password(peer, want) && !matches!(peer.state, super::peer::State::Idle) {
            bounce_ident = Some(peer.ident);
        }
    }

    // Reconcile the listener state for this peer regardless of
    // whether the field-store branch fired. The reconciler reads from
    // peer.config.transport.md5_password, so callers later in the
    // commit can still get the install when the peer materializes
    // (we run apply_md5_refresh_all from config_peer too).
    apply_md5_refresh_for(bgp, addr);

    if let Some(ident) = bounce_ident {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }

    Some(())
}

/// Write a resolved TCP MD5 password onto the peer. The active
/// connect path reads it at dial time and the listener key is owned
/// by [`apply_md5_refresh_for`]. Returns `true` when the stored value
/// changed — the caller owes a listener re-key for this peer's address
/// and, for a live session, a reset (`Event::Stop`) so the new key
/// takes effect on the next connection (the per-neighbor callback and
/// the group inherit sweep both honour this).
pub(super) fn apply_md5_password(peer: &mut Peer, want: Option<String>) -> bool {
    if peer.config.transport.md5_password == want {
        return false;
    }
    peer.config.transport.md5_password = want;
    true
}

/// Reconcile the listener TCP MD5 key for a single peer. Reads
/// `peer.config.transport.md5_password` and installs (or removes,
/// with an empty key) on the appropriate listening socket. Silent
/// when there is no listener fd yet — `apply_md5_refresh_all` from
/// `listen()` will fill in once the bind completes.
pub(super) fn apply_md5_refresh_for(bgp: &mut Bgp, addr: IpAddr) {
    match bgp.peers.get(&addr).map(|p| p.ident) {
        Some(ident) => apply_md5_refresh_for_ident(bgp, ident),
        // Peer absent (defensive delete path): clear any stale listener
        // key for this address with an empty key.
        None => md5_set_on_listener(bgp, addr, &[]),
    }
}

/// Reconcile the listener TCP MD5 key for one peer by its stable
/// ident. Reads the source address from `peer.address`, so an
/// interface-keyed (unnumbered) peer is serviced too — its link-local
/// is not a map key, so an addr re-lookup would silently drop it. A
/// dormant peer (unspecified address, no session yet) is skipped:
/// there is no source address to key the listener on.
pub(super) fn apply_md5_refresh_for_ident(bgp: &mut Bgp, ident: usize) {
    let Some(peer) = bgp.peers.get_by_idx(ident) else {
        return;
    };
    let addr = peer.address;
    if addr.is_unspecified() {
        return;
    }
    let password_bytes: Vec<u8> = peer
        .config
        .transport
        .md5_password
        .as_ref()
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();
    md5_set_on_listener(bgp, addr, &password_bytes);
}

/// Install (or, with an empty key, remove) the listener TCP MD5 entry
/// for `addr` on the address-family-matching listening socket. Silent
/// when there is no listener fd yet — the post-bind reconciler in
/// `listen()` fills it in.
fn md5_set_on_listener(bgp: &Bgp, addr: IpAddr, password_bytes: &[u8]) {
    let listen_fd = match addr {
        IpAddr::V4(_) => bgp.listen_fd_v4,
        IpAddr::V6(_) => bgp.listen_fd_v6,
    };
    let Some(fd) = listen_fd else {
        // Listener not bound yet. The startup reconciler in `listen()`
        // will install the key once the fd is captured.
        return;
    };

    match super::auth::set_tcp_md5_key(fd, addr, password_bytes) {
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
            // Removing a key that was never on this socket is a no-op,
            // not a failure: the kernel answers ENOENT. It happens for
            // every password-less peer when the post-(re)bind sweep
            // (`listen()` / `relisten()`) reconciles a fresh listener,
            // so only a failed install — or a failed removal of a key
            // that could really be present — deserves the warning.
            if password_bytes.is_empty() && e.kind() == std::io::ErrorKind::NotFound {
                return;
            }
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
    for ident in bgp.peers.idents() {
        apply_md5_refresh_for_ident(bgp, ident);
    }
}

fn config_peer_tcp_md5_encoding(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else {
        let addr = args.v6addr()?;
        IpAddr::V6(addr)
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
///
/// A live (non-Idle) session whose *resolved* key materially changes —
/// new algorithm, key material, SendID/RecvID, or include-tcp-options —
/// is bounced with `Event::Stop`. The MKT is installed on the listener
/// and inherited by the established child socket, so re-installing a
/// rotated key here does not reset the connection by itself; without the
/// bounce the session would keep authenticating with the old key until
/// the hold timer expired. This single, delta-gated check covers every
/// caller: a per-neighbor key-chain *name* change, a key-chain *content*
/// rotation pushed through the policy actor, and an include-tcp-options
/// edit all funnel through here, and repeated calls are idempotent (the
/// second sees `resolved_ao_key` already updated, so no delta).
pub(super) fn apply_ao_refresh_all(bgp: &mut Bgp) {
    let fd_v4 = bgp.listen_fd_v4;
    let fd_v6 = bgp.listen_fd_v6;
    // Snapshot key_chains to release the immutable borrow before
    // iterating peers mutably.
    let key_chains = bgp.key_chains.clone();

    // Peers whose resolved key changed under a live session; bounced
    // after the loop so `bgp.tx` is borrowed clear of the peer iteration.
    let mut bounce: Vec<usize> = Vec::new();

    // Every peer regardless of key variant. The listener entry is
    // keyed by the peer's source address read from `peer.address`, so
    // an interface-keyed (unnumbered) peer is serviced too — it cannot
    // be round-tripped through `get(&addr)`. A dormant peer
    // (unspecified address, no session yet) is skipped: there is no
    // source address to key on.
    for ident in bgp.peers.idents() {
        let Some(peer) = bgp.peers.get_mut_by_idx(ident) else {
            continue;
        };
        let addr = peer.address;
        if addr.is_unspecified() {
            continue;
        }

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

        // Did the resolved key materially change from what we last
        // cached? Drives both the live-session bounce and the
        // del-before-set below. Captured before we overwrite the cache.
        let changed = peer.config.transport.resolved_ao_key != resolved;

        // Queue a bounce if a session is live under a key that just
        // changed. An Idle peer just adopts the new key on its next
        // connect.
        if changed && !matches!(peer.state, super::peer::State::Idle) {
            bounce.push(ident);
        }
        peer.config.transport.resolved_ao_key = resolved.clone();

        let new_ids = resolved.as_ref().map(|r| (r.send_id, r.recv_id));

        // Remove the stale listener entry when the resolved key
        // disappears, switches SendID/RecvID, OR rotates its material
        // under the *same* SendID/RecvID. The kernel keys MKTs by
        // (address, send_id, recv_id) and `TCP_AO_ADD_KEY` returns
        // EEXIST on a duplicate, so a same-id rotation must del before it
        // can re-add — otherwise the listener keeps serving the old key.
        if let (Some(prev_ids), Some(fd)) = (peer.last_ao_installed, fd)
            && (new_ids != Some(prev_ids) || changed)
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
        // Already installed and unchanged: skip the redundant
        // `TCP_AO_ADD_KEY`, which would only return EEXIST. Any real
        // change cleared `last_ao_installed` in the del step above.
        if peer.last_ao_installed == Some((r.send_id, r.recv_id)) {
            continue;
        }
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

    // Bounce the sessions whose key changed. `Event::Stop` is the
    // `clear … hard` teardown; the peer re-handshakes from Idle under
    // the new key.
    for ident in bounce {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
}

// ---------- TCP-AO per-neighbor callbacks ----------

fn config_peer_tcp_ao_key_chain(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let addr = if let Some(addr) = args.v4addr() {
        IpAddr::V4(addr)
    } else {
        let addr = args.v6addr()?;
        IpAddr::V6(addr)
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
            // Leave `resolved_ao_key` for `apply_ao_refresh_all` to
            // clear: dropping it here would hide the Some→None delta it
            // uses to bounce a live session off a removed key.
            peer.config.transport.ao_config = None;
            (ident, prior, None)
        }
    };
    // Subscribe (or rebind) the peer's interest in the chain so the
    // policy actor pushes future `PolicyRx::KeyChain` updates for it.
    // `apply_ao_refresh_all` then reconciles the live listener entries
    // and bounces the session if its resolved key changed — a key-chain
    // *name* change here, a removal, or an in-chain content rotation
    // pushed through the policy actor all funnel through that one
    // delta-gated check, so this callback no longer resets the session
    // itself.
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
    } else {
        let addr = args.v6addr()?;
        IpAddr::V6(addr)
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
        self.callback_add("/router/bgp/global/router-id", config_global_router_id);
        // `hostname`, `no-fib-install` and `fast-external-failover` were
        // hoisted out of the `global` container to be direct children of
        // `bgp` (ietf-bgp.yang), so the paths dropped the `/global`
        // segment. The handlers are unchanged — `global` is a presence
        // container with no key, so it never contributed an arg.
        self.callback_add("/router/bgp/hostname", config_global_hostname);
        self.callback_add("/router/bgp/no-fib-install", config_global_no_fib_install);
        self.callback_add(
            "/router/bgp/fast-external-failover",
            config_global_fast_external_failover,
        );
        self.callback_add("/router/bgp/as-sets-withdraw", config_as_sets_withdraw);
        // `router bgp port <0-65535>` (zebra-bgp-transport.yang): the
        // listener port; 0 disables listening.
        self.callback_add("/router/bgp/port", config_global_port);
        self.callback_add(
            "/router/bgp/segment-routing/srv6/locator",
            config_srv6_locator,
        );
        self.callback_add(
            "/router/bgp/segment-routing/srv6/ipv6-unicast",
            config_srv6_ipv6_unicast,
        );
        // Embedded Lua scripting (zebra-bgp-lua.yang): define scripts and
        // bind the IPv4-unicast Adj-RIB-In → Loc-RIB import hook.
        self.callback_add("/router/bgp/lua-script", config_lua_script);
        self.callback_add(
            "/router/bgp/lua-script/source-path",
            config_lua_script_source_path,
        );
        self.callback_add(
            "/router/bgp/loc-rib-hook/ipv4-unicast/import",
            config_loc_rib_hook_import_v4,
        );
        self.callback_add(
            "/router/bgp/loc-rib-hook/ipv4-unicast/withdraw",
            config_loc_rib_hook_withdraw_v4,
        );
        self.callback_add(
            "/router/bgp/loc-rib-hook/l2vpn-evpn/import",
            config_loc_rib_hook_import_evpn,
        );
        self.callback_add(
            "/router/bgp/loc-rib-hook/l2vpn-evpn/withdraw",
            config_loc_rib_hook_withdraw_evpn,
        );
        self.callback_add(
            "/router/bgp/adj-rib-out-hook/ipv4-unicast/export",
            config_adj_rib_out_hook_export_v4,
        );
        self.callback_add(
            "/router/bgp/adj-rib-out-hook/l2vpn-evpn/export",
            config_adj_rib_out_hook_export_evpn,
        );
        self.callback_add("/router/bgp/lua-map", config_lua_map);
        self.callback_add(
            "/router/bgp/lua-map/source-path",
            config_lua_map_source_path,
        );
        self.callback_peer("", config_peer);
        self.callback_peer("/remote-as", config_remote_as);
        // Per-peer reference to a `neighbor-group`: stores the
        // back-reference and resolves the inheritable attributes
        // (remote-as, afi-safi).
        self.callback_peer("/neighbor-group", config_peer_neighbor_group);
        // Free-form operator note; storage-only, shown by
        // `show bgp neighbors`.
        self.callback_peer("/description", config_peer_description);
        // `set router bgp neighbor-group <name> [...]`.
        self.callback_add(
            "/router/bgp/neighbor-group",
            super::neighbor_group::config_neighbor_group,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/remote-as",
            super::neighbor_group::config_neighbor_group_remote_as,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/afi-safi",
            super::neighbor_group::config_neighbor_group_afi_safi,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/afi-safi/enabled",
            super::neighbor_group::config_neighbor_group_afi_safi_enabled,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/afi-safi/next-hop-self",
            super::neighbor_group::config_neighbor_group_afi_safi_next_hop_self,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/ttl-security",
            super::neighbor_group::config_neighbor_group_ttl_security,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/port",
            super::neighbor_group::config_neighbor_group_port,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/ebgp-multihop",
            super::neighbor_group::config_neighbor_group_ebgp_multihop,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/disable-connected-check",
            super::neighbor_group::config_neighbor_group_disable_connected_check,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/ip-transparent",
            super::neighbor_group::config_neighbor_group_ip_transparent,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/passive",
            super::neighbor_group::config_neighbor_group_passive,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/allowas-in",
            super::neighbor_group::config_neighbor_group_allowas_in,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/allowas-in/count",
            super::neighbor_group::config_neighbor_group_allowas_in_count,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/allowas-in/origin",
            super::neighbor_group::config_neighbor_group_allowas_in_origin,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/as-override",
            super::neighbor_group::config_neighbor_group_as_override,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/remove-private-as",
            super::neighbor_group::config_neighbor_group_remove_private_as,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/remove-private-as/all",
            super::neighbor_group::config_neighbor_group_remove_private_as_all,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/remove-private-as/replace-as",
            super::neighbor_group::config_neighbor_group_remove_private_as_replace_as,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/enforce-first-as",
            super::neighbor_group::config_neighbor_group_enforce_first_as,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/route-reflector/client",
            super::neighbor_group::config_neighbor_group_route_reflector_client,
        );
        // RFC 9572 §6.1: mark a neighbor-group as a segmentation region.
        self.callback_add(
            "/router/bgp/neighbor-group/region-id",
            super::neighbor_group::config_neighbor_group_region_id,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/update-source",
            super::neighbor_group::config_neighbor_group_update_source,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/tcp-mss",
            super::neighbor_group::config_neighbor_group_tcp_mss,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/password",
            super::neighbor_group::config_neighbor_group_password,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/policy/in",
            super::neighbor_group::config_neighbor_group_policy_in,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/policy/out",
            super::neighbor_group::config_neighbor_group_policy_out,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/prefix-set/in",
            super::neighbor_group::config_neighbor_group_prefix_set_in,
        );
        self.callback_add(
            "/router/bgp/neighbor-group/prefix-set/out",
            super::neighbor_group::config_neighbor_group_prefix_set_out,
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
            "/router/bgp/vrf/inter-as-hybrid",
            super::vrf_config::config_vrf_inter_as_hybrid,
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
            "/router/bgp/vrf/neighbor/afi-safi/enabled",
            super::vrf_config::config_vrf_neighbor_afi_safi_enabled,
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
            "/router/bgp/vrf/afi-safi/ipv4/redistribute",
            super::vrf_config::config_vrf_afi_ipv4_redistribute,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4/redistribute/connected",
            super::vrf_config::config_vrf_afi_ipv4_redistribute_connected,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4/redistribute/static",
            super::vrf_config::config_vrf_afi_ipv4_redistribute_static,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4/redistribute/ospf",
            super::vrf_config::config_vrf_afi_ipv4_redistribute_ospf,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv4/redistribute/isis",
            super::vrf_config::config_vrf_afi_ipv4_redistribute_isis,
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
            "/router/bgp/vrf/afi-safi/ipv6/redistribute",
            super::vrf_config::config_vrf_afi_ipv6_redistribute,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6/redistribute/connected",
            super::vrf_config::config_vrf_afi_ipv6_redistribute_connected,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6/redistribute/static",
            super::vrf_config::config_vrf_afi_ipv6_redistribute_static,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6/redistribute/ospf",
            super::vrf_config::config_vrf_afi_ipv6_redistribute_ospf,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/ipv6/redistribute/isis",
            super::vrf_config::config_vrf_afi_ipv6_redistribute_isis,
        );
        self.callback_add(
            "/router/bgp/vrf/evpn/advertise-ipv4",
            super::vrf_config::config_vrf_evpn_advertise_ipv4,
        );
        self.callback_add(
            "/router/bgp/vrf/evpn/advertise-ipv6",
            super::vrf_config::config_vrf_evpn_advertise_ipv6,
        );
        self.callback_add(
            "/router/bgp/vrf/evpn/l3vni",
            super::vrf_config::config_vrf_evpn_l3vni,
        );
        self.callback_add(
            "/router/bgp/vrf/evpn/router-mac",
            super::vrf_config::config_vrf_evpn_router_mac,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/dataplane",
            super::vrf_config::config_vrf_mup_dataplane,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/segment",
            super::vrf_config::config_vrf_mup_segment,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/segment/mup-ext-comm",
            super::vrf_config::config_vrf_mup_ext_comm,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/segment/prefix",
            super::vrf_config::config_vrf_mup_segment_prefix,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/route",
            super::vrf_config::config_vrf_mup_route,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/route/network-instance",
            super::vrf_config::config_vrf_mup_route_network_instance,
        );
        self.callback_add(
            "/router/bgp/vrf/afi-safi/mup/route/mup-ext-comm",
            super::vrf_config::config_vrf_mup_route_mup_ext_comm,
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
        // zebra-bgp-transport.yang. Presence-container flag — directly
        // connected only, TTL pinned to 255. Lowered onto the session
        // socket in `fsm_connected`.
        self.callback_peer("/ttl-security", config_ttl_security);
        // FRR-style `neighbor X ebgp-multihop <1-255>` from
        // zebra-bgp-transport.yang. Raises the eBGP egress TTL; resolved
        // by Peer::session_ttl and applied at connect / fsm_connected.
        self.callback_peer("/ebgp-multihop", config_ebgp_multihop);
        self.callback_peer("/tcp-mss", config_tcp_mss);
        // FRR-style `neighbor X port <1-65535>` from
        // zebra-bgp-transport.yang: TCP destination port used when
        // dialing this neighbor (default 179).
        self.callback_peer("/port", config_peer_port);
        // FRR-style `neighbor X disable-connected-check` from
        // zebra-bgp-transport.yang. Exempts a single-hop eBGP neighbor from
        // the directly-connected-network check (Peer::connected_check_ok).
        self.callback_peer("/disable-connected-check", config_disable_connected_check);
        // FRR 10.4 `neighbor X ip-transparent` from
        // zebra-bgp-transport.yang: IP_TRANSPARENT on the session socket
        // so a non-local `update-source` can be used.
        self.callback_peer("/ip-transparent", config_ip_transparent);
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
        self.callback_peer("/bfd/enabled", config_peer_bfd_enable);
        self.callback_peer("/bfd/multihop", config_peer_bfd_multihop);
        self.callback_peer("/bfd/minimum-ttl", config_peer_bfd_min_ttl);
        self.callback_peer("/bfd/echo-mode", config_peer_bfd_echo_mode);
        self.callback_peer("/bfd/echo-transmit-interval", config_peer_bfd_echo_tx);
        self.callback_peer("/bfd/echo-receive-interval", config_peer_bfd_echo_rx);
        self.callback_peer("/bfd/detect-offload", config_peer_bfd_detect_offload);
        // Instance-level `router bgp { bfd { ... } }` defaults.
        self.callback_add("/router/bgp/bfd/enabled", config_bgp_bfd_enable);
        self.callback_add("/router/bgp/bfd/echo-mode", config_bgp_bfd_echo_mode);
        self.callback_add(
            "/router/bgp/bfd/echo-transmit-interval",
            config_bgp_bfd_echo_tx,
        );
        self.callback_add(
            "/router/bgp/bfd/echo-receive-interval",
            config_bgp_bfd_echo_rx,
        );
        self.callback_add(
            "/router/bgp/bfd/detect-offload",
            config_bgp_bfd_detect_offload,
        );
        self.callback_peer("/tcp-ao/key-chain", config_peer_tcp_ao_key_chain);
        self.callback_peer(
            "/tcp-ao/include-tcp-options",
            config_peer_tcp_ao_include_tcp_options,
        );

        self.callback_peer("/afi-safi/enabled", config_afi_safi);
        self.callback_peer("/afi-safi/add-path", config_add_path);
        self.callback_peer("/afi-safi/encapsulation-type", config_encapsulation_type);
        self.callback_peer("/afi-safi/next-hop-self", config_next_hop_self);
        self.callback_peer("/afi-safi/next-hop-unchanged", config_next_hop_unchanged);
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

        // EVPN overlay encapsulation (RFC 9252) under
        // `router bgp afi-safi evpn encapsulation {vxlan|srv6}`. With
        // srv6, Type-2/Type-3 routes carry End.DT2U/End.DT2M SIDs.
        self.callback_add(
            "/router/bgp/afi-safi/encapsulation",
            config_evpn_encapsulation,
        );

        // EVPN IGMP/MLD proxy capability (RFC 9251 §6) under
        // `router bgp afi-safi evpn igmp-mld-proxy`. When set, the
        // Multicast Flags EC rides the originated Type-3 IMET route.
        self.callback_add("/router/bgp/afi-safi/igmp-mld-proxy", config_igmp_mld_proxy);

        // EVPN BUM tunnel-segmentation support (RFC 9572 §8) under
        // `router bgp afi-safi evpn segmentation`. When set, the Multicast
        // Flags EC's segmentation bit rides the originated Type-3 IMET route.
        self.callback_add("/router/bgp/afi-safi/segmentation", config_segmentation);

        // EVPN Ethernet Segment (RFC 7432), under
        // `router bgp afi-safi evpn ethernet-segment <name> …`. Augmented in
        // by zebra-bgp-evpn.yang. Config + state only in this phase.
        self.callback_add(
            "/router/bgp/afi-safi/ethernet-segment",
            config_ethernet_segment,
        );
        self.callback_add(
            "/router/bgp/afi-safi/ethernet-segment/esi",
            config_ethernet_segment_esi,
        );
        self.callback_add(
            "/router/bgp/afi-safi/ethernet-segment/redundancy-mode",
            config_ethernet_segment_redundancy_mode,
        );
        self.callback_add(
            "/router/bgp/afi-safi/ethernet-segment/interface",
            config_ethernet_segment_interface,
        );

        // EVPN VPWS E-Line services (RFC 8214), under
        // `router bgp afi-safi evpn vpws <name> …`. Augmented in by
        // zebra-bgp-evpn.yang.
        self.callback_add("/router/bgp/afi-safi/vpws", config_vpws);
        self.callback_add("/router/bgp/afi-safi/vpws/evi", config_vpws_evi);
        self.callback_add(
            "/router/bgp/afi-safi/vpws/local-service-id",
            config_vpws_local_service_id,
        );
        self.callback_add(
            "/router/bgp/afi-safi/vpws/remote-service-id",
            config_vpws_remote_service_id,
        );
        self.callback_add("/router/bgp/afi-safi/vpws/interface", config_vpws_interface);
        self.callback_add("/router/bgp/afi-safi/vpws/mtu", config_vpws_mtu);
        self.callback_add("/router/bgp/afi-safi/vpws/vlan", config_vpws_vlan);

        // MUP controller (`router bgp mup-c …`, draft-ietf-bess-mup-safi).
        // Augmented in by zebra-bgp-mup-controller.yang; the controller
        // task is spawned/torn down at CommitEnd by `apply_mup_c_commit_diff`.
        self.callback_add("/router/bgp/mup-c/enabled", config_mup_c_enable);
        self.callback_add(
            "/router/bgp/mup-c/controller-address",
            config_mup_c_controller_address,
        );
        self.callback_add("/router/bgp/mup-c/upf-address", config_mup_c_upf_address);
        self.callback_add("/router/bgp/mup-c/upf-teid", config_mup_c_upf_teid);
        self.callback_add("/router/bgp/mup-c/pfcp/node-id", config_mup_c_pfcp_node_id);
        self.callback_add(
            "/router/bgp/mup-c/pfcp/listen-address",
            config_mup_c_pfcp_listen_address,
        );
        self.callback_add("/router/bgp/mup-c/pfcp/port", config_mup_c_pfcp_port);
        self.callback_add("/router/bgp/mup-c/srv6/locator", config_mup_c_srv6_locator);
        self.callback_add("/router/bgp/mup-c/architecture", config_mup_c_architecture);

        // EVPN Assisted Replication role + AR-IP (RFC 9574), under
        // `router bgp afi-safi evpn assisted-replication`. Augmented in by
        // zebra-bgp-evpn.yang.
        self.callback_add(
            "/router/bgp/afi-safi/assisted-replication/role",
            config_assisted_replication_role,
        );
        self.callback_add(
            "/router/bgp/afi-safi/assisted-replication/replicator-ip",
            config_assisted_replication_ip,
        );
        self.callback_add(
            "/router/bgp/afi-safi/assisted-replication/selective",
            config_assisted_replication_selective,
        );
        // EVPN Pruned-Flood-List (RFC 9574), under `router bgp afi-safi evpn
        // pruned-flood-list`. Augmented in by zebra-bgp-evpn.yang.
        self.callback_add(
            "/router/bgp/afi-safi/pruned-flood-list/broadcast-multicast",
            config_pruned_flood_bm,
        );
        self.callback_add(
            "/router/bgp/afi-safi/pruned-flood-list/unknown-unicast",
            config_pruned_flood_unknown,
        );
        // EVPN inclusive BUM P-tunnel selection (RFC 9524 SR P2MP trees vs.
        // ingress replication), under `router bgp afi-safi evpn
        // bum-tunnel-type`. Augmented in by zebra-bgp-evpn.yang.
        self.callback_add(
            "/router/bgp/afi-safi/bum-tunnel-type",
            config_evpn_bum_tunnel_type,
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

        // Per-AFI table-map (zebra-bgp-table-map.yang): policy gate /
        // rewrite at BGP-to-RIB install time.
        self.callback_add("/router/bgp/afi-safi/table-map", config_table_map);

        // Applying policy. Per-AFI policy / prefix-set is the only
        // per-neighbor binding location; the peer-wide `neighbor X
        // policy {in,out}` and `prefix-set {in,out}` nodes were retired.
        // A neighbor-group can still inherit a peer-wide route-policy /
        // prefix-set into the per-family fallback slots.
        self.callback_peer("/afi-safi/policy/in", config_afi_safi_policy_in);
        self.callback_peer("/afi-safi/policy/out", config_afi_safi_policy_out);
        self.callback_peer("/afi-safi/prefix-set/in", config_afi_safi_prefix_in);
        self.callback_peer("/afi-safi/prefix-set/out", config_afi_safi_prefix_out);

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
        self.callback_peer("/pic-retention", config_pic_retention);

        // Debug/test knob (zebra-bgp-unknown-attr.yang): attach a synthetic
        // unrecognized path attribute to routes advertised to this
        // neighbor — exercises RFC 4271 §9 receiver handling end to end.
        self.callback_peer("/attach-unknown-attribute", config_attach_unknown_attribute);

        // Per-neighbor local-as (zebra-bgp-local-as.yang): a
        // single-entry list keyed by the substitute AS number, with
        // three independent boolean modifier leaves.
        self.callback_peer("/local-as", config_local_as);
        self.callback_peer("/local-as/no-prepend", config_local_as_no_prepend);
        self.callback_peer("/local-as/replace-as", config_local_as_replace_as);
        self.callback_peer("/local-as/dual-as", config_local_as_dual_as);
    }
}

#[cfg(test)]
mod table_map_ident_tests {
    use super::*;

    /// The watch `ident` must survive the round trip for every family
    /// the codec covers — a drift here silently misroutes `PolicyRx`
    /// pushes and the table-map never refreshes.
    #[test]
    fn ident_roundtrip() {
        for afi_safi in [
            AfiSafi::new(Afi::Ip, Safi::Unicast),
            AfiSafi::new(Afi::Ip6, Safi::Unicast),
        ] {
            let ident = table_map_ident(&afi_safi).expect("codec covers the family");
            assert_eq!(table_map_ident_decode(ident), Some(afi_safi));
        }
        assert_eq!(
            table_map_ident(&AfiSafi::new(Afi::Ip, Safi::MplsVpn)),
            None,
            "uncovered families must not register a watch"
        );
        assert_eq!(table_map_ident_decode(999), None);
    }

    /// v4 + v6 unicast are the families the callback accepts; the
    /// YANG augment attaches the leaf to every afi-safi entry, so the
    /// gate is what rejects the rest at commit time.
    #[test]
    fn afi_gate_is_unicast_only() {
        assert!(table_map_afi_valid(&AfiSafi::new(Afi::Ip, Safi::Unicast)));
        assert!(table_map_afi_valid(&AfiSafi::new(Afi::Ip6, Safi::Unicast)));
        assert!(!table_map_afi_valid(&AfiSafi::new(Afi::Ip, Safi::MplsVpn)));
        assert!(!table_map_afi_valid(&AfiSafi::new(
            Afi::Ip,
            Safi::MplsLabel
        )));
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

    /// `bfd enabled true` on a known iBGP neighbor (the default peer
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

    /// A single-hop session is keyed by the connected interface once the
    /// covering address is known, and `detect-offload` rides the params —
    /// both feed the per-interface XDP helper. An address learned AFTER
    /// `bfd enable` re-keys the session (unsubscribe + resubscribe).
    #[tokio::test]
    async fn single_hop_key_carries_connected_ifindex_and_detect_offload() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.5"]), ConfigOp::Set).unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        bgp.peers.get_mut(&addr).unwrap().peer_type = PeerType::EBGP;

        // Enable before any address knowledge → ifindex 0, helper-less.
        config_peer_bfd_detect_offload(&mut bgp, arg_words(&["10.0.0.5", "true"]), ConfigOp::Set);
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.5", "true"]), ConfigOp::Set).unwrap();
        match bfd_rx.try_recv().expect("initial subscribe") {
            ClientReq::Subscribe { key, params, .. } => {
                assert_eq!(key.ifindex, 0, "no connected info yet");
                assert!(params.detect_offload, "knob rides the params");
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }

        // The covering interface address arrives → re-keyed onto ifindex 3.
        let net: ipnet::Ipv4Net = "10.0.0.1/24".parse().unwrap();
        bgp.connected_subnets.record(&crate::rib::link::LinkAddr {
            addr: ipnet::IpNet::V4(net),
            ifindex: 3,
            secondary: false,
            config: false,
            fib: true,
        });
        bfd_reconcile_all(&mut bgp);

        match bfd_rx
            .try_recv()
            .expect("re-key unsubscribes the stale key")
        {
            ClientReq::Unsubscribe { key, .. } => assert_eq!(key.ifindex, 0),
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
        match bfd_rx.try_recv().expect("re-key resubscribes") {
            ClientReq::Subscribe { key, params, .. } => {
                assert_eq!(key.ifindex, 3, "keyed by the connected interface");
                assert!(params.detect_offload);
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// `detect-offload` is single-hop only: a multihop session keeps
    /// `detect_offload: false` in its params (and ifindex 0) even when the
    /// leaf is set — mirroring the Echo gate.
    #[tokio::test]
    async fn detect_offload_inert_on_multihop() {
        let (mut bgp, mut bfd_rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.6"]), ConfigOp::Set).unwrap();
        // Default peer type is iBGP ⇒ inferred multihop.
        config_peer_bfd_detect_offload(&mut bgp, arg_words(&["10.0.0.6", "true"]), ConfigOp::Set);
        config_peer_bfd_enable(&mut bgp, arg_words(&["10.0.0.6", "true"]), ConfigOp::Set).unwrap();
        match bfd_rx.try_recv().expect("subscribe") {
            ClientReq::Subscribe { key, params, .. } => {
                assert!(key.multihop);
                assert_eq!(key.ifindex, 0, "multihop has no single egress");
                assert!(!params.detect_offload, "inert on multihop");
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

    fn peer_attach_unknown(bgp: &Bgp, addr: &str) -> Option<UnknownAttr> {
        bgp.peers
            .get(&addr.parse().unwrap())
            .unwrap()
            .config
            .attach_unknown_attr
            .clone()
    }

    /// The `attach-unknown-attribute` debug knob parses the compact
    /// `<type>:<flags>:<value-hex>` spec onto the peer; delete clears it.
    #[tokio::test]
    async fn attach_unknown_attr_set_and_delete() {
        let (mut bgp, _rx) = fresh_bgp_with_bfd();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        assert!(peer_attach_unknown(&bgp, "10.0.0.2").is_none());

        config_attach_unknown_attribute(
            &mut bgp,
            arg_words(&["10.0.0.2", "250:192:deadbeef"]),
            ConfigOp::Set,
        )
        .unwrap();
        let u = peer_attach_unknown(&bgp, "10.0.0.2").expect("attr set");
        assert_eq!(u.type_code, 250);
        assert_eq!(u.flags, 192);
        assert!(u.is_optional() && u.is_transitive());
        assert_eq!(u.value, vec![0xde, 0xad, 0xbe, 0xef]);

        config_attach_unknown_attribute(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete)
            .unwrap();
        assert!(peer_attach_unknown(&bgp, "10.0.0.2").is_none());
    }

    /// Spec parsing: empty value is a zero-length attribute; odd-length
    /// hex and non-numeric fields are rejected.
    #[test]
    fn attach_unknown_attr_spec_parsing() {
        let z = parse_attach_unknown_attr("251:128:").expect("empty value ok");
        assert_eq!(z.type_code, 251);
        assert_eq!(z.flags, 128);
        assert!(z.value.is_empty());

        assert!(
            parse_attach_unknown_attr("250:192:dea").is_none(),
            "odd hex"
        );
        assert!(
            parse_attach_unknown_attr("999:0:00").is_none(),
            "type > 255"
        );
        assert!(
            parse_attach_unknown_attr("250:xx:00").is_none(),
            "bad flags"
        );
        assert!(
            parse_attach_unknown_attr("250:192").is_none(),
            "missing value"
        );
    }
}

#[cfg(test)]
mod neighbor_group_wiring_tests {
    //! End-to-end exercise of the neighbor-group inheritance callback
    //! paths for the static-peer resolver, the reactive sweep on group
    //! remote-as Set/Delete, and the group-level delete cascade. Asserts
    //! the user-observable
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

    /// `ttl-security` is a presence flag: Set turns it on, Delete
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

    /// Like [`link_addr`] but on a caller-chosen interface.
    fn link_addr_on(cidr: &str, ifindex: u32) -> crate::rib::link::LinkAddr {
        crate::rib::link::LinkAddr {
            ifindex,
            ..link_addr(cidr)
        }
    }

    /// Drain `bgp.rx`, returning the peer-ident of every queued
    /// `Event::Start`. Other event variants are ignored.
    fn drain_start_events(bgp: &mut Bgp) -> Vec<usize> {
        use crate::bgp::inst::Message;
        use crate::bgp::peer::Event;
        let mut out = Vec::new();
        while let Ok(msg) = bgp.rx.try_recv() {
            if let Message::Event(ident, Event::Start) = msg {
                out.push(ident);
            }
        }
        out
    }

    /// `as-sets-withdraw` is a default-ON global boolean (RFC 9774):
    /// Set false opts out, Set true re-enables, and Delete restores the
    /// default (true).
    #[tokio::test]
    async fn as_sets_withdraw_knob_transitions() {
        let mut bgp = fresh_bgp();
        assert!(bgp.as_sets_withdraw, "must default to enabled");

        config_as_sets_withdraw(&mut bgp, arg_words(&["false"]), ConfigOp::Set).unwrap();
        assert!(!bgp.as_sets_withdraw, "set false must opt out");

        config_as_sets_withdraw(&mut bgp, arg_words(&["true"]), ConfigOp::Set).unwrap();
        assert!(bgp.as_sets_withdraw, "set true must re-enable");

        config_as_sets_withdraw(&mut bgp, arg_words(&["false"]), ConfigOp::Set).unwrap();
        config_as_sets_withdraw(&mut bgp, arg_words(&["false"]), ConfigOp::Delete).unwrap();
        assert!(
            bgp.as_sets_withdraw,
            "delete must restore the default (true)",
        );
    }

    /// `fast-external-failover` is a default-ON global boolean (IOS-XR
    /// `bgp fast-external-fallover` parity): Set false disables, Set
    /// true re-enables, and Delete restores the default (true) rather
    /// than clearing to false. Flipping the knob never bounces
    /// sessions — it only changes how a future link-down is handled.
    #[tokio::test]
    async fn fast_external_failover_knob_transitions() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        assert!(bgp.fast_external_failover, "must default to enabled");

        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_global_fast_external_failover(&mut bgp, arg_words(&["false"]), ConfigOp::Set)
            .unwrap();
        assert!(!bgp.fast_external_failover, "set false must disable");

        config_global_fast_external_failover(&mut bgp, arg_words(&["true"]), ConfigOp::Set)
            .unwrap();
        assert!(bgp.fast_external_failover, "set true must re-enable");

        config_global_fast_external_failover(&mut bgp, arg_words(&["false"]), ConfigOp::Set)
            .unwrap();
        config_global_fast_external_failover(&mut bgp, arg_words(&["false"]), ConfigOp::Delete)
            .unwrap();
        assert!(
            bgp.fast_external_failover,
            "delete must restore the default (true)",
        );

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "knob flips must not bounce sessions",
        );
    }

    /// Park a configured peer in a chosen FSM state, returning its ident.
    fn park_peer(bgp: &mut Bgp, addr: &str, state: crate::bgp::peer::State) -> usize {
        let ip: IpAddr = addr.parse().unwrap();
        let peer = bgp.peers.get_mut(&ip).unwrap();
        peer.state = state;
        peer.ident
    }

    /// `RibRx::LinkDown` resets exactly the non-Idle single-hop eBGP
    /// peers whose session rides the downed interface: `ebgp-multihop`,
    /// iBGP and other-interface peers survive; with the knob off nobody
    /// is reset. `RibRx::LinkUp` re-kicks parked (Idle/Active) peers on
    /// that interface with `Event::Start`.
    #[tokio::test]
    async fn fast_external_failover_sweep_selection() {
        use crate::bgp::peer::State;
        use crate::rib::api::RibRx;
        let mut bgp = fresh_bgp();
        config_global_asn(&mut bgp, arg_words(&["65000"]), ConfigOp::Set).unwrap();

        // Two connected subnets: 10.0.3.0/24 on ifindex 3, 10.0.4.0/24 on 4.
        bgp.connected_subnets
            .record(&link_addr_on("10.0.3.1/24", 3));
        bgp.connected_subnets
            .record(&link_addr_on("10.0.4.1/24", 4));

        for (addr, remote_as) in [
            ("10.0.3.2", "65001"), // single-hop eBGP on ifindex 3 — the victim
            ("10.0.3.3", "65001"), // eBGP but multihop — survives
            ("10.0.3.4", "65000"), // iBGP on ifindex 3 — survives
            ("10.0.4.2", "65001"), // single-hop eBGP on ifindex 4 — survives
        ] {
            config_peer(&mut bgp, arg_words(&[addr]), ConfigOp::Set).unwrap();
            config_remote_as(&mut bgp, arg_words(&[addr, remote_as]), ConfigOp::Set).unwrap();
        }
        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.3.3", "2"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        let _ = drain_start_events(&mut bgp);

        let victim = park_peer(&mut bgp, "10.0.3.2", State::Established);
        park_peer(&mut bgp, "10.0.3.3", State::Established);
        park_peer(&mut bgp, "10.0.3.4", State::Established);
        park_peer(&mut bgp, "10.0.4.2", State::Established);

        bgp.process_rib_msg(RibRx::LinkDown(3));
        assert_eq!(
            drain_stop_events(&mut bgp),
            vec![victim],
            "exactly the single-hop eBGP peer on the downed interface must be reset",
        );

        // LinkUp re-kicks a parked peer on that interface; Established
        // peers are left alone.
        park_peer(&mut bgp, "10.0.3.2", State::Active);
        bgp.process_rib_msg(RibRx::LinkUp(3));
        assert_eq!(
            drain_start_events(&mut bgp),
            vec![victim],
            "LinkUp must re-kick the parked peer (and only it)",
        );

        // Knob off: even an eligible peer survives its interface going down.
        config_global_fast_external_failover(&mut bgp, arg_words(&["false"]), ConfigOp::Set)
            .unwrap();
        bgp.process_rib_msg(RibRx::LinkDown(4));
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "knob off must disable the failover sweep",
        );
    }

    /// The link-down sweep prefers the ifindex pinned at session
    /// establish over live subnet resolution, so a session whose
    /// connected address was already deleted (AddrDel raced ahead of
    /// LinkDown) is still reset — and only by the pinned interface.
    #[tokio::test]
    async fn fast_external_failover_uses_pinned_session_ifindex() {
        use crate::bgp::peer::State;
        use crate::rib::api::RibRx;
        let mut bgp = fresh_bgp();
        config_global_asn(&mut bgp, arg_words(&["65000"]), ConfigOp::Set).unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.3.2"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.3.2", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        // No connected-subnet knowledge at all — live resolution has
        // nothing to offer; only the pinned mapping can match.
        let victim = park_peer(&mut bgp, "10.0.3.2", State::Established);
        let ip: IpAddr = "10.0.3.2".parse().unwrap();
        bgp.peers.get_mut(&ip).unwrap().session_ifindex = Some(3);

        bgp.process_rib_msg(RibRx::LinkDown(4));
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a different interface going down must not reset the peer",
        );
        bgp.process_rib_msg(RibRx::LinkDown(3));
        assert_eq!(
            drain_stop_events(&mut bgp),
            vec![victim],
            "the pinned ifindex must drive the reset",
        );
    }

    /// Reset initiators park the session-down cause on the peer just
    /// before sending `Event::Stop`: the fast-external-failover sweep
    /// parks `InterfaceDown`, `clear … hard` parks `AdminReset`. (The
    /// FSM consumes the parked cause into `last_reset` when the
    /// session actually leaves Established.)
    #[tokio::test]
    async fn reset_initiators_park_down_reason() {
        use crate::bgp::peer::{BgpClearOp, PeerDownReason, State, clear_bgp_action};
        use crate::rib::api::RibRx;
        let mut bgp = fresh_bgp();
        config_global_asn(&mut bgp, arg_words(&["65000"]), ConfigOp::Set).unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.3.2"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.3.2", "65001"]), ConfigOp::Set).unwrap();
        bgp.connected_subnets
            .record(&link_addr_on("10.0.3.1/24", 3));
        let _ = drain_stop_events(&mut bgp);
        park_peer(&mut bgp, "10.0.3.2", State::Established);
        let ip: IpAddr = "10.0.3.2".parse().unwrap();

        bgp.process_rib_msg(RibRx::LinkDown(3));
        assert_eq!(
            bgp.peers.get(&ip).unwrap().down_reason,
            Some(PeerDownReason::InterfaceDown),
            "failover sweep must park InterfaceDown",
        );
        assert_eq!(drain_stop_events(&mut bgp).len(), 1);

        bgp.peers.get_mut(&ip).unwrap().down_reason = None;
        let msg = clear_bgp_action(
            &mut bgp,
            &mut arg_words(&["10.0.3.2"]),
            None,
            BgpClearOp::Hard,
        )
        .unwrap();
        assert!(
            msg.contains("cleared 1 peer"),
            "unexpected clear reply: {msg}"
        );
        assert_eq!(
            bgp.peers.get(&ip).unwrap().down_reason,
            Some(PeerDownReason::AdminReset),
            "hard clear must park AdminReset",
        );
        assert_eq!(drain_stop_events(&mut bgp).len(), 1);
    }

    /// `resolve_session_ifindex` precedence: the *local* socket address
    /// beats the peer-address subnet (it stays unambiguous across
    /// parallel links), and a link-local v6 local address resolves by
    /// its scope-id outright.
    #[tokio::test]
    async fn resolve_session_ifindex_prefers_local_address() {
        use std::net::{SocketAddr, SocketAddrV6};
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.3.2"]), ConfigOp::Set).unwrap();
        bgp.connected_subnets
            .record(&link_addr_on("10.0.3.1/24", 8));
        bgp.connected_subnets
            .record(&link_addr_on("10.0.99.1/24", 7));
        let ip: IpAddr = "10.0.3.2".parse().unwrap();
        let subnets = &bgp.connected_subnets;
        let peer = bgp.peers.get_mut(&ip).unwrap();

        assert_eq!(
            peer.resolve_session_ifindex(subnets),
            Some(8),
            "without a local address, the peer-address subnet decides",
        );

        peer.param.local_addr = Some("10.0.99.1:34567".parse().unwrap());
        assert_eq!(
            peer.resolve_session_ifindex(subnets),
            Some(7),
            "the local socket address must win over the peer-address subnet",
        );

        peer.param.local_addr = Some(SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            179,
            0,
            9,
        )));
        assert_eq!(
            peer.resolve_session_ifindex(subnets),
            Some(9),
            "a link-local local address must resolve by its scope-id",
        );
    }

    /// `disable-connected-check` is a presence flag: Set/Delete toggle
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

    /// `ip-transparent` is a presence flag with FRR `peer_change_reset`
    /// semantics: Set/Delete toggle it, a change to a live session is
    /// bounced (the option must be on the socket before bind/connect),
    /// and a no-op set does not bounce.
    #[tokio::test]
    async fn ip_transparent_toggles_field_and_bounces_live_session() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_ip_transparent(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ip_transparent,
            "set must enable the flag",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "enabling on a live session must bounce it",
        );

        config_ip_transparent(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a no-op set must not bounce the session",
        );

        config_ip_transparent(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert!(
            !bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ip_transparent,
            "delete must clear the flag",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "disabling on a live session must bounce it",
        );
    }

    /// The group spelling of `ip-transparent` propagates to members
    /// through the explicit-wins resolution: a group Set flips a member
    /// without its own statement; the member's explicit statement keeps
    /// it on across a group Delete.
    #[tokio::test]
    async fn neighbor_group_ip_transparent_inherits_and_explicit_wins() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        super::super::neighbor_group::config_neighbor_group_ip_transparent(
            &mut bgp,
            arg_words(&["G"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ip_transparent,
            "a member without its own statement must inherit the group's flag",
        );

        // An explicit per-neighbor statement survives the group losing
        // its opinion.
        config_ip_transparent(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        super::super::neighbor_group::config_neighbor_group_ip_transparent(
            &mut bgp,
            arg_words(&["G"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .ip_transparent,
            "the explicit per-neighbor flag must outlive the group opinion",
        );
    }

    /// `neighbor X port <1-65535>`: Set stores the destination port and
    /// bounces a live session (FRR `peer_change_reset`); a no-op Set
    /// does not bounce; Delete clears back to the default (179) and
    /// bounces again so the session redials on 179.
    #[tokio::test]
    async fn peer_port_set_and_delete_bounce_live_session() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_peer_port(&mut bgp, arg_words(&["10.0.0.1", "1790"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().config.transport.port,
            Some(1790),
            "set must store the configured destination port",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "changing the port on a live session must bounce it",
        );

        config_peer_port(&mut bgp, arg_words(&["10.0.0.1", "1790"]), ConfigOp::Set).unwrap();
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a no-op set must not bounce the session",
        );

        config_peer_port(&mut bgp, arg_words(&["10.0.0.1", "1790"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().config.transport.port,
            None,
            "delete must return to the default port (179)",
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "removing the port on a live session must bounce it",
        );
    }

    /// A port change on an Idle peer is stored but never bounced — the
    /// next connect picks it up (same policy as the TTL knobs).
    #[tokio::test]
    async fn peer_port_on_idle_peer_does_not_bounce() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        config_peer_port(&mut bgp, arg_words(&["10.0.0.1", "1790"]), ConfigOp::Set).unwrap();
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().config.transport.port,
            Some(1790),
            "value must still be stored on an Idle peer",
        );
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "an Idle peer must not be bounced",
        );
    }

    /// Setting `transport passive-mode true` on a started peer that is
    /// still parked in Idle must flip it to Active immediately —
    /// listening, never dialing. Idle refuses inbound connections, so
    /// leaving the peer there until the idle-hold tick would drop a
    /// remote's connect landing in that window (and park the remote on
    /// its 120s connect-retry timer).
    #[tokio::test]
    async fn passive_mode_on_idle_started_peer_goes_active_immediately() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_remote_as(&mut bgp, arg_words(&["10.0.0.1", "65001"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        assert_eq!(
            bgp.peers.get(&peer_addr()).unwrap().state,
            State::Idle,
            "started peer waits out its idle-hold in Idle",
        );

        config_transport_passive(&mut bgp, arg_words(&["10.0.0.1", "true"]), ConfigOp::Set)
            .unwrap();
        let peer = bgp.peers.get(&peer_addr()).unwrap();
        assert!(peer.config.transport.passive);
        assert_eq!(
            peer.state,
            State::Active,
            "passive peer must accept inbound connections right away",
        );
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "the flip must not bounce anything",
        );
    }

    /// Drain `bgp.rx`, counting queued `Message::Relisten`s.
    fn drain_relisten(bgp: &mut Bgp) -> usize {
        use crate::bgp::inst::Message;
        let mut count = 0;
        while let Ok(msg) = bgp.rx.try_recv() {
            if matches!(msg, Message::Relisten) {
                count += 1;
            }
        }
        count
    }

    /// `router bgp port <0-65535>`: Set records the listener port and
    /// queues a Relisten (the event loop does the async rebind); a
    /// no-op Set queues nothing; port 0 is accepted (listener
    /// disabled); Delete restores the default 179 and queues another
    /// Relisten.
    #[tokio::test]
    async fn global_port_records_value_and_queues_relisten() {
        let mut bgp = fresh_bgp();
        assert_eq!(bgp.port, BGP_PORT, "fresh instance defaults to 179");

        config_global_port(&mut bgp, arg_words(&["1790"]), ConfigOp::Set).unwrap();
        assert_eq!(bgp.port, 1790);
        assert_eq!(
            drain_relisten(&mut bgp),
            1,
            "a port change must queue exactly one Relisten",
        );

        config_global_port(&mut bgp, arg_words(&["1790"]), ConfigOp::Set).unwrap();
        assert_eq!(
            drain_relisten(&mut bgp),
            0,
            "a no-op set must not cycle a healthy listener",
        );

        config_global_port(&mut bgp, arg_words(&["0"]), ConfigOp::Set).unwrap();
        assert_eq!(bgp.port, 0, "port 0 (listener disabled) is accepted");
        assert_eq!(drain_relisten(&mut bgp), 1);

        config_global_port(&mut bgp, arg_words(&["0"]), ConfigOp::Delete).unwrap();
        assert_eq!(bgp.port, BGP_PORT, "delete must restore the default 179");
        assert_eq!(drain_relisten(&mut bgp), 1);
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

    // ---- group afi-safi inheritance ------------------------------

    use super::super::neighbor_group::{
        config_neighbor_group_afi_safi, config_neighbor_group_afi_safi_enabled,
    };

    fn v4() -> AfiSafi {
        AfiSafi::new(Afi::Ip, Safi::Unicast)
    }

    fn v6() -> AfiSafi {
        AfiSafi::new(Afi::Ip6, Safi::Unicast)
    }

    fn peer_mp_families(bgp: &Bgp) -> Vec<AfiSafi> {
        bgp.peers
            .get(&peer_addr())
            .expect("peer exists")
            .config
            .mp
            .keys()
            .copied()
            .collect()
    }

    /// Group `afi-safi ipv6 enabled true` flows to a member peer's
    /// effective MP set, and `enabled false` on ipv4 overrides the built-in
    /// default. The member here is not Established, so it does not bounce —
    /// its first OPEN carries the change (the Established case bounces; see
    /// `group_afi_safi_change_bounces_established_member`).
    #[tokio::test]
    async fn group_afi_safi_propagates_to_member() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv6", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(peer_mp_families(&bgp), vec![v4(), v6()]);

        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv4", "false"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(peer_mp_families(&bgp), vec![v6()]);
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a not-yet-Established member must not bounce",
        );
    }

    /// Changing a group's afi-safi opinion is a capability change, so an
    /// Established member renegotiates: its MP set changes and it is sent
    /// `Event::Stop` (the `clear bgp ... hard` teardown). Mirrors the
    /// per-peer `config_afi_safi` bounce, on the group path.
    #[tokio::test]
    async fn group_afi_safi_change_bounces_established_member() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let peer_ident = bgp.peers.get(&peer_addr()).unwrap().ident;
        // Bring the member up, then drain the setup events.
        bgp.peers.get_mut(&peer_addr()).unwrap().state = crate::bgp::peer::State::Established;
        let _ = drain_stop_events(&mut bgp);

        // Enabling a new family on the group bounces the Established member.
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "mup", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(peer_mp_families(&bgp).len(), 3, "v4 + IPv4/IPv6 MUP");
        assert!(
            drain_stop_events(&mut bgp).contains(&peer_ident),
            "enabling a group afi-safi must bounce an Established member",
        );

        // A redundant set (no family-set change) must not bounce.
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "mup", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "a redundant group afi-safi set must not bounce",
        );

        // Disabling the family again also bounces (capability withdrawn).
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "mup", "true"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(
            drain_stop_events(&mut bgp).contains(&peer_ident),
            "disabling a group afi-safi must bounce an Established member",
        );
    }

    /// An explicit per-peer `afi-safi <name> enabled` statement wins
    /// over the group's opinion — in either order of arrival.
    #[tokio::test]
    async fn peer_explicit_afi_safi_wins_over_group() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();

        // Peer says ipv4 on; a later group opinion of ipv4 off must
        // not override it.
        config_afi_safi(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv4", "false"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(peer_mp_families(&bgp), vec![v4()]);

        // Removing the explicit statement lets the group opinion
        // through.
        config_afi_safi(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4", "true"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert_eq!(peer_mp_families(&bgp), Vec::<AfiSafi>::new());
    }

    /// An AFI/SAFI is a Multiprotocol *capability*: enabling or disabling
    /// one on an Established neighbor changes the negotiated set, which is
    /// fixed at OPEN time, so the session must bounce (`Event::Stop`, the
    /// `clear bgp ... hard` teardown) to renegotiate. This is NOT
    /// MUP-specific — pinned across IPv6 unicast, EVPN, VPNv4 and
    /// mup. A peer that has not Established yet carries the change
    /// in its first OPEN (no bounce); a redundant set leaves the family set
    /// unchanged (no bounce).
    #[tokio::test]
    async fn afi_safi_change_bounces_established_peer() {
        for fam in ["ipv6", "evpn", "vpnv4", "mup"] {
            let mut bgp = fresh_bgp();
            config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
            let peer_ident = bgp.peers.get(&peer_addr()).unwrap().ident;

            // Not Established yet → the upcoming OPEN carries it → no bounce.
            config_afi_safi(
                &mut bgp,
                arg_words(&["10.0.0.1", fam, "true"]),
                ConfigOp::Set,
            )
            .unwrap();
            assert!(
                drain_stop_events(&mut bgp).is_empty(),
                "{fam}: a not-yet-Established peer must not bounce",
            );

            // Bring the session up.
            bgp.peers.get_mut(&peer_addr()).unwrap().state = crate::bgp::peer::State::Established;
            let _ = drain_stop_events(&mut bgp);

            // Redundant set (already enabled) → family set unchanged → no bounce.
            config_afi_safi(
                &mut bgp,
                arg_words(&["10.0.0.1", fam, "true"]),
                ConfigOp::Set,
            )
            .unwrap();
            assert!(
                drain_stop_events(&mut bgp).is_empty(),
                "{fam}: a redundant set must not bounce",
            );

            // Disabling on the live session withdraws the capability → bounce.
            config_afi_safi(
                &mut bgp,
                arg_words(&["10.0.0.1", fam, "true"]),
                ConfigOp::Delete,
            )
            .unwrap();
            assert!(
                drain_stop_events(&mut bgp).contains(&peer_ident),
                "{fam}: disabling on an Established peer must bounce",
            );

            // Re-enabling changes the set back → bounce again.
            config_afi_safi(
                &mut bgp,
                arg_words(&["10.0.0.1", fam, "true"]),
                ConfigOp::Set,
            )
            .unwrap();
            assert!(
                drain_stop_events(&mut bgp).contains(&peer_ident),
                "{fam}: re-enabling on an Established peer must bounce",
            );
        }
    }

    /// Deleting one group afi-safi entry (or the whole group) drops
    /// its opinions and the member falls back to the built-in default
    /// plus its own statements.
    #[tokio::test]
    async fn group_afi_safi_delete_restores_default() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv4", "false"]),
            ConfigOp::Set,
        )
        .unwrap();
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv6", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(peer_mp_families(&bgp), vec![v6()]);

        // Whole-entry delete (the per-leaf delete may be skipped by
        // the commit path — the entry callback must cope alone).
        config_neighbor_group_afi_safi(&mut bgp, arg_words(&["G", "ipv4"]), ConfigOp::Delete)
            .unwrap();
        assert_eq!(peer_mp_families(&bgp), vec![v4(), v6()]);

        // Group delete cascade: opinions gone entirely.
        config_neighbor_group(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert_eq!(peer_mp_families(&bgp), vec![v4()]);
    }

    /// Group afi-safi changes must reach interface-keyed (IPv6
    /// unnumbered) members too. `PeerMap::iter_mut` silently skips
    /// interface-keyed peers — sweeping with it left the unnumbered
    /// peer's families frozen (caught by the
    /// `@bgp_unnumbered_afi_safi` BDD, pinned here).
    #[tokio::test]
    async fn group_afi_safi_reaches_interface_keyed_member() {
        use super::super::interface_neighbor::{
            config_interface_neighbor, config_interface_neighbor_neighbor_group,
            config_interface_neighbor_remote_as, materialize_peer,
        };
        use super::super::peer_key::PeerKey;

        let mut bgp = fresh_bgp();
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv6", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        config_interface_neighbor(&mut bgp, arg_words(&["i1"]), ConfigOp::Set).unwrap();
        config_interface_neighbor_neighbor_group(&mut bgp, arg_words(&["i1", "G"]), ConfigOp::Set)
            .unwrap();
        config_interface_neighbor_remote_as(
            &mut bgp,
            arg_words(&["i1", "internal"]),
            ConfigOp::Set,
        )
        .unwrap();

        let link_local: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        materialize_peer(&mut bgp, "i1", 7, link_local).expect("peer materializes");

        let families = |bgp: &Bgp| -> Vec<AfiSafi> {
            bgp.peers
                .get_by_key(&PeerKey::Interface(7))
                .expect("interface peer exists")
                .config
                .mp
                .keys()
                .copied()
                .collect()
        };
        assert_eq!(
            families(&bgp),
            vec![v4(), v6()],
            "materialization inherits the group families",
        );

        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv4", "false"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(
            families(&bgp),
            vec![v6()],
            "the sweep must reach the interface-keyed member",
        );
    }

    // ---- interface-neighbor dormant materialization ---------------
    // A configured `interface-neighbor` must exist as a Peer (and so
    // be listed by `show bgp summary`) even when the remote node has
    // never sent an RA — before dormant materialization the neighbor
    // was invisible until the first NeighborDiscovered event.

    /// Config alone (link already known to RIB) materializes a dormant
    /// Idle peer; the first RA upgrades it in place — address learned,
    /// FSM kicked — instead of re-creating it.
    #[tokio::test]
    async fn interface_neighbor_is_visible_before_first_ra() {
        use super::super::interface_neighbor::{
            config_interface_neighbor, config_interface_neighbor_remote_as, materialize_peer,
        };
        use super::super::peer_key::PeerKey;
        use crate::bgp::peer::State;

        let mut bgp = fresh_bgp();
        // RIB announced the link; no RA has arrived.
        bgp.link_index_by_name.insert("i1".to_string(), 7);
        config_interface_neighbor(&mut bgp, arg_words(&["i1"]), ConfigOp::Set).unwrap();
        config_interface_neighbor_remote_as(&mut bgp, arg_words(&["i1", "65002"]), ConfigOp::Set)
            .unwrap();

        let peer = bgp
            .peers
            .get_by_key(&PeerKey::Interface(7))
            .expect("dormant peer must materialize from config alone");
        assert_eq!(peer.ifname.as_deref(), Some("i1"));
        assert_eq!(peer.remote_as, 65002);
        assert_eq!(peer.state, State::Idle);
        assert!(peer.address.is_unspecified(), "no RA yet — no address");
        assert!(!peer.active, "FSM must not dial an unspecified address");
        let ident = peer.ident;

        let link_local: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
        materialize_peer(&mut bgp, "i1", 7, link_local).expect("RA upgrades the peer");
        let peer = bgp.peers.get_by_key(&PeerKey::Interface(7)).unwrap();
        assert_eq!(peer.ident, ident, "upgraded in place, not re-created");
        assert_eq!(peer.address, IpAddr::from(link_local));
        assert!(peer.active, "the first RA must kick the FSM");
    }

    /// Config typed before RIB announces the interface (startup config
    /// replay races the link dump): the `RibRx::LinkAdd` arm must
    /// materialize the dormant peer.
    #[tokio::test]
    async fn interface_neighbor_materializes_on_link_add() {
        use super::super::interface_neighbor::{
            config_interface_neighbor, config_interface_neighbor_remote_as,
        };
        use super::super::peer_key::PeerKey;

        let mut bgp = fresh_bgp();
        config_interface_neighbor(&mut bgp, arg_words(&["i1"]), ConfigOp::Set).unwrap();
        config_interface_neighbor_remote_as(&mut bgp, arg_words(&["i1", "65002"]), ConfigOp::Set)
            .unwrap();
        assert!(
            bgp.peers.get_by_key(&PeerKey::Interface(7)).is_none(),
            "no link yet — nothing to key the peer by"
        );

        let link = crate::rib::Link {
            index: 7,
            name: "i1".to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: Default::default(),
            link_type: crate::rib::LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vrf_table: None,
            bridge: false,
            vxlan_local: None,
            mtu_error: None,
        };
        bgp.process_rib_msg(crate::rib::api::RibRx::LinkAdd(link));

        let peer = bgp
            .peers
            .get_by_key(&PeerKey::Interface(7))
            .expect("LinkAdd must materialize the configured neighbor");
        assert_eq!(peer.ifname.as_deref(), Some("i1"));
        assert!(!peer.active, "still no RA — stays dormant");
    }

    /// The group supplies the remote-as after an interface-neighbor
    /// referenced it: the group callback must surface the dormant
    /// member — the remote-as sweep only reaches peers that already
    /// exist.
    #[tokio::test]
    async fn group_remote_as_materializes_dormant_interface_member() {
        use super::super::interface_neighbor::{
            config_interface_neighbor, config_interface_neighbor_neighbor_group,
        };
        use super::super::peer_key::PeerKey;

        let mut bgp = fresh_bgp();
        bgp.link_index_by_name.insert("i1".to_string(), 7);
        config_interface_neighbor(&mut bgp, arg_words(&["i1"]), ConfigOp::Set).unwrap();
        config_interface_neighbor_neighbor_group(&mut bgp, arg_words(&["i1", "G"]), ConfigOp::Set)
            .unwrap();
        assert!(
            bgp.peers.get_by_key(&PeerKey::Interface(7)).is_none(),
            "no remote-as resolvable yet"
        );

        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65003"]), ConfigOp::Set)
            .unwrap();
        let peer = bgp
            .peers
            .get_by_key(&PeerKey::Interface(7))
            .expect("the group's remote-as completes the config gates");
        assert_eq!(peer.remote_as, 65003);
        assert!(peer.config.remote_as_inherited);
        assert!(!peer.active, "still no RA — stays dormant");
    }

    // ---- whole-session knob inheritance (ttl-security exemplar) --

    use super::super::neighbor_group::config_neighbor_group_ttl_security;

    fn member_ttl_security(bgp: &Bgp) -> bool {
        bgp.peers
            .get(&peer_addr())
            .expect("peer exists")
            .config
            .transport
            .ttl_security
    }

    /// Group ttl-security flows to a member with the same ritual as
    /// the per-neighbor knob: applied on an Idle peer without a
    /// bounce, bounced on a live session, and removed when the group
    /// opinion goes away.
    #[tokio::test]
    async fn group_ttl_security_propagates_and_bounces_live_member() {
        use crate::bgp::peer::State;
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        // Idle member: flag lands, no bounce.
        config_neighbor_group_ttl_security(&mut bgp, arg_words(&["G"]), ConfigOp::Set).unwrap();
        assert!(member_ttl_security(&bgp), "group opinion must apply");
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "an Idle member must not be bounced",
        );

        // Live member: a group flip bounces it, exactly like the
        // per-neighbor callback would.
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;
        config_neighbor_group_ttl_security(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert!(!member_ttl_security(&bgp), "group delete must clear");
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "a live member must bounce to drop GTSM",
        );
    }

    /// Explicit per-neighbor ttl-security outlives group changes, and
    /// deleting the explicit statement falls back to the group's
    /// opinion instead of off.
    #[tokio::test]
    async fn peer_explicit_ttl_security_wins_and_falls_back() {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();

        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_neighbor_group_ttl_security(&mut bgp, arg_words(&["G"]), ConfigOp::Set).unwrap();
        assert!(member_ttl_security(&bgp));

        // Deleting the explicit statement keeps GTSM via the group.
        config_ttl_security(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert!(
            member_ttl_security(&bgp),
            "delete of the explicit statement must fall back to the group opinion",
        );

        // Dropping the group opinion finally clears it.
        config_neighbor_group_ttl_security(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert!(!member_ttl_security(&bgp));
    }

    /// Per-family next-hop-self inherits through the group's afi-safi
    /// entry with explicit-wins semantics.
    #[tokio::test]
    async fn group_next_hop_self_propagates_with_explicit_priority() {
        use super::super::neighbor_group::config_neighbor_group_afi_safi_next_hop_self;

        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();

        let nhs = |bgp: &Bgp| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .sub
                .get(&v4())
                .map(|s| s.next_hop_self)
                .unwrap_or(false)
        };

        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv4", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        config_neighbor_group_afi_safi_next_hop_self(
            &mut bgp,
            arg_words(&["G", "ipv4", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert!(nhs(&bgp), "group next-hop-self must apply");

        // Explicit per-neighbor false outranks the group's true.
        config_next_hop_self(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4", "false"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert!(!nhs(&bgp), "explicit statement must win");

        // Removing the explicit statement falls back to the group.
        config_next_hop_self(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4", "false"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(nhs(&bgp), "fallback to group opinion");

        // Dropping the family entry (enabled delete removes the whole
        // entry, next-hop-self opinion included) clears it.
        config_neighbor_group_afi_safi_enabled(
            &mut bgp,
            arg_words(&["G", "ipv4", "true"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(!nhs(&bgp), "entry delete clears the inherited value");
    }

    // ---- the nine additional inheritable whole-session knobs --------
    //
    // One focused test per knob. Bounce-family knobs (port,
    // ebgp-multihop, disable-connected-check) mirror the ttl-security
    // exemplar: value propagates, a live member bounces, explicit wins
    // and falls back. Write-only knobs (passive, allowas-in,
    // as-override, remove-private-as, enforce-first-as,
    // route-reflector) additionally assert the sweep never bounces.

    use super::super::neighbor_group::{
        config_neighbor_group_allowas_in, config_neighbor_group_allowas_in_count,
        config_neighbor_group_allowas_in_origin, config_neighbor_group_as_override,
        config_neighbor_group_disable_connected_check, config_neighbor_group_ebgp_multihop,
        config_neighbor_group_enforce_first_as, config_neighbor_group_passive,
        config_neighbor_group_port, config_neighbor_group_remove_private_as,
        config_neighbor_group_remove_private_as_all,
        config_neighbor_group_remove_private_as_replace_as,
        config_neighbor_group_route_reflector_client,
    };

    /// Attach `10.0.0.1` to group `G` (which has a remote-as so the
    /// member can start), draining the setup events. Returns a `Bgp`
    /// with the member parked Idle.
    fn bgp_with_member() -> Bgp {
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);
        bgp
    }

    fn member(bgp: &Bgp) -> &Peer {
        bgp.peers.get(&peer_addr()).expect("peer exists")
    }

    /// Group `port` flows to an Idle member without a bounce, bounces a
    /// live member, and the explicit per-neighbor value wins and falls
    /// back to the group on explicit-delete.
    #[tokio::test]
    async fn group_port_propagates_explicit_wins_and_bounces_live() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();

        // Idle member: value lands, no bounce.
        config_neighbor_group_port(&mut bgp, arg_words(&["G", "1790"]), ConfigOp::Set).unwrap();
        assert_eq!(member(&bgp).config.transport.port, Some(1790));
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "an Idle member must not be bounced",
        );

        // Explicit per-neighbor value wins over the group's.
        config_peer_port(&mut bgp, arg_words(&["10.0.0.1", "1791"]), ConfigOp::Set).unwrap();
        assert_eq!(member(&bgp).config.transport.port, Some(1791));
        let _ = drain_stop_events(&mut bgp);

        // Live member: a group flip bounces it (only matters once the
        // explicit value is gone, so delete it first).
        config_peer_port(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            member(&bgp).config.transport.port,
            Some(1790),
            "explicit delete falls back to the group opinion",
        );
        let _ = drain_stop_events(&mut bgp);

        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;
        config_neighbor_group_port(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            member(&bgp).config.transport.port,
            None,
            "group delete clears"
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "a live member must bounce to re-dial on the new port",
        );
    }

    /// Group `ebgp-multihop` propagates with explicit-wins / fallback
    /// and bounces a live member.
    #[tokio::test]
    async fn group_ebgp_multihop_propagates_explicit_wins_and_bounces_live() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();

        config_neighbor_group_ebgp_multihop(&mut bgp, arg_words(&["G", "5"]), ConfigOp::Set)
            .unwrap();
        assert_eq!(member(&bgp).config.transport.ebgp_multihop, Some(5));
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "an Idle member must not be bounced",
        );

        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1", "10"]), ConfigOp::Set).unwrap();
        assert_eq!(member(&bgp).config.transport.ebgp_multihop, Some(10));
        let _ = drain_stop_events(&mut bgp);

        config_ebgp_multihop(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            member(&bgp).config.transport.ebgp_multihop,
            Some(5),
            "explicit delete falls back to the group opinion",
        );
        let _ = drain_stop_events(&mut bgp);

        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;
        config_neighbor_group_ebgp_multihop(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert_eq!(member(&bgp).config.transport.ebgp_multihop, None);
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "a live member must bounce to apply the new TTL",
        );
    }

    /// Group `disable-connected-check` (a presence flag)
    /// propagates with explicit-wins / fallback and bounces a live
    /// member.
    #[tokio::test]
    async fn group_disable_connected_check_propagates_and_bounces_live() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();

        config_neighbor_group_disable_connected_check(&mut bgp, arg_words(&["G"]), ConfigOp::Set)
            .unwrap();
        assert!(member(&bgp).config.transport.disable_connected_check);
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "an Idle member must not be bounced",
        );

        // Live member: dropping the group opinion bounces it.
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;
        config_neighbor_group_disable_connected_check(
            &mut bgp,
            arg_words(&["G"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(
            !member(&bgp).config.transport.disable_connected_check,
            "group delete clears"
        );
        assert_eq!(
            drain_stop_events(&mut bgp).len(),
            1,
            "a live member must bounce when the check is re-enabled",
        );
    }

    /// Group `passive` flows to the member, the explicit per-neighbor
    /// value wins and falls back, and the sweep never bounces.
    #[tokio::test]
    async fn group_passive_propagates_explicit_wins_no_bounce() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_neighbor_group_passive(&mut bgp, arg_words(&["G", "true"]), ConfigOp::Set).unwrap();
        assert!(
            member(&bgp).config.transport.passive,
            "group opinion must apply"
        );

        // Explicit per-neighbor false outranks the group's true.
        config_transport_passive(&mut bgp, arg_words(&["10.0.0.1", "false"]), ConfigOp::Set)
            .unwrap();
        assert!(
            !member(&bgp).config.transport.passive,
            "explicit statement must win"
        );

        // Removing the explicit statement falls back to the group.
        config_transport_passive(
            &mut bgp,
            arg_words(&["10.0.0.1", "false"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(
            member(&bgp).config.transport.passive,
            "fallback to group opinion"
        );

        // Dropping the group opinion clears it.
        config_neighbor_group_passive(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert!(
            !member(&bgp).config.transport.passive,
            "group delete clears"
        );

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "passive changes must never bounce the session",
        );
    }

    /// Group `allowas-in` (bare + count + origin) propagates with
    /// explicit-wins / fallback and never bounces.
    #[tokio::test]
    async fn group_allowas_in_propagates_explicit_wins_no_bounce() {
        use crate::bgp::peer::AllowAsIn;
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        // Bare form → default count.
        config_neighbor_group_allowas_in(&mut bgp, arg_words(&["G"]), ConfigOp::Set).unwrap();
        assert_eq!(member(&bgp).config.allowas_in, Some(AllowAsIn::Count(3)));

        // Group count then origin (order-independent cooperative leaves).
        config_neighbor_group_allowas_in_count(&mut bgp, arg_words(&["G", "7"]), ConfigOp::Set)
            .unwrap();
        assert_eq!(member(&bgp).config.allowas_in, Some(AllowAsIn::Count(7)));
        config_neighbor_group_allowas_in_origin(&mut bgp, arg_words(&["G"]), ConfigOp::Set)
            .unwrap();
        assert_eq!(member(&bgp).config.allowas_in, Some(AllowAsIn::Origin));

        // Explicit per-neighbor count wins over the group's origin.
        config_allowas_in_count(&mut bgp, arg_words(&["10.0.0.1", "5"]), ConfigOp::Set).unwrap();
        assert_eq!(member(&bgp).config.allowas_in, Some(AllowAsIn::Count(5)));

        // Removing the whole explicit container falls back to the group.
        config_allowas_in(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert_eq!(
            member(&bgp).config.allowas_in,
            Some(AllowAsIn::Origin),
            "fallback to group opinion",
        );

        // Dropping the group container clears it.
        config_neighbor_group_allowas_in(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert_eq!(member(&bgp).config.allowas_in, None, "group delete clears");

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "allowas-in changes must never bounce the session",
        );
    }

    /// Group `as-override` (presence) propagates with explicit-wins /
    /// fallback and never bounces.
    #[tokio::test]
    async fn group_as_override_propagates_explicit_wins_no_bounce() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_neighbor_group_as_override(&mut bgp, arg_words(&["G"]), ConfigOp::Set).unwrap();
        assert!(member(&bgp).config.as_override, "group opinion must apply");

        // Presence knob: explicit can only assert "on", so explicit-wins
        // is exercised via the fallback path like the ttl-security
        // exemplar — an explicit statement keeps the value through a
        // group delete, then dropping the explicit one finally clears it.
        config_as_override(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_neighbor_group_as_override(&mut bgp, arg_words(&["G"]), ConfigOp::Delete).unwrap();
        assert!(
            member(&bgp).config.as_override,
            "explicit statement survives the group delete",
        );
        config_as_override(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert!(!member(&bgp).config.as_override, "dropping both clears it");

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "as-override changes must never bounce the session",
        );
    }

    /// Group `remove-private-as` (bare + all + replace-as) propagates
    /// with explicit-wins / fallback and never bounces.
    #[tokio::test]
    async fn group_remove_private_as_propagates_explicit_wins_no_bounce() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_neighbor_group_remove_private_as(&mut bgp, arg_words(&["G"]), ConfigOp::Set)
            .unwrap();
        let rpa = member(&bgp)
            .config
            .remove_private_as
            .expect("group opinion applies");
        assert!(!rpa.all && !rpa.replace_as, "bare form: both modifiers off");

        config_neighbor_group_remove_private_as_all(&mut bgp, arg_words(&["G"]), ConfigOp::Set)
            .unwrap();
        config_neighbor_group_remove_private_as_replace_as(
            &mut bgp,
            arg_words(&["G"]),
            ConfigOp::Set,
        )
        .unwrap();
        let rpa = member(&bgp)
            .config
            .remove_private_as
            .expect("group opinion applies");
        assert!(rpa.all && rpa.replace_as, "both modifiers on");

        // Explicit per-neighbor bare form (both off) wins over the
        // group's all+replace-as.
        config_remove_private_as(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        let rpa = member(&bgp)
            .config
            .remove_private_as
            .expect("explicit applies");
        assert!(!rpa.all && !rpa.replace_as, "explicit statement must win");

        // Removing the explicit container falls back to the group.
        config_remove_private_as(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        let rpa = member(&bgp)
            .config
            .remove_private_as
            .expect("fallback to group");
        assert!(rpa.all && rpa.replace_as, "fallback to group opinion");

        // Dropping the group container clears it.
        config_neighbor_group_remove_private_as(&mut bgp, arg_words(&["G"]), ConfigOp::Delete)
            .unwrap();
        assert_eq!(
            member(&bgp).config.remove_private_as,
            None,
            "group delete clears"
        );

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "remove-private-as changes must never bounce the session",
        );
    }

    /// Group `enforce-first-as` (presence) propagates and never
    /// bounces.
    #[tokio::test]
    async fn group_enforce_first_as_propagates_no_bounce() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_neighbor_group_enforce_first_as(&mut bgp, arg_words(&["G"]), ConfigOp::Set).unwrap();
        assert!(
            member(&bgp).config.enforce_first_as,
            "group opinion must apply"
        );

        // Presence knob: explicit-wins via the fallback path (see
        // as-override test).
        config_enforce_first_as(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_neighbor_group_enforce_first_as(&mut bgp, arg_words(&["G"]), ConfigOp::Delete)
            .unwrap();
        assert!(
            member(&bgp).config.enforce_first_as,
            "explicit statement survives the group delete",
        );
        config_enforce_first_as(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Delete).unwrap();
        assert!(
            !member(&bgp).config.enforce_first_as,
            "dropping both clears it"
        );

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "enforce-first-as changes must never bounce the session",
        );
    }

    /// Group `route-reflector client` flows to the member's
    /// `reflector_client` (a `Peer` field), explicit wins / falls back,
    /// and the sweep never bounces.
    #[tokio::test]
    async fn group_route_reflector_client_propagates_explicit_wins_no_bounce() {
        use crate::bgp::peer::State;
        let mut bgp = bgp_with_member();
        bgp.peers.get_mut(&peer_addr()).unwrap().state = State::Established;

        config_neighbor_group_route_reflector_client(
            &mut bgp,
            arg_words(&["G", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert!(member(&bgp).reflector_client, "group opinion must apply");

        // Explicit per-neighbor false outranks the group's true.
        config_route_reflector(&mut bgp, arg_words(&["10.0.0.1", "false"]), ConfigOp::Set).unwrap();
        assert!(
            !member(&bgp).reflector_client,
            "explicit statement must win"
        );

        // Removing the explicit statement falls back to the group.
        config_route_reflector(
            &mut bgp,
            arg_words(&["10.0.0.1", "false"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(member(&bgp).reflector_client, "fallback to group opinion");

        // Dropping the group opinion clears it.
        config_neighbor_group_route_reflector_client(&mut bgp, arg_words(&["G"]), ConfigOp::Delete)
            .unwrap();
        assert!(!member(&bgp).reflector_client, "group delete clears");

        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "route-reflector changes must never bounce the session",
        );
    }

    // ---- side-effectful knobs: tcp-mss / password / update-source /
    // ---- policy refs ---------------------------------------------

    /// Group tcp-mss flows to a member without a bounce; explicit
    /// wins; explicit-delete falls back to the group clamp.
    #[tokio::test]
    async fn group_tcp_mss_propagates_with_explicit_priority() {
        use super::super::neighbor_group::config_neighbor_group_tcp_mss;
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        let mss = |bgp: &Bgp| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .tcp_mss
        };

        config_neighbor_group_tcp_mss(&mut bgp, arg_words(&["G", "1300"]), ConfigOp::Set).unwrap();
        assert_eq!(mss(&bgp), Some(1300), "group clamp must apply");

        config_tcp_mss(&mut bgp, arg_words(&["10.0.0.1", "1200"]), ConfigOp::Set).unwrap();
        assert_eq!(mss(&bgp), Some(1200), "explicit statement must win");

        config_tcp_mss(&mut bgp, arg_words(&["10.0.0.1", "1200"]), ConfigOp::Delete).unwrap();
        assert_eq!(mss(&bgp), Some(1300), "fallback to group clamp");

        config_neighbor_group_tcp_mss(&mut bgp, arg_words(&["G", "1300"]), ConfigOp::Delete)
            .unwrap();
        assert_eq!(mss(&bgp), None, "group delete clears");
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "tcp-mss changes must never bounce the session",
        );
    }

    /// Group MD5 password flows to a member; explicit wins; fallback
    /// on explicit-delete; never bounces.
    #[tokio::test]
    async fn group_password_propagates_with_explicit_priority() {
        use super::super::neighbor_group::config_neighbor_group_password;
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        let _ = drain_stop_events(&mut bgp);

        let pw = |bgp: &Bgp| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .config
                .transport
                .md5_password
                .clone()
        };

        config_neighbor_group_password(&mut bgp, arg_words(&["G", "groupsecret"]), ConfigOp::Set)
            .unwrap();
        assert_eq!(pw(&bgp).as_deref(), Some("groupsecret"));

        config_peer_tcp_md5_password(
            &mut bgp,
            arg_words(&["10.0.0.1", "mysecret"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(pw(&bgp).as_deref(), Some("mysecret"), "explicit wins");

        config_peer_tcp_md5_password(
            &mut bgp,
            arg_words(&["10.0.0.1", "mysecret"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert_eq!(
            pw(&bgp).as_deref(),
            Some("groupsecret"),
            "fallback to group password",
        );

        config_neighbor_group_password(
            &mut bgp,
            arg_words(&["G", "groupsecret"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert_eq!(pw(&bgp), None, "group delete clears");
        assert!(
            drain_stop_events(&mut bgp).is_empty(),
            "password changes must never bounce the session",
        );
    }

    /// A group update-source applies only to members whose address
    /// family matches the source — a v4 source lands on the v4 member
    /// and is skipped (with a warning) on the v6 member.
    #[tokio::test]
    async fn group_update_source_respects_address_family() {
        use super::super::neighbor_group::config_neighbor_group_update_source;
        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();
        config_peer(&mut bgp, arg_words(&["2001:db8::2"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["2001:db8::2", "G"]), ConfigOp::Set)
            .unwrap();
        let _ = drain_stop_events(&mut bgp);

        config_neighbor_group_update_source(
            &mut bgp,
            arg_words(&["G", "192.0.2.10"]),
            ConfigOp::Set,
        )
        .unwrap();

        let src = |bgp: &Bgp, addr: &str| {
            bgp.peers
                .get(&addr.parse().unwrap())
                .unwrap()
                .config
                .transport
                .update_source
        };
        assert_eq!(
            src(&bgp, "10.0.0.1"),
            Some("192.0.2.10".parse().unwrap()),
            "v4 member adopts the v4 source",
        );
        assert_eq!(
            src(&bgp, "2001:db8::2"),
            None,
            "v6 member must skip the mismatched-family source",
        );
    }

    /// Group policy/prefix-set references bind to the member's peer-wide
    /// fallback slots. With the per-neighbor `policy {in,out}` CLI retired,
    /// a neighbor-group is the only producer of those slots.
    #[tokio::test]
    async fn group_policy_refs_bind_to_peer_wide_slots() {
        use super::super::neighbor_group::{
            config_neighbor_group_policy_out, config_neighbor_group_prefix_set_in,
        };
        use crate::bgp::InOut;

        let mut bgp = fresh_bgp();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();

        // The group bindings land in the peer-wide fallback slots, not the
        // per-AFI map.
        let pol_out = |bgp: &Bgp| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .policy_list_legacy
                .get(&InOut::Output)
                .name
                .clone()
        };
        let pfx_in = |bgp: &Bgp| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .prefix_set_legacy
                .get(&InOut::Input)
                .name
                .clone()
        };

        config_neighbor_group_policy_out(&mut bgp, arg_words(&["G", "EGRESS"]), ConfigOp::Set)
            .unwrap();
        config_neighbor_group_prefix_set_in(&mut bgp, arg_words(&["G", "INGRESS"]), ConfigOp::Set)
            .unwrap();
        assert_eq!(pol_out(&bgp).as_deref(), Some("EGRESS"));
        assert_eq!(pfx_in(&bgp).as_deref(), Some("INGRESS"));

        // Dropping the group reference unbinds.
        config_neighbor_group_policy_out(&mut bgp, arg_words(&["G", "EGRESS"]), ConfigOp::Delete)
            .unwrap();
        assert_eq!(pol_out(&bgp), None, "group delete unbinds");
    }

    /// A per-AFI `afi-safi <name> policy/prefix-set` binding wins for its
    /// own family; other families fall back to the peer-wide route-policy
    /// inherited from a neighbor-group (now the only producer of the
    /// peer-wide slot — the per-neighbor `policy {in,out}` CLI was
    /// retired). Deleting the per-AFI binding restores the fallback.
    #[tokio::test]
    async fn afi_safi_policy_overrides_inherited_peer_wide_per_family() {
        use super::super::neighbor_group::config_neighbor_group_policy_in;
        use crate::bgp::InOut;
        use bgp_packet::{Afi, AfiSafi, Safi};

        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.1"]), ConfigOp::Set).unwrap();
        config_neighbor_group_remote_as(&mut bgp, arg_words(&["G", "65000"]), ConfigOp::Set)
            .unwrap();
        config_peer_neighbor_group(&mut bgp, arg_words(&["10.0.0.1", "G"]), ConfigOp::Set).unwrap();

        let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let evpn = AfiSafi::new(Afi::L2vpn, Safi::Evpn);
        let pol_in = |bgp: &Bgp, af: AfiSafi| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .policy_list_at(af, InOut::Input)
                .name
                .clone()
        };
        let pfx_in = |bgp: &Bgp, af: AfiSafi| {
            bgp.peers
                .get(&peer_addr())
                .unwrap()
                .prefix_set_at(af, InOut::Input)
                .name
                .clone()
        };

        // The peer-wide fallback, inherited from the neighbor-group,
        // applies to every family with no per-AFI override.
        config_neighbor_group_policy_in(&mut bgp, arg_words(&["G", "LEGACY"]), ConfigOp::Set)
            .unwrap();
        assert_eq!(pol_in(&bgp, v4).as_deref(), Some("LEGACY"));
        assert_eq!(pol_in(&bgp, evpn).as_deref(), Some("LEGACY"));

        // A per-AFI ipv4 binding overrides the fallback — but only for
        // ipv4; evpn still sees the inherited fallback.
        super::config_afi_safi_policy_in(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4", "PERAFI"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(pol_in(&bgp, v4).as_deref(), Some("PERAFI"), "per-AFI wins");
        assert_eq!(
            pol_in(&bgp, evpn).as_deref(),
            Some("LEGACY"),
            "other family keeps the inherited fallback",
        );

        // prefix-set has no per-neighbor CLI and the group sets none, so
        // it is per-AFI only here.
        super::config_afi_safi_prefix_in(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4", "PFX4"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(pfx_in(&bgp, v4).as_deref(), Some("PFX4"));
        assert_eq!(pfx_in(&bgp, evpn), None, "no prefix-set fallback");

        // Deleting the per-AFI policy restores the inherited fallback for ipv4.
        super::config_afi_safi_policy_in(
            &mut bgp,
            arg_words(&["10.0.0.1", "ipv4"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert_eq!(
            pol_in(&bgp, v4).as_deref(),
            Some("LEGACY"),
            "per-AFI delete falls back to the inherited peer-wide policy",
        );
    }
}

#[cfg(test)]
mod afi_safi_next_hop_self_tests {
    //! `afi-safi <name> next-hop-self` per-neighbor callback wiring
    //! (Inter-AS MPLS/VPN Option C). `yang_load_tests` validates that the
    //! YANG loads, but not that the callback actually records the flag on
    //! the peer — that's asserted here. Independent test module with its
    //! own mock channels, mirroring `bfd_wiring_tests`.

    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

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

    fn fresh_bgp() -> Bgp {
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        Box::leak(Box::new(_inbound_rx));
        let ctx = crate::context::ProtoContext::default_table(client);

        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _sub_inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_rib_rx));
        Box::leak(Box::new(_sub_inbound_rx));
        let next_proto_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1));
        let subscriber =
            crate::config::RibSubscriber::for_test(rib_tx, rib_inbound_tx, next_proto_id);

        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_policy_rx));
        Bgp::new(
            ctx,
            rib_rx,
            subscriber,
            policy_tx,
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
        )
    }

    /// `afi-safi label-v4 next-hop-self true` records the flag for that AF
    /// only; `delete` clears it. This is the knob an Inter-AS Option C ASBR
    /// sets on its iBGP labeled-unicast session to the PE so re-advertised
    /// eBGP-LU routes carry the ASBR as next-hop (`route_update_labelv4`),
    /// not the unreachable foreign-AS next-hop.
    #[tokio::test]
    async fn label_v4_next_hop_self_records_per_af() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Default: off for every AF.
        assert!(
            !bgp.peers
                .get(&addr)
                .unwrap()
                .next_hop_self(Afi::Ip, Safi::MplsLabel),
            "next-hop-self defaults off",
        );

        config_next_hop_self(
            &mut bgp,
            arg_words(&["10.0.0.2", "label-v4", "true"]),
            ConfigOp::Set,
        )
        .unwrap();

        let peer = bgp.peers.get(&addr).unwrap();
        assert!(
            peer.next_hop_self(Afi::Ip, Safi::MplsLabel),
            "label-v4 flag recorded",
        );
        // Scoped to the AF it was set on — label-v6 is untouched.
        assert!(
            !peer.next_hop_self(Afi::Ip6, Safi::MplsLabel),
            "other AF unaffected",
        );

        config_next_hop_self(
            &mut bgp,
            arg_words(&["10.0.0.2", "label-v4"]),
            ConfigOp::Delete,
        )
        .unwrap();
        assert!(
            !bgp.peers
                .get(&addr)
                .unwrap()
                .next_hop_self(Afi::Ip, Safi::MplsLabel),
            "delete clears the flag",
        );
    }
}

#[cfg(test)]
mod neighbor_description_tests {
    //! `neighbor <addr> description <text>` callback wiring.
    //! `yang_load_tests` validates that the restored leaf loads; this
    //! asserts the callback actually records the note on the peer.
    //! Independent test module with its own mock channels, mirroring
    //! `bfd_wiring_tests`.

    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

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

    fn fresh_bgp() -> Bgp {
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        Box::leak(Box::new(_inbound_rx));
        let ctx = crate::context::ProtoContext::default_table(client);

        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _sub_inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_rib_rx));
        Box::leak(Box::new(_sub_inbound_rx));
        let next_proto_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1));
        let subscriber =
            crate::config::RibSubscriber::for_test(rib_tx, rib_inbound_tx, next_proto_id);

        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_policy_rx));
        Bgp::new(
            ctx,
            rib_rx,
            subscriber,
            policy_tx,
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
        )
    }

    /// `neighbor X description <text>` records the note on the peer;
    /// a re-set overwrites it and `delete` clears it.
    #[tokio::test]
    async fn description_set_overwrite_delete() {
        let mut bgp = fresh_bgp();
        config_peer(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Set).unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(bgp.peers.get(&addr).unwrap().config.description.is_none());

        config_peer_description(
            &mut bgp,
            arg_words(&["10.0.0.2", "core uplink"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(
            bgp.peers.get(&addr).unwrap().config.description.as_deref(),
            Some("core uplink"),
        );

        config_peer_description(
            &mut bgp,
            arg_words(&["10.0.0.2", "lab peer"]),
            ConfigOp::Set,
        )
        .unwrap();
        assert_eq!(
            bgp.peers.get(&addr).unwrap().config.description.as_deref(),
            Some("lab peer"),
            "re-set overwrites",
        );

        config_peer_description(&mut bgp, arg_words(&["10.0.0.2"]), ConfigOp::Delete).unwrap();
        assert!(
            bgp.peers.get(&addr).unwrap().config.description.is_none(),
            "delete clears the note",
        );
    }
}

#[cfg(test)]
mod mup_dual_origination_tests {
    //! VRF-first MUP origination splits into a pure NI→VRF correlation
    //! (`mup_session_targets`) and per-direction NLRI building
    //! (`build_mup_st_route`). `mup_session_targets` fans one PFCP session out
    //! to *every* VRF whose `afi-safi mup route {st1|st2}` binding matches the
    //! session's Network Instance — so a single session under `internet`
    //! targets both the downlink (st1 / N6) and uplink (st2 / N3) VRF —
    //! and `build_mup_st_route` builds the RD-free T1ST / T2ST NLRI.

    use std::collections::BTreeMap;
    use std::str::FromStr;

    use bgp_packet::{MupPrefix, RouteDistinguisher};
    use tokio::sync::mpsc;

    use super::super::inst::Bgp;
    use super::super::route::build_mup_st_route;
    use super::super::vrf::inst::mup_session_targets;
    use super::super::vrf_config::{BgpVrfConfig, MupSrv6Direction, MupSrv6Mobile};

    fn fresh_bgp() -> Bgp {
        let (inbound_tx, _inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        Box::leak(Box::new(_inbound_rx));
        let ctx = crate::context::ProtoContext::default_table(client);

        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _sub_inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_rib_rx));
        Box::leak(Box::new(_sub_inbound_rx));
        let next_proto_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1));
        let subscriber =
            crate::config::RibSubscriber::for_test(rib_tx, rib_inbound_tx, next_proto_id);

        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(_policy_rx));
        Bgp::new(
            ctx,
            rib_rx,
            subscriber,
            policy_tx,
            None,
            None,
            tokio::sync::mpsc::channel(1).0,
        )
    }

    /// A handover Session-Modification re-dispatches `MupOriginate` to every
    /// VRF the session targets, so the direction the modification didn't
    /// touch (the ST2 — the core tunnel stays put while the gNB moves)
    /// reaches `mup_export` rebuilt byte-identical. The export boundary must
    /// drop it — peers used to see a spurious ST2 UPDATE on every handover —
    /// while the genuinely-changed ST1 (moved endpoint/TEID, off the NLRI
    /// key) still falls through and replaces in place.
    #[tokio::test]
    async fn mup_export_drops_identical_reexport() {
        use bgp_packet::{BgpAttr, MupSt1Fields};

        let mut bgp = fresh_bgp();
        let rd: RouteDistinguisher = "65501:2".parse().unwrap();
        bgp.vrfs.insert(
            "N3".to_string(),
            BgpVrfConfig {
                rd: Some(rd),
                ..Default::default()
            },
        );

        let st2 = MupPrefix::T2st {
            endpoint: "10.9.0.1".parse().unwrap(),
            teid: 0x9999,
        };
        let attr = BgpAttr::new();
        assert!(
            bgp.mup_export("N3".into(), st2.clone(), None, attr.clone()),
            "first ST2 export lands"
        );
        assert!(
            !bgp.mup_export("N3".into(), st2.clone(), None, attr.clone()),
            "an identical ST2 re-export (handover re-dispatch) is dropped"
        );

        let ue = MupPrefix::T1st {
            prefix: "192.0.2.5/32".parse().unwrap(),
        };
        let mk = |endpoint: &str, teid| {
            Some(MupSt1Fields {
                teid,
                qfi: 9,
                endpoint: endpoint.parse().unwrap(),
                source: None,
            })
        };
        assert!(bgp.mup_export(
            "N3".into(),
            ue.clone(),
            mk("10.0.0.1", 0x1234),
            attr.clone()
        ));
        assert!(
            !bgp.mup_export(
                "N3".into(),
                ue.clone(),
                mk("10.0.0.1", 0x1234),
                attr.clone()
            ),
            "an unchanged ST1 re-export is dropped too"
        );
        assert!(
            bgp.mup_export(
                "N3".into(),
                ue.clone(),
                mk("10.0.0.9", 0x5678),
                attr.clone()
            ),
            "the handover's moved gNB endpoint/TEID (off-key ST1 fields) falls through"
        );
        // The in-place replace kept a single Originated candidate — the gate
        // must not let duplicate rows accumulate across handovers.
        let cands = bgp.local_rib.mup.get(&rd).unwrap().cands.get(&ue).unwrap();
        assert_eq!(cands.len(), 1, "one Originated candidate after handover");
        assert_eq!(
            cands[0].mup_st1.map(|f| (f.teid, f.endpoint)),
            Some((0x5678, "10.0.0.9".parse().unwrap())),
            "the stored ST1 carries the post-handover tunnel"
        );
    }

    fn mup_vrf(rd: &str, direction: MupSrv6Direction, ni: &str, ext: Option<&str>) -> BgpVrfConfig {
        let mut cfg = BgpVrfConfig {
            rd: Some(RouteDistinguisher::from_str(rd).unwrap()),
            ..BgpVrfConfig::default()
        };
        cfg.mobile_uplane.srv6_mobile = Some(MupSrv6Mobile {
            direction,
            network_instance: Some(ni.to_string()),
            mup_ext_comm: ext.map(|e| RouteDistinguisher::from_str(e).unwrap()),
        });
        cfg
    }

    fn session(ni: &str) -> crate::mup_c::session::MupSession {
        crate::mup_c::session::MupSession {
            seid: 1,
            cp_seid: 0x1111,
            peer: "10.0.0.2:8805".parse().unwrap(),
            ue_ipv4: Some("192.0.2.5".parse().unwrap()),
            ue_ipv6: None,
            teid: 0x1234,
            endpoint: Some("10.0.0.1".parse().unwrap()),
            core_teid: 0,
            core_endpoint: None,
            network_instance: Some(ni.to_string()),
            qfi: Some(9),
        }
    }

    /// One NI bound by both an st1 (N6 / downlink) VRF and an st2 (N3 /
    /// uplink) VRF targets BOTH VRFs from a single session — the dual-ST
    /// fan-out.
    #[test]
    fn one_session_targets_both_st1_and_st2() {
        let mut vrfs = BTreeMap::new();
        vrfs.insert(
            "N6".to_string(),
            mup_vrf("65501:1", MupSrv6Direction::Encapsulation, "internet", None),
        );
        vrfs.insert(
            "N3".to_string(),
            mup_vrf(
                "65501:2",
                MupSrv6Direction::Decapsulation,
                "internet",
                Some("100:1"),
            ),
        );

        let targets = mup_session_targets(&vrfs, &session("internet"));
        assert_eq!(targets.len(), 2, "one session → both st1 and st2 VRFs");
        assert!(
            targets
                .iter()
                .any(|(_, d, _)| matches!(d, MupSrv6Direction::Encapsulation)),
            "downlink st1 (N6) is a target",
        );
        assert!(
            targets
                .iter()
                .any(|(_, d, _)| matches!(d, MupSrv6Direction::Decapsulation)),
            "uplink st2 (N3) is a target",
        );
    }

    /// A session whose NI matches no VRF binding targets nothing.
    #[test]
    fn unmatched_ni_targets_nothing() {
        let mut vrfs = BTreeMap::new();
        vrfs.insert(
            "N3".to_string(),
            mup_vrf("65501:2", MupSrv6Direction::Decapsulation, "internet", None),
        );
        assert!(
            mup_session_targets(&vrfs, &session("ims")).is_empty(),
            "no VRF binds NI `ims`",
        );
    }

    /// st1 (Encapsulation) builds a Type-1 ST NLRI; st2 (Decapsulation)
    /// builds a Type-2 ST NLRI carrying the Direct-segment MUP ext-comm. The
    /// RD / export-RTs / next-hop are applied later at the global export
    /// boundary, so the bare attr here carries only the route-specific ecom.
    #[test]
    fn st1_builds_t1st_st2_builds_t2st_with_ext_comm() {
        // ST1's downlink outer source is the UPF anchor (core-side) endpoint,
        // so a session with a core endpoint carries it as the ST1 source.
        let mut s1 = session("internet");
        s1.core_endpoint = Some("10.9.0.1".parse().unwrap());
        let (p1, st1, attr1) =
            build_mup_st_route(&s1, MupSrv6Direction::Encapsulation, None).unwrap();
        assert!(matches!(p1, MupPrefix::T1st { .. }), "st1 → Type-1 ST");
        assert!(attr1.ecom.is_none(), "st1 carries no ext-comm");
        assert_eq!(
            st1.and_then(|f| f.source),
            Some("10.9.0.1".parse().unwrap()),
            "st1 source is the UPF anchor (core) endpoint for the GTP4.E outer src",
        );
        // No core endpoint ⇒ no anchor source ⇒ the GTP encap can't be built.
        let (_p, st1_nosrc, _a) =
            build_mup_st_route(&session("internet"), MupSrv6Direction::Encapsulation, None)
                .unwrap();
        assert_eq!(
            st1_nosrc.and_then(|f| f.source),
            None,
            "st1 source is absent when the session has no core endpoint",
        );

        // ST2 needs a real core tunnel (endpoint + non-zero TEID); it never
        // borrows the access tunnel.
        let seg = RouteDistinguisher::from_str("100:1").unwrap();
        let mut s2 = session("internet");
        s2.core_endpoint = Some("10.9.0.1".parse().unwrap());
        s2.core_teid = 0x9999;
        let (p2, _st1, attr2) =
            build_mup_st_route(&s2, MupSrv6Direction::Decapsulation, Some(seg)).unwrap();
        assert!(matches!(p2, MupPrefix::T2st { .. }), "st2 → Type-2 ST");
        assert!(
            attr2.ecom.is_some(),
            "st2 carries the Direct-segment MUP ext-comm",
        );
        assert!(
            attr2.nexthop.is_none(),
            "next-hop applied at export, not here"
        );
    }
}
