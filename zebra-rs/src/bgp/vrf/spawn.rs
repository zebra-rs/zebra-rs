//! Spawn / despawn of [`BgpVrf`] tasks driven by the global Bgp's
//! `CommitEnd` diff.
//!
//! The committed intent lives in [`crate::bgp::Bgp::vrfs`] (a
//! `BTreeMap<String, BgpVrfConfig>` populated by the VRF config
//! callbacks). The running task set lives in
//! [`crate::bgp::Bgp::vrf_registry`]. After every commit the
//! diff between the two maps is computed, new VRF names get a
//! fresh [`BgpVrf`] + [`serve_vrf`], deleted names get a
//! [`BgpVrfMsg::Shutdown`].
//!
//! When kernel info isn't yet available the spawn falls back to a
//! placeholder [`ProtoContext::default_table_no_rib`]; once the
//! matching `VrfAdd` arrives the task is respawned with a real
//! [`ProtoContext::for_vrf`] built from a fresh per-VRF `RibClient`
//! subscription that carries the kernel `table_id` through to
//! [`crate::rib::client::ClientRegistry`].

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use tokio::sync::mpsc::UnboundedSender;

use crate::context::{ProtoContext, Task};

use super::super::inst::RibKnownVrf;
use super::super::neighbor_group::NeighborGroup;
use super::super::vrf_config::{BgpVrfConfig, BgpVrfEncapsulation};
use super::inst::{BgpVrf, BgpVrfInbox, serve_vrf};
use super::msg::{BgpGlobalMsg, BgpVrfMsg};
use super::sid::Srv6VrfSid;

use crate::config::RibSubscriber;

/// Per-VRF task handle stashed on [`crate::bgp::Bgp::vrf_registry`].
/// Holds the inbound sender so the global task can dispatch
/// `Shutdown` / `Accept` / import deliveries, plus the spawned
/// [`Task`] so dropping the handle aborts the runtime cleanly.
pub struct BgpVrfHandle {
    pub inbox: BgpVrfInbox,
    /// Clone of the per-VRF task's show channel sender. Registered with
    /// the config manager (`SubscribeShowVrf`) so `show bgp vrf <name>
    /// …` is redirected into this task; deregistered on despawn.
    pub show_tx: tokio::sync::mpsc::UnboundedSender<crate::config::DisplayRequest>,
    /// Held so dropping the handle aborts the spawned event loop
    /// even if `despawn_bgp_vrf` was never called (defence in
    /// depth — a clean teardown sends `Shutdown` first). Not
    /// read directly anywhere; `Task` already runs its
    /// `AbortHandle` via `Drop`.
    #[allow(dead_code)]
    pub task: Task<()>,
    /// MPLS label allocated for this VRF by `Bgp::vrf_label_alloc`
    /// at spawn time. Mirrored back onto the handle so the global
    /// `Bgp` can reclaim it on despawn and reuse it on
    /// respawn-with-kernel-ctx — a respawn must keep the same
    /// label, otherwise a brief outage would invalidate PE-side
    /// FIB entries that already point at this VRF's old label.
    pub label: u32,
    /// VRF master ifindex used in the AF_MPLS DecapVrf ILM, when
    /// the spawn site successfully installed one. `None` when the
    /// spawn ran with no kernel info (placeholder ctx); the next
    /// `maybe_respawn_vrf_with_kernel_ctx` after the kernel VRF
    /// appears installs the ILM.
    pub ilm_decap_ifindex: Option<u32>,
    /// SRv6 End.DT46 service SID `(addr, locator-function)` allocated
    /// for an `encapsulation srv6` VRF. The function is preserved
    /// across kernel-ctx / relabel respawns and freed back to
    /// `Bgp::srv6_sid_pool` at despawn; the addr drives the
    /// `Message::SidDel` withdrawal. `None` for MPLS-mode VRFs and for
    /// srv6 VRFs spawned before their locator resolved.
    pub srv6_sid: Option<(Ipv6Addr, u16)>,
    /// Snapshot of the VRF's RD at spawn. The despawn-time export
    /// purge needs it, and by then the cfg (`Bgp::vrfs[name]`) is
    /// already gone — despawn is exactly the "removed from intent"
    /// case.
    pub rd: Option<bgp_packet::RouteDistinguisher>,
    /// Snapshots of `evpn advertise-ipv4` / `advertise-ipv6` for the
    /// same reason: the despawn purge mirrors each withdrawn export's
    /// EVPN Type-5 withdrawal exactly when the live withdraw would
    /// have.
    pub evpn_advertise_v4: bool,
    pub evpn_advertise_v6: bool,
    /// Policy / prefix-set watches this VRF's peers registered, as
    /// `(name, ident, policy_type)`. Kept on the handle so
    /// [`despawn_bgp_vrf`] can withdraw them synchronously *before* a
    /// respawn re-registers — see [`BgpVrf::policy_watch_list`] for why
    /// doing it from the task's own shutdown path would delete the
    /// incoming incarnation's watches instead of the outgoing one's.
    pub policy_watches: Vec<(String, usize, crate::policy::PolicyType)>,
    /// BFD session keys this VRF's peers subscribed, withdrawn
    /// synchronously by `despawn_bgp_vrf` before a respawn re-subscribes
    /// — same ordering hazard as `policy_watches`.
    pub bfd_sessions: Vec<crate::bfd::session::SessionKey>,
    /// Kept so `despawn_bgp_vrf` can address the BFD unsubscribes.
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// The BFD client id (`bfd-vrf:<name>`) the unsubscribes must use.
    pub bfd_client: String,
    /// Accept-loop tasks for this VRF's own listener sockets (v4/v6).
    /// Held so they abort when the handle is dropped at despawn, closing
    /// the listeners; a respawn opens fresh ones. Empty for a
    /// placeholder-ctx spawn (no VRF-bound socket yet).
    #[allow(dead_code)]
    pub listen_tasks: Vec<Task<()>>,
}

/// Pure diff: which VRF names need to be spawned (in `desired`
/// but not `running`) and which need to be despawned (in
/// `running` but not `desired`). Names that appear in both are
/// considered unchanged — the diff does not yet detect edits to
/// `rd` / `router-id` / `label-mode`; a follow-up will layer edit
/// detection on top by hashing the cfg.
pub fn compute_vrf_diff(
    desired: &BTreeMap<String, BgpVrfConfig>,
    running: &BTreeMap<String, BgpVrfHandle>,
) -> (Vec<String>, Vec<String>) {
    let to_spawn: Vec<String> = desired
        .keys()
        .filter(|name| !running.contains_key(*name))
        .cloned()
        .collect();
    let to_despawn: Vec<String> = running
        .keys()
        .filter(|name| !desired.contains_key(*name))
        .cloned()
        .collect();
    (to_spawn, to_despawn)
}

/// Build + spawn a per-VRF task. Returns the handle the caller
/// stashes on `vrf_registry`. `kernel` carries the matching
/// kernel VRF master info if RIB has already told us about it;
/// when `None`, the spawn falls back to a placeholder
/// `ProtoContext::default_table_no_rib()` and the per-VRF runtime
/// won't bind sockets to a VRF master until the global Bgp task
/// re-spawns via
/// [`super::super::inst::Bgp::maybe_respawn_vrf_with_kernel_ctx`].
///
/// `rib_subscriber` mints the per-VRF [`RibClient`] when kernel
/// info is present — route installs from this task flow through
/// the matching `vrf_tables[table_id]` via the RIB inbound
/// dispatcher. With no kernel info, the spawn uses a parked
/// `RibClient`; routes sent through it land in the global table
/// until the respawn happens.
///
/// `global_tx` is the shared sender every VRF task uses to push
/// back to the global runtime (one channel, fanned in from every
/// VRF).
/// Open this VRF's own passive listener sockets (v4 + v6) on the BGP
/// port and spawn an accept loop per family that hands each connection to
/// the VRF task via [`BgpVrfMsg::Accept`] — the same message the global
/// accept dispatcher forwards, so both feed one `handle_peer_connection`.
///
/// Returns the accept-loop [`Task`]s; the caller stashes them on the
/// handle so they abort (and the listeners close) at despawn. Empty when
/// `ctx` is not VRF-bound: a device-unbound listener on the shared BGP
/// port would join the global listener's REUSEPORT group and steal
/// default-VRF connections, so the listener waits for the kernel-ctx
/// respawn.
fn spawn_vrf_listeners(ctx: &ProtoContext, inbox: &BgpVrfInbox, name: &str) -> Vec<Task<()>> {
    use std::net::SocketAddr;
    if !ctx.is_vrf_bound() {
        return Vec::new();
    }
    let mut tasks = Vec::new();
    let v4: SocketAddr = "0.0.0.0:179".parse().unwrap();
    let v6: SocketAddr = "[::]:179".parse().unwrap();
    for (addr, is_v6) in [(v4, false), (v6, true)] {
        let ctx = ctx.clone();
        let inbox = inbox.clone();
        let name = name.to_string();
        tasks.push(Task::spawn(async move {
            let listener = if is_v6 {
                ctx.tcp_listen_v6_only(addr).await
            } else {
                ctx.tcp_listen(addr).await
            };
            let listener = match listener {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(
                        vrf = %name,
                        %addr,
                        error = %e,
                        "bgp vrf: failed to open per-VRF listener; passive \
                         accept for this family falls back to the global \
                         dispatcher",
                    );
                    return;
                }
            };
            loop {
                match listener.accept().await {
                    Ok((stream, sockaddr)) => {
                        // Unbounded send; the VRF task's inbox never
                        // backpressures. If the task is gone the send
                        // errors and we exit the loop.
                        if inbox.send(BgpVrfMsg::Accept(stream, sockaddr)).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(vrf = %name, error = %e, "bgp vrf: accept error");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }));
    }
    tasks
}

pub fn spawn_bgp_vrf(
    name: String,
    cfg: &BgpVrfConfig,
    groups: &BTreeMap<String, NeighborGroup>,
    router_id: std::net::Ipv4Addr,
    asn: u32,
    label: u32,
    kernel: Option<RibKnownVrf>,
    rib_subscriber: &RibSubscriber,
    srv6: Option<Srv6VrfSid>,
    tracing_cfg: crate::bgp::tracing::BgpTracing,
    global_tx: UnboundedSender<BgpGlobalMsg>,
    policy_tx: UnboundedSender<crate::policy::Message>,
    bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
) -> BgpVrfHandle {
    // Snapshot for logging + ILM install so we can move
    // `kernel` into the ctx-building arm without re-borrowing
    // later.
    let kernel_table_id = kernel.as_ref().map(|k| k.table_id);
    let kernel_ifindex = kernel.as_ref().map(|k| k.ifindex);
    let (ctx, rib_rx) = match kernel {
        Some(k) => {
            // Mint a fresh `RibClient` for this VRF. The
            // subscription's `vrf_id` tells RIB to route the task's
            // route installs into `vrf_tables[table_id]` and (now that
            // the `RibRx` half is consumed) to stream this VRF's
            // redistributed routes back for VPNv4/v6 origination.
            let proto = format!("bgp:vrf:{name}");
            let (rib_client, rib_rx) = rib_subscriber.subscribe_for_vrf(&proto, k.table_id);
            (
                ProtoContext::for_vrf(rib_client, k.table_id, name.clone()),
                rib_rx,
            )
        }
        None => {
            tracing::debug!(
                vrf = %name,
                "bgp: spawning per-VRF task with placeholder context (kernel VRF not yet known)",
            );
            // No subscription without a kernel table; hand the task a
            // closed channel so its redistribute select arm stays inert
            // until `maybe_respawn_vrf_with_kernel_ctx` re-spawns with a
            // live subscription.
            let (_closed_tx, rib_rx) = tokio::sync::mpsc::unbounded_channel();
            (ProtoContext::default_table_no_rib(), rib_rx)
        }
    };
    // Per-VRF override on router-id wins over the global one. An
    // operator edit to router-id post-spawn doesn't bubble through
    // yet — a follow-up adds the respawn-on-edit detection.
    let effective_router_id = cfg.router_id.unwrap_or(router_id);
    let (mut vrf, inbox) = BgpVrf::new(
        name.clone(),
        ctx,
        effective_router_id,
        asn,
        label,
        global_tx,
        rib_rx,
    );
    // Subscribe before `materialize_peers` runs: peers register their
    // policy bindings during materialisation, and a Register sent before
    // the Subscribe would be answered into a channel the actor does not
    // have yet.
    vrf.subscribe_policy(policy_tx);
    vrf.set_bfd_client(bfd_client_tx);
    // Inter-AS Option AB: re-export imported VPNv4 routes (see the field
    // doc on `BgpVrf`). Carried from the staged VRF config.
    vrf.inter_as_hybrid = cfg.inter_as_hybrid;
    // The VRF's RD scopes its per-VRF MUP RIB to its own RD (imported MUP
    // routes are re-keyed under it, not their origin RD). Captured at spawn
    // like router-id; an `rd` edit on a live VRF doesn't re-key the running
    // task yet (a follow-up adds respawn-on-edit, same as router-id).
    vrf.rd = cfg.rd;
    // The MUP forwarding-plane mode (End.DT46 stand-in vs cradle GTP-U).
    // Spawn-time capture like `rd`; a live `dataplane` edit respawns the VRF.
    vrf.dataplane = cfg.mobile_uplane.dataplane;
    // Seed the instance-wide tracing snapshot so the task's gated trace
    // sites are live from its first event. Unlike `rd`/`dataplane` this
    // is *not* a spawn-time capture — `Bgp::broadcast_tracing` refreshes
    // it via `BgpVrfMsg::Tracing` on every edit, no respawn needed.
    vrf.tracing = tracing_cfg;

    // Materialise per-VRF peers from the BgpVrfConfig snapshot.
    // `peer.start()`'s timer events get logged at debug and
    // dropped by `BgpVrf::event_loop` until the per-VRF FSM
    // driver lands. Peers without a `remote_as` are skipped:
    // `Peer::start` gates on `remote_as != 0`, so inserting them
    // would only litter the map with permanently-Idle entries.
    let peer_count = materialize_peers(&mut vrf, cfg, groups);

    // Register each materialised peer with the global accept
    // dispatcher so an inbound `:179` from that IP lands on this
    // VRF task via `BgpVrfMsg::Accept` instead of the global
    // instance.
    for addr in vrf.peers.keys().copied().collect::<Vec<_>>() {
        let _ = vrf.global_tx.send(BgpGlobalMsg::RegisterPeer {
            vrf: name.clone(),
            addr,
        });
    }

    // Self-originated networks from
    // `router bgp vrf X afi-safi ipv4-unicast network <p>` land
    // in `vrf.shard.v4` as `BgpRibType::Originated` and
    // emit a `BgpGlobalMsg::Export` so the global instance
    // promotes them to VPNv4 advertisements toward PE peers.
    let network_count = materialize_self_originated_networks(&mut vrf, cfg)
        + materialize_self_originated_networks_v6(&mut vrf, cfg);

    // Replay staged `afi-safi {ipv4,ipv6} redistribute {connected,
    // static}` by (re)sending RedistAdd to the RIB. The walk's matching
    // routes stream back on `rib_rx` for origination + VPNv4/v6 export
    // once the event loop runs. A placeholder-ctx spawn has no live RIB
    // client, so the sends are dropped harmlessly; the kernel-ctx
    // respawn (which reads the same staged config) replays them.
    let redist_count = materialize_vrf_redistribute(&name, cfg, rib_subscriber);

    // Install the AF_MPLS DecapVrf ILM at the allocated label so a
    // remote PE's VPNv4 packet with this label pops + lands in
    // `vrf_tables[table_id]`. Only when we have kernel info — a
    // placeholder-ctx spawn skips the install; the
    // `maybe_respawn_vrf_with_kernel_ctx` path re-runs with kernel
    // info and installs the ILM then.
    //
    // SRv6-mode VRFs (`encapsulation srv6`) skip the MPLS decap
    // entirely: their per-VRF End.DT46 service SID replaces the
    // label-bound ILM (programmed in a follow-up). Guarding here keeps
    // the kernel MPLS table clean of entries that would never be
    // advertised.
    let ilm_decap_ifindex = match (kernel_table_id, kernel_ifindex) {
        (Some(table_id), Some(vrf_ifindex))
            if label != 0 && cfg.encapsulation == BgpVrfEncapsulation::Mpls =>
        {
            let entry = crate::rib::inst::IlmEntry {
                ilm_type: crate::rib::inst::IlmType::DecapVrf {
                    table_id,
                    vrf_ifindex,
                },
                nexthop: crate::rib::Nexthop::default(),
                ..crate::rib::inst::IlmEntry::new(crate::rib::RibType::Bgp)
            };
            rib_subscriber.send_ilm_add(label, entry);
            Some(vrf_ifindex)
        }
        _ => None,
    };

    // SRv6 egress decap: program the per-VRF End.DT46 service SID into
    // the VRF's kernel table via a seg6local `End.DT46 vrftable`. Like
    // the MPLS ILM this is gated on kernel info (the decap needs the
    // VRF table id); a placeholder-ctx spawn defers to
    // `maybe_respawn_vrf_with_kernel_ctx`, which re-runs with the
    // preserved SID once the kernel VRF appears. The 16-byte SID is the
    // full address (no transposition); `ifindex: 0` lets the RIB
    // resolve a loopback oif, the same as IS-IS End / uN.
    if let (Some(s), Some(table_id)) = (srv6.as_ref(), kernel_table_id) {
        let sid = crate::rib::Sid {
            addr: s.addr,
            behavior: crate::rib::SidBehavior::EndDT46,
            context: crate::rib::SidContext::None,
            owner: crate::rib::SidOwner::new("bgp", 0),
            locator: s.locator.clone(),
            allocation_type: crate::rib::SidAllocationType::Dynamic,
            ifindex: 0,
            nh6: None,
            structure: None,
            table_id,
            segs: Vec::new(),
            flavors: 0,
        };
        rib_subscriber.send_sid_add(sid);
    }
    // Keep the SID `(addr, function)` on the handle whether or not it
    // was installed this spawn — the function must be freed at despawn
    // and the addr withdrawn, and a placeholder spawn re-installs it on
    // respawn.
    let srv6_sid = srv6.as_ref().map(|s| (s.addr, s.function));

    // Capture the show channel before `vrf` is moved into the task, so
    // the global instance can register it with the config manager for
    // `show bgp vrf <name> …` redirection.
    let show_tx = vrf.show.tx.clone();
    // Snapshot before `vrf` moves into the task.
    let policy_watches = vrf.policy_watch_list();
    let bfd_sessions = vrf.bfd_session_list();
    let bfd_client_handle = vrf.bfd_client_tx.clone();
    let bfd_client_id = vrf.bfd_client();

    // Per-VRF passive listener. Only when the ctx is VRF-bound (the
    // kernel-ctx spawn) so the socket carries `SO_BINDTODEVICE`: a
    // device-unbound listener on the BGP port would join the global
    // listener's REUSEPORT group and steal default-VRF connections.
    // A placeholder spawn (no kernel info yet) skips this; the
    // kernel-ctx respawn opens it, like the ILM/SID installs.
    //
    // Behaviour is equivalent to today's global-dispatch detour
    // (`peer_index` → `BgpVrfMsg::Accept`): the CE's inbound now lands on
    // this VRF-bound socket directly (which wins over the global listener
    // for the VRF's interfaces) and feeds the same `handle_peer_connection`
    // path. The detour stays as a fallback for the pre-respawn window.
    let listen_tasks = spawn_vrf_listeners(&vrf.ctx, &inbox, &name);

    let task = serve_vrf(vrf);
    if crate::rib::tracing::task() {
        tracing::info!(
            vrf = %name,
            rd = ?cfg.rd,
            router_id = %effective_router_id,
            table_id = ?kernel_table_id,
            label,
            ilm_installed = ilm_decap_ifindex.is_some(),
            srv6_sid = ?srv6_sid.map(|(addr, _)| addr),
            peers = peer_count,
            networks = network_count,
            redistribute = redist_count,
            "bgp: spawned per-VRF task",
        );
    }
    BgpVrfHandle {
        inbox,
        policy_watches,
        bfd_sessions,
        bfd_client_tx: bfd_client_handle,
        bfd_client: bfd_client_id,
        listen_tasks,
        show_tx,
        task,
        label,
        ilm_decap_ifindex,
        srv6_sid,
        rd: cfg.rd,
        evpn_advertise_v4: cfg.evpn_advertise_v4,
        evpn_advertise_v6: cfg.evpn_advertise_v6,
    }
}

/// Build `Peer` objects from `cfg.neighbors` and insert them into
/// `vrf.peers`. Calls `peer.start()` on each — that arms the
/// idle-hold timer; once it fires the FSM event lands on
/// `vrf.tx`.
fn materialize_peers(
    vrf: &mut BgpVrf,
    cfg: &BgpVrfConfig,
    groups: &BTreeMap<String, NeighborGroup>,
) -> usize {
    use super::super::peer::{Peer, PeerType};
    use super::super::peer_key::PeerKey;
    use bgp_packet::{Afi, AfiSafi, AfiSafis, Safi};

    let mut count = 0usize;
    for (addr, nbr_cfg) in &cfg.neighbors {
        // Resolve the optionally-referenced neighbor-group once. Its
        // attributes act as a fallback layer beneath the neighbor's own —
        // the same precedence the global neighbor uses, except a CE peer's
        // group is resolved here at materialization (and re-resolved on the
        // next respawn) rather than swept live, because the group lives on
        // the global `Bgp` and these peers run in a separate per-VRF task.
        let group = nbr_cfg.peer_group().and_then(|name| groups.get(name));

        // `Peer::start()` gates on `remote_as != 0` already, but
        // skipping the insert entirely keeps the per-VRF peer map
        // free of dormant rows the show path would have to render
        // as "remote-as: unset". When the operator later types
        // the missing leaf the follow-up commit re-runs
        // `materialize_peers` and the peer arrives. The neighbor's own
        // `remote-as` wins; otherwise inherit the group's (so a peer-group
        // that carries `remote-as` makes its members live without a
        // per-neighbor leaf).
        let Some(remote_as) = nbr_cfg
            .remote_as
            .or_else(|| group.and_then(|g| g.remote_as))
        else {
            tracing::debug!(
                vrf = %vrf.name,
                peer = %addr,
                "bgp vrf: skip peer without remote-as",
            );
            continue;
        };
        let mut peer = Peer::new(
            0,
            vrf.asn,
            vrf.router_id,
            remote_as,
            *addr,
            // Per-VRF hostnames aren't a thing today; the global
            // hostname / OS hostname applies to every session.
            None,
            vrf.tx.clone(),
            vrf.ctx.clone(),
        );
        // `Peer::new` defaults `peer_type` to IBGP and, unlike the global
        // `config_remote_as` path, nothing else recomputes it for a VRF
        // peer — so derive it here from the AS comparison. Without this a
        // per-VRF PE-CE *eBGP* session (remote-as != the VRF's AS) is
        // treated as iBGP: its routes are marked internal, carry no
        // AS-path prepend, and (the symptom) are never re-advertised to
        // the iBGP VPNv4 core, so an Inter-AS Option A remote-AS customer
        // prefix never reaches the far PE.
        peer.peer_type = if remote_as == vrf.asn {
            PeerType::IBGP
        } else {
            PeerType::EBGP
        };
        // Adopt the staged config wholesale. `BgpVrfNeighborConfig::config`
        // IS a `PeerConfig`, so every knob the per-VRF schema stages —
        // description, peer-group binding, `timers`, and the per-family
        // `afi-safi` knobs — lands here in one move, and importing another
        // knob from the global neighbor needs no line of its own.
        //
        // Anything the schema doesn't expose keeps its
        // `PeerConfig::default()` value, which is exactly what `Peer::new`
        // had just installed, so this is behaviour-preserving for
        // unconfigured fields.
        //
        // Done before `start()` below so the first idle-hold timer a peer
        // arms already honours a configured `idle-hold-time`; arming from
        // the default and fixing up afterwards would leave the first dial
        // on the wrong cadence.
        //
        // Two things this deliberately does NOT carry:
        //   - MRAI. Advertisement pacing comes from the `AdvInterval`
        //     snapshot on the peer, which per-VRF tasks have no plumbing
        //     for, so a CE session still runs the stock 30s eBGP / 5s iBGP
        //     cadence.
        //   - Policy / prefix-set names. Those need a policy-actor
        //     Register to resolve, and `BgpVrf` holds no `policy_tx`; a
        //     staged name would sit inert. They stay out of the schema
        //     until that plumbing exists.
        peer.config = nbr_cfg.config.clone();

        // Derive the negotiated address-family set for this CE peer.
        // `Peer::new` defaults to IPv4 unicast only, which is wrong for
        // an IPv6 CE peer — so resolve the family set in three layers,
        // lowest precedence first (mirroring `neighbor_group::effective_mp`
        // for the global neighbor, but with an address-derived base):
        //
        //   1. base = the peer's own address family (an IPv6 peer →
        //      IPv6 unicast, an IPv4 peer → IPv4 unicast). Unlike the
        //      global neighbor we deliberately do NOT force IPv4 unicast
        //      on for a v6 peer.
        //   2. the referenced neighbor-group's `afi-safi` opinions
        //      (`enabled true` adds a family, `false` removes it).
        //   3. the per-neighbor explicit `afi-safi <fam> enabled`
        //      statements — "any field set on the neighbor itself wins".
        //
        // The family set is a Multiprotocol capability fixed at OPEN
        // time; peers are (re)materialized before the session
        // establishes, so the resolved set rides the first OPEN with no
        // bounce needed.
        let base = if addr.is_ipv6() {
            AfiSafi::new(Afi::Ip6, Safi::Unicast)
        } else {
            AfiSafi::new(Afi::Ip, Safi::Unicast)
        };
        let mut mp = AfiSafis::new();
        mp.insert(base, true);
        if let Some(g) = group {
            for (fam, entry) in &g.afi_safi {
                if entry.enabled {
                    mp.insert(*fam, true);
                } else {
                    mp.remove(fam);
                }
            }
        }
        for (fam, enabled) in &nbr_cfg.config.mp_explicit {
            if *enabled {
                mp.insert(*fam, true);
            } else {
                mp.remove(fam);
            }
        }
        // `mp` is the *resolved* set, so it is computed here rather than
        // staged; `mp_explicit` (the verbatim statements it was resolved
        // from) already arrived with the config adoption above.
        peer.config.mp = mp;

        // `next-hop-self` is the one imported knob that is not simply
        // stored: like `mp`, the staged value is the *verbatim* statement
        // and the effective value has to be resolved through
        // neighbor-group precedence (explicit wins, else the group's
        // per-family opinion, else off). The global neighbor does this in
        // its config callback against `Bgp::neighbor_groups`; here the
        // same helper runs against the `groups` map this function is
        // already handed, so the precedence rule has one implementation.
        //
        // Resolve over the negotiated families plus any family carrying an
        // explicit statement: a statement for a family that never
        // negotiates is inert, but resolving it costs nothing and keeps
        // the stored state honest if the family is enabled later.
        let nhs_families: std::collections::BTreeSet<AfiSafi> = peer
            .config
            .mp
            .0
            .keys()
            .copied()
            .chain(peer.config.nhs_explicit.keys().copied())
            .collect();
        for fam in nhs_families {
            let value =
                super::super::neighbor_group::resolve_next_hop_self(groups, &peer.config, fam);
            peer.config.sub.entry(fam).or_default().next_hop_self = value;
        }

        // Resolve + apply the inheritable session knobs (passive,
        // ebgp-multihop, ttl-security, …) the same way the global
        // neighbor does, layering the referenced neighbor-group under the
        // peer's own explicit statements. `mp` and next-hop-self are done
        // above (the VRF's base-family rule differs from the global one),
        // so this covers everything else that is a pure peer mutation;
        // auth and BFD knobs land in their own follow-ups.
        super::super::neighbor_group::apply_inherited_session_knobs(groups, &mut peer);

        vrf.peers.insert_with_key(PeerKey::Addr(*addr), peer);

        // Bind the staged policy / prefix-set names and register a watch
        // for each, so the actor resolves them and keeps them current.
        //
        // This MUST run after the insert, for the same reason `start()`
        // does: `peer_policy_ident` encodes `peer.ident`, which
        // `insert_with_key` is what assigns. Registering beforehand would
        // key every peer's watch under ident 0, and the resolution would
        // come back addressed to the first peer in the map — the exact
        // shape of the bug fixed in #2071, but silent, because a
        // mis-delivered policy just filters the wrong session's routes.
        //
        // The names go straight onto the peer's slots; the resolved set
        // arrives later on `policy_rx` (see
        // `BgpVrf::process_policy_msg`). Until it does the binding is
        // deny-all, which is the same fail-closed posture the global
        // neighbor has.
        let ident = {
            let peer = vrf.peers.get_mut(addr).expect("peer was just inserted");
            for ((fam, kind), name) in &nbr_cfg.policy_refs {
                use super::super::policy::InOut;
                use super::super::vrf_config::VrfPolicyRef;
                match kind {
                    VrfPolicyRef::PolicyIn => {
                        peer.policy_list_slot(*fam, InOut::Input).name = Some(name.clone())
                    }
                    VrfPolicyRef::PolicyOut => {
                        peer.policy_list_slot(*fam, InOut::Output).name = Some(name.clone())
                    }
                    VrfPolicyRef::PrefixSetIn => {
                        peer.prefix_set_slot(*fam, InOut::Input).name = Some(name.clone())
                    }
                    VrfPolicyRef::PrefixSetOut => {
                        peer.prefix_set_slot(*fam, InOut::Output).name = Some(name.clone())
                    }
                }
            }
            peer.ident
        };
        // The TCP-AO key-chain name a resolved `ao_config` references, if
        // any — captured here (the peer borrow ends with the `ident`
        // block above) so the Register below can subscribe it. Resolving
        // the actual key material waits for the actor's reply, handled in
        // `BgpVrf::process_policy_msg`.
        let ao_key_chain = vrf
            .peers
            .get(addr)
            .and_then(|p| p.config.transport.ao_config.as_ref())
            .map(|ao| ao.key_chain.clone())
            .filter(|c| !c.is_empty());

        if (!nbr_cfg.policy_refs.is_empty() || ao_key_chain.is_some())
            && let Some(policy_tx) = vrf.policy_tx.clone()
        {
            let proto = vrf.policy_proto();
            for ((fam, kind), name) in &nbr_cfg.policy_refs {
                let _ = policy_tx.send(crate::policy::Message::Register {
                    proto: proto.clone(),
                    name: name.clone(),
                    ident: super::super::config::peer_policy_ident(ident, Some(*fam)),
                    policy_type: kind.policy_type(),
                });
            }
            // TCP-AO key-chain: raw peer ident (matching the global
            // neighbor) + the `KeyChain` policy type. The actor's reply
            // lands on `policy_rx` and populates `resolved_ao_key`.
            if let Some(chain) = &ao_key_chain {
                let _ = policy_tx.send(crate::policy::Message::Register {
                    proto: proto.clone(),
                    name: chain.clone(),
                    ident,
                    policy_type: crate::policy::PolicyType::KeyChain(
                        crate::policy::KeyChainScope::BgpNeighbor,
                    ),
                });
            }
        }

        // `PeerMap::insert_with_key` assigns the stable ident used in every
        // timer/FSM message. Starting before insertion leaves every peer at
        // Peer::new's ident 0, so a second neighbor's Start events are
        // delivered to the first neighbor and the second session never
        // leaves Idle/Active.
        vrf.peers
            .get_mut(addr)
            .expect("peer was just inserted")
            .start();

        // Bring up BFD for this CE if configured. After the ident is
        // assigned (the session key derives from `peer.address`, but the
        // subscription is tracked by ident) and after start(), matching
        // the global neighbor's order. A no-op when `bfd enabled` is
        // unset or no BFD client is wired (placeholder spawn / tests).
        vrf.bfd_reconcile(ident);
        count += 1;
    }
    count
}

/// Insert each prefix from `cfg.ipv4_unicast.networks` into the
/// per-VRF Loc-RIB as a `BgpRibType::Originated` row and emit a
/// `BgpGlobalMsg::Export` so the global instance promotes it to a
/// VPNv4 advertisement.
///
/// Mirrors `Bgp::route_add` (the global-Bgp equivalent for plain
/// IPv4-unicast `network` statements) but bypasses the
/// `route_advertise_to_peers` call — CE peers under this VRF
/// reach the same prefix via the existing best-path → advertise
/// path when an actual CE session establishes; the only emit
/// path we need at spawn time is the cross-task `Export` toward
/// PE peers.
///
/// We *don't* go through `route_ipv4_update` (which would also
/// fire the export hook) because that entry takes a `BgpTop` and
/// treats the new candidate as if it came from a real peer —
/// split-horizon and policy filters would have to be threaded
/// through. The direct-write here is the same shape `Bgp::route_add`
/// uses for the global case.
fn materialize_self_originated_networks(vrf: &mut BgpVrf, cfg: &BgpVrfConfig) -> usize {
    let Some(af) = cfg.ipv4_unicast.as_ref() else {
        return 0;
    };
    // `originate_self_network_v4` is the exact per-prefix work the
    // dynamic `BgpVrfMsg::OriginateNetwork` path runs, so spawn-time
    // and post-spawn origination stay identical. (`cfg` and `vrf`
    // are distinct borrows — the loop reads one, mutates the other.)
    for prefix in &af.networks {
        vrf.originate_self_network_v4(*prefix);
    }
    af.networks.len()
}

/// IPv6 counterpart of [`materialize_self_originated_networks`]: insert each
/// `router bgp vrf X afi-safi ipv6 network <p>` into `vrf.shard.v6` as an
/// `Originated` row and emit `ExportV6` so the global instance promotes it
/// to a VPNv6 advertisement. The next-hop is a placeholder — the global
/// re-advertise rewrites it to next-hop-self (`BgpNexthop::Vpnv6`) in
/// `route_update_ipv6`.
fn materialize_self_originated_networks_v6(vrf: &mut BgpVrf, cfg: &BgpVrfConfig) -> usize {
    let Some(af) = cfg.ipv6_unicast.as_ref() else {
        return 0;
    };
    for prefix in &af.networks {
        vrf.originate_self_network_v6(*prefix);
    }
    af.networks.len()
}

/// Replay `afi-safi {ipv4,ipv6} redistribute {connected,static}` from
/// the staged config by (re)sending RedistAdd to the RIB for each
/// enabled source. Spawn-time twin of the dynamic
/// [`BgpVrfMsg::RedistEnable`] path, so initial-config and post-spawn
/// subscription stay identical. Returns the number of (afi, source)
/// subscriptions replayed.
fn materialize_vrf_redistribute(
    name: &str,
    cfg: &BgpVrfConfig,
    rib_subscriber: &RibSubscriber,
) -> usize {
    // Issue the RedistAdds on the main RIB channel (`rib_tx`) so they
    // stay FIFO-ordered after this spawn's `Subscribe` (and a respawn's
    // `ProtoCleanup`). Going through the per-task `RibClient` (`ctx.rib`,
    // a separate channel) races the `Subscribe` and can lose the filter —
    // see `RibSubscriber::send_redist_add`. The live reconfig path
    // (`BgpVrfMsg::RedistEnable`) keeps using `ctx.rib`: by then the
    // subscriber is long registered, so there is no ordering hazard.
    let proto = format!("bgp:vrf:{name}");
    let mut count = 0;
    if let Some(af) = cfg.ipv4_unicast.as_ref() {
        for source in &af.redistribute {
            rib_subscriber.send_redist_add(
                &proto,
                crate::rib::RedistAfi::Ipv4,
                super::inst::redist_source_rtype(*source),
                Default::default(),
            );
            count += 1;
        }
    }
    if let Some(af) = cfg.ipv6_unicast.as_ref() {
        for source in &af.redistribute {
            rib_subscriber.send_redist_add(
                &proto,
                crate::rib::RedistAfi::Ipv6,
                super::inst::redist_source_rtype(*source),
                Default::default(),
            );
            count += 1;
        }
    }
    count
}

/// Send `Shutdown` to the per-VRF task. Caller drops the handle
/// from `vrf_registry` *after* this returns; dropping the handle
/// without sending `Shutdown` first would leak a final
/// `BgpVrfMsg` send window — the FSM might miss state it needs to
/// flush. The handle's `Task` aborts on drop regardless, so a
/// failure path here doesn't strand the runtime.
pub fn despawn_bgp_vrf(
    name: &str,
    handle: &BgpVrfHandle,
    rib_subscriber: &RibSubscriber,
    policy_tx: &UnboundedSender<crate::policy::Message>,
) {
    // Withdraw this incarnation's policy watches first, on this thread,
    // so they are ordered ahead of the Registers a respawn's
    // `materialize_peers` is about to send on the same channel. The
    // actor matches watches on `(proto, ident, policy_type)`, all of
    // which a respawned VRF reuses, so a later withdraw would take out
    // the new task's watch and its `None` reply would clear the freshly
    // resolved policy. Same ordering argument as the RIB cleanup below.
    let proto = format!("bgp-vrf:{name}");
    for (watch_name, ident, policy_type) in &handle.policy_watches {
        let _ = policy_tx.send(crate::policy::Message::Unregister {
            proto: proto.clone(),
            name: watch_name.clone(),
            ident: *ident,
            policy_type: *policy_type,
        });
    }
    // Withdraw this incarnation's BFD sessions, on this thread, ahead of
    // any Subscribe a respawn's `materialize_peers` sends on the same
    // client channel — the same ordering hazard as the policy watches:
    // BFD matches on `(client, key)`, both of which a respawn reuses.
    if let Some(bfd_client_tx) = &handle.bfd_client_tx {
        for key in &handle.bfd_sessions {
            let _ = bfd_client_tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
                client: handle.bfd_client.clone(),
                key: *key,
            });
        }
    }
    // Drop this VRF's RIB redistribute subscription (client-registry +
    // redist-filter rows) so a respawn under the same `bgp:vrf:<name>`
    // proto doesn't leave a stale subscriber shadowing the live one —
    // `subscriber_for_proto` returns the first match by name. ProtoCleanup
    // for a per-VRF proto only drops these rows (the VRF's routes live in
    // `vrf_tables` and are reclaimed by `VrfDel`), so it's safe to call on
    // both teardown and respawn. Sent before `Shutdown` so it's ordered
    // ahead of any later re-subscribe by the respawn's `spawn_bgp_vrf`.
    rib_subscriber.send_proto_cleanup(&format!("bgp:vrf:{name}"));
    if handle.inbox.send(BgpVrfMsg::Shutdown).is_err() {
        // Receiver already gone — the task exited on its own
        // (e.g. inbox-drop path). Nothing left to do.
        tracing::debug!(
            vrf = %name,
            "bgp: despawn target already exited; cleanup is a no-op",
        );
        return;
    }
    if crate::rib::tracing::task() {
        tracing::info!(vrf = %name, "bgp: sent Shutdown to per-VRF task");
    }
}

#[cfg(test)]
mod tests {
    //! Pure-function tests on [`compute_vrf_diff`]. Spawn /
    //! despawn themselves need a `Bgp` to drive end-to-end, which
    //! BDD scenarios cover; the diff function is the part worth
    //! unit-testing in isolation because it's where the spawn /
    //! despawn decision actually lives.
    use std::net::Ipv4Addr;

    use tokio::sync::mpsc::unbounded_channel;

    use super::*;

    fn handle(name: &str) -> BgpVrfHandle {
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let cfg = BgpVrfConfig::default();
        // Pass `None` for the kernel info — the diff tests don't
        // need the per-VRF `SO_BINDTODEVICE` binding; the
        // placeholder context is enough for lifecycle testing.
        let subscriber = test_rib_subscriber();
        let groups = BTreeMap::new();
        // The policy actor isn't running in these lifecycle tests; the
        // Subscribe just lands in a channel nobody drains.
        let (policy_tx, _policy_rx) = unbounded_channel();
        spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            &groups,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            None,
            &subscriber,
            /* srv6 */ None,
            /* tracing */ Default::default(),
            global_tx,
            policy_tx,
            /* bfd */ None,
        )
    }

    fn test_rib_subscriber() -> RibSubscriber {
        let (rib_tx, rib_rx) = unbounded_channel();
        let (rib_inbound_tx, inbound_rx) = unbounded_channel();
        Box::leak(Box::new(rib_rx));
        Box::leak(Box::new(inbound_rx));
        RibSubscriber::for_test(
            rib_tx,
            rib_inbound_tx,
            std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
        )
    }

    #[tokio::test]
    async fn materialize_peers_inserts_neighbors_with_remote_as() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        // Construct a BgpVrf directly (no spawn) so we can inspect
        // `vrf.peers` after `materialize_peers` runs. Per-VRF FSM
        // events go through `vrf.tx`, which the event loop drains
        // in production — but the loop isn't running in this test,
        // so the timer events `peer.start()` arms stay queued until
        // the rx is dropped at end of scope.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let mut cfg = BgpVrfConfig::default();
        let with_as: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let no_as: std::net::IpAddr = "192.0.2.2".parse().unwrap();
        cfg.neighbors.insert(
            with_as,
            BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            },
        );
        cfg.neighbors.insert(no_as, BgpVrfNeighborConfig::default());

        let count = materialize_peers(&mut vrf, &cfg, &BTreeMap::new());

        // Only the neighbor with `remote-as` set is materialised —
        // `Peer::start()` gates on `remote_as != 0`, and inserting
        // a dormant entry would clutter `show bgp vrf v1 summary`
        // output until the operator filled the leaf in.
        assert_eq!(count, 1);
        let peer = vrf
            .peers
            .get(&with_as)
            .expect("peer with remote-as inserted");
        // remote-as 65001 != the VRF's AS 65000 → eBGP. `Peer::new`
        // defaults to IBGP, so `materialize_peers` must derive this — else
        // a per-VRF PE-CE eBGP session is treated as iBGP and its routes
        // never re-advertise into the VPNv4 core (Inter-AS Option A).
        assert_eq!(
            peer.peer_type,
            crate::bgp::peer::PeerType::EBGP,
            "remote-as != VRF AS must be classified eBGP"
        );
        assert!(
            vrf.peers.get(&no_as).is_none(),
            "neighbor without remote-as skipped"
        );
    }

    /// The transport / session knobs must be resolved through
    /// neighbor-group precedence and applied to the built peer — the
    /// per-VRF equivalent of the global neighbor's live callbacks.
    /// Covers all three precedence arms in one peer plus the
    /// ebgp-multihop↔ttl-security ordering.
    #[tokio::test]
    async fn materialize_peers_applies_session_knobs() {
        use super::super::super::neighbor_group::{InheritableKnobs, NeighborGroup};
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            16,
            global_tx,
            rib_rx,
        );

        // Group turns passive on and sets ebgp-multihop 5.
        let g = NeighborGroup {
            knobs: InheritableKnobs {
                passive: Some(true),
                ebgp_multihop: Some(5),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut groups = BTreeMap::new();
        groups.insert("g1".to_string(), g);

        let inherits: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let overrides: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        let mut cfg = BgpVrfConfig::default();
        // Inherits passive + ebgp-multihop from the group.
        cfg.neighbors.insert(inherits, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n
        });
        // Explicitly overrides ebgp-multihop; also sets ttl-security,
        // which is mutually exclusive — ebgp-multihop is applied first,
        // so the ttl-security guard must refuse and leave multihop win.
        cfg.neighbors.insert(overrides, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            };
            n.config.knobs_explicit.ebgp_multihop = Some(9);
            n.config.knobs_explicit.ttl_security = Some(true);
            n
        });

        materialize_peers(&mut vrf, &cfg, &groups);

        let a = vrf.peers.get(&inherits).expect("peer a");
        assert!(a.is_passive(), "passive must be inherited from the group");
        assert_eq!(
            a.config.transport.ebgp_multihop,
            Some(5),
            "ebgp-multihop must be inherited from the group"
        );

        let b = vrf.peers.get(&overrides).expect("peer b");
        assert_eq!(
            b.config.transport.ebgp_multihop,
            Some(9),
            "explicit ebgp-multihop must beat the group's"
        );
        assert!(
            !b.config.transport.ttl_security,
            "ttl-security must be refused when ebgp-multihop is set (mutual exclusion)"
        );
    }

    /// The TCP-MD5 `password` must resolve (explicit over group) onto
    /// `config.transport.md5_password`, which the shared connect path
    /// reads — that is what authenticates the PE's outbound dial.
    #[tokio::test]
    async fn materialize_peers_resolves_md5_password() {
        use super::super::super::neighbor_group::{InheritableKnobs, NeighborGroup};
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            16,
            global_tx,
            rib_rx,
        );

        // Group carries a password; one peer inherits it, one overrides.
        let g = NeighborGroup {
            knobs: InheritableKnobs {
                password: Some("group-secret".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut groups = BTreeMap::new();
        groups.insert("g1".to_string(), g);

        let inherits: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let overrides: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.insert(inherits, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n
        });
        cfg.neighbors.insert(overrides, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n.config.knobs_explicit.password = Some("peer-secret".to_string());
            n
        });

        materialize_peers(&mut vrf, &cfg, &groups);

        assert_eq!(
            vrf.peers
                .get(&inherits)
                .unwrap()
                .config
                .transport
                .md5_password
                .as_deref(),
            Some("group-secret"),
            "password inherited from the group"
        );
        assert_eq!(
            vrf.peers
                .get(&overrides)
                .unwrap()
                .config
                .transport
                .md5_password
                .as_deref(),
            Some("peer-secret"),
            "explicit password beats the group's"
        );
    }

    /// TCP-AO: a staged key-chain reference must land on
    /// `config.transport.ao_config` at materialize, and a subsequent
    /// `PolicyRx::KeyChain` reply (the policy actor answering the
    /// per-VRF Register) must resolve `resolved_ao_key` — which is what
    /// the connect socket applies.
    #[tokio::test]
    async fn tcp_ao_key_chain_resolves_on_reply() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::bgp::auth::AoConfig;
        use crate::context::ProtoContext;
        use crate::policy::{CryptoAlgorithm, PolicyRx, PolicyType};
        use crate::policy::{Key, KeyChain, KeyChainScope};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            16,
            global_tx,
            rib_rx,
        );

        let addr: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.insert(addr, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            };
            n.config.knobs_explicit.ao_config = Some(AoConfig {
                key_chain: "KC".to_string(),
                include_tcp_options: true,
            });
            n
        });

        materialize_peers(&mut vrf, &cfg, &groups_none());

        // Staged onto config; not resolved yet (no chain snapshot).
        let peer = vrf.peers.get(&addr).unwrap();
        assert_eq!(
            peer.config
                .transport
                .ao_config
                .as_ref()
                .map(|a| &a.key_chain),
            Some(&"KC".to_string()),
        );
        assert!(peer.config.transport.resolved_ao_key.is_none());

        // The actor answers with the chain's key material.
        let ident = vrf.peers.get(&addr).unwrap().ident;
        let mut chain = KeyChain::default();
        chain.keys.insert(
            1,
            Key {
                algo: Some(CryptoAlgorithm::HmacSha256),
                key_material: b"secret-material".to_vec(),
                send_id: Some(10),
                recv_id: Some(20),
                ..Default::default()
            },
        );
        vrf.process_policy_msg(PolicyRx::KeyChain {
            name: "KC".to_string(),
            ident,
            policy_type: PolicyType::KeyChain(KeyChainScope::BgpNeighbor),
            key_chain: Some(chain),
        });

        let resolved = vrf
            .peers
            .get(&addr)
            .unwrap()
            .config
            .transport
            .resolved_ao_key
            .as_ref()
            .expect("resolved_ao_key populated by the KeyChain reply");
        assert_eq!(resolved.send_id, 10);
        assert_eq!(resolved.recv_id, 20);
        assert_eq!(resolved.key_material, b"secret-material");
    }

    fn groups_none() -> BTreeMap<String, super::super::super::neighbor_group::NeighborGroup> {
        BTreeMap::new()
    }

    /// The remaining inheritable knobs (as-override, allowas-in,
    /// remove-private-as, …) must reach the built peer with group
    /// precedence, exercising the structured staging state machines. The
    /// override arm — explicit allowas-in origin beating the group's
    /// count — is the one that would pass trivially if resolution were
    /// skipped.
    #[tokio::test]
    async fn materialize_peers_applies_inherit_knobs() {
        use super::super::super::neighbor_group::{InheritableKnobs, NeighborGroup};
        use super::super::super::peer::{AllowAsIn, RemovePrivateAs};
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            16,
            global_tx,
            rib_rx,
        );

        // Group: as-override on, allowas-in count 4.
        let g = NeighborGroup {
            knobs: InheritableKnobs {
                as_override: Some(true),
                allowas_in: Some(AllowAsIn::Count(4)),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut groups = BTreeMap::new();
        groups.insert("g1".to_string(), g);

        let inherits: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let overrides: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.insert(inherits, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n
        });
        // Overrides allowas-in to origin (beats the group's count) and
        // adds remove-private-as with replace-as via the staging helpers.
        cfg.neighbors.insert(overrides, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n.config.knobs_explicit.stage_allowas_in_origin(true);
            n.config
                .knobs_explicit
                .stage_remove_private_as_replace_as(true);
            n
        });

        materialize_peers(&mut vrf, &cfg, &groups);

        let a = vrf.peers.get(&inherits).expect("peer a");
        assert!(a.config.as_override, "as-override inherited from the group");
        assert_eq!(
            a.config.allowas_in,
            Some(AllowAsIn::Count(4)),
            "allowas-in count inherited from the group"
        );

        let b = vrf.peers.get(&overrides).expect("peer b");
        assert_eq!(
            b.config.allowas_in,
            Some(AllowAsIn::Origin),
            "explicit allowas-in origin must beat the group's count"
        );
        assert_eq!(
            b.config.remove_private_as,
            Some(RemovePrivateAs {
                all: false,
                replace_as: true,
            }),
            "remove-private-as replace-as must be staged and applied"
        );
    }

    /// A CE with `bfd enabled true` must have `materialize_peers` fire a
    /// single-hop BFD Subscribe (multihop false, GTSM min-ttl 255, the
    /// single-hop port); a CE without it must fire nothing. Proves the
    /// reconcile is wired and that the single-hop invariant holds even
    /// though the config path never sets multihop.
    #[tokio::test]
    async fn materialize_peers_brings_up_single_hop_bfd() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::bfd::inst::ClientReq;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            16,
            global_tx,
            rib_rx,
        );
        let (bfd_tx, mut bfd_rx) = unbounded_channel::<ClientReq>();
        vrf.set_bfd_client(Some(bfd_tx));

        let on: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let off: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.insert(on, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            };
            n.config.bfd.enable = Some(true);
            n
        });
        cfg.neighbors.insert(
            off,
            BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            },
        );

        materialize_peers(&mut vrf, &cfg, &BTreeMap::new());

        // Exactly one Subscribe, for the enabled CE, single-hop.
        let mut subscribes = Vec::new();
        while let Ok(req) = bfd_rx.try_recv() {
            if let ClientReq::Subscribe { key, params, .. } = req {
                subscribes.push((key, params));
            }
        }
        assert_eq!(subscribes.len(), 1, "only the bfd-enabled CE subscribes");
        let (key, params) = &subscribes[0];
        assert_eq!(key.remote, on);
        assert!(!key.multihop, "per-VRF BFD must be single-hop");
        assert_eq!(params.min_ttl, 255, "single-hop GTSM min-ttl");
        assert_eq!(params.dst_port, crate::bfd::socket::BFD_SINGLE_HOP_PORT);
    }

    /// `neighbor <addr> timers { … }` must reach the peer that
    /// `materialize_peers` builds — the per-VRF equivalent of the global
    /// neighbor's `timer::config::*` callbacks, which mutate a live peer
    /// directly. Here the staged config is the only carrier: nothing
    /// re-applies it after the peer exists, so if the copy is dropped the
    /// session silently runs the stock cadence and the operator's
    /// `timers` block does nothing at all.
    #[tokio::test]
    async fn materialize_peers_applies_configured_timers() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let mut cfg = BgpVrfConfig::default();
        let tuned: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let bare: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        let mut nbr = BgpVrfNeighborConfig {
            remote_as: Some(65001),
            ..Default::default()
        };
        nbr.config.timer.connect_retry_time = Some(3);
        nbr.config.timer.hold_time = Some(9);
        nbr.config.timer.idle_hold_time = Some(1);
        cfg.neighbors.insert(tuned, nbr);

        cfg.neighbors.insert(
            bare,
            BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            },
        );

        materialize_peers(&mut vrf, &cfg, &BTreeMap::new());

        let peer = vrf.peers.get(&tuned).expect("tuned peer inserted");
        assert_eq!(peer.config.timer.connect_retry_time, Some(3));
        assert_eq!(peer.config.timer.hold_time, Some(9));
        assert_eq!(peer.config.timer.idle_hold_time, Some(1));
        // Read back through the accessors the timer code actually calls,
        // so the test pins the effective value and not just the field.
        assert_eq!(peer.config.timer.connect_retry_time(), 3);
        assert_eq!(peer.config.timer.hold_time(), 9);
        assert_eq!(peer.config.timer.idle_hold_time(), 1);

        // A neighbor with no `timers` block is untouched: all three fall
        // through to the documented defaults (RFC 4271 §10 suggests 120s
        // ConnectRetry; hold-time 180s; idle-hold 5s).
        let peer = vrf.peers.get(&bare).expect("bare peer inserted");
        assert!(peer.config.timer.connect_retry_time.is_none());
        assert_eq!(peer.config.timer.connect_retry_time(), 120);
        assert_eq!(peer.config.timer.hold_time(), 180);
        assert_eq!(peer.config.timer.idle_hold_time(), 5);
    }

    /// Per-AFI knobs imported from the global neighbor must survive the
    /// staging round-trip onto the built peer. This is the payoff of
    /// staging a real `PeerConfig`: `materialize_peers` adopts it
    /// wholesale, so this test covers every knob at once rather than one
    /// assertion per import.
    #[tokio::test]
    async fn materialize_peers_applies_per_afi_knobs() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;
        use bgp_packet::{AddPathSendReceive, AddPathValue, Afi, AfiSafi, Safi};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let v4u = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let tuned: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let bare: std::net::IpAddr = "192.0.2.2".parse().unwrap();

        let mut nbr = BgpVrfNeighborConfig {
            remote_as: Some(65001),
            ..Default::default()
        };
        nbr.config.addpath.insert(
            v4u,
            AddPathValue {
                afi: v4u.afi,
                safi: v4u.safi,
                send_receive: AddPathSendReceive::SendReceive,
            },
        );
        {
            let sub = nbr.config.sub.entry(v4u).or_default();
            sub.graceful_restart = Some(120);
            sub.llgr = Some(300);
            sub.next_hop_unchanged = true;
        }

        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.insert(tuned, nbr);
        cfg.neighbors.insert(
            bare,
            BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            },
        );

        materialize_peers(&mut vrf, &cfg, &BTreeMap::new());

        let peer = vrf.peers.get(&tuned).expect("tuned peer inserted");
        assert_eq!(
            peer.config.addpath.get(&v4u).map(|v| v.send_receive),
            Some(AddPathSendReceive::SendReceive),
            "add-path must ride the staged config onto the peer"
        );
        let sub = peer.config.sub.get(&v4u).expect("per-AFI sub-config");
        assert_eq!(sub.graceful_restart, Some(120));
        assert_eq!(sub.llgr, Some(300));
        assert!(sub.next_hop_unchanged);

        // A neighbor that configured none of them is untouched — the
        // wholesale adoption must not invent per-AFI state.
        let peer = vrf.peers.get(&bare).expect("bare peer inserted");
        assert!(peer.config.addpath.get(&v4u).is_none());
        assert!(
            peer.config.sub.get(&v4u).is_none_or(|s| {
                s.graceful_restart.is_none() && s.llgr.is_none() && !s.next_hop_unchanged
            }),
            "an unconfigured neighbor must keep PeerConfig defaults"
        );
    }

    /// A CE peer's negotiated MP family set is derived from its own
    /// address family (an IPv6 peer → IPv6 unicast, an IPv4 peer → IPv4
    /// unicast) and then layered with explicit `afi-safi <fam> enabled`
    /// overrides. Unlike the global neighbor, IPv4 unicast is NOT forced
    /// on for a v6 peer — so a bare IPv6 CE peer negotiates IPv6 unicast
    /// only (the bug this branch fixes: `Peer::new` defaults to IPv4
    /// unicast, which left a v6 CE session with no usable family).
    #[tokio::test]
    async fn materialize_peers_derives_mp_from_address_and_explicit() {
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;
        use bgp_packet::{Afi, AfiSafi, Safi};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let v4_only: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let v6_only: std::net::IpAddr = "2001:db8::2".parse().unwrap();
        let v6_dual: std::net::IpAddr = "2001:db8::3".parse().unwrap();

        let ipv4u = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let ipv6u = AfiSafi::new(Afi::Ip6, Safi::Unicast);

        let mut cfg = BgpVrfConfig::default();
        // Bare IPv4 peer: IPv4 unicast only.
        cfg.neighbors.insert(
            v4_only,
            BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            },
        );
        // Bare IPv6 peer: IPv6 unicast only (no implicit IPv4 unicast).
        cfg.neighbors.insert(
            v6_only,
            BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            },
        );
        // IPv6 peer with an explicit `afi-safi ipv4 enabled true` override:
        // negotiates both families (v4-over-v6).
        let mut dual = BgpVrfNeighborConfig {
            remote_as: Some(65001),
            ..Default::default()
        };
        dual.config.mp_explicit.insert(ipv4u, true);
        cfg.neighbors.insert(v6_dual, dual);

        materialize_peers(&mut vrf, &cfg, &BTreeMap::new());

        let p4 = vrf.peers.get(&v4_only).expect("v4 peer");
        assert!(p4.config.mp.has(&ipv4u), "v4 peer negotiates IPv4 unicast");
        assert!(
            !p4.config.mp.has(&ipv6u),
            "v4 peer must not negotiate IPv6 unicast"
        );

        let p6 = vrf.peers.get(&v6_only).expect("v6 peer");
        assert!(p6.config.mp.has(&ipv6u), "v6 peer negotiates IPv6 unicast");
        assert!(
            !p6.config.mp.has(&ipv4u),
            "bare v6 peer must NOT force IPv4 unicast on"
        );

        let pd = vrf.peers.get(&v6_dual).expect("dual peer");
        assert!(
            pd.config.mp.has(&ipv6u) && pd.config.mp.has(&ipv4u),
            "explicit afi-safi ipv4 enabled adds v4 over a v6 session"
        );
    }

    /// `next-hop-self` is the only imported knob whose staged value is
    /// the *verbatim* statement rather than the effective one, so it is
    /// the only one where the wholesale config adoption is not the whole
    /// story: `materialize_peers` must additionally resolve
    /// explicit-wins-else-group-else-off, the same precedence the global
    /// neighbor's callback applies. All three arms are pinned here.
    #[tokio::test]
    async fn materialize_peers_resolves_next_hop_self_through_group_precedence() {
        use super::super::super::neighbor_group::{GroupAfiSafi, NeighborGroup};
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;
        use bgp_packet::{Afi, AfiSafi, Safi};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let ipv4u = AfiSafi::new(Afi::Ip, Safi::Unicast);

        // Group turns next-hop-self ON for IPv4 unicast.
        let mut g1 = NeighborGroup::default();
        g1.afi_safi.insert(
            ipv4u,
            GroupAfiSafi {
                enabled: true,
                next_hop_self: Some(true),
            },
        );
        let mut groups = BTreeMap::new();
        groups.insert("g1".to_string(), g1);

        let inherits: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let overrides: std::net::IpAddr = "192.0.2.2".parse().unwrap();
        let bare: std::net::IpAddr = "192.0.2.3".parse().unwrap();

        let mut cfg = BgpVrfConfig::default();

        // 1. No own statement, references the group → inherits `true`.
        cfg.neighbors.insert(inherits, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65001),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n
        });

        // 2. Explicit `false` against the group's `true` → explicit wins.
        //    This is the arm that would silently pass if the resolution
        //    were skipped and the group consulted directly.
        cfg.neighbors.insert(overrides, {
            let mut n = BgpVrfNeighborConfig {
                remote_as: Some(65002),
                ..Default::default()
            };
            n.config.neighbor_group = Some("g1".to_string());
            n.config.nhs_explicit.insert(ipv4u, false);
            n
        });

        // 3. Neither → off.
        cfg.neighbors.insert(
            bare,
            BgpVrfNeighborConfig {
                remote_as: Some(65003),
                ..Default::default()
            },
        );

        materialize_peers(&mut vrf, &cfg, &groups);

        let nhs = |addr: &std::net::IpAddr| -> bool {
            vrf.peers
                .get(addr)
                .expect("peer inserted")
                .config
                .sub
                .get(&ipv4u)
                .map(|s| s.next_hop_self)
                .unwrap_or(false)
        };

        assert!(nhs(&inherits), "group's next-hop-self must be inherited");
        assert!(
            !nhs(&overrides),
            "an explicit `false` must beat the group's `true`"
        );
        assert!(!nhs(&bare), "no statement and no group → off");
    }

    /// A CE neighbor that references a `neighbor-group` inherits the
    /// group's `remote-as` (when its own is unset, so the peer is created
    /// at all) and the group's `afi-safi` opinions (layered above the
    /// address-derived base). A per-neighbor explicit `afi-safi <fam>
    /// enabled` statement still wins over the group — the same precedence
    /// the global neighbor uses.
    #[tokio::test]
    async fn materialize_peers_inherits_remote_as_and_afi_safi_from_group() {
        use super::super::super::neighbor_group::{GroupAfiSafi, NeighborGroup};
        use super::super::super::vrf_config::{BgpVrfConfig, BgpVrfNeighborConfig};
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;
        use bgp_packet::{Afi, AfiSafi, Safi};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v1".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let ipv4u = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let ipv6u = AfiSafi::new(Afi::Ip6, Safi::Unicast);

        // Group "g1": carries remote-as and switches IPv6 unicast on.
        let mut g1 = NeighborGroup {
            remote_as: Some(65010),
            ..Default::default()
        };
        g1.afi_safi.insert(
            ipv6u,
            GroupAfiSafi {
                enabled: true,
                next_hop_self: None,
            },
        );
        let mut groups = BTreeMap::new();
        groups.insert("g1".to_string(), g1);

        // Inheriting peer: no own remote-as, no own afi-safi. v4 address.
        let inherit: std::net::IpAddr = "192.0.2.5".parse().unwrap();
        // Overriding peer: own remote-as wins; explicit `ipv6 enabled false`
        // overrides the group's `ipv6 enabled true`.
        let override_peer: std::net::IpAddr = "192.0.2.6".parse().unwrap();

        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.insert(inherit, {
            let mut n = BgpVrfNeighborConfig::default();
            n.config.neighbor_group = Some("g1".to_string());
            n
        });
        let mut over = BgpVrfNeighborConfig {
            remote_as: Some(65020),
            ..Default::default()
        };
        over.config.neighbor_group = Some("g1".to_string());
        over.config.mp_explicit.insert(ipv6u, false);
        cfg.neighbors.insert(override_peer, over);

        let count = materialize_peers(&mut vrf, &cfg, &groups);
        assert_eq!(count, 2, "both peers materialise (remote-as inherited)");

        let p1 = vrf.peers.get(&inherit).expect("inheriting peer");
        assert_eq!(p1.remote_as, 65010, "remote-as inherited from the group");
        assert!(
            p1.config.mp.has(&ipv4u) && p1.config.mp.has(&ipv6u),
            "address base (v4) + group opinion (v6) both negotiated"
        );

        let p2 = vrf.peers.get(&override_peer).expect("overriding peer");
        assert_eq!(p2.remote_as, 65020, "own remote-as wins over group");
        assert!(
            p2.config.mp.has(&ipv4u) && !p2.config.mp.has(&ipv6u),
            "per-neighbor explicit `ipv6 enabled false` overrides the group"
        );
    }

    #[tokio::test]
    async fn materialize_peers_with_no_neighbors_returns_zero() {
        use super::super::super::vrf_config::BgpVrfConfig;
        use super::super::inst::BgpVrf;
        use crate::context::ProtoContext;

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = ProtoContext::default_table_no_rib();
        let (_rib_tx, rib_rx) = unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "v0".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let cfg = BgpVrfConfig::default();
        assert_eq!(materialize_peers(&mut vrf, &cfg, &BTreeMap::new()), 0);
    }

    #[tokio::test]
    async fn diff_with_no_running_yields_all_as_spawn() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        desired.insert("v2".to_string(), BgpVrfConfig::default());
        let running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert_eq!(to_spawn, vec!["v1".to_string(), "v2".to_string()]);
        assert!(to_despawn.is_empty());
    }

    #[tokio::test]
    async fn diff_with_no_desired_yields_all_as_despawn() {
        let desired: BTreeMap<String, BgpVrfConfig> = BTreeMap::new();
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1"));
        running.insert("v2".to_string(), handle("v2"));

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert!(to_spawn.is_empty());
        assert_eq!(to_despawn, vec!["v1".to_string(), "v2".to_string()]);
    }

    #[tokio::test]
    async fn diff_mixed_returns_only_deltas() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        desired.insert("v3".to_string(), BgpVrfConfig::default()); // new
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1")); // unchanged
        running.insert("v2".to_string(), handle("v2")); // removed

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert_eq!(to_spawn, vec!["v3".to_string()]);
        assert_eq!(to_despawn, vec!["v2".to_string()]);
    }

    #[tokio::test]
    async fn diff_with_matching_sets_is_empty() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1"));

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert!(to_spawn.is_empty());
        assert!(to_despawn.is_empty());
    }
}
