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
        let group = nbr_cfg
            .peer_group
            .as_ref()
            .and_then(|name| groups.get(name));

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
        // Record the group binding so `show bgp vrf` reflects it. The
        // inheritance below is resolved eagerly (the global group sweep
        // doesn't reach per-VRF tasks); a later edit to the group's
        // opinions takes effect when the VRF task next respawns or the
        // session is cleared.
        peer.config.neighbor_group = nbr_cfg.peer_group.clone();

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
        for (fam, enabled) in &nbr_cfg.mp_explicit {
            if *enabled {
                mp.insert(*fam, true);
            } else {
                mp.remove(fam);
            }
        }
        peer.config.mp = mp;
        peer.config.mp_explicit = nbr_cfg.mp_explicit.clone();

        vrf.peers.insert_with_key(PeerKey::Addr(*addr), peer);
        // `PeerMap::insert_with_key` assigns the stable ident used in every
        // timer/FSM message. Starting before insertion leaves every peer at
        // Peer::new's ident 0, so a second neighbor's Start events are
        // delivered to the first neighbor and the second session never
        // leaves Idle/Active.
        vrf.peers
            .get_mut(addr)
            .expect("peer was just inserted")
            .start();
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
pub fn despawn_bgp_vrf(name: &str, handle: &BgpVrfHandle, rib_subscriber: &RibSubscriber) {
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
        dual.mp_explicit.insert(ipv4u, true);
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
        cfg.neighbors.insert(
            inherit,
            BgpVrfNeighborConfig {
                peer_group: Some("g1".to_string()),
                ..Default::default()
            },
        );
        let mut over = BgpVrfNeighborConfig {
            remote_as: Some(65020),
            peer_group: Some("g1".to_string()),
            ..Default::default()
        };
        over.mp_explicit.insert(ipv6u, false);
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
