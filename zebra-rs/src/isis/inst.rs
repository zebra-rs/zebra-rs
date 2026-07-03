use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::net::Ipv4Addr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::isis_event_trace;
use crate::rib::{
    Block, Locator, LocatorBehavior, RibSrRx, Sid, SidAllocationType, SidBehavior, SidContext,
    SidOwner,
};

use crate::config::{DisplayRequest, ShowChannel};
use crate::context::{Task, Timer};
use crate::isis::tracing::IsisTracing;
use crate::isis::{ifsm, lsdb};
use crate::rib::api::RibRx;
use crate::rib::{self, MacAddr};
use crate::spf;
use crate::{
    config::{
        Args, CommandPath, ConfigChannel, ConfigOp, ConfigRequest, RibSubscriber,
        path_from_command, vrf_config_split,
    },
    context::ProtoContext,
};

use super::config::{IsisConfig, MtId};
use super::flood;
use super::graph::{LspMap, ReachMapV4, ReachMapV6};
use super::ifsm::{csnp_timer, has_level};
use super::link::{Afis, IsisLinks, LinkTop};
use super::lsdb::insert_self_originate;
use super::lsp::{
    TlvKey, dis_generate, lsp_emit, lsp_generate, resolve_dis_ifindex, target_block_name,
    target_locator_name,
};
use super::nfsm::nbr_hold_timer_expire;
use super::rib::{
    RetainEntry, SpfIlm, SpfRoute, V4, V6, apply_spf_result, build_spf_input, compute_spf,
    egress_retention_expire, update_self_sid_ilm,
};
use super::srlg::{SrlgGroup, SrlgGroupBuilder};
use super::srmpls::IsisLabelMap;
use super::throttle::Throttle;
use super::{
    Hostname, IfsmEvent, Lsdb, LsdbEvent, NfsmEvent, NfsmState, csnp_send, srm_set_for_all_lsp,
};
use super::{Level, Levels, process_packet};
use crate::spf::label_pool::LabelPool;

pub type Callback = fn(&mut Isis, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Isis, Args, bool) -> std::result::Result<String, std::fmt::Error>;

pub type MsgSender = UnboundedSender<Message>;

/// RFC 5306 §3.1 T1 cadence — retransmit IIH+RR every 3s while
/// restarting. Default per RFC; not currently operator-tunable
/// (a YANG knob can be added if interop bench shows operators
/// want a longer/shorter cycle).
const T1_RETRANSMIT_SECS: u64 = 3;

/// Build the T1 retransmit timer. Pulled out so both the
/// operator-staged (`gr_restart_begin`) and checkpoint-load
/// (`gr_restart_load_checkpoint`) paths arm it identically.
fn arm_t1_timer(tx: &UnboundedSender<Message>) -> crate::context::Timer {
    let tx = tx.clone();
    crate::context::Timer::repeat(T1_RETRANSMIT_SECS, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::GrT1Tick);
        }
    })
}

/// In-progress RFC 5306 restart state. `Some` between
/// `clear isis graceful-restart begin` and either `abort`, the
/// `restarter-enabled` knob flipping off, or the successful
/// exit-restart completion.
#[derive(Debug)]
pub struct RestartingState {
    /// Wall-clock at restart start. Used by the checkpoint
    /// freshness check and T3 to bound how long the restart can
    /// take.
    pub started_at: std::time::SystemTime,
    /// Grace period requested at restart begin (seconds). Carried
    /// in the Restart TLV's `Remaining Time` field so helpers can
    /// seed their T3 from a meaningful value.
    pub grace_period_secs: u32,
    /// One-shot timer that ends the restart phase. Parked here so
    /// its Drop doesn't cancel the wakeup before it fires. Two
    /// concrete uses:
    ///
    /// - **commit-exit**: `gr_restart_commit` arms a
    ///   `Timer::once_ms(DRAIN_MS)` that fires `GrRestartExit` to
    ///   run `std::process::exit(0)` once the IIH+RR drain
    ///   completes.
    /// - **load-checkpoint auto-abort**:
    ///   `gr_restart_load_checkpoint` arms a
    ///   `Timer::once(remaining_secs)` that fires `GrRestartAbort`
    ///   when the grace window expires without the exit-success
    ///   path firing first.
    ///
    /// `None` outside both windows.
    pub abort_timer: Option<crate::context::Timer>,
    /// Exit-success driver. At load time
    /// (`gr_restart_load_checkpoint`) this is populated with the
    /// sys-ids of every adjacency the checkpoint recorded. Each
    /// post-restart NFSM Up transition (`Message::GrNeighborUp`)
    /// removes the matching entry; the set going from non-empty
    /// to empty as a result of that removal triggers
    /// `gr_restart_exit_success`.
    ///
    /// Empty when no checkpoint was loaded (operator-staged
    /// `begin` / `commit` flows) — the GrNeighborUp removal
    /// returns `false` for an entry that wasn't there, so the
    /// success path never fires. Operator restarts always end via
    /// `abort` or `commit`+exit, not the success path.
    pub pending_neighbors: std::collections::BTreeSet<IsisSysId>,
    /// RFC 5306 §3.1 T1 retransmit timer — repeats every 3s while
    /// restarting, fires `Message::GrT1Tick` which kicks
    /// `HelloOriginate` on every link. Speeds up the
    /// helper-acknowledgement loop versus the normal
    /// hello_interval (default 10s). Auto-cancelled when
    /// `RestartingState` drops (Timer Drop). `allow(dead_code)`
    /// because the field is never accessed post-construction — it
    /// exists solely to bind the Timer's lifetime to the restart
    /// window; the wakeup arrives via the channel into `process_msg`,
    /// not via this field.
    #[allow(dead_code)]
    pub t1_timer: Option<crate::context::Timer>,
}

pub struct Isis {
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub ctx: ProtoContext,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: IsisLinks,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub config: IsisConfig,

    /// In-progress RFC 5306 restart, if any. `None` outside a
    /// staged restart. Read by the IIH send path to attach RR=1 to
    /// outbound Hellos, and by the LSP refresh dispatcher to
    /// suppress seq bumps mid-restart (RFC 5306 §3.1 forbids
    /// re-originating at higher seq during restart — would trip
    /// helpers' MaxSeqAdvance recovery).
    pub restarting: Option<RestartingState>,

    /// RFC 5306 §3.1 exit-failure overload: set when `gr_restart_
    /// expire` fired before exit-success completed. While true,
    /// `lsp_generate` builds self-LSPs with `IsisLspTypes.ol_bits =
    /// true`, telling the rest of the IS-IS network that we should
    /// be used only as a transit-of-last-resort. Cleared 30s later
    /// by `Message::ClearOverload` which re-originates without OL.
    pub overloaded: bool,

    /// Parks the `Timer::once(30, …)` armed by `gr_restart_expire`
    /// so its Drop doesn't cancel the wakeup before it fires.
    /// `None` outside the post-expire overload window.
    pub overload_clear_timer: Option<crate::context::Timer>,

    /// Flex-Algorithm (RFC 9350) configuration tree, keyed by the
    /// numeric algorithm identifier (128..=255). Owns its own
    /// pending-cache → commit pipeline mirroring the static-route
    /// config builder in rib/static/config.rs.
    pub flex_algo: super::flex_algo::FlexAlgoConfig,
    /// Affinity (admin-group) name table local to this IS-IS instance,
    /// from /affinity-map. Resolves the per-link `affinity`
    /// leaf-list names into 256-bit Extended Admin Group bit positions
    /// (RFC 7308) at LSP-build time.
    pub affinity_map: super::affinity_map::AffinityMap,
    pub tracing: IsisTracing,
    pub lsdb: Levels<Lsdb>,
    pub lsp_map: Levels<LspMap>,
    pub reach_map: Levels<Afis<ReachMapV4>>,
    pub reach_map_v6: Levels<ReachMapV6>,

    /// MT 2 (IPv6 unicast) IPv6 reach indexed per peer. Populated from
    /// TLV 237 entries with mt=2. Kept separate from reach_map_v6 so
    /// the strict per-topology RIB build can pull MT 2's view
    /// without mixing it with legacy TLV 236 from non-MT peers.
    pub mt2_reach_map_v6: Levels<ReachMapV6>,

    /// Per-peer set of MT IDs the peer advertised in TLV 229. Empty
    /// (or absent key) means the peer is single-topology / legacy.
    /// Used by the per-MT graph builder to filter peers and by
    /// show callbacks to render the MT-aware view.
    pub mt_membership: Levels<BTreeMap<IsisSysId, BTreeSet<MtId>>>,
    pub label_map: Levels<IsisLabelMap>,

    /// Peer SRv6 End SID per system id. Populated from the IsisTlvSrv6
    /// sub-TLV `IsisSubSrv6EndSid` carried inside each peer's LSP
    /// (parallel to label_map for SR-MPLS). Used by TI-LFA to
    /// assemble the SRH segment list for a 1-segment repair.
    pub srv6_end_map: Levels<BTreeMap<IsisSysId, super::srv6::Srv6EndSidInfo>>,

    /// Per-peer Flex-Algorithm Definition store. Outer key is peer
    /// sys-id; inner key is the algo identifier (128..=255). Populated
    /// from peer LSP fragment 0 Router Capability TLV by
    /// `lsdb::rebuild_sys_state`. Consumers (future SPF gating,
    /// `show isis flex-algo`) read from here instead of re-walking
    /// the LSDB. Cleared on peer purge.
    pub peer_fad: Levels<BTreeMap<IsisSysId, BTreeMap<u8, isis_packet::IsisSubFlexAlgoDef>>>,

    /// Per-peer per-link affinity bitmaps. Outer key is peer sys-id;
    /// inner key is the IS-reach neighbor identifier (a 7-byte tuple
    /// of 6-byte sys-id and 1-byte circuit/pseudo id). Populated
    /// from IsisSubAsla sub-TLVs on Ext IS-Reach (TLV 22) and MT
    /// IS-Reach (TLV 222) entries whose SABM byte 0 has the
    /// Flex-Algorithm X-bit set (RFC 9479 §4.2). Cleared on peer
    /// purge.
    pub peer_link_affinity: Levels<
        BTreeMap<IsisSysId, BTreeMap<isis_packet::IsisNeighborId, isis_packet::ExtAdminGroup>>,
    >,

    /// Per-peer per-algorithm Prefix-SIDs. Outer key is peer sys-id;
    /// inner key is `(algo, prefix)` so SPF can pick the SID for a
    /// resolved (algo, destination prefix) pair in one lookup.
    /// Populated from Ext IP-Reach (TLV 135) sub-TLVs whose Algorithm
    /// field is in 128..=255 (RFC 9350 §7). Cleared on peer purge.
    pub peer_algo_sid:
        Levels<BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), isis_packet::SidLabelValue>>>,

    /// Per-peer set of SR algorithms the peer participates in. Outer
    /// key is peer sys-id; inner set contains the algo identifiers
    /// the peer listed in its SR-Algorithms sub-TLV (RFC 8667 §3.2,
    /// sub-TLV 19) — algo 0 (SPF), algo 1 (Strict SPF), and any
    /// Flex-Algo identifiers in 128..=255. Populated from peer LSP
    /// fragment 0 Router Capability TLV by `lsdb::rebuild_sys_state`.
    /// Per-algo SPF must drop peers whose `peer_algos[sys_id]` does
    /// not contain the algo being computed (RFC 9350 §5.2
    /// participation requirement). Cleared on peer purge.
    pub peer_algos: Levels<BTreeMap<IsisSysId, BTreeSet<u8>>>,

    /// Per-peer per-Flexible-Algorithm SRv6 locators. Outer key is peer
    /// sys-id; inner key is the algorithm (128..=255). Populated from
    /// SRv6 Locator TLV 27 sub-locators whose Algorithm field is a
    /// Flex-Algo id (RFC 9352 §7.1). Each value is the per-algo locator
    /// prefix plus its node End SID; the per-algo IPv6 RIB build routes
    /// the prefix over the algo-N constrained topology. Cleared on peer
    /// purge.
    pub peer_algo_srv6: Levels<BTreeMap<IsisSysId, BTreeMap<u8, super::srv6::Srv6AlgoLoc>>>,
    pub rib: Levels<PrefixMap<Ipv4Net, SpfRoute<V4>>>,
    pub rib_v6: Levels<PrefixMap<Ipv6Net, SpfRoute<V6>>>,
    /// Mirror SID node-protection stale-route retention: protected egress
    /// locators currently kept alive in the FIB (mapped to the Mirror SID
    /// they redirect to) after the protected egress's LSP aged out, so a
    /// node-down failover survives SPF reconvergence. Keyed per level;
    /// reconciled each SPF and withdrawn when the egress returns.
    pub retained_locators: Levels<BTreeMap<Ipv6Net, RetainEntry>>,
    /// Last set of received Mirror SID egress-protection registrations
    /// pushed to the RIB, keyed by protected locator → `(mirror_sid,
    /// protector)`. Carries the protector so `register_egress_protections`
    /// can tell a genuine withdrawal (protector's LSP present but no longer
    /// advertising) from a convergence-transient empty scan (protector's
    /// LSP absent — keep, PIC-like).
    pub egress_protect_registered: BTreeMap<Ipv6Net, (std::net::Ipv6Addr, IsisSysId)>,
    pub ilm: Levels<BTreeMap<u32, SpfIlm>>,
    /// Currently-installed local (self-originated) Prefix-SID ILM
    /// entries, keyed by MPLS label. Level-independent (the label is
    /// derived from interface config + the global SR block, not per-
    /// level SPF), so this is a single map rather than `Levels<_>`.
    /// `rib::update_self_sid_ilm` diffs the desired set against this
    /// after each SPF publish and reconciles the kernel LFIB.
    pub self_sid_ilm: BTreeMap<u32, SpfIlm>,
    pub hostname: Levels<Hostname>,
    pub spf_timer: Levels<Option<Timer>>,
    pub spf_throttle: Levels<Throttle>,
    /// True while a `tokio::task::spawn_blocking` SPF run is in flight
    /// for the level. Subsequent `Message::SpfCalc(level)` arrivals
    /// during this window are coalesced via `spf_pending` rather than
    /// dispatched concurrently. Cleared in the `SpfDone` handler.
    pub spf_inflight: Levels<bool>,
    /// Latch set when a `Message::SpfCalc(level)` arrives while
    /// `spf_inflight[level]` is true. The completion path (`SpfDone`)
    /// drains it with `mem::take`; if it was set, it re-fires exactly
    /// one follow-up `Message::SpfCalc(level)` so coalesced LSDB
    /// changes during the run still get observed.
    pub spf_pending: Levels<bool>,
    /// Wall-clock time the most recent `compute_spf` for `level` spent
    /// running Dijkstra + TI-LFA, written by `apply_spf_result` from
    /// `SpfOutput::duration`. None until the first SPF completes for
    /// the level. Surfaced by `show isis spf`.
    pub spf_duration: Levels<Option<std::time::Duration>>,
    /// `Instant` at which the most recent `compute_spf` for `level`
    /// finished, written by `apply_spf_result` from `SpfOutput::last`.
    /// None until the first SPF completes for the level. Surfaced by
    /// `show isis spf` as "Last SPF: N s ago".
    pub spf_last: Levels<Option<std::time::Instant>>,
    /// TI-LFA compute telemetry for the most recent SPF run (legacy +
    /// MT2 merged), written by `apply_spf_result` from
    /// `SpfOutput::tilfa_stats`. None until TI-LFA runs (and cleared
    /// when it is disabled). Surfaced by `show isis spf`.
    pub tilfa_stats: Levels<Option<spf::TilfaStats>>,
    /// LSP-gen coalescing slot. None means no run is currently pending;
    /// Some(Timer) means a LspGenFire is armed and additional
    /// LspOriginate events will fold into the same run.
    pub lsp_gen_timer: Levels<Option<Timer>>,
    pub lsp_gen_throttle: Levels<Throttle>,
    /// Accumulated seq-number floor across coalesced LspOriginate
    /// events. Reset to None after the throttled run consumes it.
    pub lsp_gen_pending_floor: Levels<Option<u32>>,
    pub local_pool: Option<LabelPool>,
    pub graph: Levels<Option<spf::Graph>>,
    pub spf_result: Levels<Option<BTreeMap<usize, spf::Path>>>,
    pub tilfa_result: Levels<Option<BTreeMap<usize, Vec<spf::RepairPath>>>>,

    /// MT 2 (IPv6 unicast) graph and SPF result. Computed alongside
    /// the legacy graph when `mt_enabled` and MT 2 is in
    /// `mt_topologies`. Drives the v6 RIB build in that case.
    pub mt2_graph: Levels<Option<spf::Graph>>,
    pub mt2_spf_result: Levels<Option<BTreeMap<usize, spf::Path>>>,

    /// Per-algorithm SPF graphs (RFC 9350). Outer key is the algo id
    /// from `flex_algo.config` (128..=255); inner Option mirrors the
    /// legacy `graph` shape — None means SPF could not run this cycle
    /// (e.g. we have no source LSP yet). Recomputed every SPF cycle
    /// by `build_spf_input` / `apply_spf_result`; stale algos no longer in
    /// `flex_algo.config` are purged before each refill so the
    /// snapshot stays consistent with current config.
    pub graph_flex_algo: Levels<BTreeMap<u8, Option<spf::Graph>>>,
    pub spf_flex_algo: Levels<BTreeMap<u8, Option<BTreeMap<usize, spf::Path>>>>,

    /// Per-algorithm IPv4 RIB. Outer key is algo id; inner map is the
    /// prefix → SpfRoute table built from `spf_flex_algo` plus the
    /// per-algo Prefix-SIDs in `peer_algo_sid`. Held in-memory for
    /// show commands and for the MPLS LFIB build pass — per-algo
    /// IPv4 routes do **not** flow to the kernel today because the
    /// global IPv4 table has no algorithm dimension. The MPLS LFIB
    /// entries derived from these routes do install (labels are
    /// globally unique, so they merge into the same `Isis::ilm` map
    /// alongside the algo-0 entries).
    pub rib_flex_algo: Levels<BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>>,

    /// Per-algorithm IPv6 RIB (SRv6 dataplane). Outer key is the
    /// algorithm (128..=255); each value routes that algo's per-node
    /// SRv6 locator prefixes over the algo-N constrained topology. Held
    /// in-memory for `show isis ipv6 route algorithm N`; the routes are
    /// also installed into the kernel FIB as plain IPv6 routes.
    pub rib6_flex_algo: Levels<BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>>,

    /// Per-algorithm SRv6 colour-steering export, the prior snapshot
    /// against which each SPF cycle diffs `Message::FlexAlgoSrv6Route
    /// Add/Del` to RIB (→ BGP colour-aware resolver). Outer key is the
    /// algorithm; inner map is (destination prefix reachable in algo-N →
    /// the advertising node's algo-N End SID). Held only to compute the
    /// diff; the live state lives in BGP's `flex_algo_srv6_routes`.
    pub flex_algo_srv6_export: Levels<BTreeMap<u8, BTreeMap<ipnet::IpNet, std::net::Ipv6Addr>>>,

    /// SR-update return channel from the RIB. Carries the current value of
    /// the watched block / locator and any subsequent updates.
    pub sr_rx: UnboundedReceiver<RibSrRx>,

    /// Currently-watched block name on the RIB side. Used by the
    /// reconcile helper to compute Watch / Unwatch transitions when
    /// `sr_mpls_enabled` toggles.
    pub watched_block: Option<String>,
    pub watched_locator: Option<String>,

    /// Latest applied snapshot received from the RIB for the watched
    /// names. None means the watched name doesn't exist (or no watch).
    pub sr_block: Option<Block>,
    pub sr_locator: Option<Locator>,

    /// End (Node) SID currently registered with the RIB SID registry.
    /// Tracked separately from the locator so we can issue a SidDel for
    /// the previous address before allocating a new one when the
    /// locator's prefix changes underneath us.
    pub sr_end_sid: Option<std::net::Ipv6Addr>,

    /// End.M (Mirror SID) addresses currently registered with the RIB
    /// SID registry for egress protection. Tracked so `update_mirror_sids`
    /// can SidDel the previous set before re-adding the entries that still
    /// qualify (the protected-locator config or the local locator may have
    /// changed underneath us).
    pub installed_mirror_sids: std::collections::BTreeSet<std::net::Ipv6Addr>,

    /// Protected-locator prefixes for which a mirror-context route is
    /// currently installed (the static `via-vrf` path). Tracked so
    /// `update_mirror_context_routes` can withdraw the previous set before
    /// re-adding the entries that still qualify.
    pub installed_mirror_routes: std::collections::BTreeSet<ipnet::Ipv6Net>,

    /// SR-MPLS Mirror Context labels currently allocated for egress
    /// protection, keyed by protected-locator. Each `dataplane: mpls`
    /// entry gets one **context label** (RFC 8679), allocated from the
    /// SRLB `local_pool` and advertised in a SID/Label Binding TLV (149)
    /// with the M-flag. Held so the label is stable across LSP
    /// regenerations and released back to the pool when the entry is
    /// removed.
    pub mirror_labels: std::collections::BTreeMap<ipnet::IpNet, u32>,

    /// Context labels for which a Mirror Context ILM decap is currently
    /// installed in the kernel LFIB (the `via-vrf` MPLS path). Tracked so
    /// `update_mirror_context_labels` can withdraw the previous set before
    /// re-adding the entries that still qualify — the MPLS analog of
    /// `installed_mirror_routes`.
    pub installed_mirror_ilm: std::collections::BTreeSet<u32>,

    /// ELIB function pool used for End.X (adjacency) SID allocation.
    /// Reset whenever the watched locator changes so stale function
    /// reservations don't leak across prefix swaps.
    pub elib: super::srv6::ElibPool,

    /// Per-Flexible-Algorithm SRv6 locator subscriptions. Mirrors the
    /// single-locator `watched_locator` / `sr_locator` / `sr_end_sid`
    /// trio but keyed by algorithm (128..=255). Populated from
    /// `IsisConfig::sr_srv6_flex_algo_locators` via
    /// `reconcile_locator_watch`; the resolved snapshot and node (End)
    /// SID arrive on the same `sr_rx` channel as the base locator and
    /// land here in `process_sr_rx`. Each algorithm advertises its own
    /// locator (RFC 9352 §7.1, Algorithm field = N) so reaching a node
    /// "in algo N" is plain longest-prefix IPv6 to its algo-N locator.
    pub watched_flex_algo_locators: BTreeMap<u8, String>,
    pub sr_flex_algo_locators: BTreeMap<u8, Locator>,
    pub sr_flex_algo_end_sid: BTreeMap<u8, std::net::Ipv6Addr>,

    /// Per-fragment seq-number-wrap wait. Keyed by fragment id
    /// (LSPID byte 7). Armed when a fragment's next emission would
    /// hit seq == 0xFFFFFFFF: we push a purge (RemainingLifetime = 0)
    /// for that specific fragment and freeze its re-emission until
    /// the timer fires, then re-originate with seq = 1.
    ///
    /// Wait length = `config.hold_time() + 60s` — long enough that
    /// any peer's surviving copy of our old fragment has fully aged
    /// out so they accept the seq = 1 origination as newer.
    ///
    /// Fragment 0's freeze blocks the entire LSP set from emitting,
    /// since receivers treat a router without fragment 0 as missing
    /// its node-wide attributes (hostname, capability, OL bit) and
    /// drop it from SPF. Higher fragments' freezes only suppress
    /// that specific fragment's re-emission; the rest of the set
    /// continues to refresh normally.
    ///
    /// See ISO 10589 §7.3.16.4.
    pub lsp_seq_wrap_wait: Levels<BTreeMap<u8, Timer>>,

    /// Memoised TLV-to-fragment placement for the router's self-LSP
    /// set, keyed by stable per-TLV identity (e.g. TLV 22 keyed by
    /// neighbor id). The packer consults this before greedy bin-
    /// packing so a previously-placed TLV ends up in the same
    /// fragment it lived in last origination, as long as it still
    /// fits. Without this, adding or removing one TLV can cascade-
    /// shift every TLV after it across fragment boundaries, causing
    /// every fragment's seq + checksum to churn and the whole set
    /// to re-flood.
    ///
    /// The memory is rebuilt from scratch after every successful
    /// origination — only TLVs in the emitted fragments get
    /// recorded, so stale entries (TLVs that disappeared from the
    /// origination) naturally fall out.
    ///
    /// Only the router LSP path stabilises today. Pseudonode LSPs
    /// (`dis_generate`) use the greedy packer directly; their
    /// neighbor list is comparatively static so reshuffle pressure
    /// is low.
    pub lsp_placement_memory: Levels<BTreeMap<TlvKey, u8>>,

    /// Redistribute snapshot — routes the RIB delivered via
    /// `RouteAdd`/`RouteDel` for our `RedistAdd` subscriptions.
    /// Keyed by `(RibType, prefix)` so different source protocols
    /// advertising the same prefix stay distinct (each row carries
    /// its own policy / metric override at LSP-emit time).
    /// Populated by `process_rib_msg`; consumed by the LSP emitter
    /// in a follow-up.
    pub redist_v4: BTreeMap<(crate::rib::RibType, Ipv4Net), crate::rib::RouteEntryV4>,
    pub redist_v6: BTreeMap<(crate::rib::RibType, Ipv6Net), crate::rib::RouteEntryV6>,

    /// In-flight `/srlg/group/*` config staged by libyang
    /// callbacks and folded into `srlg_groups` on `ConfigOp::CommitEnd`.
    pub srlg_config: SrlgGroupBuilder,

    /// Applied SRLG group table. Keyed by group name (matches the
    /// per-link `srlg_groups` entries in `LinkConfig`); the value
    /// carries the 32-bit on-wire SRLG identifier that `lsp_generate`
    /// emits into sub-TLV 138 (RFC 5307).
    pub srlg_groups: BTreeMap<String, SrlgGroup>,

    /// Handle into the BFD instance's client-request channel — used
    /// by [`Self::process_bfd_subscribe`] / [`Self::process_bfd_unsubscribe`]
    /// when an adjacency on a `bfd { enable true }` interface
    /// reaches Up (or backslides). `None` means BFD has not (yet)
    /// been configured. Captured at spawn time from
    /// `ConfigManager::bfd_client_tx`; not refreshed if BFD respawns
    /// later (late-binding refresh is a follow-up).
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// BGP task inbox, for pushing BGP Link-State (RFC 9552) producer
    /// routes. `None` when no BGP task exists (BGP not configured, or
    /// configured in a later commit than `router isis`).
    pub bgp_tx: Option<mpsc::Sender<crate::bgp::inst::Message>>,
    /// BGP-LS objects last advertised to BGP, so the producer emits only
    /// deltas (add/withdraw) on each SPF trigger rather than the full set
    /// (RFC 9552 §5.2 — withdraw-old-on-change).
    pub bgp_ls_advertised: std::collections::BTreeMap<bgp_packet::BgpLsNlri, bgp_packet::BgpLsAttr>,
    /// Sender half of the per-instance `BfdEvent` channel, cloned and
    /// handed to BFD as the `notifier` on every `Subscribe`.
    pub bfd_event_tx: UnboundedSender<crate::bfd::inst::BfdEvent>,
    /// Receive half drained by the IS-IS event loop in
    /// [`Self::event_loop`]. Events are logged and drive adjacency
    /// teardown on `BfdEvent::Down`.
    pub bfd_event_rx: UnboundedReceiver<crate::bfd::inst::BfdEvent>,
    /// Handle into the STAMP instance's client-request channel — used
    /// by [`Self::stamp_reconcile_link`] to (un)subscribe measurement
    /// sessions for `te-metric measurement` interfaces. Same capture
    /// contract as `bfd_client_tx`; `None` for per-VRF children
    /// (sessions are default-VRF only in Phase 1).
    pub stamp_client_tx: Option<UnboundedSender<crate::stamp::client::ClientReq>>,
    /// Sender half of the per-instance `StampEvent` channel, handed to
    /// STAMP as the `notifier` on every `Subscribe`.
    pub stamp_event_tx: UnboundedSender<crate::stamp::client::StampEvent>,
    /// Receive half drained by the event loop; `MetricUpdate`s land in
    /// [`Self::process_stamp_event`], which stores the measured
    /// te-metric on the link and re-originates.
    pub stamp_event_rx: UnboundedReceiver<crate::stamp::client::StampEvent>,
    /// Snapshot of `/key-chains/key-chain <name>` entries the policy
    /// actor has pushed to this IS-IS instance via
    /// `PolicyRx::KeyChain`. The canonical map lives in
    /// `policy::Policy`; the area-password / domain-password /
    /// per-link `hello-authentication` scopes resolve their
    /// `key-chain <name>` leaf against this snapshot at sign /
    /// verify time. Inline cleartext `password` continues to win
    /// when set — chains are the alternative for HMAC keys we
    /// don't want sitting in the running-config.
    pub key_chains: BTreeMap<String, crate::policy::KeyChain>,
    /// Send half of the policy channel. Stashed so per-scope
    /// `key-chain` config callbacks can fire Register / Unregister
    /// without threading it through every layer.
    pub policy_tx: UnboundedSender<crate::policy::Message>,
    /// Receive half of the policy channel. Drained by the IS-IS
    /// event loop and forwarded to `process_policy_msg`, which
    /// updates `key_chains` and re-originates LSPs at the affected
    /// level for area/domain-password scope changes.
    pub policy_rx: UnboundedReceiver<crate::policy::PolicyRx>,

    /// Protocol identity used for name-keyed RIB / policy / SR
    /// registrations. `"isis"` for the default instance,
    /// `"isis:vrf:<name>"` for a per-VRF instance — so the two never
    /// clobber each other's rows in the (name-keyed) policy / SR /
    /// redistribute registries. Route-install attribution is by the
    /// numeric `ProtoId` carried in `ctx.rib`, so it is unaffected.
    pub proto_label: String,
    /// Send-capable RIB-subscription factory. The default instance
    /// uses it to mint a per-VRF `RibClient` bound to the VRF's kernel
    /// `table_id` when spawning a child; cloned into each child too.
    pub rib_subscriber: RibSubscriber,
    /// Sender into the config manager, for (de)registering a child's
    /// `show isis vrf <name>` channel via `SubscribeShowVrf` /
    /// `UnsubscribeShowVrf`. Bounded — send with `try_send`.
    pub config_tx: mpsc::Sender<crate::config::Message>,
    /// Per-VRF buffered config (parent only). Each `router isis vrf
    /// <name> ...` line, rewritten to strip the `vrf <name>` prefix,
    /// is appended in commit order; replayed into a child at spawn
    /// time and kept so a `VrfDel`→`VrfAdd` flap respawns from intent.
    /// Empty for child instances.
    pub vrf_log: BTreeMap<String, Vec<(Vec<CommandPath>, ConfigOp)>>,
    /// Running per-VRF child tasks (parent only), keyed by VRF name.
    pub vrf_registry: BTreeMap<String, super::vrf::IsisVrfHandle>,
    /// Kernel VRF master info from `RibRx::VrfAdd` (parent only):
    /// VRF name → (table_id, ifindex). A child spawns once both
    /// config intent (`vrf_log`) and kernel info exist.
    pub rib_known_vrfs: BTreeMap<String, (u32, u32)>,
}

pub struct IsisTop<'a> {
    pub tx: &'a UnboundedSender<Message>,
    pub links: &'a mut IsisLinks,
    pub config: &'a IsisConfig,
    /// Snapshot of `Isis.overloaded`. Consumed by `lsp.rs::lsp_generate`
    /// (and the pseudonode origination path) to set
    /// `IsisLspTypes.ol_bits` on the freshly-built self-LSPs.
    pub overloaded: bool,
    pub tracing: &'a IsisTracing,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub lsp_map: &'a mut Levels<LspMap>,
    pub reach_map: &'a mut Levels<Afis<ReachMapV4>>,
    pub reach_map_v6: &'a mut Levels<ReachMapV6>,
    pub mt2_reach_map_v6: &'a mut Levels<ReachMapV6>,
    pub mt_membership: &'a mut Levels<BTreeMap<IsisSysId, BTreeSet<MtId>>>,
    pub label_map: &'a mut Levels<IsisLabelMap>,
    pub srv6_end_map: &'a mut Levels<BTreeMap<IsisSysId, super::srv6::Srv6EndSidInfo>>,
    /// Per-peer FAD store (see `Isis::peer_fad`). Threaded through
    /// IsisTop so the LSDB rebuild path can populate it from peer
    /// Router Capability TLVs.
    pub peer_fad:
        &'a mut Levels<BTreeMap<IsisSysId, BTreeMap<u8, isis_packet::IsisSubFlexAlgoDef>>>,

    /// Per-peer per-link affinity bitmaps (see
    /// `Isis::peer_link_affinity`). Threaded through IsisTop so the
    /// LSDB rebuild path can populate it from peer IS-reach ASLA
    /// sub-TLVs.
    pub peer_link_affinity: &'a mut Levels<
        BTreeMap<IsisSysId, BTreeMap<isis_packet::IsisNeighborId, isis_packet::ExtAdminGroup>>,
    >,

    /// Per-peer per-algorithm Prefix-SIDs (see `Isis::peer_algo_sid`).
    /// Threaded through IsisTop so the LSDB rebuild path can populate
    /// it from peer Ext IP-Reach TLVs.
    pub peer_algo_sid:
        &'a mut Levels<BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), isis_packet::SidLabelValue>>>,

    /// Per-peer SR algorithm participation sets (see
    /// `Isis::peer_algos`). Threaded through IsisTop so the LSDB
    /// rebuild path can populate it from peer Router Capability
    /// SR-Algorithms sub-TLVs.
    pub peer_algos: &'a mut Levels<BTreeMap<IsisSysId, BTreeSet<u8>>>,

    /// Per-peer per-algo SRv6 locators (see `Isis::peer_algo_srv6`).
    /// Threaded through IsisTop so the LSDB rebuild path can populate it
    /// from peer SRv6 Locator TLVs and the per-algo IPv6 RIB build can
    /// read it.
    pub peer_algo_srv6: &'a mut Levels<BTreeMap<IsisSysId, BTreeMap<u8, super::srv6::Srv6AlgoLoc>>>,
    pub rib: &'a mut Levels<PrefixMap<Ipv4Net, SpfRoute<V4>>>,
    pub rib_v6: &'a mut Levels<PrefixMap<Ipv6Net, SpfRoute<V6>>>,
    pub retained_locators: &'a mut Levels<BTreeMap<Ipv6Net, RetainEntry>>,
    pub egress_protect_registered: &'a mut BTreeMap<Ipv6Net, (std::net::Ipv6Addr, IsisSysId)>,
    pub ilm: &'a mut Levels<BTreeMap<u32, SpfIlm>>,
    pub rib_client: &'a crate::rib::client::RibClient,
    pub hostname: &'a mut Levels<Hostname>,
    pub spf_timer: &'a mut Levels<Option<Timer>>,
    pub spf_throttle: &'a mut Levels<Throttle>,
    /// Inflight gate for the SPF offload — see `Isis::spf_inflight`.
    pub spf_inflight: &'a mut Levels<bool>,
    /// Pending latch for the SPF offload — see `Isis::spf_pending`.
    pub spf_pending: &'a mut Levels<bool>,
    /// Last SPF duration per level — see `Isis::spf_duration`.
    pub spf_duration: &'a mut Levels<Option<std::time::Duration>>,
    /// Last SPF completion instant per level — see `Isis::spf_last`.
    pub spf_last: &'a mut Levels<Option<std::time::Instant>>,
    /// Last TI-LFA compute telemetry per level — see `Isis::tilfa_stats`.
    pub tilfa_stats: &'a mut Levels<Option<spf::TilfaStats>>,
    pub graph: &'a mut Levels<Option<spf::Graph>>,
    pub spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,
    pub tilfa_result: &'a mut Levels<Option<BTreeMap<usize, Vec<spf::RepairPath>>>>,
    pub mt2_graph: &'a mut Levels<Option<spf::Graph>>,
    pub mt2_spf_result: &'a mut Levels<Option<BTreeMap<usize, spf::Path>>>,

    /// Per-algorithm SPF state (see `Isis::graph_flex_algo` /
    /// `spf_flex_algo`). Threaded through IsisTop so the SPF pipeline
    /// (`build_spf_input` / `apply_spf_result`) can refresh per-algo
    /// runs alongside the legacy + MT 2 SPF.
    pub graph_flex_algo: &'a mut Levels<BTreeMap<u8, Option<spf::Graph>>>,
    pub spf_flex_algo: &'a mut Levels<BTreeMap<u8, Option<BTreeMap<usize, spf::Path>>>>,

    /// Per-algorithm IPv4 RIB (see `Isis::rib_flex_algo`). Threaded
    /// so `apply_spf_result` can install the per-algo RIB snapshot
    /// after each SPF cycle.
    pub rib_flex_algo: &'a mut Levels<BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>>,

    /// Per-algorithm IPv6 RIB (see `Isis::rib6_flex_algo`). Threaded so
    /// `apply_spf_result` can install + snapshot the per-algo SRv6
    /// locator routes after each SPF cycle.
    pub rib6_flex_algo: &'a mut Levels<BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>>,

    /// Per-algorithm SRv6 colour-steering export diff state (see
    /// `Isis::flex_algo_srv6_export`).
    pub flex_algo_srv6_export:
        &'a mut Levels<BTreeMap<u8, BTreeMap<ipnet::IpNet, std::net::Ipv6Addr>>>,

    /// Read-only access to the SR snapshot the IS-IS instance is caching
    /// from RIB::SrSubscribe. lsp_generate uses these to populate the SR
    /// Capability / SRv6 sub-TLVs.
    pub sr_block: &'a Option<Block>,
    pub sr_locator: &'a Option<Locator>,
    pub sr_end_sid: &'a Option<std::net::Ipv6Addr>,

    /// Per-Flex-Algorithm SRv6 locator snapshots + node (End) SIDs
    /// (see `Isis::sr_flex_algo_locators` / `sr_flex_algo_end_sid`).
    /// `lsp_generate` emits one SRv6 Locator TLV sub-locator per
    /// resolved entry with Algorithm=N; the per-algo IPv6 RIB build
    /// exports the local End SID for colour steering.
    pub sr_flex_algo_locators: &'a BTreeMap<u8, Locator>,
    pub sr_flex_algo_end_sid: &'a BTreeMap<u8, std::net::Ipv6Addr>,

    /// Read-only access to the cached SRLG table (see
    /// `Isis::srlg_groups`). lsp_generate resolves per-link SRLG group
    /// names through this map when emitting TLVs 138 / 139.
    pub srlg_groups: &'a BTreeMap<String, SrlgGroup>,

    /// Read-only access to the Flex-Algorithm definition store. The
    /// LSP emitter walks the entries with `advertise_definition=true`
    /// and emits one FAD sub-TLV (RFC 9350 §5.1) per entry inside
    /// Router Capability TLV 242.
    pub flex_algo: &'a super::flex_algo::FlexAlgoConfig,

    /// Read-only access to the affinity-map. Used to resolve admin-
    /// group names referenced by FAD constraint sub-TLVs into the
    /// 256-bit Extended Admin Group bitmap (RFC 7308).
    pub affinity_map: &'a super::affinity_map::AffinityMap,

    /// Read-only snapshot of the policy-driven key-chain registry
    /// (see `Isis::key_chains`). Sign / verify paths consult this
    /// when an auth-scope's `key-chain` leaf is set.
    pub key_chains: &'a std::collections::BTreeMap<String, crate::policy::KeyChain>,

    /// Seq-wrap wait timers (see `Isis::lsp_seq_wrap_wait`). Threaded
    /// through so `lsp_generate` can short-circuit per fragment and
    /// arm the timer without round-tripping through the event loop.
    pub lsp_seq_wrap_wait: &'a mut Levels<BTreeMap<u8, Timer>>,

    /// Stable-placement memory for the self-LSP packer; see
    /// `Isis::lsp_placement_memory`.
    pub lsp_placement_memory: &'a mut Levels<BTreeMap<TlvKey, u8>>,

    /// Redistribute snapshots (see `Isis::redist_v{4,6}`). Read by
    /// `lsp_generate` to emit TLV 135 / 236 / MT 237 entries for
    /// every (rtype, prefix) covered by an active redistribute
    /// config row.
    pub redist_v4: &'a BTreeMap<(crate::rib::RibType, Ipv4Net), crate::rib::RouteEntryV4>,
    pub redist_v6: &'a BTreeMap<(crate::rib::RibType, Ipv6Net), crate::rib::RouteEntryV6>,
    /// SR-MPLS Mirror Context labels per protected-locator (see
    /// `Isis::mirror_labels`); read by `lsp_generate` to emit the
    /// SID/Label Binding TLV (149) for `dataplane: mpls` entries.
    pub mirror_labels: &'a BTreeMap<IpNet, u32>,
}

impl Isis {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: ProtoContext,
        rib_rx: UnboundedReceiver<RibRx>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
        stamp_client_tx: Option<UnboundedSender<crate::stamp::client::ClientReq>>,
        bgp_tx: Option<mpsc::Sender<crate::bgp::inst::Message>>,
        policy_tx: UnboundedSender<crate::policy::Message>,
        proto_label: String,
        rib_subscriber: RibSubscriber,
        config_tx: mpsc::Sender<crate::config::Message>,
    ) -> Self {
        let policy_chan = crate::policy::PolicyRxChannel::new();
        let _ = policy_tx.send(crate::policy::Message::Subscribe {
            proto: proto_label.clone(),
            tx: policy_chan.tx.clone(),
        });
        // SR config subscription channel. One-time registration with the
        // RIB; subsequent SrBlockWatch / SrLocatorWatch messages drive
        // which named entries we receive updates for. Goes through the
        // typed handle just like every other protocol-to-RIB send.
        let (sr_tx, sr_rx) = mpsc::unbounded_channel::<RibSrRx>();
        let _ = ctx.rib.send(rib::Message::SrSubscribe {
            proto: proto_label.clone(),
            tx: sr_tx,
        });

        let (tx, rx) = mpsc::unbounded_channel();
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        let (stamp_event_tx, stamp_event_rx) = mpsc::unbounded_channel();
        let mut isis =
            Self {
                tx,
                rx,
                cm: ConfigChannel::new(),
                callbacks: HashMap::new(),
                rib_rx,
                ctx,
                links: IsisLinks::default(),
                show: ShowChannel::new(),
                show_cb: HashMap::new(),
                config: IsisConfig::default(),
                restarting: None,
                overloaded: false,
                overload_clear_timer: None,
                flex_algo: super::flex_algo::FlexAlgoConfig::new("/router/isis/flex-algo"),
                affinity_map: super::affinity_map::AffinityMap::new(),
                tracing: IsisTracing::default(),
                lsdb: Levels::<Lsdb>::default(),
                lsp_map: Levels::<LspMap>::default(),
                reach_map: Levels::<Afis<ReachMapV4>>::default(),
                reach_map_v6: Levels::<ReachMapV6>::default(),
                mt2_reach_map_v6: Levels::<ReachMapV6>::default(),
                mt_membership: Levels::<BTreeMap<IsisSysId, BTreeSet<MtId>>>::default(),
                label_map: Levels::<IsisLabelMap>::default(),
                srv6_end_map: Levels::<BTreeMap<IsisSysId, super::srv6::Srv6EndSidInfo>>::default(),
                peer_fad: Levels::<
                    BTreeMap<IsisSysId, BTreeMap<u8, isis_packet::IsisSubFlexAlgoDef>>,
                >::default(),
                peer_link_affinity: Levels::<
                    BTreeMap<
                        IsisSysId,
                        BTreeMap<isis_packet::IsisNeighborId, isis_packet::ExtAdminGroup>,
                    >,
                >::default(),
                peer_algo_sid: Levels::<
                    BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), isis_packet::SidLabelValue>>,
                >::default(),
                peer_algos: Levels::<BTreeMap<IsisSysId, BTreeSet<u8>>>::default(),
                peer_algo_srv6:
                    Levels::<BTreeMap<IsisSysId, BTreeMap<u8, super::srv6::Srv6AlgoLoc>>>::default(),
                rib: Levels::<PrefixMap<Ipv4Net, SpfRoute<V4>>>::default(),
                rib_v6: Levels::<PrefixMap<Ipv6Net, SpfRoute<V6>>>::default(),
                retained_locators: Levels::<BTreeMap<Ipv6Net, RetainEntry>>::default(),
                egress_protect_registered: BTreeMap::new(),
                ilm: Levels::<BTreeMap<u32, SpfIlm>>::default(),
                self_sid_ilm: BTreeMap::new(),
                hostname: Levels::<Hostname>::default(),
                spf_timer: Levels::<Option<Timer>>::default(),
                spf_throttle: Levels::<Throttle>::default(),
                spf_inflight: Levels::<bool>::default(),
                spf_pending: Levels::<bool>::default(),
                spf_duration: Levels::<Option<std::time::Duration>>::default(),
                spf_last: Levels::<Option<std::time::Instant>>::default(),
                tilfa_stats: Levels::<Option<spf::TilfaStats>>::default(),
                lsp_gen_timer: Levels::<Option<Timer>>::default(),
                lsp_gen_throttle: Levels::<Throttle>::default(),
                lsp_gen_pending_floor: Levels::<Option<u32>>::default(),
                // Adjacency-SID label pool is owned by the SR-MPLS feature.
                // Stays None until `segment-routing mpls` is configured —
                // otherwise we'd allocate labels for every hello and emit
                // LanAdjSid sub-TLVs that turn into MPLS ILM installs the
                // kernel rejects (EOPNOTSUPP) on hosts without an MPLS path.
                local_pool: None,
                graph: Levels::<Option<spf::Graph>>::default(),
                spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
                tilfa_result: Levels::<Option<BTreeMap<usize, Vec<spf::RepairPath>>>>::default(),
                mt2_graph: Levels::<Option<spf::Graph>>::default(),
                mt2_spf_result: Levels::<Option<BTreeMap<usize, spf::Path>>>::default(),
                graph_flex_algo: Levels::<BTreeMap<u8, Option<spf::Graph>>>::default(),
                spf_flex_algo: Levels::<BTreeMap<u8, Option<BTreeMap<usize, spf::Path>>>>::default(
                ),
                rib_flex_algo: Levels::<BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>>::default(),
                rib6_flex_algo: Levels::<BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>>::default(),
                flex_algo_srv6_export: Levels::<
                    BTreeMap<u8, BTreeMap<ipnet::IpNet, std::net::Ipv6Addr>>,
                >::default(),
                sr_rx,
                watched_block: None,
                watched_locator: None,
                watched_flex_algo_locators: BTreeMap::new(),
                sr_flex_algo_locators: BTreeMap::new(),
                sr_flex_algo_end_sid: BTreeMap::new(),
                sr_block: None,
                sr_locator: None,
                sr_end_sid: None,
                installed_mirror_sids: std::collections::BTreeSet::new(),
                installed_mirror_routes: std::collections::BTreeSet::new(),
                mirror_labels: std::collections::BTreeMap::new(),
                installed_mirror_ilm: std::collections::BTreeSet::new(),
                elib: super::srv6::ElibPool::new(),
                lsp_seq_wrap_wait: Levels::<BTreeMap<u8, Timer>>::default(),
                lsp_placement_memory: Levels::<BTreeMap<TlvKey, u8>>::default(),
                redist_v4: BTreeMap::new(),
                redist_v6: BTreeMap::new(),
                srlg_config: SrlgGroupBuilder::new(),
                srlg_groups: BTreeMap::new(),
                bfd_client_tx,
                stamp_client_tx,
                bgp_tx,
                bgp_ls_advertised: std::collections::BTreeMap::new(),
                bfd_event_tx,
                bfd_event_rx,
                stamp_event_tx,
                stamp_event_rx,
                key_chains: BTreeMap::new(),
                policy_tx,
                policy_rx: policy_chan.rx,
                proto_label,
                rib_subscriber,
                config_tx,
                vrf_log: BTreeMap::new(),
                vrf_registry: BTreeMap::new(),
                rib_known_vrfs: BTreeMap::new(),
            };
        isis.callback_build();
        isis.show_build();
        // Restart-aware boot. No-op when no checkpoint on disk
        // (cold-start). When present + fresh, restores self-LSPs +
        // sets restarting state so the first IIH on every link
        // goes out with RR=1. Only the default instance loads the
        // checkpoint — the on-disk path is fixed (`isis.cbor`), so a
        // per-VRF child must not restore the default instance's LSPs.
        if isis.proto_label == "isis" {
            isis.gr_restart_load_checkpoint();
        }
        isis
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        // CommitEnd is the only signal IS-IS reacts to outside the
        // YANG callback table — fold the staged SRLG cache into the
        // applied snapshot and re-originate if it moved. The default
        // instance also fans CommitEnd out to its per-VRF children and
        // prunes any whose `router isis vrf <name>` block was deleted.
        if msg.op == ConfigOp::CommitEnd {
            self.vrf_commit_end();
            self.commit_srlg();
            // Reconcile STAMP measurement sessions against the
            // just-committed config — one robust hook covers every
            // config path that can flip a session (measurement
            // enable/interval, network-type, afi enable, ...).
            self.stamp_reconcile_all();
            // Reconcile the local Prefix-SID ILM against the just-committed
            // config. This is what withdraws the pop entry when
            // `prefix-sid` / `segment-routing mpls` is removed or
            // `no-local-prefix-sid` is set — those handlers only mutate
            // config state and don't schedule SPF, so the `SpfDone`
            // reconcile alone would never see the change. Idempotent: a
            // no-op when nothing self-SID-relevant changed.
            update_self_sid_ilm(self);
            return;
        }
        if msg.op == ConfigOp::CommitStart {
            return;
        }

        // Dynamic tab-completion (`ext:dynamic "isis:<handler>"`): the
        // manager sends the handler name as the sole path segment and
        // waits on `msg.resp` for the candidate list. Answer directly —
        // these are instance-level, not VRF-scoped.
        if msg.op == ConfigOp::Completion {
            let (path, _) = path_from_command(&msg.paths);
            let comps = match path.as_str() {
                "/neighbor" => self.neighbor_comps(),
                _ => Vec::new(),
            };
            if let Some(resp) = msg.resp {
                let _ = resp.send(comps);
            }
            return;
        }

        // `/router/isis/vrf/<name>/...` belongs to a per-VRF instance,
        // not the default one. Strip the `vrf <name>` selector and
        // buffer the rewritten line (replayed into the child at spawn;
        // kept for VrfDel→VrfAdd respawn); forward it live if the child
        // is already running. The default instance never runs these
        // through its own callback table. Only the default instance
        // owns children — a child's paths never carry a `vrf` segment,
        // so this is a no-op there. Anchored to `router isis` (see
        // `vrf_config_split`): the manager broadcasts every committed
        // line to every protocol, so a generic match would otherwise
        // spawn a phantom child for the top-level `/vrf/<name>` list or
        // for another protocol's `router <other> vrf <name>` block.
        if let Some((name, rewritten)) = vrf_config_split("isis", &msg.paths) {
            self.vrf_config_record(name, rewritten, msg.op);
            return;
        }

        let (path, mut args) = path_from_command(&msg.paths);

        // Clear ops don't go through the YANG callback table — they
        // map directly to runtime side-effects (kick SPF, drop a
        // peer, ...) the way `clear ip bgp` works in BGP. Match on
        // the path explicitly so the rest of the pipeline keeps
        // treating Set / Delete uniformly.
        if msg.op == ConfigOp::Clear {
            match path.as_str() {
                "/clear/isis/spf" => {
                    // Bare `clear isis spf` (no arg) recalculates both
                    // levels; `clear isis spf level-1|level-2` carries
                    // the level as a matched enum key in `args`.
                    self.clear_spf(args.string().as_deref());
                }
                "/clear/isis/neighbor" => {
                    // `clear isis neighbor [<system-id|name>]`. The bare
                    // form (no arg) tears down every adjacency; a trailing
                    // argument tears down only that neighbor. Accept either
                    // the canonical `xxxx.xxxx.xxxx` system-id or the
                    // hostname mapped in L1/L2. Ignore unresolvable input
                    // rather than falling through to "clear all" — a typo
                    // shouldn't reset the whole instance.
                    match args.string() {
                        None => self.clear_neighbor(None),
                        Some(s) => {
                            let sys_id = s.parse::<IsisSysId>().ok().or_else(|| {
                                self.hostname
                                    .l1
                                    .lookup_by_name(&s)
                                    .or_else(|| self.hostname.l2.lookup_by_name(&s))
                            });
                            if let Some(id) = sys_id {
                                self.clear_neighbor(Some(id));
                            }
                        }
                    }
                }
                "/clear/isis/checkpoint/write" => {
                    self.checkpoint_write_debug();
                }
                "/clear/isis/checkpoint/clear" => {
                    self.checkpoint_clear_debug();
                }
                "/clear/isis/graceful-restart/begin" => {
                    // Default grace period 120s — matches OSPF's
                    // operator-default.
                    self.gr_restart_begin(120);
                }
                "/clear/isis/graceful-restart/commit" => {
                    self.gr_restart_commit();
                }
                "/clear/isis/graceful-restart/abort" => {
                    self.gr_restart_abort();
                }
                _ => {
                    //
                }
            }
            return;
        }

        // `/srlg/group/...` is the global SRLG table (shared with
        // OSPF), dispatched through the SRLG builder's own path →
        // handler table (the same shape the RIB uses for
        // `/segment-routing/block`); the applied snapshot lands in
        // `srlg_groups` at CommitEnd.
        if path.starts_with("/srlg/group") {
            let _ = self.srlg_config.exec(path, args, msg.op);
            return;
        }

        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        } else if path.starts_with("/router/isis/tracing") {
            // `/router/isis/tracing/...` is not in the callback table —
            // its category names are YANG presence containers, so a
            // single subtree dispatcher parses the path tail (mirrors
            // OSPF's `config_tracing_dispatch`).
            super::tracing::config_tracing_dispatch(self, &path, args, msg.op);
        }
    }

    /// Record a rewritten per-VRF config line (parent only). Appends to
    /// the VRF's replay log and, if its child is already running,
    /// forwards the line live to the child's config inbox.
    fn vrf_config_record(&mut self, name: String, rewritten: Vec<CommandPath>, op: ConfigOp) {
        if let Some(handle) = self.vrf_registry.get(&name) {
            let _ = handle.cm_tx.send(ConfigRequest::new(rewritten.clone(), op));
        }
        self.vrf_log
            .entry(name.clone())
            .or_default()
            .push((rewritten, op));
        // The kernel VrfAdd may already have been processed BEFORE this
        // intent line: in a same-commit `vrf X` + `router isis vrf X ...`
        // apply, the netlink-acked VrfAdd and the config lines race on
        // separate channels, and `vrf_add` alone only spawns when intent
        // landed first. Spawn here too (no-op while either half is still
        // missing) instead of waiting for a VrfDel/VrfAdd flap.
        self.vrf_spawn_if_ready(&name);
    }

    /// Spawn the per-VRF child once BOTH halves exist — kernel info
    /// (`rib_known_vrfs`, from `VrfAdd`) and active config intent
    /// (`vrf_log`). Called from `vrf_add` (kernel half arriving) and
    /// `vrf_config_record` (intent half arriving); whichever lands
    /// second performs the spawn.
    fn vrf_spawn_if_ready(&mut self, name: &str) {
        if self.vrf_registry.contains_key(name) {
            return;
        }
        let Some(&(table_id, _)) = self.rib_known_vrfs.get(name) else {
            return;
        };
        let has_intent = self
            .vrf_log
            .get(name)
            .is_some_and(|log| super::vrf::vrf_log_active(log));
        if !has_intent {
            return;
        }
        // Clone the replay log so the spawn borrow doesn't overlap the
        // `vrf_registry` insert below.
        let log = self.vrf_log.get(name).cloned().unwrap_or_default();
        let handle = super::vrf::spawn_isis_vrf(
            name,
            table_id,
            &self.rib_subscriber,
            &self.config_tx,
            &self.policy_tx,
            &log,
        );
        self.vrf_registry.insert(name.to_string(), handle);
    }

    /// CommitEnd fan-out for the default instance: tear down per-VRF
    /// children whose `router isis vrf <name>` block was fully deleted
    /// this commit, then forward `CommitEnd` to every surviving live
    /// child so it runs its own commit-time reconcile.
    fn vrf_commit_end(&mut self) {
        let emptied: Vec<String> = self
            .vrf_log
            .iter()
            .filter(|(_, log)| !super::vrf::vrf_log_active(log))
            .map(|(name, _)| name.clone())
            .collect();
        for name in emptied {
            self.vrf_log.remove(&name);
            // Kernel info (`rib_known_vrfs`) is owned by VrfAdd/VrfDel,
            // not by config — leave it so a re-added block respawns if
            // the kernel VRF still exists.
            if self.vrf_registry.remove(&name).is_some() {
                super::vrf::despawn_isis_vrf(&name, &self.config_tx, &self.rib_subscriber);
            }
        }
        for handle in self.vrf_registry.values() {
            let _ = handle
                .cm_tx
                .send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
        }
    }

    /// Force-recalculate the IS-IS SPF. Mirrors FRR's `clear isis
    /// spf` — useful when an operator wants to re-derive the route
    /// table without waiting for the next LSDB update or the debounce
    /// timer to fire. `level` selects a single level (`level-1` /
    /// `level-2`); `None` (the bare command) recalculates both.
    /// Levels with no SPF state yet are no-ops on the receiver side.
    fn clear_spf(&mut self, level: Option<&str>) {
        let levels: &[Level] = match level {
            Some("level-1") => &[Level::L1],
            Some("level-2") => &[Level::L2],
            _ => &[Level::L1, Level::L2],
        };
        for level in levels {
            let _ = self.tx.send(Message::SpfCalc(*level));
        }
    }

    /// `clear isis neighbor [<system-id>]` — tear down adjacencies the
    /// same way a hold-timer expiry would. With `id == None` every
    /// adjacency on the instance is reset; with a system-id only the
    /// neighbor(s) whose System ID matches (a neighbor can appear on
    /// more than one link / level). We reuse the existing
    /// `Message::Nfsm(HoldTimerExpire, …)` path — the same one the
    /// inactivity timer fires — so the teardown (drop the adjacency,
    /// re-originate Hello+LSP, re-elect the DIS on LAN, release
    /// labels/SIDs, unsubscribe BFD, reschedule SPF) runs through one
    /// code path. A live peer keeps Helloing, so the adjacency re-forms
    /// from scratch (Down -> Up). Snapshot the targets first so the
    /// borrow on `self.links` is released before we send (mirrors the
    /// OSPF `clear_neighbor`).
    fn clear_neighbor(&self, id: Option<IsisSysId>) {
        let mut targets: Vec<(Level, u32, IsisSysId)> = Vec::new();
        for (ifindex, link) in self.links.iter() {
            for level in [Level::L1, Level::L2] {
                for sys_id in link.state.nbrs.get(&level).keys() {
                    if id.is_none_or(|want| want == *sys_id) {
                        targets.push((level, *ifindex, *sys_id));
                    }
                }
            }
        }
        for (level, ifindex, sys_id) in targets {
            let _ = self.tx.send(Message::Nfsm(
                NfsmEvent::HoldTimerExpire,
                level,
                ifindex,
                sys_id,
            ));
        }
    }

    /// Candidate completions for `ext:dynamic "isis:neighbor"` — the
    /// System IDs of the current adjacencies (the "System Id" column in
    /// `show isis neighbor`), formatted `xxxx.xxxx.xxxx`. Deduped +
    /// sorted via `BTreeSet` (a neighbor can appear on more than one
    /// link / level).
    fn neighbor_comps(&self) -> Vec<String> {
        let mut ids: BTreeSet<IsisSysId> = BTreeSet::new();
        for link in self.links.values() {
            for level in [Level::L1, Level::L2] {
                for sys_id in link.state.nbrs.get(&level).keys() {
                    ids.insert(*sys_id);
                }
            }
        }
        ids.iter()
            .map(|id| {
                self.hostname
                    .l1
                    .get(id)
                    .or_else(|| self.hostname.l2.get(id))
                    .map(|(name, _)| name.clone())
                    .unwrap_or_else(|| id.to_string())
            })
            .collect()
    }

    /// Debug entry — capture the current IS-IS state and atomically
    /// write a checkpoint to disk. The grace period (60s) is a
    /// placeholder; the actual commit path derives it from the
    /// YANG knob.
    fn checkpoint_write_debug(&mut self) {
        use super::checkpoint::{IsisCheckpoint, default_path};

        let cp = IsisCheckpoint::from_instance(self, 60);
        let path = default_path();
        match cp.write_to_path(&path) {
            Ok(()) => {
                tracing::info!(
                    "[GR Checkpoint] wrote {} L1 LSPs, {} L2 LSPs, {} adjacencies to {}",
                    cp.levels
                        .iter()
                        .find(|l| l.level == 1)
                        .map(|l| l.self_lsps.len())
                        .unwrap_or(0),
                    cp.levels
                        .iter()
                        .find(|l| l.level == 2)
                        .map(|l| l.self_lsps.len())
                        .unwrap_or(0),
                    cp.adjacencies.len(),
                    path.display(),
                );
            }
            Err(e) => {
                tracing::error!("[GR Checkpoint] write to {} failed: {}", path.display(), e);
            }
        }
    }

    /// Restart-aware boot. Called from `Isis::new()` after the
    /// default-constructed instance. If a recent checkpoint is on
    /// disk:
    ///   - per-level self-LSPs are restored into the LSDB verbatim
    ///     (so re-flood on first link-up post-restart is
    ///     byte-identical to what helpers snapshotted),
    ///   - `self.restarting = Some(...)` so the IIH send path
    ///     attaches RR=1 from the first Hello,
    ///   - the checkpoint file is deleted (replay of stale state
    ///     on a second boot would propagate the wrong LSDB),
    ///   - an auto-abort `Timer::once` fires `GrRestartAbort` when
    ///     the remaining grace window expires, so the restart
    ///     state doesn't pin indefinitely until the exit-success
    ///     drive fires.
    ///
    /// Cold-starts (returns silently) when:
    ///   - the file is absent,
    ///   - it's unreadable / undecodable,
    ///   - `now - written_at > 1.5 × grace_period_secs` (locked
    ///     freshness rule per the design doc).
    fn gr_restart_load_checkpoint(&mut self) {
        use super::checkpoint::{IsisCheckpoint, default_path};
        use super::lsdb::Lsa;
        use crate::context::Timer;
        // `IsisLsp::parse_be` comes from nom_derive's `Parse` trait,
        // re-exported via `isis_packet::sub::*` (sub/mod.rs has
        // `pub use nom_derive::*`).
        use isis_packet::{IsisLspId, Parse};
        use std::time::{Duration, SystemTime};

        let path = default_path();
        let cp = match IsisCheckpoint::read_from_path(&path) {
            Ok(cp) => cp,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!(
                    "[GR Restart] checkpoint at {} unreadable, cold-starting: {}",
                    path.display(),
                    e
                );
                return;
            }
        };

        // Freshness: wall-clock age must be within 1.5× the grace
        // period the restarter requested. Beyond that, helpers
        // have already given up on us and our LSDB is stale.
        let max_age = Duration::from_secs((cp.grace_period_secs as u64).saturating_mul(3) / 2);
        let age = SystemTime::now()
            .duration_since(cp.written_at)
            .unwrap_or(Duration::ZERO);
        if age > max_age {
            tracing::warn!(
                "[GR Restart] checkpoint at {} stale (age {:?} > {:?}), cold-starting",
                path.display(),
                age,
                max_age
            );
            let _ = IsisCheckpoint::delete(&path);
            return;
        }

        // Replay self-LSPs verbatim. Hold/refresh timers stay None
        // until exit-success completes — `process_lsdb` gates both
        // expiry arms on `restarting.is_some()` so the entries don't
        // age out during the restart window.
        let mut total = 0usize;
        for lvl_cp in &cp.levels {
            let level = match lvl_cp.level {
                1 => Level::L1,
                2 => Level::L2,
                _ => continue,
            };
            for snap in &lvl_cp.self_lsps {
                let lsp = match isis_packet::IsisLsp::parse_be(&snap.body) {
                    Ok((_, lsp)) => lsp,
                    Err(e) => {
                        tracing::warn!(
                            "[GR Restart] failed to parse checkpointed LSP id={:?}, skipping: {:?}",
                            snap.lsp_id,
                            e
                        );
                        continue;
                    }
                };
                let key = IsisLspId { id: snap.lsp_id };
                let mut lsa = Lsa::new(lsp);
                lsa.originated = true;
                lsa.bytes = snap.body.clone();
                self.lsdb.get_mut(&level).map.insert(key, lsa);
                total += 1;
            }
        }

        // Arm the auto-abort timer for whatever's left of the grace
        // window. The exit-success path takes over once adjacencies
        // recover.
        let remaining = max_age.saturating_sub(age);
        let remaining_secs = remaining.as_secs().max(1);
        let tx = self.tx.clone();
        let abort_timer = Timer::once(remaining_secs, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::GrRestartAbort);
            }
        });

        // Pending-set: drives the exit-success path. Each NFSM Up
        // transition that matches a sys-id here removes it from the
        // set; the last removal fires `gr_restart_exit_success`.
        let pending_neighbors: std::collections::BTreeSet<isis_packet::IsisSysId> = cp
            .adjacencies
            .iter()
            .map(|a| isis_packet::IsisSysId { id: a.sys_id })
            .collect();

        let t1_timer = arm_t1_timer(&self.tx);
        self.restarting = Some(RestartingState {
            // Preserve original checkpoint write time so the show
            // command and helpers' grace-period view stay aligned
            // with when we actually went down.
            started_at: cp.written_at,
            grace_period_secs: cp.grace_period_secs,
            abort_timer: Some(abort_timer),
            pending_neighbors,
            t1_timer: Some(t1_timer),
        });

        let _ = IsisCheckpoint::delete(&path);

        tracing::info!(
            "[GR Restart] restored from checkpoint at {}: {} self-LSPs, grace remaining ~{}s",
            path.display(),
            total,
            remaining_secs,
        );
    }

    /// `clear isis graceful-restart begin` — stage a restart per
    /// RFC 5306 §3.1. Arms `self.restarting`, freezes self-LSP
    /// refresh, and kicks an IIH on every link so the next
    /// outbound Hello carries RR=1. Helpers around us see this and
    /// enter helper mode, replying with RA.
    ///
    /// No actual exit happens here — `commit` extends the staging
    /// with checkpoint write + drain + despawn; `abort` walks the
    /// staging back without exiting.
    fn gr_restart_begin(&mut self, grace_period_secs: u32) {
        if !self.config.gr_restarter_enabled {
            tracing::warn!(
                "[GR Restart] begin ignored: graceful-restart restarter-enabled is false"
            );
            return;
        }
        if self.restarting.is_some() {
            tracing::warn!("[GR Restart] begin ignored: already restarting");
            return;
        }
        let t1_timer = arm_t1_timer(&self.tx);
        self.restarting = Some(RestartingState {
            started_at: std::time::SystemTime::now(),
            grace_period_secs,
            abort_timer: None,
            // Operator-staged restart — no checkpointed neighbor
            // set. Exit-success never fires here; operator ends
            // the restart via `abort` or `commit`+exit.
            pending_neighbors: std::collections::BTreeSet::new(),
            t1_timer: Some(t1_timer),
        });
        tracing::info!(
            "[GR Restart] staged, grace period {}s; flooding IIH+RR on all links",
            grace_period_secs,
        );
        self.kick_hello_all_links();
    }

    /// `clear isis graceful-restart commit` — stage (if not
    /// already staged) and execute the planned restart:
    ///   1. Originate IIH+RR on every link.
    ///   2. Build a checkpoint and atomically write it to
    ///      `default_path()`.
    ///   3. Arm a `Timer::once_ms(DRAIN_MS)` parked on
    ///      `RestartingState.abort_timer` so the IIH+RR packets
    ///      reach the wire before the socket closes.
    ///   4. When the timer fires, `Message::GrRestartExit` runs
    ///      `std::process::exit(0)`. Supervisor (systemd /
    ///      operator script) restarts the process; kernel routes
    ///      tagged `RibType::Isis` survive because no
    ///      `ProtoCleanup` is dispatched.
    ///
    /// Aborts and logs (no exit) when:
    ///   - `restarter-enabled` is off,
    ///   - checkpoint write fails (we'd lose seq continuity on
    ///     restart — helpers would trip MaxSeqAdvance recovery).
    fn gr_restart_commit(&mut self) {
        use super::checkpoint::{IsisCheckpoint, default_path};
        use crate::context::Timer;

        // Drain default — matches OSPF's locked design. YANG knob
        // can land in a follow-up if operators report tunnel/WAN
        // paths needing more.
        const DRAIN_MS: u64 = 200;

        if !self.config.gr_restarter_enabled {
            tracing::warn!(
                "[GR Restart] commit ignored: graceful-restart restarter-enabled is false"
            );
            return;
        }

        // Stage if not staged. `gr_restart_begin` arms `restarting`
        // and kicks IIH+RR; calling commit on an already-staged
        // restart skips the begin step and just adds the
        // checkpoint + exit on top.
        if self.restarting.is_none() {
            self.gr_restart_begin(120);
        } else {
            // Already staged — re-kick Hellos so the next outbound
            // IIH is fresh before the drain elapses.
            self.kick_hello_all_links();
        }

        let grace_period_secs = self
            .restarting
            .as_ref()
            .map(|r| r.grace_period_secs)
            .unwrap_or(120);

        let cp = IsisCheckpoint::from_instance(self, grace_period_secs);
        let path = default_path();
        if let Err(e) = cp.write_to_path(&path) {
            tracing::error!(
                "[GR Restart] commit aborted: checkpoint write to {} failed: {}",
                path.display(),
                e
            );
            return;
        }
        tracing::info!(
            "[GR Restart] committed: checkpoint at {} ({} L1 self-LSPs, {} L2 self-LSPs, {} adjacencies), drain={}ms",
            path.display(),
            cp.levels
                .iter()
                .find(|l| l.level == 1)
                .map(|l| l.self_lsps.len())
                .unwrap_or(0),
            cp.levels
                .iter()
                .find(|l| l.level == 2)
                .map(|l| l.self_lsps.len())
                .unwrap_or(0),
            cp.adjacencies.len(),
            DRAIN_MS,
        );

        // Arm the drain timer. Parked on RestartingState so its
        // Drop doesn't cancel the wakeup before it fires. Replaces
        // any 5e-i auto-abort timer that was sitting there — once a
        // commit fires, the auto-abort path is moot.
        let tx = self.tx.clone();
        let drain_timer = Timer::once_ms(DRAIN_MS, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::GrRestartExit);
            }
        });
        if let Some(state) = self.restarting.as_mut() {
            state.abort_timer = Some(drain_timer);
        }
    }

    /// NFSM Up transition observed for `sys_id`.
    /// Trim `pending_neighbors`; the last removal that empties the
    /// set fires `gr_restart_exit_success`. Returns early when no
    /// restart is in progress or when the sys_id wasn't part of
    /// the loaded checkpoint (operator-staged restarts always have
    /// an empty pending set, so the success path never fires from
    /// them).
    fn gr_check_exit_success(&mut self, sys_id: IsisSysId) {
        let Some(state) = self.restarting.as_mut() else {
            return;
        };
        if !state.pending_neighbors.remove(&sys_id) {
            return;
        }
        if state.pending_neighbors.is_empty() {
            self.gr_restart_exit_success();
        }
    }

    /// Every checkpointed neighbor is back to Up.
    /// Clear the restart state (drops `abort_timer` via Drop so
    /// the auto-abort safety net is cancelled), re-originate self
    /// LSPs at `seq+1` so helpers see fresh content with the new
    /// process's view, log success. SPF runs naturally on the
    /// next LSDB event now that the dispatch-side gate has lifted.
    fn gr_restart_exit_success(&mut self) {
        let elapsed = self
            .restarting
            .as_ref()
            .and_then(|s| s.started_at.elapsed().ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.restarting = None;
        tracing::info!(
            "[GR Restart] exit-success: all checkpointed neighbors re-converged in ~{}s; re-originating self-LSPs at seq+1",
            elapsed,
        );
        // `LspOriginate` with floor=None bumps `existing+1` per
        // `lsp.rs:447-451`. Existing comes from the LSDB which
        // the load-checkpoint path restored at the original seq,
        // so the bump is +1 relative to what helpers snapshotted —
        // no MaxSeqAdvance trip, fresh content takes effect.
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }

    /// RFC 5306 §3.1 exit-failure path. Auto-abort timer fired
    /// before `gr_restart_exit_success` — i.e. the checkpointed
    /// neighbors didn't all come back inside the grace window.
    /// Per the RFC: set the OL bit on our self-LSPs, resume normal
    /// operation, then clear OL after a short grace.
    ///
    /// Distinct from `gr_restart_abort` (operator-driven `clear …
    /// abort`), which exits cleanly without overload.
    fn gr_restart_expire(&mut self) {
        use crate::context::Timer;
        // OL-CLEAR-DELAY: how long we keep the overload bit set
        // after exit-failure. RFC 5306 §3.1 ties it to T2's
        // completion — without proper T2 modeling here, 30s is a
        // pragmatic default that gives the network time to route
        // around us before we re-advertise as a normal transit.
        const OL_CLEAR_DELAY_SECS: u64 = 30;

        // Clear restart state first so the SPF gate lifts and the
        // re-originate below produces fresh content (instead of
        // being suppressed).
        self.restarting = None;
        self.overloaded = true;

        tracing::warn!(
            "[GR Restart] exit-failure: setting OL bit, will clear after {}s",
            OL_CLEAR_DELAY_SECS
        );

        // Re-originate at seq+1 with OL=true. lsp_generate reads
        // top.overloaded which we just flipped.
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));

        // Kick Hellos so peers see RR=0 (we're no longer
        // restarting) and stop their helper mode.
        self.kick_hello_all_links();

        // Arm the OL-clear timer. Replaces any existing
        // overload_clear_timer (multiple expires would re-set OL
        // and re-arm — last one wins, that's fine).
        let tx = self.tx.clone();
        let clear_timer = Timer::once(OL_CLEAR_DELAY_SECS, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::ClearOverload);
            }
        });
        self.overload_clear_timer = Some(clear_timer);
    }

    /// Clear the post-restart OL bit. Called from
    /// `Message::ClearOverload` when the `overload_clear_timer`
    /// armed by `gr_restart_expire` fires.
    fn clear_overload(&mut self) {
        if !self.overloaded {
            return;
        }
        self.overloaded = false;
        self.overload_clear_timer = None;
        tracing::info!("[GR Restart] clearing OL bit; re-originating self-LSPs");
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }

    /// `clear isis graceful-restart abort` — walk back a staged
    /// restart. Clears `self.restarting`, re-allows LSP refresh,
    /// and kicks an IIH on every link so peers see RR=0 and exit
    /// helper mode. No-op when no restart is staged.
    fn gr_restart_abort(&mut self) {
        if self.restarting.take().is_none() {
            tracing::warn!("[GR Restart] abort: no restart staged");
            return;
        }
        tracing::info!("[GR Restart] aborted; flooding IIH with RR=0");
        self.kick_hello_all_links();
    }

    /// Fire `HelloOriginate` for every (link, level) pair so the
    /// next IIH on every interface reflects the freshly-changed
    /// `self.restarting` state. `hello_send`'s own `has_level`
    /// filter drops the level the link doesn't run, so sending
    /// both unconditionally is safe.
    fn kick_hello_all_links(&self) {
        for (ifindex, _) in self.links.iter() {
            for level in [Level::L1, Level::L2] {
                let _ = self.tx.send(Message::Ifsm(
                    IfsmEvent::HelloOriginate,
                    *ifindex,
                    Some(level),
                ));
            }
        }
    }

    /// Debug entry — delete the on-disk checkpoint. The post-restart
    /// success path will call this from production; today it's
    /// behind a `clear` so the storage layer can be exercised
    /// independently.
    fn checkpoint_clear_debug(&mut self) {
        use super::checkpoint::{IsisCheckpoint, default_path};

        let path = default_path();
        match IsisCheckpoint::delete(&path) {
            Ok(()) => {
                tracing::info!("[GR Checkpoint] deleted {}", path.display());
            }
            Err(e) => {
                tracing::error!("[GR Checkpoint] delete of {} failed: {}", path.display(), e);
            }
        }
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(link) => {
                self.link_add(link);
            }
            RibRx::LinkUp(ifindex) => {
                self.link_state_up(ifindex);
            }
            RibRx::LinkDown(ifindex) => {
                self.link_state_down(ifindex);
            }
            RibRx::LinkMtu { ifindex, mtu } => {
                self.link_mtu(ifindex, mtu);
            }
            RibRx::AddrAdd(addr) => {
                // isis_info!("Isis::AddrAdd {}", addr.addr);
                self.addr_add(addr);
            }
            RibRx::AddrDel(addr) => {
                // isis_info!("Isis::AddrDel {}", addr.addr);
                self.addr_del(addr);
            }
            RibRx::RouterIdUpdate(router_id) => {
                self.rib_router_id_update(router_id);
            }
            // Redistribute deliveries from RIB — initial walk (chunks
            // ending in `bulk: Eor`) plus steady-state deltas
            // (single-entry `bulk: More`). Stored in `redist_v{4,6}`
            // keyed by `(rtype, prefix)`; consumed at LSP-emit time
            // in a follow-up.
            RibRx::RouteAdd { rtype, routes, .. } => {
                self.route_redist_add(rtype, routes);
            }
            RibRx::RouteDel { rtype, routes, .. } => {
                self.route_redist_del(rtype, routes);
            }
            // VRF master lifecycle (default instance only — a per-VRF
            // child's subscription is bound to its own table and never
            // owns sub-VRFs). The kernel `table_id` lets us bind a
            // child's RibClient so its SPF routes install into the VRF
            // table; the spawn waits until config intent exists too.
            RibRx::VrfAdd {
                name,
                table_id,
                ifindex,
            } => {
                self.vrf_add(name, table_id, ifindex);
            }
            RibRx::VrfDel { name } => {
                self.vrf_del(name);
            }
            _ => {
                //
            }
        }
    }

    /// Kernel VRF master appeared (or was replayed at subscribe time).
    /// Record its `table_id`/`ifindex`, and spawn the per-VRF IS-IS
    /// child if config intent for this VRF exists and it isn't already
    /// running. Default instance only.
    fn vrf_add(&mut self, name: String, table_id: u32, ifindex: u32) {
        self.rib_known_vrfs
            .insert(name.clone(), (table_id, ifindex));
        self.vrf_spawn_if_ready(&name);
        // A mirror-context route whose `via-vrf` is this VRF was dropped
        // by the RIB if the VRF's kernel table wasn't registered yet
        // (config apply races the netlink VRF creation). Now that the
        // table exists, re-run the reconcile so the protected locator's
        // End.DT46-into-VRF route installs. Idempotent (del-then-add).
        self.update_mirror_context_routes();
        // Same race for the SR-MPLS Mirror Context ILM: it needs the VRF's
        // `(table_id, vrf_ifindex)` to install, now available.
        self.update_mirror_context_labels();
    }

    /// Kernel VRF master removed. Despawn the child but KEEP its config
    /// log so a later `VrfAdd` (master re-created) respawns from intent.
    /// RIB reclaims the VRF's FIB table on its side. Default instance
    /// only.
    fn vrf_del(&mut self, name: String) {
        self.rib_known_vrfs.remove(&name);
        if self.vrf_registry.remove(&name).is_some() {
            super::vrf::despawn_isis_vrf(&name, &self.config_tx, &self.rib_subscriber);
        }
    }

    fn route_redist_add(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        let changed = match batch {
            crate::rib::RouteBatch::V4(entries) => {
                let changed = !entries.is_empty();
                for e in entries {
                    self.redist_v4.insert((rtype, e.prefix), e);
                }
                changed
            }
            crate::rib::RouteBatch::V6(entries) => {
                let changed = !entries.is_empty();
                for e in entries {
                    self.redist_v6.insert((rtype, e.prefix), e);
                }
                changed
            }
        };
        if changed {
            self.reoriginate_self_lsps("redistribute route add");
        }
    }

    fn route_redist_del(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        let mut changed = false;
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    if self.redist_v4.remove(&(rtype, e.prefix)).is_some() {
                        changed = true;
                    }
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                for e in entries {
                    if self.redist_v6.remove(&(rtype, e.prefix)).is_some() {
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.reoriginate_self_lsps("redistribute route delete");
        }
    }

    /// Re-originate the fragment-0 self-LSP at both levels after a state
    /// change (e.g. a redistributed route added/withdrawn by RIB). Only
    /// fires for a level that already holds a self-LSP — matching
    /// `rib_router_id_update`; when no self-LSP exists yet the eventual
    /// initial origination reads the current `redist_v{4,6}` maps. The
    /// per-level `LspOriginate` events coalesce through the throttle, so
    /// a bulk RIB walk collapses into a single origination run rather
    /// than one per chunk.
    fn reoriginate_self_lsps(&self, reason: &str) {
        let key = IsisLspId::new(self.config.net.sys_id(), 0, 0);
        for level in [Level::L1, Level::L2] {
            if self.lsdb.get(&level).get(&key).is_some() {
                isis_event_trace!(
                    self.tracing,
                    LspOriginate,
                    &level,
                    "LSP Originate {} due to {}",
                    level,
                    reason
                );
                let _ = self.tx.send(Message::LspOriginate(level, None));
            }
        }
    }

    fn rib_router_id_update(&mut self, router_id: Ipv4Addr) {
        let new = (!router_id.is_unspecified()).then_some(router_id);
        if self.config.rib_router_id == new {
            return;
        }
        self.config.rib_router_id = new;

        // Configured te_router_id wins; nothing to re-originate when the
        // RIB-derived id changes underneath an explicit override.
        if self.config.te_router_id.is_some() {
            return;
        }

        let key = IsisLspId::new(self.config.net.sys_id(), 0, 0);
        if self.lsdb.get(&Level::L1).get(&key).is_some() {
            isis_event_trace!(
                self.tracing,
                LspOriginate,
                &Level::L1,
                "LSP Originate L1 due to RIB router-id change"
            );
            self.tx
                .send(Message::LspOriginate(Level::L1, None))
                .unwrap();
        }
        if self.lsdb.get(&Level::L2).get(&key).is_some() {
            isis_event_trace!(
                self.tracing,
                LspOriginate,
                &Level::L2,
                "LSP Originate L2 due to RIB router-id change"
            );
            self.tx
                .send(Message::LspOriginate(Level::L2, None))
                .unwrap();
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            let _ = msg.resp.send(output).await;
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Srm(level, ifindex) => {
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                flood::srm_advertise(&mut link, level, ifindex);
            }
            Message::Ssn(level, ifindex) => {
                let _sys_id = self.config.net.sys_id();
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                flood::ssn_advertise(&mut link, level);
            }
            Message::Nfsm(ev, level, ifindex, sys_id) => {
                if ev != NfsmEvent::HoldTimerExpire {
                    return;
                }
                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };
                // Genuine hold-timer expiry: the peer is gone, so release the
                // BFD session too (release_bfd = true).
                nbr_hold_timer_expire(&mut link, level, sys_id, true);

                link.state.nbrs.get_mut(&level).remove(&sys_id);
            }
            Message::SpfCalc(level) => {
                // FIB hold-back: while restarting, skip SPF
                // entirely. Kernel routes from before the restart
                // are still installed (despawn_isis_graceful sent
                // ProtoQuiesce, not ProtoCleanup); recomputing and
                // installing new routes mid-restart would partially
                // overwrite that set with output from a
                // possibly-stale LSDB. The exit-success path
                // (re-originate at seq+1 + next LSDB event) drives
                // an authoritative SPF after restart clears.
                if self.restarting.is_some() {
                    return;
                }
                // Offloaded SPF: build the graph snapshot on the main
                // task, then dispatch Dijkstra + TI-LFA to
                // `tokio::task::spawn_blocking`. The worker sends the
                // result back as `Message::SpfDone`, which runs the
                // RIB build + diff on the main task. Mirrors the OSPF
                // pipeline in `ospf/inst.rs::process_message`.
                let tx = self.tx.clone();
                let mut top = self.top();
                if *top.spf_inflight.get(&level) {
                    // Another SPF is already running for this level —
                    // latch a follow-up so the completion path re-fires
                    // exactly one `SpfCalc` once it returns.
                    *top.spf_pending.get_mut(&level) = true;
                    return;
                }
                // Clear the slot first so a new schedule can arm a
                // timer if more LSDB changes arrive while the worker
                // is running; stamp the throttle so the next schedule
                // sees this run as the most recent.
                *top.spf_timer.get_mut(&level) = None;
                top.spf_throttle.get_mut(&level).mark_run();
                let Some(input) = build_spf_input(&mut top, level) else {
                    return;
                };
                *top.spf_inflight.get_mut(&level) = true;
                tokio::task::spawn_blocking(move || {
                    let output = compute_spf(input);
                    let _ = tx.send(Message::SpfDone(Box::new(output)));
                });
            }
            Message::SpfDone(output) => {
                let level = output.level;
                let mut top = self.top();
                apply_spf_result(&mut top, *output);
                *top.spf_inflight.get_mut(&level) = false;
                if std::mem::take(top.spf_pending.get_mut(&level)) {
                    let _ = self.tx.send(Message::SpfCalc(level));
                }
                // Reconcile the local (self-originated) Prefix-SID ILM.
                // Level-independent (config + global SR block, not SPF),
                // so done once here after `top`'s borrow ends rather than
                // in the per-level apply path; idempotent across L1/L2.
                update_self_sid_ilm(self);
                // The LSDB is settled after SPF — push the BGP-LS producer's
                // delta to BGP (RFC 9552). `top` is no longer used, so its
                // mutable borrow of `self` has ended (NLL) and the disjoint
                // field borrows inside `bgp_ls_produce` are free.
                self.bgp_ls_produce();
            }
            Message::Recv(packet, ifindex, mac) => {
                let Some(mut top) = self.link_top(ifindex) else {
                    return;
                };
                let _ = process_packet(&mut top, packet, ifindex, mac);
            }
            Message::LspOriginate(level, floor) => {
                self.schedule_lsp_originate(level, floor);
            }
            Message::LspGenFire(level) => {
                // Pull the accumulated floor for the burst, run the
                // origination, then stamp throttle completion and clear
                // the timer slot so the next event can re-arm.
                let floor = self.lsp_gen_pending_floor.get_mut(&level).take();
                self.process_lsp_originate(level, floor);
                self.lsp_gen_throttle.get_mut(&level).mark_run();
                *self.lsp_gen_timer.get_mut(&level) = None;
            }
            Message::LspPurge(level, lsp_id) => {
                self.process_lsp_purge(level, lsp_id);
            }
            Message::DisOriginate(level, ifindex, base) => {
                self.process_dis_originate(level, ifindex, base);
            }
            Message::Ifsm(ev, ifindex, level) => {
                self.process_ifsm(ev, ifindex, level);
            }
            Message::Lsdb(ev, level, key) => {
                self.process_lsdb(ev, level, key);
            }
            Message::AdjacencyUp(level, ifindex) => {
                self.schedule_lsp_originate(level, None);

                let Some(mut link) = self.link_top(ifindex) else {
                    return;
                };

                if link.is_p2p() {
                    // 7.3.17 Making the update reliable.
                    //
                    // When a point-to-point circuit (including non-DA DED circuits and virtual
                    // links) starts (or restarts), the IS shall
                    //
                    // a) set SRMflag for that circuit on all LSPs, and
                    srm_set_for_all_lsp(&mut link, level);

                    // b) send a Complete set of Complete Sequence Numbers PDUs on that circuit.
                    *link.timer.csnp.get_mut(&level) = Some(csnp_timer(&link, level));
                }
            }
            Message::LspSeqWrapClear(level, frag_id) => {
                self.process_lsp_seq_wrap_clear(level, frag_id);
            }
            Message::BfdSubscribe(key) => {
                self.process_bfd_subscribe(key);
            }
            Message::BfdUnsubscribe(key) => {
                self.process_bfd_unsubscribe(key);
            }
            Message::StampReconcile(ifindex) => {
                self.stamp_reconcile_link(ifindex);
            }
            Message::GrRestartExit => {
                // Drain window elapsed. The supervisor (systemd /
                // operator) is trusted to restart us. Kernel routes
                // tagged RibType::Isis survive because no
                // ProtoCleanup is dispatched.
                tracing::info!("[GR Restart] drain complete; exiting process");
                std::process::exit(0);
            }
            Message::GrRestartAbort => {
                // Auto-abort fired (grace window expired without
                // exit-success). Per RFC 5306 §3.1, exit-failure
                // means we set the OL bit on our self-LSPs and
                // resume operation as a last-resort transit; the
                // OL clears 30s later (Message::ClearOverload).
                tracing::warn!(
                    "[GR Restart] grace window expired without exit-success; setting OL bit"
                );
                self.gr_restart_expire();
            }
            Message::GrNeighborUp(sys_id) => {
                self.gr_check_exit_success(sys_id);
            }
            Message::ClearOverload => {
                self.clear_overload();
            }
            Message::GrT1Tick => {
                if self.restarting.is_some() {
                    self.kick_hello_all_links();
                }
            }
            Message::EgressRetentionExpire { level, locator } => {
                let mut top = self.top();
                egress_retention_expire(&mut top, level, locator);
            }
        }
    }

    /// Forward a `Subscribe` to the BFD instance with `"isis"` as the
    /// ClientId. No-op when BFD is not configured.
    /// Drive the BGP-LS producer (RFC 9552): re-walk the LSDB, diff against
    /// the last-advertised set, and push add/withdraw deltas to BGP. The
    /// three field borrows are disjoint, so this `&mut self` method composes
    /// cleanly. No-op when BGP isn't wired (`bgp_tx` is `None`).
    fn bgp_ls_produce(&mut self) {
        super::bgp_ls::produce(
            &self.lsdb,
            &mut self.bgp_ls_advertised,
            self.bgp_tx.as_ref(),
        );
    }

    fn process_bfd_subscribe(&self, key: crate::bfd::session::SessionKey) {
        let Some(tx) = self.bfd_client_tx.as_ref() else {
            if self.tracing.should_trace_bfd() {
                tracing::debug!(?key, "isis: bfd not configured; skipping subscribe");
            }
            return;
        };
        // Resolve the interface's effective offload config (per-interface
        // `bfd {}` merged over the instance-level `router isis { bfd {} }`
        // default) and pass it in the session params. The BFD instance gates
        // Echo further to single-hop with a live reflector; both families
        // work (a v6 adjacency runs Echo over the link-local pair).
        let eff = self
            .links
            .get(&key.ifindex)
            .map(|l| l.config.bfd.resolve(&self.config.bfd))
            .unwrap_or_else(|| super::link::LinkBfdConfig::default().resolve(&self.config.bfd));
        let (echo_mode, echo_rx_us, echo_tx_us) = match eff.echo_mode {
            Some(mode) => (
                mode,
                eff.echo_receive_ms.saturating_mul(1000),
                eff.echo_transmit_ms.saturating_mul(1000),
            ),
            None => (crate::bfd::session::EchoMode::Off, 0, 0),
        };
        let _ = tx.send(crate::bfd::inst::ClientReq::Subscribe {
            client: "isis".to_string(),
            key,
            // Only the offload params (Echo + detect-offload) are wired here;
            // everything else uses the BFD session defaults.
            params: crate::bfd::session::SessionParams {
                echo_mode,
                required_min_echo_rx_us: echo_rx_us,
                echo_transmit_us: echo_tx_us,
                detect_offload: eff.detect_offload,
                ..crate::bfd::session::SessionParams::default()
            },
            notifier: self.bfd_event_tx.clone(),
        });
    }

    /// Re-evaluate BFD for every Up adjacency on every interface — used by the
    /// `bfd {}` config callbacks (per-interface and instance-level), whose
    /// changes (notably a blanket `enable`) affect adjacencies that are already
    /// Up. Subscribe / Unsubscribe is idempotent at the BFD instance (keyed by
    /// client+key), so we can re-drive without tracking per-adjacency state;
    /// a re-Subscribe also applies Echo-param changes to the live session
    /// (`Bfd::update_echo_params`), so flipping `echo-mode` at runtime takes
    /// effect on commit.
    pub(crate) fn bfd_reconcile_all(&self) {
        if self.bfd_client_tx.is_none() {
            return;
        }
        let mut actions: Vec<(crate::bfd::session::SessionKey, bool)> = Vec::new();
        for (ifindex, link) in self.links.iter() {
            let enable = link.config.bfd.resolve(&self.config.bfd).enable;
            let local_v4 = link.state.v4addr.first().map(|p| p.addr());
            let local_v6ll = link.state.v6laddr.first().map(|p| p.addr());
            for level in [Level::L1, Level::L2] {
                for nbr in link.state.nbrs.get(&level).values() {
                    if nbr.state != NfsmState::Up {
                        continue;
                    }
                    // v4-preferred / v6-link-local fallback, same selection as
                    // the NFSM subscribe path (see packet::bfd_session_key).
                    let remote_v4 = nbr.addr4.keys().next().copied();
                    let remote_v6ll = nbr.addr6l.first().copied();
                    let Some((local, remote)) = super::packet::bfd_session_addrs(
                        local_v4,
                        remote_v4,
                        local_v6ll,
                        remote_v6ll,
                    ) else {
                        continue;
                    };
                    let key = crate::bfd::session::SessionKey {
                        local,
                        remote,
                        ifindex: *ifindex,
                        multihop: false,
                    };
                    actions.push((key, enable));
                }
            }
        }
        for (key, enable) in actions {
            if enable {
                self.process_bfd_subscribe(key);
            } else {
                self.process_bfd_unsubscribe(key);
            }
        }
    }

    /// Forward an `Unsubscribe` to the BFD instance. No-op when BFD
    /// is not configured.
    fn process_bfd_unsubscribe(&self, key: crate::bfd::session::SessionKey) {
        let Some(tx) = self.bfd_client_tx.as_ref() else {
            return;
        };
        let _ = tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
            client: "isis".to_string(),
            key,
        });
    }

    /// Re-evaluate the STAMP measurement session for every interface —
    /// the `ConfigOp::CommitEnd` hook, so any committed change that can
    /// flip a session (measurement enable/interval, network-type, afi
    /// enable, ...) is reconciled without per-callback wiring.
    pub(crate) fn stamp_reconcile_all(&mut self) {
        if self.stamp_client_tx.is_none() {
            return;
        }
        let ifindexes: Vec<u32> = self.links.iter().map(|(ifindex, _)| *ifindex).collect();
        for ifindex in ifindexes {
            self.stamp_reconcile_link(ifindex);
        }
    }

    /// Diff the measurement session this link *should* hold (config
    /// enabled ∧ P2P circuit ∧ an Up adjacency ∧ a usable address pair)
    /// against the tracked subscription, and (un)subscribe on the
    /// edges only. Tearing a session down also clears the link's
    /// measured values — they must not survive into the next adjacency
    /// (or stay advertised after a disable) — and re-originates.
    pub(crate) fn stamp_reconcile_link(&mut self, ifindex: u32) {
        if self.stamp_client_tx.is_none() {
            return;
        }
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };

        // Desired session for the current config + adjacency state.
        // Same address selection as `bfd_reconcile_all`: v4-preferred /
        // v6-link-local fallback, the interface's own address × the
        // first Up neighbor's (P2P has at most one neighbor per level).
        // A v6-only adjacency thus yields a link-local v6 session whose
        // scope is the link's ifindex.
        let desired = if link.config.te_metric_measurement.enabled() && link.is_p2p() {
            let local_v4 = link.state.v4addr.first().map(|p| p.addr());
            let local_v6ll = link.state.v6laddr.first().map(|p| p.addr());
            let nbr = [Level::L1, Level::L2].iter().find_map(|level| {
                link.state
                    .nbrs
                    .get(level)
                    .values()
                    .find(|nbr| nbr.state == NfsmState::Up)
            });
            let remote_v4 = nbr.and_then(|n| n.addr4.keys().next().copied());
            let remote_v6ll = nbr.and_then(|n| n.addr6l.first().copied());
            super::packet::bfd_session_addrs(local_v4, remote_v4, local_v6ll, remote_v6ll).map(
                |(local, remote)| {
                    (
                        crate::stamp::session::SessionKey {
                            local,
                            remote,
                            ifindex,
                        },
                        link.config.te_metric_measurement.resolve(),
                    )
                },
            )
        } else {
            None
        };

        if desired == link.state.stamp_session {
            return;
        }
        let stale = link.state.stamp_session;
        if let Some((key, _)) = stale {
            self.stamp_unsubscribe(key);
        }
        if let Some((key, params)) = desired {
            self.stamp_subscribe(key, params);
        }
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.state.stamp_session = desired;
        // A torn-down session's measured values are stale the moment
        // the subscription ends — clear and re-advertise (static
        // config, if any, takes back over via `te_metric_effective`).
        if stale.is_some() && link.state.measured_te_metric != super::link::LinkTeMetric::default()
        {
            link.state.measured_te_metric = super::link::LinkTeMetric::default();
            let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
            let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
        }
    }

    fn stamp_subscribe(
        &self,
        key: crate::stamp::session::SessionKey,
        params: crate::stamp::session::SessionParams,
    ) {
        let Some(tx) = self.stamp_client_tx.as_ref() else {
            return;
        };
        let _ = tx.send(crate::stamp::client::ClientReq::Subscribe {
            client: self.proto_label.clone(),
            key,
            params,
            notifier: self.stamp_event_tx.clone(),
        });
    }

    fn stamp_unsubscribe(&self, key: crate::stamp::session::SessionKey) {
        let Some(tx) = self.stamp_client_tx.as_ref() else {
            return;
        };
        let _ = tx.send(crate::stamp::client::ClientReq::Unsubscribe {
            client: self.proto_label.clone(),
            key,
        });
    }

    /// A damped STAMP export arrived: store the measured values on the
    /// link and re-originate so the RFC 8570 sub-TLVs (and flex-algo
    /// metric-type-1 SPF inputs) reflect them. A `None` snapshot
    /// clears — the sub-TLVs are withdrawn unless static config backs
    /// them ([`super::link::IsisLink::te_metric_effective`]).
    pub(crate) fn process_stamp_event(&mut self, event: crate::stamp::client::StampEvent) {
        let crate::stamp::client::StampEvent::MetricUpdate { key, snapshot } = event;
        let Some(link) = self.links.get_mut(&key.ifindex) else {
            return;
        };
        // Only the tracked session may write — a late event from a
        // just-unsubscribed key must not resurrect stale values.
        if link.state.stamp_session.map(|(k, _)| k) != Some(key) {
            return;
        }
        link.state.measured_te_metric = match snapshot {
            Some(snap) => super::link::LinkTeMetric {
                unidirectional_delay: Some(snap.avg),
                min_delay: Some(snap.min),
                max_delay: Some(snap.max),
                delay_variation: Some(snap.variation),
                loss: None,
            },
            None => super::link::LinkTeMetric::default(),
        };
        tracing::info!(
            ifindex = key.ifindex,
            ?snapshot,
            "isis: stamp metric update applied"
        );
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }

    fn process_lsp_originate(&mut self, level: Level, seq_floor: Option<u32>) {
        if !has_level(self.config.is_type(), level) {
            return;
        }
        let mut top = self.top();
        // lsp_generate returns an empty Vec when origination is
        // suppressed (seq-wrap freeze active). It otherwise returns
        // one IsisLsp per fragment of the self-originated set
        // (fragment 0 always present plus N higher-numbered fragments
        // when distributable TLVs exceed lsp_mtu_size).
        let fragments = lsp_generate(&mut top, level, seq_floor);
        if fragments.is_empty() {
            return;
        }

        // Highest fragment id produced this round; trailing fragments
        // beyond this need to be purged from the LSDB so peers flush
        // stale state (a fragment that becomes empty after a topology
        // shrink stays in the LSDB until we emit a RemainingLifetime=0
        // version of it).
        let max_frag = fragments
            .iter()
            .map(|l| l.lsp_id.fragment_id())
            .max()
            .unwrap_or(0);

        // Multi-fragment originations get a single trace line at the
        // top of the burst — easier to follow than scanning N separate
        // `[LspOriginate]` lines for a fragmented set. Logged only
        // when there's actual fragmentation since the per-fragment
        // detail is already covered by `lsp_generate`.
        if fragments.len() > 1 {
            let total_bytes: usize = fragments.iter().map(|l| l.pdu_len as usize).sum();
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "[LspFragPack] {} fragments emitted, {} bytes total",
                fragments.len(),
                total_bytes
            );
        }

        let auth_cfg = super::lsp::level_auth_cfg(top.config, level).clone();
        let resolved = super::auth::resolve_send(&auth_cfg, top.key_chains, chrono::Utc::now());
        for mut frag in fragments {
            let buf = lsp_emit(&mut frag, level, resolved.as_ref());
            let lsp_id = frag.lsp_id;
            insert_self_originate(&mut top, level, frag, Some(buf.to_vec()));
            top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
        }

        // Tail-purge: any self-originated fragment with a fragment_id
        // above what we just produced is orphaned — its TLVs migrated
        // into a lower fragment on this build (or the originator's
        // total TLV footprint shrank). Send a Purge for each so the
        // network flushes them; the standard purge path emits a
        // RemainingLifetime=0 LSP at a bumped seq.
        let self_sys = self.config.net.sys_id();
        let orphans: Vec<IsisLspId> = self
            .lsdb
            .get(&level)
            .iter()
            .filter(|(id, lsa)| {
                lsa.originated
                    && id.sys_id() == self_sys
                    && !id.is_pseudo()
                    && id.fragment_id() > max_frag
            })
            .map(|(id, _)| *id)
            .collect();
        for lsp_id in orphans {
            let _ = self.tx.send(Message::LspPurge(level, lsp_id));
        }
    }

    /// Throttle-aware front door for self-LSP origination. Multiple
    /// triggers (config edits, AdjacencyUp, peer-flooded-our-LSP-back)
    /// arriving within the lsp-gen-interval window coalesce into a
    /// single `process_lsp_originate` run. The seq-number floor is
    /// folded across the burst as `max(existing, new)` so the
    /// resulting LSP bumps past the highest seq any peer demanded.
    fn schedule_lsp_originate(&mut self, level: Level, seq_floor: Option<u32>) {
        // Fold this event's seq_floor into the burst-wide accumulator.
        let pending = self.lsp_gen_pending_floor.get_mut(&level);
        *pending = match (*pending, seq_floor) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };

        // Already armed — the in-flight run will consume the accumulator.
        if self.lsp_gen_timer.get(&level).is_some() {
            return;
        }

        let wait_ms = self.lsp_gen_throttle.get_mut(&level).schedule(
            self.config.lsp_gen_initial_wait(),
            self.config.lsp_gen_secondary_wait(),
            self.config.lsp_gen_maximum_wait(),
        );

        let tx = self.tx.clone();
        *self.lsp_gen_timer.get_mut(&level) = Some(Timer::once_ms(wait_ms as u64, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::LspGenFire(level));
            }
        }));
    }

    fn process_lsp_purge(&mut self, level: Level, lsp_id: IsisLspId) {
        // Capture sys-id before `self.top()` takes the mutable borrow
        // of `self.config`; needed for the RFC 6232 POI stamp below.
        let own_sys_id = self.config.net.sys_id();
        let mut top = self.top();

        // Get current LSP if it exists. `saturating_add` so the
        // seq-number-wrap purge path (existing = u32::MAX - 1) emits
        // a final LSP at u32::MAX without panicking; the freeze
        // installed by lsp_generate then prevents a follow-on bump.
        let seq_number = if let Some(existing) = top.lsdb.get(&level).get(&lsp_id) {
            existing.lsp.seq_number.saturating_add(1)
        } else {
            isis_event_trace!(
                self.tracing,
                LspPurge,
                &level,
                "Cannot purge LSP {} - not found in LSDB",
                lsp_id
            );
            return;
        };

        // Create purged LSP with incremented sequence number. Body
        // construction lives in `build_self_originated_purge` so
        // the RFC 6232 POI stamp is unit-testable without standing
        // up the full instance.
        let mut purged_lsp = build_self_originated_purge(lsp_id, seq_number, level, own_sys_id);

        // Emit and flood the purged LSP. Purge auth follows
        // RFC 6232: the zero-lifetime LSP still carries the
        // per-level Auth TLV so receivers can verify it.
        let auth_cfg = super::lsp::level_auth_cfg(top.config, level).clone();
        let resolved = super::auth::resolve_send(&auth_cfg, top.key_chains, chrono::Utc::now());
        // The encoded purge MUST be handed to `insert_self_originate`
        // — `srm_advertise` reads `lsa.bytes` to flood, and an empty
        // bytes vector silently drops the send. Previously the buf
        // was discarded, so the POI stamp landed in the LSDB but
        // never reached peers.
        let buf = lsp_emit(&mut purged_lsp, level, resolved.as_ref());
        insert_self_originate(&mut top, level, purged_lsp, Some(buf.to_vec()));

        top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
    }

    /// ISO 10589 §7.3.16.4 wait expired for one specific fragment:
    /// drop the per-fragment freeze entry, drop that fragment's
    /// purged self-LSP record from the local LSDB so the next
    /// `lsp_generate` sees no existing entry and computes seq = 1
    /// for it, then kick LSP origination.
    fn process_lsp_seq_wrap_clear(&mut self, level: Level, frag_id: u8) {
        isis_event_trace!(
            self.tracing,
            LspOriginate,
            &level,
            "[LspSeqWrap] fragment {} MaxAge wait expired — clearing freeze and re-originating from seq 1",
            frag_id
        );
        self.lsp_seq_wrap_wait.get_mut(&level).remove(&frag_id);

        let lsp_id = IsisLspId::new(self.config.net.sys_id(), 0, frag_id);
        self.lsdb.get_mut(&level).remove(&lsp_id);

        let _ = self.tx.send(Message::LspOriginate(level, None));
    }

    fn process_dis_originate(
        &mut self,
        level: Level,
        neighbor_id: IsisNeighborId,
        base: Option<u32>,
    ) {
        if !has_level(self.config.is_type(), level) {
            return;
        }
        let mut top = self.top();

        let Some(ifindex) = resolve_dis_ifindex(top.links, level, neighbor_id) else {
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "[DisOriginate] no DIS link found for {} at {} - skip",
                neighbor_id,
                level
            );
            return;
        };

        // dis_generate returns the per-fragment Vec for this
        // pseudonode (fragment 0 always present; higher fragments
        // when the LAN's neighbor list spills past lsp_mtu_size).
        // Empty Vec = the link no longer holds the DIS adjacency or
        // (future) a freeze is in effect.
        let fragments = dis_generate(&mut top, level, ifindex, base);
        if fragments.is_empty() {
            return;
        }

        let max_frag = fragments
            .iter()
            .map(|l| l.lsp_id.fragment_id())
            .max()
            .unwrap_or(0);

        let auth_cfg = super::lsp::level_auth_cfg(top.config, level).clone();
        let resolved = super::auth::resolve_send(&auth_cfg, top.key_chains, chrono::Utc::now());
        for mut frag in fragments {
            let buf = lsp_emit(&mut frag, level, resolved.as_ref());
            let lsp_id = frag.lsp_id;
            insert_self_originate(&mut top, level, frag, Some(buf.to_vec()));
            top.lsdb.get_mut(&level).srm_set_all(top.tx, level, &lsp_id);
        }

        // Tail-purge: prior pseudonode fragments above `max_frag`
        // for this specific (sys_id, pseudo_id) are orphaned and
        // must be retired so peers flush them. Same shape as the
        // router-LSP tail-purge in `process_lsp_originate`, but
        // keyed on the pseudonode's neighbor id rather than our
        // own sys-id.
        let self_sys = self.config.net.sys_id();
        let pseudo_id = neighbor_id.pseudo_id();
        let orphans: Vec<IsisLspId> = self
            .lsdb
            .get(&level)
            .iter()
            .filter(|(id, lsa)| {
                lsa.originated
                    && id.sys_id() == self_sys
                    && id.pseudo_id() == pseudo_id
                    && id.is_pseudo()
                    && id.fragment_id() > max_frag
            })
            .map(|(id, _)| *id)
            .collect();
        for lsp_id in orphans {
            let _ = self.tx.send(Message::LspPurge(level, lsp_id));
        }
    }

    fn process_ifsm(&mut self, ev: IfsmEvent, ifindex: u32, level: Option<Level>) {
        let Some(mut top) = self.link_top(ifindex) else {
            return;
        };
        match ev {
            IfsmEvent::Start => {
                ifsm::start(&mut top);
            }
            IfsmEvent::Stop => {
                ifsm::stop(&mut top);
            }
            IfsmEvent::HelloTimerExpire => {
                if let Some(level) = level {
                    let _ = ifsm::hello_send(&mut top, level);
                }
            }
            IfsmEvent::CsnpTimerExpire => {
                if let Some(level) = level {
                    csnp_send(&mut top, level);
                }
            }
            IfsmEvent::HelloOriginate => match level {
                Some(level) => ifsm::hello_originate(&mut top, level),
                None => {
                    // In case of level is None, originate both L1/L2 Hello.
                    ifsm::hello_originate(&mut top, Level::L1);
                    ifsm::hello_originate(&mut top, Level::L2);
                }
            },
            IfsmEvent::DisSelection => match level {
                Some(level) => {
                    ifsm::dis_selection(&mut top, level);
                }
                None => {
                    // ifsm::dis_selection(&mut top, Level::L1);
                    // ifsm::dis_selection(&mut top, Level::L2);
                }
            },
        }
    }

    fn process_lsdb(&mut self, ev: LsdbEvent, level: Level, key: IsisLspId) {
        use LsdbEvent::*;
        // RFC 5306 §3.1: during restart, we MUST NOT re-originate
        // our self-LSPs at a higher sequence number — helpers
        // would treat the bump as a topology change and trip their
        // MaxSeqAdvance recovery, tearing the restart down. Skip
        // both expiry arms: refresh would bump seq, and removal
        // would age out the restored LSPs that 5e-i parked here.
        // Timers keep ticking; the post-restart `restarting=None`
        // path picks up normal cadence on the next expiry.
        if self.restarting.is_some() {
            return;
        }
        let mut top = self.top();
        match ev {
            RefreshTimerExpire => {
                lsdb::refresh_lsp(&mut top, level, key);
            }
            HoldTimerExpire => {
                lsdb::remove_lsp(&mut top, level, key);
            }
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => break,
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        loop {
            tokio::select! {
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
                Some(msg) = self.sr_rx.recv() => {
                    self.process_sr_rx(msg);
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    self.process_bfd_event(event);
                }
                Some(event) = self.stamp_event_rx.recv() => {
                    self.process_stamp_event(event);
                }
                Some(msg) = self.policy_rx.recv() => {
                    self.process_policy_msg(msg);
                }
            }
        }
    }

    /// Handle a `PolicyRx` push from the policy actor. Today we only
    /// subscribe to key-chain updates (area/domain-password and
    /// per-link `hello-authentication`). LSP sign / verify resolve
    /// lazily per packet, so all this needs to do is keep the
    /// snapshot fresh and re-fire `LspOriginate` at the affected
    /// level when an area / domain-password chain edit lands so
    /// peers see a new signature on the next refresh without
    /// waiting for the periodic timer.
    fn process_policy_msg(&mut self, msg: crate::policy::PolicyRx) {
        match msg {
            crate::policy::PolicyRx::KeyChain {
                name,
                policy_type,
                key_chain,
                ..
            } => {
                if let Some(kc) = key_chain {
                    self.key_chains.insert(name, kc);
                } else {
                    self.key_chains.remove(&name);
                }
                if let crate::policy::PolicyType::KeyChain(scope) = policy_type {
                    use crate::policy::KeyChainScope;
                    match scope {
                        KeyChainScope::IsisAreaPw => {
                            let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
                        }
                        KeyChainScope::IsisDomainPw => {
                            let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
                        }
                        // IIH / non-IS-IS scopes: next hello-timer fire
                        // (or remote subsystem) picks up the new key
                        // lazily; no proactive event needed.
                        _ => {}
                    }
                }
            }
            crate::policy::PolicyRx::PrefixSet { .. }
            | crate::policy::PolicyRx::PolicyList { .. } => {}
        }
    }

    /// Resolve the `(level, sys_id)` of the neighbour a BFD session belongs to
    /// by matching `key.remote` against the neighbour's addresses on the
    /// session's interface — `addr4` for an IPv4 session, the link-local
    /// `addr6l` (or global `addr6`) for an IPv6 session. `require_up` restricts
    /// the match to Up adjacencies (the Down path only tears an Up neighbour);
    /// the Up path passes `false` because a held neighbour sits at Init.
    fn bfd_resolve_neighbor(
        &self,
        key: &crate::bfd::session::SessionKey,
        require_up: bool,
    ) -> Option<(Level, IsisSysId)> {
        let link = self.links.get(&key.ifindex)?;
        for level in [Level::L1, Level::L2] {
            let found = link.state.nbrs.get(&level).iter().find(|(_, nbr)| {
                if require_up && nbr.state != NfsmState::Up {
                    return false;
                }
                match key.remote {
                    std::net::IpAddr::V4(r) => nbr.addr4.contains_key(&r),
                    std::net::IpAddr::V6(r) => nbr.addr6l.contains(&r) || nbr.addr6.contains(&r),
                }
            });
            if let Some((sys_id, _)) = found {
                return Some((level, *sys_id));
            }
        }
        None
    }

    /// Handle a [`crate::bfd::inst::BfdEvent`] forwarded by the BFD instance.
    /// RFC 5882: a session going **Down** is a path-failure for the IS-IS
    /// adjacency — tear it down and pin it in hold-down ([`Self::process_bfd_down`]);
    /// a session coming **Up** lifts that pin ([`Self::process_bfd_up`]).
    ///
    /// Synthetic Down→Down events (emitted by `Bfd::subscribe` so a new
    /// subscriber can act on the current state immediately) carry no real
    /// transition and are ignored.
    pub fn process_bfd_event(&mut self, event: crate::bfd::inst::BfdEvent) {
        let crate::bfd::inst::BfdEvent::StateChange { key, change } = event;
        if self.tracing.should_trace_bfd() {
            tracing::info!(
                ?key,
                from = %change.from,
                to = %change.to,
                diag = %change.diag,
                "isis: bfd session state change",
            );
        }

        if change.from == change.to {
            return;
        }
        match change.to {
            bfd_packet::State::Down => self.process_bfd_down(&key, &change),
            bfd_packet::State::Up => self.process_bfd_up(&key),
            // Init / AdminDown are not actionable for the adjacency.
            _ => {}
        }
    }

    /// BFD session went Down: tear the adjacency (RFC 5882 §5) and pin it in
    /// hold-down so subsequent IIHs cannot re-promote it. The BFD session is
    /// kept subscribed (`release_bfd = false`) so it keeps probing and can
    /// detect the peer returning, at which point [`Self::process_bfd_up`]
    /// lifts the pin.
    ///
    /// `require_up = false`: the P2P 3-way rule may step the adjacency from
    /// Up → Init (peer stops reporting our sys-id) before this BFD Down event
    /// is processed. Using `require_up = true` would miss that neighbor, leave
    /// the hold-down pin unset, and allow the adjacency to recover while BFD
    /// is still Down.
    fn process_bfd_down(
        &mut self,
        key: &crate::bfd::session::SessionKey,
        change: &crate::bfd::session::StateChange,
    ) {
        let Some((level, sys_id)) = self.bfd_resolve_neighbor(key, false) else {
            if self.tracing.should_trace_bfd() {
                tracing::debug!(?key, "isis: bfd-down for unknown neighbor; ignoring");
            }
            return;
        };
        let ifindex = key.ifindex;
        // Capture the toggle before borrowing the link — `link_top` takes
        // `&mut self`, so `self.tracing` is unreachable while `link` is held.
        let trace_bfd = self.tracing.should_trace_bfd();
        let Some(mut link) = self.link_top(ifindex) else {
            return;
        };
        if trace_bfd {
            tracing::warn!(
                peer = %key.remote,
                ifindex,
                ?level,
                diag = %change.diag,
                "isis: tearing down adjacency on bfd-down (RFC 5882 §5)",
            );
        }
        // Capture the neighbour's nexthop addresses BEFORE the teardown
        // removes the entry — these are the exact keys SPF used for this
        // adjacency's routes (v4: interface addrs from TLV 132, v6: the
        // link-locals from TLV 232), i.e. the addresses the RIB's
        // protection groups key their primaries on.
        let mut failed_nhops: Vec<std::net::IpAddr> = Vec::new();
        if let Some(nbr) = link.state.nbrs.get(&level).get(&sys_id) {
            failed_nhops.extend(nbr.addr4.keys().copied().map(std::net::IpAddr::V4));
            failed_nhops.extend(nbr.addr6l.iter().copied().map(std::net::IpAddr::V6));
        }
        // Tear the adjacency but keep the BFD session probing. This clears any
        // prior hold-down pin, so set the pin afterwards.
        nbr_hold_timer_expire(&mut link, level, sys_id, false);
        link.state.bfd_holddown.get_mut(&level).insert(sys_id);
        // Record the reverse mapping so process_bfd_up can clear the pin even
        // if the neighbour entry is absent from `nbrs` at that point (race:
        // BFD Up fires before the next IIH re-creates the entry).
        link.state.bfd_holddown_nbr.insert(*key, (level, sys_id));
        // Fast-reroute switchover (kernel-failover phase 3): rewire the
        // pre-installed protection groups onto their TI-LFA repairs NOW,
        // before the LSP regeneration / SPF / per-prefix reinstall pipeline
        // even starts. One message per failed nexthop address; the RIB
        // no-ops when nothing is protected. Channel ordering guarantees
        // this lands before the post-convergence route updates.
        for addr in failed_nhops {
            let _ = self.ctx.rib.protect_switch(addr);
        }
    }

    /// BFD session came Up: lift any hold-down pin for the neighbour so the
    /// next received IIH promotes its adjacency back to Up. A no-op when the
    /// neighbour was not held (e.g. the normal first-Up after adjacency form).
    fn process_bfd_up(&mut self, key: &crate::bfd::session::SessionKey) {
        // Primary path: resolve via the live neighbour entry in `nbrs`.
        let resolved = self.bfd_resolve_neighbor(key, false);

        // Fallback: if the neighbour entry was removed from `nbrs` by
        // nbr_hold_timer_expire (BFD Down → teardown) but BFD came back Up
        // before the next IIH re-created the entry, use the reverse map that
        // process_bfd_down recorded.
        let (level, sys_id) = match resolved {
            Some(pair) => pair,
            None => {
                let Some(link) = self.links.get_mut(&key.ifindex) else {
                    return;
                };
                match link.state.bfd_holddown_nbr.remove(key) {
                    Some(pair) => {
                        if self.tracing.should_trace_bfd() {
                            tracing::info!(
                                peer = %key.remote,
                                ifindex = key.ifindex,
                                "isis: bfd recovered via fallback map (nbr not yet re-created)",
                            );
                        }
                        pair
                    }
                    None => return,
                }
            }
        };

        let Some(link) = self.links.get_mut(&key.ifindex) else {
            return;
        };
        // Also clean up the fallback map entry for this key (may already be
        // gone if the fallback path above consumed it).
        link.state.bfd_holddown_nbr.remove(key);
        // Lift the hold-down pin (the `remove` side-effect always runs); the
        // next received IIH re-promotes the held (Init) neighbour.
        let lifted = link.state.bfd_holddown.get_mut(&level).remove(&sys_id);
        if lifted && self.tracing.should_trace_bfd() {
            tracing::info!(
                peer = %key.remote,
                ifindex = key.ifindex,
                ?level,
                "isis: bfd recovered; lifting adjacency hold-down",
            );
        }
    }
    pub fn top(&mut self) -> IsisTop<'_> {
        IsisTop {
            tx: &self.tx,
            links: &mut self.links,
            config: &self.config,
            overloaded: self.overloaded,
            tracing: &self.tracing,
            lsdb: &mut self.lsdb,
            lsp_map: &mut self.lsp_map,
            reach_map: &mut self.reach_map,
            reach_map_v6: &mut self.reach_map_v6,
            mt2_reach_map_v6: &mut self.mt2_reach_map_v6,
            mt_membership: &mut self.mt_membership,
            label_map: &mut self.label_map,
            srv6_end_map: &mut self.srv6_end_map,
            peer_fad: &mut self.peer_fad,
            peer_link_affinity: &mut self.peer_link_affinity,
            peer_algo_sid: &mut self.peer_algo_sid,
            peer_algos: &mut self.peer_algos,
            peer_algo_srv6: &mut self.peer_algo_srv6,
            rib: &mut self.rib,
            rib_v6: &mut self.rib_v6,
            retained_locators: &mut self.retained_locators,
            egress_protect_registered: &mut self.egress_protect_registered,
            ilm: &mut self.ilm,
            rib_client: &self.ctx.rib,
            hostname: &mut self.hostname,
            spf_timer: &mut self.spf_timer,
            spf_throttle: &mut self.spf_throttle,
            spf_inflight: &mut self.spf_inflight,
            spf_pending: &mut self.spf_pending,
            spf_duration: &mut self.spf_duration,
            spf_last: &mut self.spf_last,
            tilfa_stats: &mut self.tilfa_stats,
            graph: &mut self.graph,
            spf_result: &mut self.spf_result,
            tilfa_result: &mut self.tilfa_result,
            mt2_graph: &mut self.mt2_graph,
            mt2_spf_result: &mut self.mt2_spf_result,
            graph_flex_algo: &mut self.graph_flex_algo,
            spf_flex_algo: &mut self.spf_flex_algo,
            rib_flex_algo: &mut self.rib_flex_algo,
            rib6_flex_algo: &mut self.rib6_flex_algo,
            flex_algo_srv6_export: &mut self.flex_algo_srv6_export,
            sr_block: &self.sr_block,
            sr_locator: &self.sr_locator,
            sr_end_sid: &self.sr_end_sid,
            sr_flex_algo_locators: &self.sr_flex_algo_locators,
            sr_flex_algo_end_sid: &self.sr_flex_algo_end_sid,
            srlg_groups: &self.srlg_groups,
            flex_algo: &self.flex_algo,
            affinity_map: &self.affinity_map,
            key_chains: &self.key_chains,
            lsp_seq_wrap_wait: &mut self.lsp_seq_wrap_wait,
            lsp_placement_memory: &mut self.lsp_placement_memory,
            redist_v4: &self.redist_v4,
            redist_v6: &self.redist_v6,
            mirror_labels: &self.mirror_labels,
        }
    }

    pub fn link_top<'a>(&'a mut self, ifindex: u32) -> Option<LinkTop<'a>> {
        self.links.get_mut(&ifindex).map(|link| LinkTop {
            ifindex: link.ifindex,
            tx: &self.tx,
            ptx: &link.ptx,
            up_config: &self.config,
            restarting: self.restarting.as_ref(),
            tracing: &self.tracing,
            lsdb: &mut self.lsdb,
            flags: &link.flags,
            config: &mut link.config,
            state: &mut link.state,
            timer: &mut link.timer,
            local_pool: &mut self.local_pool,
            hostname: &mut self.hostname,
            reach_map: &mut self.reach_map,
            reach_map_v6: &mut self.reach_map_v6,
            mt2_reach_map_v6: &mut self.mt2_reach_map_v6,
            mt_membership: &mut self.mt_membership,
            label_map: &mut self.label_map,
            srv6_end_map: &mut self.srv6_end_map,
            peer_fad: &mut self.peer_fad,
            peer_link_affinity: &mut self.peer_link_affinity,
            peer_algo_sid: &mut self.peer_algo_sid,
            peer_algos: &mut self.peer_algos,
            peer_algo_srv6: &mut self.peer_algo_srv6,
            spf_timer: &mut self.spf_timer,
            spf_throttle: &mut self.spf_throttle,
            rib_client: &self.ctx.rib,
            sr_locator: &self.sr_locator,
            watched_locator: &self.watched_locator,
            sr_flex_algo_locators: &self.sr_flex_algo_locators,
            watched_flex_algo_locators: &self.watched_flex_algo_locators,
            elib: &mut self.elib,
            key_chains: &self.key_chains,
        })
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.state.name.clone())
    }

    /// Compare desired block subscription against the currently-watched
    /// name and emit Watch / Unwatch messages so they match. Called after
    /// any config change that could affect `target_block_name`.
    ///
    /// On the unwatch transition we also drop the cached snapshot so a
    /// subsequent re-subscription doesn't show a stale value during the
    /// gap between Watch and the RIB's reply.
    pub fn reconcile_block_watch(&mut self) {
        let desired = target_block_name(&self.config);
        if desired == self.watched_block {
            return;
        }
        if let Some(prev) = self.watched_block.take() {
            let _ = self.ctx.rib.send(rib::Message::SrBlockUnwatch {
                proto: "isis".into(),
                name: prev,
            });
            self.sr_block = None;
        }
        if let Some(next) = desired {
            let _ = self.ctx.rib.send(rib::Message::SrBlockWatch {
                proto: "isis".into(),
                name: next.clone(),
            });
            self.watched_block = Some(next);
        }
    }

    /// Reconcile `local_pool` against the current SR-MPLS gate and the
    /// watched block's SRLB. Creates the pool when SR-MPLS is enabled
    /// and the RIB has handed us an SRLB; drops it otherwise.
    ///
    /// Idempotent: a pool that already exists is kept (alloc/release
    /// state stays intact) even if the SRLB snapshot is re-delivered
    /// with the same bounds. A change in SRLB bounds while SR-MPLS
    /// stays enabled is not reflected — operators changing the block
    /// mid-life is a follow-up concern and would invalidate every
    /// adjacency-SID label already handed out.
    pub fn reconcile_local_pool(&mut self) {
        let srlb = self.sr_block.as_ref().and_then(|b| b.local.as_ref());
        match (self.config.sr_mpls_enabled, srlb) {
            (true, Some(srlb)) => {
                if self.local_pool.is_none() {
                    // LabelBlock is half-open `[start, end)`; LabelPool's
                    // `end` is inclusive (last allocable label), hence
                    // the `- 1`.
                    self.local_pool = Some(LabelPool::new(
                        srlb.start as usize,
                        Some(srlb.end.saturating_sub(1) as usize),
                    ));
                }
            }
            _ => {
                // Drop the pool. Any labels still cached on neighbor
                // addr4 entries become orphaned but stop short of
                // producing fresh MPLS installs — `nbr_hello_interpret`
                // and `lsp_generate` both gate on `local_pool` /
                // `value.label` being present.
                self.local_pool = None;
            }
        }
    }

    /// Mirror of `reconcile_block_watch` for the SRv6 locator name(s).
    ///
    /// Reconciles BOTH the base (algorithm 0) locator and every
    /// per-Flex-Algorithm locator binding
    /// (`IsisConfig::sr_srv6_flex_algo_locators`, gated on SRv6 being
    /// enabled). Watch / Unwatch is computed against the *union* of all
    /// subscribed names so a name shared by the base and a flex-algo (or
    /// by two flex-algos) is never double-unwatched while another algo
    /// still needs it.
    pub fn reconcile_locator_watch(&mut self) {
        let desired_base = target_locator_name(&self.config);
        let desired_flex: BTreeMap<u8, String> = if self.config.sr_srv6_enabled {
            self.config.sr_srv6_flex_algo_locators.clone()
        } else {
            BTreeMap::new()
        };

        // Union of names we currently watch vs. the union we want.
        let mut current_names: BTreeSet<String> = BTreeSet::new();
        current_names.extend(self.watched_locator.clone());
        current_names.extend(self.watched_flex_algo_locators.values().cloned());
        let mut desired_names: BTreeSet<String> = BTreeSet::new();
        desired_names.extend(desired_base.clone());
        desired_names.extend(desired_flex.values().cloned());

        for name in current_names.difference(&desired_names) {
            let _ = self.ctx.rib.send(rib::Message::SrLocatorUnwatch {
                proto: "isis".into(),
                name: name.clone(),
            });
        }
        for name in desired_names.difference(&current_names) {
            let _ = self.ctx.rib.send(rib::Message::SrLocatorWatch {
                proto: "isis".into(),
                name: name.clone(),
            });
        }

        // Base (algo-0) snapshot / Node SID / End.X reconcile, unchanged
        // in spirit from the single-locator version.
        if desired_base != self.watched_locator {
            if self.watched_locator.is_some() {
                self.sr_locator = None;
                self.update_end_sid();
                self.update_mirror_sids();
                self.update_mirror_context_routes();
                self.update_mirror_labels();
                self.update_mirror_context_labels();
                self.clear_all_endx_sids();
            }
            self.watched_locator = desired_base;
        }

        // Per-algo: drop snapshots + Node SIDs for algos that were
        // removed or repointed at a different locator name. The fresh
        // snapshot for any (re)added name arrives on `sr_rx` and is
        // applied in `process_sr_rx`.
        let stale: Vec<u8> = self
            .watched_flex_algo_locators
            .iter()
            .filter(|(algo, name)| desired_flex.get(algo) != Some(name))
            .map(|(algo, _)| *algo)
            .collect();
        for algo in stale {
            self.sr_flex_algo_locators.remove(&algo);
            self.update_flex_algo_end_sid(algo);
            self.watched_flex_algo_locators.remove(&algo);
        }
        for (algo, name) in desired_flex {
            self.watched_flex_algo_locators.insert(algo, name);
        }
    }

    /// Per-algo twin of `update_end_sid`: reconcile the algorithm-N
    /// node (End / uN) SID registration against the current per-algo
    /// locator snapshot. Distinct per-algo locator prefixes mean each
    /// SID has a distinct address, so the RIB registry (keyed by addr)
    /// never collides across algorithms.
    fn update_flex_algo_end_sid(&mut self, algo: u8) {
        if let Some(prev) = self.sr_flex_algo_end_sid.remove(&algo) {
            let _ = self.ctx.rib.send(rib::Message::SidDel { addr: prev });
        }
        if let Some(locator) = self.sr_flex_algo_locators.get(&algo)
            && let Some(addr) = locator.node_sid_addr()
            && let Some(loc_name) = self.watched_flex_algo_locators.get(&algo).cloned()
        {
            let (behavior, structure) = match locator.behavior {
                Some(LocatorBehavior::Usid) => (SidBehavior::UN, locator.sid_structure()),
                None => (SidBehavior::End, None),
            };
            let sid = Sid {
                addr,
                behavior,
                context: SidContext::None,
                owner: SidOwner::new("isis", 0),
                locator: loc_name,
                allocation_type: SidAllocationType::Dynamic,
                ifindex: 0,
                nh6: None,
                structure,
                table_id: 0,
                segs: Vec::new(),
                flavors: locator.flavors,
            };
            let _ = self.ctx.rib.send(rib::Message::SidAdd { sid });
            self.sr_flex_algo_end_sid.insert(algo, addr);
        }
    }

    /// Withdraw every End.X (adjacency) SID and reset the ELIB pool.
    /// Used whenever the underlying locator changes (prefix swap,
    /// locator name change, locator removed): every previously-issued
    /// End.X address is invalidated, so we drop the registry rows and
    /// let the next Hello re-allocate from a fresh pool.
    fn clear_all_endx_sids(&mut self) {
        for link in self.links.values_mut() {
            for level in [Level::L1, Level::L2] {
                for nbr in link.state.nbrs.get_mut(&level).values_mut() {
                    nbr.release_endx_sid(&mut self.elib, &self.ctx.rib);
                }
            }
        }
        self.elib.reset();
    }

    /// Reconcile the End (Node) SID registration with the current
    /// locator snapshot. The End SID is the locator's first address
    /// (RFC 8986 §4.1 — End behavior, or RFC 9800 uN when the locator
    /// is uSID). On any transition (locator resolved/disappeared,
    /// prefix changed, behavior flipped, locator name swapped) we
    /// withdraw the previous SID before adding the new one so the
    /// registry is never double-booked at the same address — and so a
    /// classic↔uSID flip lands the right behavior + structure in the
    /// FIB even when the address itself didn't change.
    fn update_end_sid(&mut self) {
        // Always del-then-add on any reconcile call. The address might
        // be unchanged (classic↔uSID flip preserves it) but the
        // behavior or structure will differ, and the FIB needs the
        // updated install. The cost of an unnecessary del+add when
        // truly nothing changed is one channel round-trip; the cost of
        // skipping a real change is FIB drift.
        if let Some(prev) = self.sr_end_sid.take() {
            let _ = self.ctx.rib.send(rib::Message::SidDel { addr: prev });
        }
        if let Some(locator) = self.sr_locator.as_ref()
            && let Some(addr) = locator.node_sid_addr()
            && let Some(loc_name) = self.watched_locator.clone()
        {
            let (behavior, structure) = match locator.behavior {
                Some(LocatorBehavior::Usid) => (SidBehavior::UN, locator.sid_structure()),
                None => (SidBehavior::End, None),
            };
            let sid = Sid {
                addr,
                behavior,
                context: SidContext::None,
                owner: SidOwner::new("isis", 0),
                locator: loc_name,
                allocation_type: SidAllocationType::Dynamic,
                // End / uN is local-processing; ifindex=0 lets the RIB
                // resolve to its loopback link before pushing to the
                // FIB. nh6 has no meaning for End / uN.
                ifindex: 0,
                nh6: None,
                structure,
                // End / uN is local-processing, no table decap.
                table_id: 0,
                segs: Vec::new(),
                flavors: locator.flavors,
            };
            let _ = self.ctx.rib.send(rib::Message::SidAdd { sid });
            self.sr_end_sid = Some(addr);
        }
    }

    /// Mirror-context routing table id used by every End.M localsid this
    /// node installs (draft-ietf-rtgwg-srv6-egress-protection). A single
    /// shared table is correct because the protected egresses' service
    /// SIDs are globally-unique IPv6 addresses — they never collide — and
    /// it sidesteps per-node table allocation. Chosen high (0x4D = 'M') to
    /// stay clear of kernel VRF table ids and the well-known
    /// main/local/default tables.
    pub const MIRROR_CONTEXT_TABLE: u32 = 0x4D00_0000;

    /// Reconcile the End.M (Mirror SID) registrations with the current
    /// egress-protection config and the resolved SRv6 locator. Del-then-add
    /// the whole set on every call (cheap, and keeps the FIB in lock-step
    /// with config / locator churn). An entry installs only when it is on
    /// the SRv6 dataplane, has an explicit `mirror-sid`, and that SID falls
    /// inside this node's own locator — exactly the gate the LSP emit
    /// (`lsp::mirror_sid_subs`) uses, so advertisement and dataplane stay
    /// consistent. The mirror-context table is empty until the context-FIB
    /// population phase; the localsid still installs so the decap path
    /// exists.
    pub(crate) fn update_mirror_sids(&mut self) {
        for addr in std::mem::take(&mut self.installed_mirror_sids) {
            let _ = self.ctx.rib.send(rib::Message::SidDel { addr });
        }
        let (Some(loc_name), Some(local)) = (
            self.watched_locator.clone(),
            self.sr_locator.as_ref().and_then(|l| l.prefix),
        ) else {
            return;
        };
        let desired: Vec<std::net::Ipv6Addr> = self
            .config
            .egress_protections
            .values()
            .filter(|e| e.dataplane == super::egress_protection::MirrorDataplane::Srv6)
            .filter_map(|e| e.mirror_sid)
            .filter(|sid| local.contains(sid))
            .collect();
        for addr in desired {
            let sid = Sid {
                addr,
                behavior: SidBehavior::EndM,
                context: SidContext::None,
                owner: SidOwner::new("isis", 0),
                locator: loc_name.clone(),
                allocation_type: SidAllocationType::Dynamic,
                // End.M is local decap processing; ifindex=0 lets the RIB
                // resolve the loopback oif. nh6 has no meaning.
                ifindex: 0,
                nh6: None,
                structure: None,
                // Decapsulated inner packet is looked up in the shared
                // mirror-context table.
                table_id: Self::MIRROR_CONTEXT_TABLE,
                segs: Vec::new(),
                // Flavors don't apply to the End.M mirror decap.
                flavors: 0,
            };
            let _ = self.ctx.rib.send(rib::Message::SidAdd { sid });
            self.installed_mirror_sids.insert(addr);
        }
    }

    /// Reconcile the static `via-vrf` mirror-context routes with the
    /// current config and resolved locator. Gated identically to
    /// [`Self::update_mirror_sids`] (so a route installs exactly when its
    /// End.M decap is active) plus a configured `via-vrf`: install, in
    /// `MIRROR_CONTEXT_TABLE`, the protected locator → the local VRF, so
    /// the End.M decap resolves the protected egress's service SIDs into
    /// the CE-facing VRF. The RIB resolves the VRF name to a kernel table
    /// (skipping a not-yet-known VRF; the next reconcile re-sends it).
    pub(crate) fn update_mirror_context_routes(&mut self) {
        let context_table = Self::MIRROR_CONTEXT_TABLE;
        for prefix in std::mem::take(&mut self.installed_mirror_routes) {
            let _ = self.ctx.rib.send(rib::Message::MirrorRouteDel {
                prefix,
                context_table,
            });
        }
        let Some(local) = self.sr_locator.as_ref().and_then(|l| l.prefix) else {
            return;
        };
        let desired = super::egress_protection::desired_context_routes(
            &self.config.egress_protections,
            local,
        );
        for (prefix, vrf_name) in desired {
            let _ = self.ctx.rib.send(rib::Message::MirrorRouteAdd {
                prefix,
                context_table,
                vrf_name,
            });
            self.installed_mirror_routes.insert(prefix);
        }
    }

    /// Reconcile the SR-MPLS Mirror Context labels against the config.
    /// Each `dataplane: mpls` egress-protection entry gets one **context
    /// label** (RFC 8679), allocated from the SRLB `local_pool` and held
    /// stable in `mirror_labels` so the advertised label doesn't churn
    /// across LSP regenerations. Entries removed from the config release
    /// their label back to the pool. A label can only be allocated once
    /// SR-MPLS is enabled (the SRLB pool exists); a not-yet-allocatable
    /// entry is retried on the next reconcile (e.g. when the SRLB lands).
    ///
    /// Note: this reuses the SRLB local pool rather than a separate
    /// context-label band — it is the node's local-SID block, the natural
    /// home for a local binding label, and the ILM install (a later
    /// phase) distinguishes context labels by their entry type.
    pub(crate) fn update_mirror_labels(&mut self) {
        use super::egress_protection::MirrorDataplane;
        let desired: std::collections::BTreeSet<ipnet::IpNet> = self
            .config
            .egress_protections
            .values()
            .filter(|e| e.dataplane == MirrorDataplane::Mpls)
            .map(|e| e.protected_locator)
            .collect();
        // Release labels for entries no longer desired.
        let stale: Vec<ipnet::IpNet> = self
            .mirror_labels
            .keys()
            .filter(|k| !desired.contains(*k))
            .copied()
            .collect();
        for key in stale {
            if let Some(label) = self.mirror_labels.remove(&key)
                && let Some(pool) = self.local_pool.as_mut()
            {
                pool.release(label as usize);
            }
        }
        // Allocate for newly-desired entries (keeps existing allocations).
        for key in desired {
            if self.mirror_labels.contains_key(&key) {
                continue;
            }
            if let Some(pool) = self.local_pool.as_mut()
                && let Some(label) = pool.allocate()
            {
                self.mirror_labels.insert(key, label as u32);
            }
        }
    }

    /// Install the SR-MPLS Mirror Context ILM decap for this node's
    /// `dataplane: mpls` egress-protection entries: at each allocated
    /// context label, an `IlmType::ContextLabel` LFIB entry that pops the
    /// label and routes the inner packet into the configured `via-vrf`
    /// (RFC 8679). So when a failed egress's PLR redirects traffic to this
    /// protector with the context label on top, it decaps into the
    /// dual-homed VRF. Resolves `via-vrf` -> `(table_id, vrf_ifindex)` from
    /// `rib_known_vrfs` (populated by `VrfAdd`); an entry whose VRF isn't
    /// known yet is skipped and retried (the `VrfAdd` reconcile re-runs
    /// this). Del-then-add against `installed_mirror_ilm`.
    pub(crate) fn update_mirror_context_labels(&mut self) {
        // Withdraw the previous set. The netlink delete keys off the label
        // + owner, so a minimal entry suffices.
        for label in std::mem::take(&mut self.installed_mirror_ilm) {
            let ilm = rib::inst::IlmEntry {
                ilm_type: rib::inst::IlmType::ContextLabel {
                    table_id: 0,
                    vrf_ifindex: 0,
                },
                nexthop: rib::Nexthop::default(),
                ..rib::inst::IlmEntry::new(rib::RibType::Isis)
            };
            let _ = self.ctx.rib.send(rib::Message::IlmDel { label, ilm });
        }
        let desired = super::egress_protection::desired_context_labels(
            &self.config.egress_protections,
            &self.mirror_labels,
            &self.rib_known_vrfs,
        );
        for (label, table_id, vrf_ifindex) in desired {
            let ilm = rib::inst::IlmEntry {
                ilm_type: rib::inst::IlmType::ContextLabel {
                    table_id,
                    vrf_ifindex,
                },
                nexthop: rib::Nexthop::default(),
                ..rib::inst::IlmEntry::new(rib::RibType::Isis)
            };
            let _ = self.ctx.rib.send(rib::Message::IlmAdd { label, ilm });
            self.installed_mirror_ilm.insert(label);
        }
    }

    /// Fold the staged `/srlg/group/*` cache into the
    /// applied snapshot at `ConfigOp::CommitEnd`. When the snapshot
    /// actually moved, re-originate both LSP levels so the new
    /// name→value mapping reaches peers without waiting for the
    /// refresh timer; the LSP-content hash short-circuits if nothing
    /// changed for our self-LSP.
    fn commit_srlg(&mut self) {
        let Some(groups) = self.srlg_config.commit() else {
            return;
        };
        if self.srlg_groups == groups {
            return;
        }
        self.srlg_groups = groups;
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }

    /// Apply a single update from the RIB SR subscription channel. We only
    /// store updates for the names we currently watch; messages for stale
    /// names (e.g. arriving after a switch) are dropped.
    fn process_sr_rx(&mut self, msg: RibSrRx) {
        match msg {
            RibSrRx::Block { name, block } => {
                if self.watched_block.as_deref() != Some(name.as_str()) {
                    return;
                }
                self.sr_block = block;
                // Pool depends on `sr_block.local`; a fresh snapshot can
                // unlock pool creation (first-time arrival) or drop it
                // (block went away on the RIB side).
                self.reconcile_local_pool();
                // The SRLB pool just (dis)appeared — (de)allocate Mirror
                // Context labels and re-flood so the Binding TLVs match.
                self.update_mirror_labels();
                self.update_mirror_context_labels();
                let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
                let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
            }
            RibSrRx::Locator { name, locator } => {
                // A single locator name may back the base (algo-0)
                // subscription and/or one or more flex-algo bindings.
                // Apply the snapshot to every subscriber of this name.
                let mut touched = false;
                if self.watched_locator.as_deref() == Some(name.as_str()) {
                    self.sr_locator = locator.clone();
                    // Locator snapshot churned — every End.X address
                    // computed against the previous prefix is now stale.
                    // Drop them all and let the next Hellos re-allocate
                    // from a fresh ELIB pool.
                    self.clear_all_endx_sids();
                    // Allocate / withdraw the Node SID against the new
                    // snapshot before flooding so the LSP carries the
                    // correct value on the very first emission.
                    self.update_end_sid();
                    // The local locator just resolved, so any configured
                    // Mirror SID can now be range-checked and installed.
                    self.update_mirror_sids();
                    self.update_mirror_context_routes();
                    self.update_mirror_labels();
                    self.update_mirror_context_labels();
                    touched = true;
                }
                let algos: Vec<u8> = self
                    .watched_flex_algo_locators
                    .iter()
                    .filter(|(_, n)| n.as_str() == name.as_str())
                    .map(|(algo, _)| *algo)
                    .collect();
                for algo in algos {
                    match &locator {
                        Some(l) => {
                            self.sr_flex_algo_locators.insert(algo, l.clone());
                        }
                        None => {
                            self.sr_flex_algo_locators.remove(&algo);
                        }
                    }
                    self.update_flex_algo_end_sid(algo);
                    touched = true;
                }
                if !touched {
                    return;
                }
            }
        }
        // Re-originate both levels so the new SR snapshot is reflected in
        // the next LSP without waiting for the refresh timer.
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
    }
}

/// Build the body of a self-originated purge (LSP with Remaining
/// Lifetime == 0). RFC 6232 §4 requires `Number == 1` POI carrying
/// just the originator's own system-id; that's stamped here so
/// receivers can attribute the phantom LSP back to its source
/// instead of looking at an anonymous zero-lifetime LSP.
fn build_self_originated_purge(
    lsp_id: IsisLspId,
    seq_number: u32,
    level: Level,
    own_sys_id: IsisSysId,
) -> IsisLsp {
    IsisLsp {
        lsp_id,
        seq_number,
        hold_time: 0,
        types: IsisLspTypes::from(level.digit()),
        tlvs: vec![IsisTlv::PurgeOrigId(IsisTlvPurgeOrigId {
            originator: own_sys_id,
            received_from: None,
        })],
        ..Default::default()
    }
}

pub fn serve(mut isis: Isis) -> Task<()> {
    Task::spawn(async move {
        isis.event_loop().await;
    })
}

pub enum Message {
    Srm(Level, u32),
    Ssn(Level, u32),
    Nfsm(NfsmEvent, Level, u32, IsisSysId),
    Ifsm(IfsmEvent, u32, Option<Level>),
    Recv(IsisPacket, u32, Option<MacAddr>),
    Lsdb(LsdbEvent, Level, IsisLspId),
    /// `gr_restart_commit` armed a `Timer::once_ms` for the drain
    /// window. When it fires, this message tells the dispatcher to
    /// run `std::process::exit(0)`. The supervisor (systemd /
    /// operator script) restarts the process; kernel routes tagged
    /// `RibType::Isis` survive because no `ProtoCleanup` is sent.
    GrRestartExit,
    /// `gr_restart_load_checkpoint` armed an auto-abort timer for
    /// the remaining grace window. When it fires, we run the
    /// `gr_restart_abort` path: clear `restarting`, kick Hellos
    /// with RR=0, resume normal operation. The exit-success path
    /// lands first when neighbors reconverge before the window
    /// expires; this auto-abort is the safety net.
    GrRestartAbort,
    /// Sent by the IIH receive path on every NFSM Down/Init→Up
    /// transition. The handler trims `pending_neighbors`; the
    /// last removal fires `gr_restart_exit_success`. Outside a
    /// loaded-checkpoint restart, `pending_neighbors` is empty
    /// and the message is a no-op.
    GrNeighborUp(IsisSysId),
    /// `gr_restart_expire` armed an `overload_clear_timer` 30s
    /// after the exit-failure path set OL on our self-LSPs. When
    /// it fires, this message clears `overloaded` and re-originates
    /// without OL so the network resumes treating us as a normal
    /// transit (RFC 5306 §3.1).
    ClearOverload,
    /// `RestartingState.t1_timer` fires every 3s while restarting
    /// to drive the per-RFC §3.1 IIH+RR retransmit cadence (faster
    /// than the normal hello_interval). Handler kicks
    /// `HelloOriginate` on every link. Auto-cancelled when
    /// `restarting` drops (the Timer is parked inside it).
    GrT1Tick,
    /// A node-protection retention hold-down fired for `locator` at
    /// `level`: if the protected egress is still down, withdraw its
    /// retained Mirror SID backup (`rib::egress_retention_expire`).
    EgressRetentionExpire {
        level: Level,
        locator: Ipv6Net,
    },
    /// Re-originate the self LSP at `level`. The optional seq-number
    /// floor carries §7.3.16.4 semantics: when a peer floods our own
    /// LSP back at us with a seq higher than what we hold, we must
    /// bump our next emission to `floor + 1` so the network converges
    /// on our authoritative copy. `None` means "use the natural
    /// existing+1" — config edits, RIB router-id changes, link-state
    /// reactions all pass None.
    LspOriginate(Level, Option<u32>),
    /// LSP generation throttle timer fired for `level`. Carries the
    /// accumulated seq-number floor across all coalesced LspOriginate
    /// events during the burst (max of all `floor` values seen).
    /// Handler runs `process_lsp_originate(level, floor)`, stamps the
    /// throttle, and clears the timer slot.
    LspGenFire(Level),
    LspPurge(Level, IsisLspId),
    /// Re-originate the pseudonode LSP whose owner is the given
    /// `IsisNeighborId` (sys_id + pseudo_id). The handler resolves
    /// this back to the local ifindex by walking `top.links`; if no
    /// link currently holds that DIS adjacency at `level`, the
    /// re-origination is skipped (the pseudonode no longer belongs to
    /// us).
    DisOriginate(Level, IsisNeighborId, Option<u32>),
    SpfCalc(Level),
    /// SPF run completed off the main task. Carries the owned
    /// `SpfOutput` produced by `compute_spf`; the handler applies it
    /// to `IsisTop` and clears `spf_inflight[level]`. If a
    /// `Message::SpfCalc(level)` arrived while the worker was running
    /// (latched on `spf_pending[level]`), the handler re-fires exactly
    /// one follow-up `SpfCalc` so coalesced LSDB changes still
    /// converge.
    SpfDone(Box<super::rib::SpfOutput>),
    AdjacencyUp(Level, u32),
    /// MaxAge wait expired after a seq-number-wrap purge (ISO 10589
    /// §7.3.16.4). Clears the per-fragment freeze entry for
    /// `(level, fragment_id)` and re-originates the self LSP set,
    /// which will compute seq = 1 for the freshly-unfrozen fragment
    /// (no existing entry in LSDB once the purge has been removed).
    LspSeqWrapClear(Level, u8),
    /// An adjacency on a `bfd { enable true }` interface reached
    /// Up. The IS-IS event loop forwards this as a
    /// `ClientReq::Subscribe` against the BFD instance — see
    /// [`Isis::process_bfd_subscribe`].
    BfdSubscribe(crate::bfd::session::SessionKey),
    /// An adjacency on a previously-subscribed interface backslid
    /// from Up (Hello timer expiry, peer signaling Down, etc.) or
    /// the interface had `bfd { enable }` removed; release the BFD
    /// session by sending `ClientReq::Unsubscribe`.
    BfdUnsubscribe(crate::bfd::session::SessionKey),
    /// Something that can flip this interface's STAMP measurement
    /// session changed at runtime (an NFSM transition to/from Up,
    /// adjacency teardown). The handler re-runs
    /// [`Isis::stamp_reconcile_link`]; config-driven changes go
    /// through the `CommitEnd` `stamp_reconcile_all` instead.
    StampReconcile(u32),
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Srm(level, ifindex) => {
                write!(f, "[Message::Srm({}:{})]", level, ifindex)
            }
            Message::Ssn(level, ifindex) => {
                write!(f, "[Message::Ssn({}:{})]", level, ifindex)
            }
            Message::Recv(isis_packet, _, _mac_addr) => {
                write!(f, "[Message::Recv({})]", isis_packet.pdu_type)
            }
            Message::Ifsm(ifsm_event, _, _level) => write!(f, "[Message::Ifsm({:?})]", ifsm_event),
            Message::Nfsm(nfsm_event, _, _isis_sys_id, _level) => {
                write!(f, "[Message::Nfsm({:?})]", nfsm_event)
            }
            Message::Lsdb(lsdb_event, _level, _isis_lsp_id) => {
                write!(f, "[Message::Lsdb({:?})]", lsdb_event)
            }
            Message::LspOriginate(level, floor) => {
                write!(f, "[Message::LspOriginate({}, floor={:?})]", level, floor)
            }
            Message::LspGenFire(level) => write!(f, "[Message::LspGenFire({})]", level),
            Message::LspPurge(level, lsp_id) => {
                write!(f, "[Message::LspPurge({}, {})]", level, lsp_id)
            }
            Message::DisOriginate(level, neighbor_id, _) => {
                write!(f, "[Message::DisOriginate({}, {})]", level, neighbor_id)
            }
            Message::SpfCalc(level) => write!(f, "[Message::SpfCalc({})]", level),
            Message::SpfDone(output) => write!(f, "[Message::SpfDone({})]", output.level),
            Message::AdjacencyUp(level, ifindex) => {
                write!(f, "[Message::AdjacencyUp({}:{})]", level, ifindex)
            }
            Message::BfdSubscribe(key) => {
                write!(f, "[Message::BfdSubscribe({:?})]", key.remote)
            }
            Message::BfdUnsubscribe(key) => {
                write!(f, "[Message::BfdUnsubscribe({:?})]", key.remote)
            }
            Message::StampReconcile(ifindex) => {
                write!(f, "[Message::StampReconcile({})]", ifindex)
            }
            Message::LspSeqWrapClear(level, frag_id) => {
                write!(f, "[Message::LspSeqWrapClear({}, frag={})]", level, frag_id)
            }
            Message::GrRestartExit => write!(f, "[Message::GrRestartExit]"),
            Message::GrRestartAbort => write!(f, "[Message::GrRestartAbort]"),
            Message::GrNeighborUp(sys_id) => write!(f, "[Message::GrNeighborUp({})]", sys_id),
            Message::ClearOverload => write!(f, "[Message::ClearOverload]"),
            Message::GrT1Tick => write!(f, "[Message::GrT1Tick]"),
            Message::EgressRetentionExpire { level, locator } => {
                write!(f, "[Message::EgressRetentionExpire {locator} {level}]")
            }
        }
    }
}

#[cfg(test)]
mod bfd_wiring_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;

    use super::*;
    use crate::bfd::inst::ClientReq;
    use crate::bfd::session::SessionKey;
    use crate::context::ProtoContext;

    fn loopback_key() -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ifindex: 0,
            multihop: false,
        }
    }

    /// Build a parked `ProtoContext` plus its `rib_rx` half for
    /// tests. Mirrors `bgp::config::tests::test_ctx`.
    fn test_ctx() -> (
        ProtoContext,
        mpsc::UnboundedReceiver<crate::rib::api::RibRx>,
    ) {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
        let client = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        Box::leak(Box::new(inbound_rx));
        (ProtoContext::default_table(client), rib_rx)
    }

    /// Parked `RibSubscriber` for `Isis::new` tests. Its receivers are
    /// leaked so sends never trip a `SendError`.
    fn test_rib_subscriber() -> crate::config::RibSubscriber {
        let (rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, rib_inbound_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(rib_rx));
        Box::leak(Box::new(rib_inbound_rx));
        crate::config::RibSubscriber::for_test(
            rib_tx,
            rib_inbound_tx,
            std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
        )
    }

    /// Parked config-manager sender for `Isis::new` tests.
    fn test_config_tx() -> mpsc::Sender<crate::config::Message> {
        let (tx, rx) = mpsc::channel(16);
        Box::leak(Box::new(rx));
        tx
    }

    fn fresh_isis_with_bfd() -> (Isis, mpsc::UnboundedReceiver<ClientReq>) {
        let (ctx, rib_rx) = test_ctx();
        let (bfd_client_tx, bfd_client_rx) = mpsc::unbounded_channel();
        let (policy_tx, policy_rx) = mpsc::unbounded_channel();
        // Park the policy_rx so the Subscribe send in `new` doesn't
        // drop and panic on its own send.
        Box::leak(Box::new(policy_rx));
        let isis = Isis::new(
            ctx,
            rib_rx,
            Some(bfd_client_tx),
            /* stamp_client_tx */ None,
            None,
            policy_tx,
            "isis".to_string(),
            test_rib_subscriber(),
            test_config_tx(),
        );
        (isis, bfd_client_rx)
    }

    /// `process_bfd_subscribe` forwards a Subscribe with the right
    /// ClientId, key, and bfd_event_tx clone as the notifier.
    #[tokio::test]
    async fn subscribe_forwards_to_bfd() {
        let (isis, mut bfd_rx) = fresh_isis_with_bfd();
        let key = loopback_key();
        isis.process_bfd_subscribe(key);

        let req = bfd_rx.try_recv().expect("Subscribe must reach BFD");
        match req {
            ClientReq::Subscribe { client, key: k, .. } => {
                assert_eq!(client, "isis");
                assert_eq!(k, key);
            }
            other => panic!("expected Subscribe, got {other:?}"),
        }
    }

    /// `process_bfd_unsubscribe` forwards the matching Unsubscribe.
    #[tokio::test]
    async fn unsubscribe_forwards_to_bfd() {
        let (isis, mut bfd_rx) = fresh_isis_with_bfd();
        let key = loopback_key();
        isis.process_bfd_unsubscribe(key);

        let req = bfd_rx.try_recv().expect("Unsubscribe must reach BFD");
        match req {
            ClientReq::Unsubscribe { client, key: k } => {
                assert_eq!(client, "isis");
                assert_eq!(k, key);
            }
            other => panic!("expected Unsubscribe, got {other:?}"),
        }
    }

    /// When IS-IS was spawned before BFD, `bfd_client_tx` is None;
    /// both handlers must no-op cleanly without panicking.
    #[tokio::test]
    async fn no_bfd_handle_is_noop() {
        let (ctx, rib_rx) = test_ctx();
        let (policy_tx, policy_rx) = mpsc::unbounded_channel();
        Box::leak(Box::new(policy_rx));
        let isis = Isis::new(
            ctx,
            rib_rx,
            None,
            /* stamp_client_tx */ None,
            None,
            policy_tx,
            "isis".to_string(),
            test_rib_subscriber(),
            test_config_tx(),
        );
        let key = loopback_key();
        isis.process_bfd_subscribe(key);
        isis.process_bfd_unsubscribe(key);
        // Reaching this line without panic is the assertion.
    }

    // ----------------------------------------------------------------
    // process_bfd_event teardown behaviour
    // ----------------------------------------------------------------

    use crate::bfd::inst::BfdEvent;
    use crate::bfd::session::StateChange;
    use bfd_packet::{Diag, State};

    fn make_event(remote: Ipv4Addr, from: State, to: State) -> BfdEvent {
        BfdEvent::StateChange {
            key: SessionKey {
                local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote: IpAddr::V4(remote),
                ifindex: 0,
                multihop: false,
            },
            change: StateChange {
                from,
                to,
                diag: Diag::None,
            },
        }
    }

    /// Synthetic Down→Down events emitted by `Bfd::subscribe` (so a
    /// new subscriber can act on the current state immediately) must
    /// NOT trigger teardown.
    #[tokio::test]
    async fn synthetic_down_to_down_is_ignored() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        // No links / nbrs configured; the assertion is that this
        // call completes without panic or side effects.
        isis.process_bfd_event(make_event(
            Ipv4Addr::new(10, 0, 0, 99),
            State::Down,
            State::Down,
        ));
    }

    /// BFD coming Up is informational — IS-IS doesn't tear down on
    /// it.
    #[tokio::test]
    async fn bfd_up_is_ignored() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        isis.process_bfd_event(make_event(
            Ipv4Addr::new(10, 0, 0, 99),
            State::Init,
            State::Up,
        ));
    }

    /// A Down event for a peer with no matching link / nbr (raced
    /// against neighbor cleanup) is logged but otherwise ignored —
    /// no panic, no crash.
    #[tokio::test]
    async fn bfd_down_for_unknown_peer_is_noop() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        isis.process_bfd_event(make_event(
            Ipv4Addr::new(10, 99, 99, 99),
            State::Up,
            State::Down,
        ));
    }

    fn make_event_v6(remote: std::net::Ipv6Addr, from: State, to: State) -> BfdEvent {
        BfdEvent::StateChange {
            key: SessionKey {
                local: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                remote: IpAddr::V6(remote),
                ifindex: 0,
                multihop: false,
            },
            change: StateChange {
                from,
                to,
                diag: Diag::None,
            },
        }
    }

    /// An IPv6 BFD Down for an unknown peer exercises the v6 match arm of
    /// `bfd_resolve_neighbor` (addr6l / addr6) and is a clean no-op when no
    /// link / nbr matches — the IPv6 analogue of the IPv4 case above.
    #[tokio::test]
    async fn bfd_down_for_unknown_v6_peer_is_noop() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        isis.process_bfd_event(make_event_v6(
            "fe80::1".parse().unwrap(),
            State::Up,
            State::Down,
        ));
    }

    /// An IPv6 BFD Up with no held neighbour lifts nothing and must not panic.
    #[tokio::test]
    async fn bfd_up_for_unknown_v6_peer_is_noop() {
        let (mut isis, _bfd_rx) = fresh_isis_with_bfd();
        isis.process_bfd_event(make_event_v6(
            "fe80::2".parse().unwrap(),
            State::Init,
            State::Up,
        ));
    }
}

#[cfg(test)]
mod purge_poi_tests {
    use super::*;

    /// RFC 6232 §4: self-originated purges MUST carry POI with the
    /// originator's own system-id (Number == 1). Verifies the
    /// purge-body helper that `process_lsp_purge` delegates to.
    #[test]
    fn self_originated_purge_carries_poi() {
        let own = IsisSysId {
            id: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        };
        let lsp_id = IsisLspId::new(own, 0, 0);

        let purged = build_self_originated_purge(lsp_id, 42, Level::L2, own);

        assert_eq!(purged.hold_time, 0, "must be a purge");
        assert_eq!(purged.seq_number, 42);
        assert_eq!(purged.lsp_id, lsp_id);

        let poi = purged
            .tlvs
            .iter()
            .find_map(|t| match t {
                IsisTlv::PurgeOrigId(p) => Some(p),
                _ => None,
            })
            .expect("POI must be present on self-originated purge");
        assert_eq!(poi.originator, own);
        assert_eq!(
            poi.received_from, None,
            "self-originated purges use Number == 1 (no received_from)"
        );
    }

    /// The purge body must round-trip through the wire codec — a
    /// purge with POI emitted by the daemon must come back from
    /// the parser carrying the same POI variant, not as Unknown(13).
    #[test]
    fn self_originated_purge_wire_round_trip() {
        use bytes::BytesMut;
        let own = IsisSysId {
            id: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        };
        let lsp_id = IsisLspId::new(own, 0, 0);
        let purged = build_self_originated_purge(lsp_id, 7, Level::L1, own);

        let mut buf = BytesMut::new();
        purged.emit(&mut buf);
        let (rest, parsed) = IsisLsp::parse_be(&buf).expect("purge body must parse with own codec");
        assert!(rest.is_empty());
        let poi = parsed
            .tlvs
            .iter()
            .find_map(|t| match t {
                IsisTlv::PurgeOrigId(p) => Some(p),
                _ => None,
            })
            .expect("POI must survive emit→parse");
        assert_eq!(poi.originator, own);
        assert_eq!(poi.received_from, None);
    }
}
