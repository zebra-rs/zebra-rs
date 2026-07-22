//! Shared per-AFI neighbor knob setters.
//!
//! Every `neighbor <addr> afi-safi <name> <knob>` statement has exactly
//! one definition of its semantics, living here as a pure function of
//! `(&mut PeerConfig, AfiSafi, ConfigOp, &mut Args)`. Two callers use
//! each one:
//!
//!   * the **global** neighbor (`/router/bgp/neighbor/afi-safi/…`),
//!     which looks up a live [`super::peer::Peer`] and then runs
//!     whatever side effects the knob needs (a session bounce, an
//!     update-group refresh, a policy-actor registration);
//!   * the **per-VRF** neighbor (`/router/bgp/vrf/neighbor/afi-safi/…`),
//!     which stages onto
//!     [`super::vrf_config::BgpVrfNeighborConfig::config`] — itself a
//!     `PeerConfig` — and relies on the VRF respawn to apply it, because
//!     a CE peer lives in a separate task the config callback cannot
//!     reach.
//!
//! Keeping the mutation pure is what makes the second caller possible at
//! all: the global callbacks take `&mut Bgp` and a live peer, neither of
//! which exists while staging. It also means the two subtrees cannot
//! drift in *meaning* — only in which knobs they expose, which
//! `vrf_afi_knob_parity` in `config::manager` pins.
//!
//! ## What belongs here
//!
//! Only knobs that are a pure function of the config. A knob that must
//! talk to another actor (`policy` / `prefix-set`, which register with
//! the policy actor to resolve a name) does **not** fit this shape and
//! is deliberately absent — see the module docs on
//! [`super::vrf_config`].

use bgp_packet::{AddPathSendReceive, AddPathValue, AfiSafi};

use super::peer::{AfiSafiEncapType, PeerConfig};
use crate::config::{Args, ConfigOp};

/// `afi-safi <name> add-path <send|receive|send-receive>`.
pub(super) fn set_add_path(
    cfg: &mut PeerConfig,
    afi_safi: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    if op.is_set() {
        let send_receive: AddPathSendReceive = args.string()?.parse().ok()?;
        cfg.addpath.insert(
            afi_safi,
            AddPathValue {
                afi: afi_safi.afi,
                safi: afi_safi.safi,
                send_receive,
            },
        );
    } else {
        cfg.addpath.remove(&afi_safi);
    }
    Some(())
}

/// `afi-safi <name> graceful-restart enabled <bool>` (RFC 4724).
///
/// `enabled` is a boolean leaf, so the value is honoured — `enabled
/// false` must not enable GR. On enable the *default Restart Time in
/// seconds* is stored, not a bare `1`: the OPEN advertises this value
/// verbatim, and a 1-second restart time makes the peer's helper flush
/// retained routes almost immediately, defeating the feature.
pub(super) fn set_graceful_restart(
    cfg: &mut PeerConfig,
    afi_safi: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    let enable = op.is_set() && args.boolean()?;
    cfg.sub.entry(afi_safi).or_default().graceful_restart =
        enable.then_some(super::peer::GR_RESTART_TIME_DEFAULT);
    Some(())
}

/// `afi-safi <name> long-lived-graceful-restart enabled`.
pub(super) fn set_llgr(cfg: &mut PeerConfig, afi_safi: AfiSafi, op: ConfigOp) -> Option<()> {
    cfg.sub.entry(afi_safi).or_default().llgr = op.is_set().then_some(1);
    Some(())
}

/// `afi-safi <name> long-lived-graceful-restart restart-time <SECS>`.
///
/// Delete restores the bare enabled marker (`1`) rather than clearing
/// LLGR outright — dropping just the restart-time leaf must not also
/// turn the feature off.
pub(super) fn set_llgr_restart_time(
    cfg: &mut PeerConfig,
    afi_safi: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    let time = args.u32()?;
    cfg.sub.entry(afi_safi).or_default().llgr = if op.is_set() { Some(time) } else { Some(1) };
    Some(())
}

/// `afi-safi <name> encapsulation-type <srv6|srv6-relax>`.
///
/// Both this leaf and the global neighbor's carry a YANG `when "../name
/// = 'ipv6'"`, but that guard is **not enforced** by the config engine —
/// verified live: `… afi-safi ipv4 encapsulation-type srv6` commits
/// successfully on the global neighbor and on a VRF neighbor alike. So
/// do not assume `afi_safi` is IPv6 unicast here; the value is keyed by
/// whatever family the operator typed, and the advertise/accept paths
/// look it up per family anyway.
pub(super) fn set_encapsulation_type(
    cfg: &mut PeerConfig,
    afi_safi: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    let encap = if op.is_set() {
        Some(AfiSafiEncapType::parse(&args.string()?)?)
    } else {
        None
    };
    cfg.sub.entry(afi_safi).or_default().encapsulation_type = encap;
    Some(())
}

/// `afi-safi <name> next-hop-unchanged <bool>`.
pub(super) fn set_next_hop_unchanged(
    cfg: &mut PeerConfig,
    afi_safi: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    let value = op.is_set() && args.boolean()?;
    cfg.sub.entry(afi_safi).or_default().next_hop_unchanged = value;
    Some(())
}

/// `afi-safi <name> next-hop-self <bool>` — records the verbatim
/// statement only.
///
/// The *effective* value is resolved through neighbor-group precedence
/// by the caller, which is the one thing this knob needs beyond its own
/// config: the global path calls
/// `neighbor_group::resolve_next_hop_self` against `Bgp::neighbor_groups`,
/// and `materialize_peers` resolves it against the `groups` map it is
/// already handed. Splitting it this way keeps the verbatim record
/// shared while letting each caller supply its own group source.
pub(super) fn set_next_hop_self_explicit(
    cfg: &mut PeerConfig,
    afi_safi: AfiSafi,
    op: ConfigOp,
    args: &mut Args,
) -> Option<()> {
    if op.is_set() {
        let value = args.boolean()?;
        cfg.nhs_explicit.insert(afi_safi, value);
    } else {
        cfg.nhs_explicit.remove(&afi_safi);
    }
    Some(())
}
