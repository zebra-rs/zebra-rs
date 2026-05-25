//! OSPFv3 YANG-path callback handlers.
//!
//! Sibling of v2's `config.rs`. Registers the
//! `/router/ospfv3/area/interface/*` handlers — `enable`,
//! `priority`, `hello-interval`, `dead-interval`,
//! `retransmit-interval`, `mtu-ignore`. The handler bodies mirror
//! v2 almost line-for-line; the generic helpers in `config.rs`
//! (`link_should_enable`, `apply_link_enable_transition`,
//! `ospf_link_get_mut_by_name`, `parse_area_id`, `ospf_hello_timer`)
//! make this possible without duplication.

use super::config::{
    Callback, apply_link_enable_transition, link_should_enable, ospf_link_get_mut_by_name,
    parse_area_id,
};
use super::ifsm::{IfsmEvent, ospf_hello_timer};
use super::link::OspfNetworkType;
use super::version::Ospfv3;
use super::{Message, Ospf, OspfLink};

use crate::config::{Args, ConfigOp};

const OSPFV3: &str = "/router/ospfv3";

impl Ospf<Ospfv3> {
    /// Register the v3 YANG-path → handler dispatch table. Mirrors
    /// v2's `callback_build` shape; the table is keyed by full path
    /// (e.g. `/router/ospfv3/area/interface/enable`) so `process_msg`
    /// can look up handlers directly.
    pub fn callback_build(&mut self) {
        let prefix = OSPFV3;
        let entries: &[(&str, Callback<Ospfv3>)] = &[
            ("/area/interface/enable", config_ospfv3_interface_enable),
            (
                "/area/interface/network-type",
                config_ospfv3_interface_network_type,
            ),
            ("/area/interface/priority", config_ospfv3_interface_priority),
            (
                "/area/interface/hello-interval",
                config_ospfv3_interface_hello_interval,
            ),
            (
                "/area/interface/dead-interval",
                config_ospfv3_interface_dead_interval,
            ),
            (
                "/area/interface/retransmit-interval",
                config_ospfv3_interface_retransmit_interval,
            ),
            (
                "/area/interface/mtu-ignore",
                config_ospfv3_interface_mtu_ignore,
            ),
            (
                "/area/interface/prefix-sid/index",
                config_ospfv3_interface_prefix_sid_index,
            ),
            (
                "/area/interface/prefix-sid/absolute",
                config_ospfv3_interface_prefix_sid_absolute,
            ),
            (
                "/area/interface/adjacency-sid/index",
                config_ospfv3_interface_adjacency_sid_index,
            ),
            (
                "/area/interface/adjacency-sid/absolute",
                config_ospfv3_interface_adjacency_sid_absolute,
            ),
            ("/segment-routing/mpls", config_ospfv3_sr_mpls),
        ];
        for (path, cb) in entries {
            self.callbacks.insert(format!("{}{}", prefix, path), *cb);
        }
    }
}

/// Toggle the link's `enabled` state and re-evaluate the IFSM
/// transition. Mirrors v2's `config_ospf_interface_enable`: the
/// path-args queue carries `(area-id, if-name, enable-bool)`.
///
/// On `Set` with `enable = true`, the area is captured from the
/// parent list key; on `Delete` (or `enable = false`), both `enable`
/// and the cached area are cleared. The transition helper
/// (`apply_link_enable_transition`) fires `Message::Enable` /
/// `Message::Disable` into the instance channel, which drives the
/// v3 cascade (LSA origination, IFSM `InterfaceUp` / `Down`).
fn config_ospfv3_interface_enable(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let enable = args.boolean()?;

    let link: &mut OspfLink<Ospfv3> = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;

    if op.is_set() {
        link.config.enable = enable;
        link.config.area = Some(area_id);
    } else {
        link.config.enable = false;
        link.config.area = None;
    }

    let (next, next_id) = link_should_enable(link);
    apply_link_enable_transition(link, next, next_id);

    Some(())
}

/// `/router/ospfv3/area/<id>/interface/<name>/network-type` — same
/// shape as the v2 handler in `config.rs`. Stores the configured
/// type in `LinkConfig::network_type` (shared between v2 and v3)
/// and bounces the interface on any change so the IFSM re-enters
/// from the correct initial state (PointToPoint vs Waiting).
fn config_ospfv3_interface_network_type(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let network_type = args.string()?.parse::<OspfNetworkType>().ok()?;

    let link: &mut OspfLink<Ospfv3> = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let old = link.config_network_type();
    if op.is_set() {
        link.config.network_type = Some(network_type);
    } else {
        link.config.network_type = None;
    }
    let new = link.config_network_type();

    if old != new && link.enabled {
        let area_id = link.area_id;
        let _ = link.tx.send(Message::Disable(link.index, area_id));
        let _ = link.tx.send(Message::Enable(link.index, area_id));
    }

    Some(())
}

fn config_ospfv3_interface_priority(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let priority = args.u8()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.priority = Some(priority);
    } else {
        link.config.priority = None;
    }
    link.ident.priority = link.priority();

    let ifindex = link.index;
    let _ = link
        .tx
        .send(Message::Ifsm(ifindex, IfsmEvent::NeighborChange));

    Some(())
}

fn config_ospfv3_interface_hello_interval(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let hello_interval = args.u16()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.hello_interval = Some(hello_interval);
    } else {
        link.config.hello_interval = None;
    }

    if link.timer.hello.is_some() {
        link.timer.hello = Some(ospf_hello_timer(link));
    }

    Some(())
}

fn config_ospfv3_interface_dead_interval(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let dead_interval = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.dead_interval = Some(dead_interval);
    } else {
        link.config.dead_interval = None;
    }

    Some(())
}

fn config_ospfv3_interface_retransmit_interval(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let retransmit_interval = args.u16()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.retransmit_interval = Some(retransmit_interval);
    } else {
        link.config.retransmit_interval = None;
    }

    Some(())
}

fn config_ospfv3_interface_mtu_ignore(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let mtu_ignore = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    link.config.mtu_ignore = op.is_set() && mtu_ignore;

    Some(())
}

/// Record the per-interface Prefix-SID index and re-originate the
/// matching E-Intra-Area-Prefix-LSA. Mirrors v2's
/// `config_ospf_interface_prefix_sid_index`. The originator gates
/// on SR-MPLS enabled + the link being up with the Prefix-SID set,
/// so the LSA is flushed automatically if any precondition fails.
fn config_ospfv3_interface_prefix_sid_index(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let index = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.prefix_sid = Some(super::link::PrefixSid::Index(index));
    } else {
        link.config.prefix_sid = None;
    }
    let ifindex = link.index;

    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

fn config_ospfv3_interface_prefix_sid_absolute(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let absolute = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.prefix_sid = Some(super::link::PrefixSid::Absolute(absolute));
    } else {
        link.config.prefix_sid = None;
    }
    let ifindex = link.index;

    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

/// Store the per-interface Adjacency-SID and re-originate the
/// matching E-Router-LSA. Mirrors v2's
/// `config_ospf_interface_adjacency_sid_index`. The originator
/// gates on its own preconditions (SR-MPLS + P2P + Full neighbor),
/// so the LSA is flushed automatically when any are unmet.
fn config_ospfv3_interface_adjacency_sid_index(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let index = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.adjacency_sid = Some(super::link::AdjacencySid::Index(index));
    } else {
        link.config.adjacency_sid = None;
    }
    let ifindex = link.index;

    ospf.e_router_v3_lsa_originate(ifindex);

    Some(())
}

fn config_ospfv3_interface_adjacency_sid_absolute(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let absolute = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.adjacency_sid = Some(super::link::AdjacencySid::Absolute(absolute));
    } else {
        link.config.adjacency_sid = None;
    }
    let ifindex = link.index;

    ospf.e_router_v3_lsa_originate(ifindex);

    Some(())
}

/// Toggle the v3 SR-MPLS enable bit and fan out to every link with
/// a configured Prefix-SID so the matching E-Intra-Area-Prefix-LSA
/// is originated (on enable) or flushed (on disable). Router-Info /
/// Adj-SID origination wires onto the same toggle in follow-up PRs.
fn config_ospfv3_sr_mpls(ospf: &mut Ospf<Ospfv3>, _args: Args, op: ConfigOp) -> Option<()> {
    use super::srmpls::SegmentRoutingMode;
    ospf.segment_routing = if op.is_set() {
        SegmentRoutingMode::Mpls
    } else {
        SegmentRoutingMode::None
    };

    // Re-originate / flush E-Intra-Area-Prefix-LSAs for every link
    // with a Prefix-SID. The originator gates on the mode, so on
    // disable each call lands in the flush path.
    let ifindexes: Vec<u32> = ospf
        .links
        .iter()
        .filter(|(_, link)| link.config.prefix_sid.is_some())
        .map(|(ifindex, _)| *ifindex)
        .collect();
    for ifindex in ifindexes {
        ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);
    }

    // Same for E-Router-LSAs (Adj-SID).
    let ifindexes: Vec<u32> = ospf
        .links
        .iter()
        .filter(|(_, link)| link.config.adjacency_sid.is_some())
        .map(|(ifindex, _)| *ifindex)
        .collect();
    for ifindex in ifindexes {
        ospf.e_router_v3_lsa_originate(ifindex);
    }

    Some(())
}
