use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::Ospf;
use super::OspfLink;
use super::ifsm::{IfsmEvent, ospf_hello_timer};
use super::link::OspfNetworkType;
use super::tracing::{config_tracing_fsm, config_tracing_packet};
use super::version::{OspfVersion, Ospfv2};

use crate::config::{Args, ConfigOp};
use crate::ospf::Message;

/// YANG-path → handler dispatch type. Parameterized over `V` so an
/// `Ospf<Ospfv3>` instance carries its own `Callback<Ospfv3>` table,
/// distinct from `Ospf<Ospfv2>`'s. Defaults to `Ospfv2` to keep
/// existing v2 callsites resolving unchanged.
pub type Callback<V = Ospfv2> = fn(&mut Ospf<V>, Args, ConfigOp) -> Option<()>;

impl Ospf {
    const OSPF: &str = "/router/ospf";
    const TRACING: &str = "/router/ospf/tracing";

    pub fn ospf_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(format!("{}{}", Self::OSPF, path), cb);
    }

    pub fn tracing_add(&mut self, path: &str, cb: Callback) {
        self.callbacks
            .insert(format!("{}{}", Self::TRACING, path), cb);
    }

    pub fn callback_build(&mut self) {
        self.ospf_add("/router-id", config_ospf_router_id);
        self.ospf_add("/area/interface/enable", config_ospf_interface_enable);
        self.ospf_add(
            "/area/interface/network-type",
            config_ospf_interface_network_type,
        );
        self.ospf_add("/area/interface/priority", config_ospf_interface_priority);
        self.ospf_add(
            "/area/interface/hello-interval",
            config_ospf_interface_hello_interval,
        );
        self.ospf_add(
            "/area/interface/dead-interval",
            config_ospf_interface_dead_interval,
        );
        self.ospf_add(
            "/area/interface/retransmit-interval",
            config_ospf_interface_retransmit_interval,
        );
        self.ospf_add(
            "/area/interface/mtu-ignore",
            config_ospf_interface_mtu_ignore,
        );
        self.ospf_add(
            "/area/interface/prefix-sid/index",
            config_ospf_interface_prefix_sid_index,
        );
        self.ospf_add(
            "/area/interface/prefix-sid/absolute",
            config_ospf_interface_prefix_sid_absolute,
        );
        self.ospf_add(
            "/area/interface/adjacency-sid/index",
            config_ospf_interface_adjacency_sid_index,
        );
        self.ospf_add(
            "/area/interface/adjacency-sid/absolute",
            config_ospf_interface_adjacency_sid_absolute,
        );
        self.ospf_add("/segment-routing/mpls", config_ospf_sr_mpls);
        self.tracing_add("/fsm", config_tracing_fsm);
        self.tracing_add("/packet", config_tracing_packet);
    }
}

/// Parse a YANG `union { uint32; inet:ipv4-address }` area-id arg into
/// the 32-bit area ID. `area 0` and `area 0.0.0.0` both normalize to
/// `0.0.0.0`. Tries dotted-quad first (more specific) so a bare digit
/// only falls through to the decimal interpretation.
pub(super) fn parse_area_id(s: &str) -> Option<Ipv4Addr> {
    if let Ok(addr) = s.parse::<Ipv4Addr>() {
        return Some(addr);
    }
    s.parse::<u32>().ok().map(Ipv4Addr::from)
}

/// Resolve the desired (enabled, area) state for `link`. The area now
/// comes from the parent `area` list in the YANG schema; each
/// per-interface callback writes it into `link.config.area` so this
/// IFSM transition helper keeps working unchanged.
pub(super) fn link_should_enable<V: OspfVersion>(link: &OspfLink<V>) -> (bool, Ipv4Addr) {
    if !link.config.enable {
        return (false, Ipv4Addr::UNSPECIFIED);
    }
    let area = link.config.area.unwrap_or(Ipv4Addr::UNSPECIFIED);
    (true, area)
}

pub(super) fn apply_link_enable_transition<V: OspfVersion>(
    link: &OspfLink<V>,
    next: bool,
    next_id: Ipv4Addr,
) {
    let curr = link.enabled;
    let curr_id = link.area_id;

    if curr {
        if next {
            if curr_id != next_id {
                // Enabled -> Enabled (area change).
                let _ = link.tx.send(Message::Disable(link.index, curr_id));
                let _ = link.tx.send(Message::Enable(link.index, next_id));
            }
        } else {
            // Enabled -> Disabled.
            let _ = link.tx.send(Message::Disable(link.index, curr_id));
        }
    } else if next {
        // Disabled -> Enabled.
        let _ = link.tx.send(Message::Enable(link.index, next_id));
    }
}

fn config_ospf_router_id(_ospf: &mut Ospf, mut args: Args, _op: ConfigOp) -> Option<()> {
    let _router_id = args.v4addr()?;
    None
}

pub(super) fn ospf_link_get_mut_by_name<'a, V: OspfVersion>(
    links: &'a mut BTreeMap<u32, OspfLink<V>>,
    name: &str,
) -> Option<&'a mut OspfLink<V>> {
    links.values_mut().find(|link| link.name == name)
}

fn config_ospf_interface_enable(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let enable = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;

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

/// `/router/ospf/area/<id>/interface/<name>/network-type` — accepts
/// `broadcast` or `point-to-point` (YANG enum, kebab-case). Mirrors
/// the IS-IS `network-type` knob: bounce the interface on any change
/// so the IFSM re-initializes from the new type's entry state (P2P
/// skips Waiting / DR election; Broadcast goes through Waiting).
fn config_ospf_interface_network_type(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let network_type = args.string()?.parse::<OspfNetworkType>().ok()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let old = link.config_network_type();
    if op.is_set() {
        link.config.network_type = Some(network_type);
    } else {
        link.config.network_type = None;
    }
    let new = link.config_network_type();

    // Network-type change on an already-enabled interface invalidates
    // the IFSM state (P2P shouldn't be in Waiting/DROther; broadcast
    // shouldn't be in PointToPoint) and the cached neighbor list.
    // Disable+Enable through the existing channel rebuilds both.
    if old != new && link.enabled {
        let area_id = link.area_id;
        let _ = link.tx.send(Message::Disable(link.index, area_id));
        let _ = link.tx.send(Message::Enable(link.index, area_id));
    }

    Some(())
}

fn config_ospf_interface_priority(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
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

fn config_ospf_interface_hello_interval(
    ospf: &mut Ospf,
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

fn config_ospf_interface_dead_interval(
    ospf: &mut Ospf,
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

fn config_ospf_interface_retransmit_interval(
    ospf: &mut Ospf,
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

fn config_ospf_interface_mtu_ignore(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let mtu_ignore = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    link.config.mtu_ignore = op.is_set() && mtu_ignore;

    Some(())
}

fn config_ospf_interface_prefix_sid_index(
    ospf: &mut Ospf,
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

    ospf.ext_prefix_lsa_originate(ifindex);

    Some(())
}

fn config_ospf_interface_prefix_sid_absolute(
    ospf: &mut Ospf,
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

    ospf.ext_prefix_lsa_originate(ifindex);

    Some(())
}

/// Store the Index-form Adjacency-SID for this interface and re-
/// originate the per-link Extended-Link Opaque LSA. The originator
/// gates on SR-MPLS enabled + a Full neighbor on a P2P link, so the
/// LSA is flushed automatically if any precondition is unmet.
fn config_ospf_interface_adjacency_sid_index(
    ospf: &mut Ospf,
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

    ospf.ext_link_lsa_originate(ifindex);

    Some(())
}

fn config_ospf_interface_adjacency_sid_absolute(
    ospf: &mut Ospf,
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

    ospf.ext_link_lsa_originate(ifindex);

    Some(())
}

fn config_ospf_sr_mpls(ospf: &mut Ospf, _args: Args, op: ConfigOp) -> Option<()> {
    use super::srmpls::{SRLB_RANGE, SRLB_START, SegmentRoutingMode};
    use crate::spf::label_pool::LabelPool;
    ospf.segment_routing = if op.is_set() {
        SegmentRoutingMode::Mpls
    } else {
        SegmentRoutingMode::None
    };

    // Manage the per-instance Adjacency-SID label pool alongside the
    // mode toggle, mirroring IS-IS (`isis/config.rs::config_sr_mpls_enable`).
    // The pool is bounded by the SRLB (15000..16000 by default) so any
    // re-enable that happens before existing adjacencies regress will
    // simply hand out fresh labels without colliding with stale ones.
    if op.is_set() {
        if ospf.local_pool.is_none() {
            ospf.local_pool = Some(LabelPool::new(
                SRLB_START as usize,
                Some((SRLB_START + SRLB_RANGE - 1) as usize),
            ));
        }
        // Sweep existing Full neighbors and allocate labels for any
        // that don't have one. Necessary when SR-MPLS is enabled after
        // adjacencies have already reached Full -- the NFSM-driven
        // allocation only fires on the Full transition itself, so those
        // pre-existing adjacencies would otherwise be missing from
        // `lan_adj_sids` and excluded from LAN Adj-SID origination.
        let pending: Vec<(u32, std::net::Ipv4Addr)> = ospf
            .links
            .iter()
            .flat_map(|(ifindex, link)| {
                link.nbrs.values().filter_map(move |nbr| {
                    if nbr.state == super::nfsm::NfsmState::Full {
                        Some((*ifindex, nbr.ident.prefix.addr()))
                    } else {
                        None
                    }
                })
            })
            .filter(|key| !ospf.lan_adj_sids.contains_key(key))
            .collect();
        for key in pending {
            if let Some(pool) = ospf.local_pool.as_mut()
                && let Some(label) = pool.allocate()
            {
                ospf.lan_adj_sids.insert(key, label as u32);
            }
        }
    } else {
        ospf.local_pool = None;
        ospf.lan_adj_sids.clear();
    }

    ospf.router_info_lsa_originate();

    // Originate/flush Extended Prefix LSAs for all links with prefix-sid.
    let ifindexes: Vec<u32> = ospf
        .links
        .iter()
        .filter(|(_, link)| link.config.prefix_sid.is_some())
        .map(|(ifindex, _)| *ifindex)
        .collect();
    for ifindex in ifindexes {
        ospf.ext_prefix_lsa_originate(ifindex);
    }

    // Same for Extended Link LSAs (Adj-SID).
    let ifindexes: Vec<u32> = ospf
        .links
        .iter()
        .filter(|(_, link)| link.config.adjacency_sid.is_some())
        .map(|(ifindex, _)| *ifindex)
        .collect();
    for ifindex in ifindexes {
        ospf.ext_link_lsa_originate(ifindex);
    }

    Some(())
}
