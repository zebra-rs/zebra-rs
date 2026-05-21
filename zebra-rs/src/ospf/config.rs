use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::Ospf;
use super::OspfLink;
use super::ifsm::{IfsmEvent, ospf_hello_timer};
use super::tracing::{config_tracing_fsm, config_tracing_packet};

use crate::config::{Args, ConfigOp};
use crate::ospf::Message;

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;

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
        self.ospf_add("/interface/enable", config_ospf_interface_enable);
        self.ospf_add("/interface/area", config_ospf_interface_area);
        self.ospf_add("/interface/priority", config_ospf_interface_priority);
        self.ospf_add(
            "/interface/hello-interval",
            config_ospf_interface_hello_interval,
        );
        self.ospf_add(
            "/interface/dead-interval",
            config_ospf_interface_dead_interval,
        );
        self.ospf_add(
            "/interface/retransmit-interval",
            config_ospf_interface_retransmit_interval,
        );
        self.ospf_add("/interface/mtu-ignore", config_ospf_interface_mtu_ignore);
        self.ospf_add(
            "/interface/prefix-sid/index",
            config_ospf_interface_prefix_sid_index,
        );
        self.ospf_add(
            "/interface/prefix-sid/absolute",
            config_ospf_interface_prefix_sid_absolute,
        );
        self.ospf_add("/segment-routing", config_ospf_segment_routing);
        self.tracing_add("/fsm", config_tracing_fsm);
        self.tracing_add("/packet", config_tracing_packet);
    }
}

/// Resolve the desired (enabled, area) state for `link` from its
/// per-interface config. IS-IS-style: there is no `network X area Y`
/// table; the interface is in OSPF iff `enable` is set, and its area
/// comes from the per-interface `area` leaf (defaulting to the
/// backbone 0.0.0.0 when unspecified).
pub(super) fn link_should_enable(link: &OspfLink) -> (bool, Ipv4Addr) {
    if !link.config.enable {
        return (false, Ipv4Addr::UNSPECIFIED);
    }
    let area = link.config.area.unwrap_or(Ipv4Addr::UNSPECIFIED);
    (true, area)
}

pub(super) fn apply_link_enable_transition(link: &OspfLink, next: bool, next_id: Ipv4Addr) {
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

fn ospf_link_get_mut_by_name<'a>(
    links: &'a mut BTreeMap<u32, OspfLink>,
    name: &str,
) -> Option<&'a mut OspfLink> {
    links.values_mut().find(|link| link.name == name)
}

fn config_ospf_interface_enable(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let enable = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;

    link.config.enable = op.is_set() && enable;

    let (next, next_id) = link_should_enable(link);
    apply_link_enable_transition(link, next, next_id);

    Some(())
}

fn config_ospf_interface_area(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let area_id_u32 = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.area = Some(Ipv4Addr::from(area_id_u32));
    } else {
        link.config.area = None;
    }

    let (next, next_id) = link_should_enable(link);
    apply_link_enable_transition(link, next, next_id);

    Some(())
}

fn config_ospf_interface_priority(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
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

fn config_ospf_segment_routing(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let mode = args.string()?;

    use super::srmpls::SegmentRoutingMode;
    if op.is_set() {
        ospf.segment_routing = match mode.as_str() {
            "mpls" => SegmentRoutingMode::Mpls,
            _ => SegmentRoutingMode::None,
        };
    } else {
        ospf.segment_routing = SegmentRoutingMode::None;
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

    Some(())
}
