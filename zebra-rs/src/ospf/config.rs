use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::OspfLink;
use super::ifsm::{IfsmEvent, ospf_hello_timer};
use super::tracing::{config_tracing_fsm, config_tracing_packet};
use super::{Ospf, addr::OspfAddr};

use crate::config::{Args, ConfigOp};
use crate::ospf::Message;
use crate::rib::util::*;

pub struct OspfNetworkConfig {
    pub area_id: Ipv4Addr,
    pub addr: Option<OspfAddr>,
}

impl Default for OspfNetworkConfig {
    fn default() -> Self {
        Self {
            area_id: Ipv4Addr::UNSPECIFIED,
            addr: None,
        }
    }
}

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;

impl Ospf {
    const OSPF: &str = "/routing/ospf";
    const TRACING: &str = "/routing/ospf/tracing";

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn ospf_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(format!("{}{}", Self::OSPF, path), cb);
    }

    pub fn tracing_add(&mut self, path: &str, cb: Callback) {
        self.callbacks
            .insert(format!("{}{}", Self::TRACING, path), cb);
    }

    pub fn callback_build(&mut self) {
        self.ospf_add("/router-id", config_ospf_router_id);
        self.ospf_add("/network/area", config_ospf_network);
        self.ospf_add("/interface/enable", config_ospf_interface_enable);
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
        self.tracing_add("/fsm", config_tracing_fsm);
        self.tracing_add("/packet", config_tracing_packet);
    }
}

/// Determine whether an OSPF link should be enabled and its area ID.
/// A link is enabled if either the explicit per-interface enable is set
/// or the network table matches one of its addresses.
pub(super) fn link_should_enable(
    link: &OspfLink,
    table: &PrefixMap<Ipv4Net, OspfNetworkConfig>,
) -> (bool, Ipv4Addr) {
    // Check network table match first (provides area ID).
    for addr in link.addr.iter() {
        let prefix = addr.prefix.addr().to_host_prefix();
        if let Some((_, network_config)) = table.get_lpm(&prefix) {
            return (true, network_config.area_id);
        }
    }
    // Explicit per-interface enable uses area 0 as default.
    if link.config.enable {
        return (true, Ipv4Addr::UNSPECIFIED);
    }
    (false, Ipv4Addr::UNSPECIFIED)
}

pub(super) fn apply_link_enable_transition(link: &OspfLink, next: bool, next_id: Ipv4Addr) {
    let curr = link.enabled;
    let curr_id = link.area_id;

    if curr {
        if next {
            if curr_id != next_id {
                // Enabled -> Enabled (area change).
                link.tx.send(Message::Disable(link.index, curr_id));
                link.tx.send(Message::Enable(link.index, next_id));
            }
        } else {
            // Enabled -> Disabled.
            link.tx.send(Message::Disable(link.index, curr_id));
        }
    } else if next {
        // Disabled -> Enabled.
        link.tx.send(Message::Enable(link.index, next_id));
    }
}

fn config_ospf_network_apply(
    links: &mut BTreeMap<u32, OspfLink>,
    table: &PrefixMap<Ipv4Net, OspfNetworkConfig>,
) {
    for (_, link) in links.iter() {
        let (next, next_id) = link_should_enable(link, table);
        apply_link_enable_transition(link, next, next_id);
    }
}

fn config_ospf_network(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let network = args.v4net()?;
    let area_id_u32 = args.u32()?;
    let area_id = Ipv4Addr::from(area_id_u32);

    if op.is_set() {
        let area = ospf.areas.fetch(area_id);
        let network_config = ospf.table.entry(network).or_default();
        network_config.area_id = area.id;
    } else {
        ospf.table.remove(&network);
    }

    config_ospf_network_apply(&mut ospf.links, &ospf.table);

    Some(())
}

fn config_ospf_router_id(_ospf: &mut Ospf, mut args: Args, _op: ConfigOp) -> Option<()> {
    let router_id = args.v4addr()?;
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

    if op.is_set() && enable {
        link.config.enable = true;
    } else {
        link.config.enable = false;
    }

    let (next, next_id) = link_should_enable(link, &ospf.table);
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
    link.tx
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
    if op.is_set() && mtu_ignore {
        link.config.mtu_ignore = true;
    } else {
        link.config.mtu_ignore = false;
    }

    Some(())
}
