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
