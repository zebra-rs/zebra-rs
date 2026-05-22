//! OSPFv3 YANG-path callback handlers.
//!
//! Sibling of v2's `config.rs`. Currently registers just the
//! `/area/interface/enable` handler — the minimum needed for a v3
//! instance to bring an interface up via the existing
//! `container ospfv3 { area { interface { enable } } }` YANG stub
//! (PR #759). Per-link priority / hello-interval / dead-interval /
//! retransmit-interval / mtu-ignore / prefix-sid callbacks aren't
//! in the v3 YANG schema yet; they're added alongside the schema
//! expansion in a follow-up.

use super::config::{
    Callback, apply_link_enable_transition, link_should_enable, ospf_link_get_mut_by_name,
    parse_area_id,
};
use super::version::Ospfv3;
use super::{Ospf, OspfLink};

use crate::config::{Args, ConfigOp};

const OSPFV3: &str = "/router/ospfv3";

impl Ospf<Ospfv3> {
    /// Register the v3 YANG-path → handler dispatch table. Mirrors
    /// v2's `callback_build` shape; the table is keyed by full path
    /// (e.g. `/router/ospfv3/area/interface/enable`) so `process_msg`
    /// can look up handlers directly.
    pub fn callback_build(&mut self) {
        let prefix = OSPFV3;
        self.callbacks.insert(
            format!("{}{}", prefix, "/area/interface/enable"),
            config_ospfv3_interface_enable as Callback<Ospfv3>,
        );
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
