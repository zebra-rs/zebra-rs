use super::{Ospf, addr::OspfAddr, area::OspfArea};

use crate::config::{Args, ConfigOp};
use crate::ospf::area::MapVec;

#[derive(Default)]
pub struct OspfNetworkConfig {
    pub area: usize,
    pub addr: Option<OspfAddr>,
}

impl Ospf {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/ospf/network/area", config_ospf_network);
    }
}

fn config_ospf_network(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let network = args.v4net()?;
    let area_id = args.u32()?;

    let area = ospf.areas.fetch(area_id)?;

    if op.is_set() {
        let entry = ospf.table.entry(network).or_default();
        entry.area = area.id();
    }

    Some(())
}
