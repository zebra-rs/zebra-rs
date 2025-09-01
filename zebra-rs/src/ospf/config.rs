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

// network 192.168.10.0/24 area 0
// network 192.168.3.0/24 area 0

fn config_ospf_network(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let network = args.v4net()?;
    let area_id = args.u32()?;

    if op.is_set() {
        let area = ospf.areas.fetch(area_id)?;
        let network_area = ospf.table.entry(network).or_default();
        network_area.area = area.id();
    } else {
        ospf.table.remove(&network);
    }

    for (_, link) in ospf.links.iter() {
        let enabled = link.enabled;
        let area_id = link.area_id;

        for addr in link.addr.iter() {
            // ospf.table.get();
        }
    }

    Some(())
}
