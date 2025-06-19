use crate::config::{Args, ConfigOp};

use super::{Ospf, addr::OspfAddr, area::OspfArea};

#[derive(Default)]
pub struct OspfNetworkConfig {
    pub area: Option<OspfArea>,
    pub addr: Option<OspfAddr>,
}

impl Ospf {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/ospf/network/area", config_ospf_network);
    }
}

fn config_ospf_network(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    // println!("OSPF network config");
    let network = args.v4net()?;
    let id = args.u8()?;
    // println!(" netwwork {}", network);
    // println!(" area {}", id);
    let area = OspfArea { id };
    if op == ConfigOp::Set {
        let entry = ospf.table.entry(network).or_default();
        entry.area = Some(area);
    }

    Some(())
}
