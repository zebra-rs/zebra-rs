use crate::config::{Args, ConfigOp};

use super::{addr::OspfAddr, area::OspfArea, Ospf};

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
    println!("OSPF network config");
    Some(())
}
