use std::collections::BTreeMap;

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::OspfLink;
use super::area::OspfAreaMap;
use super::{Ospf, addr::OspfAddr, area::OspfArea};

use crate::config::{Args, ConfigOp};
use crate::ospf::Message;
use crate::rib::util::*;

#[derive(Default)]
pub struct OspfNetworkConfig {
    pub area_id: u32,
    pub addr: Option<OspfAddr>,
}

impl Ospf {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/ospf/network/area", config_ospf_network);
    }
}

fn config_ospf_network_apply(
    links: &mut BTreeMap<u32, OspfLink>,
    table: &PrefixMap<Ipv4Net, OspfNetworkConfig>,
    areas: &mut OspfAreaMap,
) {
    for (_, link) in links.iter() {
        // Enabled -> Disabled
        // Disabled -> Enabled
        // Enabled -> Enabled (area changed)
        let curr = link.enabled;
        let curr_id = link.area_id;

        let mut next = false;
        let mut next_id = 0;

        for addr in link.addr.iter() {
            let prefix = addr.prefix.addr().to_host_prefix();
            println!("Lookup {}", prefix);
            if let Some((_, network_config)) = table.get_lpm(&prefix) {
                // Found network configuration, break at here.
                next = true;
                next_id = network_config.area_id;
                break;
            }
        }

        if curr {
            if next {
                if curr_id != next_id {
                    // Enalbed -> Enabled
                    // Area id has been changed.
                    println!("LINK: {} Area change {} -> {}", link.name, curr_id, next_id);
                    // Disable link.
                    link.tx.send(Message::Disable(link.index, curr_id));
                    // Enable link.
                    link.tx.send(Message::Enable(link.index, next_id));
                }
            } else {
                // Enabled -> Disabled.
                // Stop event to the link.
                println!("LINK: {} Disable OSPF for area {}", link.name, curr_id);
                link.tx.send(Message::Disable(link.index, curr_id));
            }
        } else {
            if next {
                // Disabled -> Enabled.
                // Start event to the link.
                println!("LINK: {} Enable OSPF for area {}", link.name, next_id);
                link.tx.send(Message::Enable(link.index, next_id));
            }
        }
    }
}

fn config_ospf_network(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let network = args.v4net()?;
    let area_id = args.u32()?;

    if op.is_set() {
        let area = ospf.areas.fetch(area_id);
        let network_config = ospf.table.entry(network).or_default();
        network_config.area_id = area.id;
    } else {
        ospf.table.remove(&network);
    }

    config_ospf_network_apply(&mut ospf.links, &ospf.table, &mut ospf.areas);

    Some(())
}
