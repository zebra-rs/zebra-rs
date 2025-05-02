use crate::context::Context;
use crate::ospf::inst;

use super::ConfigManager;

pub fn spawn_ospf(config: &ConfigManager) {
    let ctx = Context::default();
    let ospf = inst::Ospf::new(ctx, config.rib_tx.clone());
    config.subscribe("ospf", ospf.cm.tx.clone());
    config.subscribe_show("ospf", ospf.show.tx.clone());
    inst::serve(ospf);
}
