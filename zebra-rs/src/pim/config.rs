//! `router pim` config callbacks. Every handler mutates the desired
//! per-interface config in [`Pim::if_config`] and then reconverges
//! the interface through [`Pim::reconcile_by_name`], so enable /
//! disable is independent of config-line and link-event ordering.

use crate::config::{Args, ConfigOp};

use super::inst::Pim;

pub type Callback = fn(&mut Pim, Args, ConfigOp) -> Option<()>;

impl Pim {
    pub fn callback_build(&mut self) {
        self.callback_add("/router/pim/interface", config_interface);
        self.callback_add("/router/pim/interface/dr-priority", config_dr_priority);
        self.callback_add(
            "/router/pim/interface/hello/interval",
            config_hello_interval,
        );
        self.callback_add(
            "/router/pim/interface/hello/holdtime",
            config_hello_holdtime,
        );
        self.callback_add("/router/pim/interface/passive", config_passive);
        self.callback_add("/router/pim/interface/igmp/enabled", config_igmp_enabled);
        self.callback_add("/router/pim/interface/igmp/version", config_igmp_version);
        self.callback_add(
            "/router/pim/interface/igmp/query-interval",
            config_igmp_query_interval,
        );
        self.callback_add(
            "/router/pim/interface/igmp/query-max-response-time",
            config_igmp_query_max_resp,
        );
        self.callback_add("/router/pim/rp/static", config_rp_static);
        self.callback_add("/router/pim/rp/static/group", config_rp_static_group);
    }

    fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }
}

fn config_interface(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        pim.if_config.entry(name.clone()).or_default();
    } else {
        pim.if_config.remove(&name);
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_dr_priority(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let priority = args.u32()?;
        pim.if_config.entry(name.clone()).or_default().dr_priority = Some(priority);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.dr_priority = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_hello_interval(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let interval = args.u16()?;
        pim.if_config
            .entry(name.clone())
            .or_default()
            .hello_interval = Some(interval);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.hello_interval = None;
    }
    // A changed interval re-arms the hello timer on the next
    // enable; for a running interface re-arm it now.
    pim.rearm_hello_timer(&name);
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_hello_holdtime(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let holdtime = args.u16()?;
        pim.if_config.entry(name.clone()).or_default().holdtime = Some(holdtime);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.holdtime = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_passive(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let passive = args.boolean()?;
        pim.if_config.entry(name.clone()).or_default().passive = Some(passive);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.passive = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_igmp_enabled(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let enabled = args.boolean()?;
        pim.if_config.entry(name.clone()).or_default().igmp.enabled = Some(enabled);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.igmp.enabled = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_igmp_version(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let version = args.u8()?;
        pim.if_config.entry(name.clone()).or_default().igmp.version = Some(version);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.igmp.version = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_igmp_query_interval(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let interval = args.u16()?;
        pim.if_config
            .entry(name.clone())
            .or_default()
            .igmp
            .query_interval = Some(interval);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.igmp.query_interval = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}

fn config_rp_static(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let address = args.v4addr()?;
    if op.is_set() {
        pim.rp_set
            .statics
            .entry(address)
            .or_insert_with(|| "224.0.0.0/4".parse().unwrap());
    } else {
        pim.rp_set.statics.remove(&address);
    }
    pim.rp_reevaluate();
    Some(())
}

fn config_rp_static_group(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let address = args.v4addr()?;
    if op.is_set() {
        let range = args.string()?.parse().ok()?;
        pim.rp_set.statics.insert(address, range);
    } else if let Some(range) = pim.rp_set.statics.get_mut(&address) {
        *range = "224.0.0.0/4".parse().unwrap();
    }
    pim.rp_reevaluate();
    Some(())
}

fn config_igmp_query_max_resp(pim: &mut Pim, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let max_resp = args.u16()?;
        pim.if_config
            .entry(name.clone())
            .or_default()
            .igmp
            .query_max_resp = Some(max_resp);
    } else if let Some(config) = pim.if_config.get_mut(&name) {
        config.igmp.query_max_resp = None;
    }
    pim.reconcile_by_name(&name);
    Some(())
}
