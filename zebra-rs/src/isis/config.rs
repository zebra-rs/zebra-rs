use std::net::Ipv4Addr;

use isis_packet::{IsLevel, Nsap};

use crate::config::{Args, ConfigOp};

use super::Isis;
use super::link::Afis;
use super::{Level, link};

impl Isis {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/isis/net", config_net);
        self.callback_add("/routing/isis/is-type", config_is_type);
        self.callback_add("/routing/isis/hostname", config_hostname);
        self.callback_add("/routing/isis/timers/hold-time", config_hold_time);
        self.callback_add("/routing/isis/te-router-id", config_te_router_id);
        self.callback_add("/routing/isis/interface/priority", link::config_priority);
        self.callback_add("/routing/isis/tracing/event", config_tracing_event);
        self.callback_add(
            "/routing/isis/interface/circuit-type",
            link::config_circuit_type,
        );
        self.callback_add("/routing/isis/interface/link-type", link::config_link_type);
        self.callback_add(
            "/routing/isis/interface/hello/padding",
            link::config_hello_padding,
        );
        self.callback_add(
            "/routing/isis/interface/ipv4/enable",
            link::config_ipv4_enable,
        );
        self.callback_add(
            "/routing/isis/interface/ipv4/prefix-sid/index",
            link::config_ipv4_prefix_sid_index,
        );
        self.callback_add("/routing/isis/interface/metric", link::config_metric);
        self.callback_add(
            "/routing/isis/interface/ipv6/enable",
            link::config_ipv6_enable,
        );
    }
}

#[derive(Default)]
pub struct IsisConfig {
    pub net: Nsap,
    pub hostname: Option<String>,
    pub is_type: Option<IsLevel>,
    pub refresh_time: Option<u16>,
    pub hold_time: Option<u16>,
    pub te_router_id: Option<Ipv4Addr>,
    pub enable: Afis<usize>,
}

// Default refresh time: 15 min.
const DEFAULT_REFRESH_TIME: u16 = 15 * 60;
const DEFAULT_HOLD_TIME: u16 = 1200;

impl IsisConfig {
    pub fn is_type(&self) -> IsLevel {
        self.is_type.unwrap_or(IsLevel::L1L2)
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone().unwrap_or("default".into())
    }

    pub fn refresh_time(&self) -> u16 {
        self.refresh_time.unwrap_or(DEFAULT_REFRESH_TIME)
    }

    pub fn hold_time(&self) -> u16 {
        self.hold_time.unwrap_or(DEFAULT_HOLD_TIME)
    }
}

fn config_net(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let nsap = args.string()?.parse::<Nsap>().unwrap();

    if op.is_set() {
        isis.lsp_map.get_mut(&Level::L1).get(&nsap.sys_id());
        isis.lsp_map.get_mut(&Level::L2).get(&nsap.sys_id());
        isis.config.net = nsap;
    } else {
        isis.config.net = Nsap::default();
    }

    Some(())
}

fn config_is_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.is_type();
    if op.is_set() {
        let is_type = args.string()?.parse::<IsLevel>().ok()?;
        isis.config.is_type = Some(is_type);
    } else {
        isis.config.is_type = None;
    }
    let curr = isis.config.is_type();
    if prev != curr {
        for (_, link) in isis.links.iter_mut() {
            let is_level = link::config_level_common(curr, link.config.circuit_type());
            link.state.set_level(is_level);
        }
    }
    Some(())
}

fn config_hostname(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hostname = args.string()?;

    if op == ConfigOp::Set {
        isis.config.hostname = Some(hostname);
    } else {
        isis.config.hostname = None;
    }
    // TODO: Re-originate LSP for L1/L2.  That will update hostname map.

    Some(())
}

fn config_hold_time(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hold_time = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.hold_time = Some(hold_time);
    } else {
        isis.config.hold_time = None;
    }
    Some(())
}

fn config_te_router_id(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let te_router_id = args.v4addr()?;

    if op == ConfigOp::Set {
        isis.config.te_router_id = Some(te_router_id);
    } else {
        isis.config.te_router_id = None;
    }
    Some(())
}

fn config_tracing_event(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ev = args.string()?;

    match ev.as_str() {
        "dis" => {
            if op.is_set() {
                isis.tracing.event.dis.enabled = true;
                println!("DIS event tracing enabled");
            } else {
                isis.tracing.event.dis.enabled = false;
                println!("DIS event tracing disabled");
            }
        }
        _ => {
            if op.is_set() {
                println!("Trace on {} (not implemented)", ev);
            } else {
                println!("Trace off {} (not implemented)", ev);
            }
        }
    }

    Some(())
}
