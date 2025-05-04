use isis_packet::{IsLevel, Nsap};

use crate::config::{Args, ConfigOp};

use super::link;
use super::Isis;

impl Isis {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/isis/net", config_net);
        self.callback_add("/routing/isis/is-type", config_is_type);
        self.callback_add("/routing/isis/hostname", config_hostname);
        self.callback_add("/routing/isis/interface/priority", link::config_priority);
        self.callback_add(
            "/routing/isis/interface/circuit-type",
            link::config_circuit_type,
        );
        self.callback_add(
            "/routing/isis/interface/ipv4/enable",
            link::config_ipv4_enable,
        );
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
    pub refresh_time: Option<u64>,
}

// Default refresh time: 15 min.
const DEFAULT_REFRESH_TIME: u64 = 15 * 60;

impl IsisConfig {
    pub fn is_type(&self) -> IsLevel {
        self.is_type.unwrap_or(IsLevel::L1L2)
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone().unwrap_or("default".into())
    }

    pub fn refresh_time(&self) -> u64 {
        self.refresh_time.unwrap_or(DEFAULT_REFRESH_TIME)
    }
}

fn config_net(isis: &mut Isis, mut args: Args, _op: ConfigOp) -> Option<()> {
    let nsap = args.string()?.parse::<Nsap>().unwrap();

    isis.config.net = nsap;

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
    if prev != isis.config.is_type() {
        // TODO
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
