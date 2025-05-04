use isis_packet::{IsLevel, Nsap};

use crate::config::{Args, ConfigOp};

use super::link;
use super::Isis;

impl Isis {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/isis/net", config_isis_net);
        self.callback_add("/routing/isis/is-type", config_isis_is_type);
        self.callback_add("/routing/isis/hostname", config_isis_hostname);
        self.callback_add("/routing/isis/interface/priority", link::config_priority);
    }
}

#[derive(Default)]
pub struct IsisConfig {
    pub net: Nsap,
    pub hostname: Option<String>,
    pub refresh_time: Option<u64>,
}

// Default refresh time: 15 min.
const DEFAULT_REFRESH_TIME: u64 = 15 * 60;

impl IsisConfig {
    pub fn refresh_time(&self) -> u64 {
        self.refresh_time.unwrap_or(DEFAULT_REFRESH_TIME)
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone().unwrap_or("default".into())
    }
}

fn config_isis_net(isis: &mut Isis, mut args: Args, _op: ConfigOp) -> Option<()> {
    let net = args.string()?;
    let nsap = net.parse::<Nsap>().unwrap();

    println!("NET {}", nsap);
    isis.config.net = nsap;

    Some(())
}

fn config_isis_is_type(_isis: &mut Isis, mut args: Args, _op: ConfigOp) -> Option<()> {
    let is_type_str = args.string()?;

    let is_type = is_type_str.parse::<IsLevel>().ok()?;
    println!("IS-TYPE {:?}", is_type);

    Some(())
}

fn config_isis_hostname(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hostname = args.string()?;

    if op == ConfigOp::Set {
        isis.config.hostname = Some(hostname);
    } else {
        isis.config.hostname = None;
    }
    // TODO: Re-originate LSP for L1/L2.  That will update hostname map.

    Some(())
}
