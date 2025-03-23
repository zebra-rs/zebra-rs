use isis_packet::Nsap;

use crate::{
    config::{Args, ConfigOp},
    isis::IsType,
};

use super::Isis;

impl Isis {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/isis/net", config_isis_net);
        self.callback_add("/routing/isis/is-type", config_isis_is_type);
    }
}

fn config_isis_net(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let net = args.string()?;
    let nsap = net.parse::<Nsap>().unwrap();

    println!("NET {}", nsap);
    isis.net = Some(nsap);

    Some(())
}

fn config_isis_is_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let is_type_str = args.string()?;

    let is_type = is_type_str.parse::<IsType>().ok()?;
    println!("IS-TYPE {:?}", is_type);

    Some(())
}
