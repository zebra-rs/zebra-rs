use isis_packet::Nsap;

use crate::config::{Args, ConfigOp};

use super::Isis;

impl Isis {
    pub fn callback_build(&mut self) {
        self.callback_add("/routing/isis/net", config_isis_net);
    }
}

fn config_isis_net(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let net = args.string()?;
    let nsap = net.parse::<Nsap>().unwrap();

    println!("NET {}", nsap);

    isis.net = Some(nsap);

    // let area = IsisArea { id };
    // if op == ConfigOp::Set {
    //     let entry = isis.table.entry(network).or_default();
    //     entry.area = Some(area);
    // }

    Some(())
}
