// SPDX-License-Identifier: GPL-3.0-or-later

mod config;
use config::{Cli, ConfigManager};
use std::path::PathBuf;
mod bgp;
use bgp::Bgp;
mod rib;
//use rib::fib::netlink_srv6::srv6_encap;
use rib::Rib;
mod policy;

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Arg {
    #[arg(short, long, help = "YANG load path", default_value = "")]
    yang_path: String,
}

fn system_path(arg: &Arg) -> PathBuf {
    if !arg.yang_path.is_empty() {
        PathBuf::from(&arg.yang_path)
    } else {
        let mut home = dirs::home_dir().unwrap();
        home.push(".zebra");
        home.push("yang");
        if home.is_dir() {
            home
        } else {
            let mut path = PathBuf::new();
            path.push("etc");
            path.push("zebra");
            home.push("yang");
            if path.is_dir() {
                path
            } else {
                let mut cwd = std::env::current_dir().unwrap();
                cwd.push("yang");
                cwd
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // console_subscriber::init();
    //srv6_encap();
    let arg = Arg::parse();
    let mut rib = Rib::new()?;

    let bgp = Bgp::new(rib.api.tx.clone());
    rib.subscribe(bgp.redist.tx.clone());

    let mut config = ConfigManager::new(system_path(&arg))?;
    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("bgp", bgp.cm.tx.clone());

    let mut cli = Cli::new(config.tx.clone());
    cli.subscribe("rib", rib.show.tx.clone());
    cli.subscribe("bgp", bgp.show.tx.clone());

    config::serve(cli);

    bgp::serve(bgp);

    rib::serve(rib);

    println!("zebra: started");

    config::event_loop(config).await;

    Ok(())
}
