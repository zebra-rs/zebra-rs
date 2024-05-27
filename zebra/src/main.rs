// SPDX-License-Identifier: GPL-3.0-or-later

mod config;
use config::{Cli, ConfigManager};
use std::path::PathBuf;
mod bgp;
use bgp::Bgp;
mod rib;
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
        let mut path = PathBuf::new();
        path.push(&arg.yang_path);
        path
    } else {
        let mut home = dirs::home_dir().unwrap();
        home.push(".zebra");
        if home.is_dir() {
            home
        } else {
            let mut path = PathBuf::new();
            path.push("etc");
            path.push("zebra");
            if path.is_dir() {
                path
            } else {
                std::env::current_dir().unwrap()
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
