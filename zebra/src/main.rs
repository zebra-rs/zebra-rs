// SPDX-License-Identifier: GPL-3.0-or-later

mod config;
mod spf;
use config::{Cli, ConfigManager};
use std::path::PathBuf;
mod bgp;
use bgp::Bgp;
mod rib;
use rib::Rib;
mod policy;
use policy::Policy;
mod context;
mod fib;
mod isis;
mod ospf;

use clap::Parser;
use tracing::Level;

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

fn tracing_set() {
    // console_subscriber::init();
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arg = Arg::parse();
    let mut rib = Rib::new()?;

    let bgp = Bgp::new(rib.api.tx.clone());
    rib.subscribe(bgp.redist.tx.clone());

    let policy = Policy::new();

    let config = ConfigManager::new(system_path(&arg), rib.tx.clone())?;
    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("bgp", bgp.cm.tx.clone());
    config.subscribe("policy", policy.cm.tx.clone());
    config.subscribe_show("rib", rib.show.tx.clone());
    config.subscribe_show("bgp", bgp.show.tx.clone());

    let cli = Cli::new(config.tx.clone());

    config::serve(cli);

    policy::serve(policy);

    bgp::serve(bgp);

    rib::serve(rib);

    rib::nanomsg::serve();

    tracing_set();
    tracing::info!("zebra started");

    config::event_loop(config).await;

    Ok(())
}
