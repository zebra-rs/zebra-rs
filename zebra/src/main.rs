// SPDX-License-Identifier: GPL-3.0-or-later or Apache-2.0

mod config;
use config::Cli;
use config::ConfigManager;
use std::path::PathBuf;
mod bgp;
use bgp::Bgp;
mod rib;
use rib::Rib;

fn system_path() -> PathBuf {
    let mut home = dirs::home_dir().unwrap();
    home.push(".zebra");
    if home.is_dir() {
        return home;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rib = Rib::new();

    let bgp = Bgp::new(rib.api.tx.clone());
    rib.subscribe(bgp.redist.tx.clone());

    let mut config = ConfigManager::new(system_path());
    config.subscribe("rib", rib.cm.tx.clone());
    config.subscribe("bgp", bgp.cm.tx.clone());

    let mut cli = Cli::new(config.tx.clone());
    cli.subscribe(rib.show.tx.clone());
    cli.subscribe(bgp.show.tx.clone());

    config::serve(cli);

    bgp::serve(bgp);

    rib::serve(rib);

    println!("zebra: started");

    config::event_loop(config).await;

    Ok(())
}
