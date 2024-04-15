// SPDX-License-Identifier: GPL-3.0-or-later or Apache-2.0

mod config;
use config::Cli;
use config::ConfigManager;
mod bgp;
use bgp::Bgp;
mod rib;
use rib::Rib;

fn yang_path() -> String {
    let home = dirs::home_dir();
    if let Some(mut home) = home {
        home.push(".zebra");
        home.push("yang");
        home.push("...");
        home.into_os_string().into_string().unwrap()
    } else {
        "./yang/...".to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rib = Rib::new();

    let bgp = Bgp::new(rib.api.tx.clone());
    rib.subscribe(bgp.redist.tx.clone());

    let mut config = ConfigManager::new(yang_path());
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
