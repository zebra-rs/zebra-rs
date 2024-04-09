// SPDX-License-Identifier: GPL-3.0-or-later or Apache-2.0

mod config;
use crate::config::{ConfigManager, DisplayRequest};
mod bgp;
use bgp::{Bgp, Message};
mod rib;
use rib::Rib;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;

fn yang_path() -> String {
    // Set ${HOME}/.zebra/yang for YANG path.
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
    let (cli_tx, cli_rx) = mpsc::channel(255);

    let rib = Rib::new();

    let (disp_tx, disp_rx) = mpsc::unbounded_channel();
    let bgp = Bgp::new(disp_rx);

    // Configuration manager channel.
    let mut config = ConfigManager::new(yang_path(), cli_rx);
    config.subscribe(bgp.cm.tx.clone());

    bgp::serve(bgp);

    rib::serve(rib);

    config::serve(cli_tx.clone(), disp_tx.clone());

    // Banner.
    println!("zebra: started");

    config::event_loop(config).await;

    Ok(())
}
