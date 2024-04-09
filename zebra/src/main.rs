// SPDX-License-Identifier: GPL-3.0-or-later or Apache-2.0

mod config;
use config::{ConfigManager, DisplayRequest};
mod bgp;
use bgp::{Bgp, Message};
mod rib;
use rib::Rib;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;

// struct Tx {
//     pub cm: UnboundedReceiver<String>,
//     //    pub rib:
//     //    pub show:
// }

// fn test() {
//     let bgp = Bgp::new();
//     let rib = Rib::new();

//     let cm = ConfigManager::new();
//     cm.add(bgp.cm_tx.clone());
//     cm.add(rib.cm_tx.clone());

//     tokio::spawn(cli.run().await);
//     tokio::spawn(bgp.run().await);
//     tokio::spawn(rib.run().await);
//     tokio::spawn(cm.run().await);
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // cli gRPC channel.
    let (cli_tx, cli_rx) = mpsc::channel(255);

    // Set ${HOME}/.zebra/yang for YANG path.
    let home = dirs::home_dir();
    let path = if let Some(mut home) = home {
        home.push(".zebra");
        home.push("yang");
        home.push("...");
        home.into_os_string().into_string().unwrap()
    } else {
        "./yang/...".to_string()
    };

    // let bgp = Bgp::new();

    // Configuration manager channel.
    let (cm_tx, cm_rx) = mpsc::unbounded_channel();
    let mut cm = ConfigManager::new(path, cli_rx);
    cm.subscribe(cm_tx.clone());
    cm.load_config();

    // BGP task.
    let (disp_tx, disp_rx) = mpsc::unbounded_channel();
    crate::bgp::fsm::spawn_protocol_module(cm_rx, disp_rx);

    // cli gRPC Server.
    config::serve(cli_tx.clone(), disp_tx.clone()).await;

    // RIB task.
    let (rib_tx, rib_rx) = mpsc::unbounded_channel();

    let rib = Rib::new(rib_rx);

    #[cfg(target_os = "linux")]
    rib::os::netlink::spawn_netlink(rib_tx.clone())
        .await
        .unwrap();

    // Banner.
    println!("zebra: started");

    // Top event loop.
    loop {
        tokio::select! {
            Some(msg) = cm.rx.recv() => {
                cm.process_message(msg);
            }
        }
    }
}
