mod config;
use config::ConfigManager;
mod bgp;
use bgp::Bgp;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config_tx, config_rx) = mpsc::channel(255);

    // vtysh gRPC Server.
    config::serve(config_tx.clone()).await;

    // Set ${HOME}/.zebra/yang for YANG path.
    let home = dirs::home_dir();
    let path = if let Some(mut home) = home {
        home.push(".zebra");
        home.push("...");
        home.into_os_string().into_string().unwrap()
    } else {
        "./yang/...".to_string()
    };

    // Configuration manager.
    let mut cm = ConfigManager::new(path, config_rx);

    // BGP task.
    let mut bgp = Bgp::new(config_tx.clone());

    println!("zebra: started");

    loop {
        tokio::select! {
            Some(msg) = cm.rx.recv() => {
                cm.process_message(msg);
            }
            Some(msg) = bgp.rx.recv() => {
                bgp.process_message(msg)
            }
        }
    }
}
