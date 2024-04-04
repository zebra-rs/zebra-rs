mod config;
use config::ConfigManager;
mod bgp;
use bgp::Bgp;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // cli gRPC channel.
    let (cli_tx, cli_rx) = mpsc::channel(255);

    // cli gRPC Server.
    config::serve(cli_tx.clone()).await;

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

    // Configuration manager channel.
    let (cm_tx, cm_rx) = mpsc::unbounded_channel();

    // Configuration manager.
    let mut cm = ConfigManager::new(path, cli_rx);
    cm.subscribe(cm_tx.clone());

    // BGP task.
    let mut bgp = Bgp::new(cm_rx);

    // Banner.
    println!("zebra: started");

    // Top event loop.
    loop {
        tokio::select! {
            Some(msg) = cm.rx.recv() => {
                cm.process_message(msg);
            }
            Some(msg) = bgp.rx.recv() => {
                bgp.process_message(msg)
            }
            Some(msg) = bgp.cm_rx.recv() => {
                bgp.process_cm_message(msg);
            }
        }
    }
}
