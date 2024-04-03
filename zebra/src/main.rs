mod config;
use config::ConfigManager;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config_tx, config_rx) = mpsc::channel(255);
    config::serve(config_tx).await;

    let home = dirs::home_dir();
    let path = if let Some(mut home) = home {
        home.push(".zebra");
        home.push("...");
        home.into_os_string().into_string().unwrap()
    } else {
        "./yang/...".to_string()
    };

    let mut cm = ConfigManager::new(path, config_rx);
    println!("zebra: started");

    loop {
        tokio::select! {
            Some(m) = cm.rx.recv() => {
                cm.process_message(m);
            }
        }
    }
}
