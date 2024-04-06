mod config;
use std::time::Duration;

use config::{ConfigManager, DisplayRequest};
mod bgp;
use bgp::Bgp;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_stream::StreamExt;

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

    // Configuration manager channel.
    let (cm_tx, cm_rx) = mpsc::unbounded_channel();
    let mut cm = ConfigManager::new(path, cli_rx);
    cm.subscribe(cm_tx.clone());
    cm.load_config();

    // BGP task.
    let (disp_tx, disp_rx) = mpsc::unbounded_channel();
    spawn_protocol_module(cm_rx, disp_rx);

    // cli gRPC Server.
    config::serve(cli_tx.clone(), disp_tx.clone()).await;

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

async fn event_loop(bgp: &mut Bgp) {
    loop {
        tokio::select! {
            Some(msg) = bgp.rx.recv() => {
                bgp.process_message(msg)
            }
            Some(msg) = bgp.cm_rx.recv() => {
                bgp.process_cm_message(msg);
            }
            Some(msg) = bgp.disp_rx.recv() => {
                let repeat = std::iter::repeat(format!("xyz\n"));
                let mut stream = Box::pin(tokio_stream::iter(repeat).throttle(Duration::from_millis(1000)));

                while let Some(mes) = stream.next().await {
                    let result = msg.resp.send(mes).await;
                    match result {
                        Ok(_) => {
                        }
                        Err(err) => {
                            println!("Send error {:?}", err);
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn run(cm_rx: UnboundedReceiver<String>, disp_rx: UnboundedReceiver<DisplayRequest>) {
    let mut bgp = Bgp::new(cm_rx, disp_rx);

    event_loop(&mut bgp).await;
}

fn spawn_protocol_module(
    cm_rx: UnboundedReceiver<String>,
    disp_rx: UnboundedReceiver<DisplayRequest>,
) {
    tokio::spawn(async move {
        run(cm_rx, disp_rx).await;
    });
}
