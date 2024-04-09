use super::os::message::{OsChannel, OsMessage};
use std::collections::BTreeMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Default, Debug)]
pub struct Link {
    //
}

#[derive(Debug)]
pub struct Rib {
    pub tx: UnboundedSender<String>,
    pub rx: UnboundedReceiver<String>,
    pub os: OsChannel,
    pub links: BTreeMap<u32, Link>,
    //pub rib: prefix_trie::PrefixMap<Ipv4Net, u32>,
}

impl Rib {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Rib {
            os: OsChannel::new(),
            links: BTreeMap::new(),
            tx,
            rx,
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.os.rx.recv() => {
                    //
                }
            }
        }
    }
}

pub fn serve(mut rib: Rib) {
    tokio::spawn(async move {
        rib.event_loop().await;
    });
    //

    #[cfg(target_os = "linux")]
    super::os::netlink::spawn_netlink(rib_tx.clone())
        .await
        .unwrap();
}
