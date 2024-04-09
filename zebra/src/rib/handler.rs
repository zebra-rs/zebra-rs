use super::os::message::OsChannel;
#[cfg(target_os = "linux")]
use super::os::netlink::spawn_netlink;
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
        #[cfg(target_os = "linux")]
        spawn_netlink(self.os.tx.clone()).await.unwrap();

        loop {
            tokio::select! {
                Some(_msg) = self.os.rx.recv() => {
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
}
