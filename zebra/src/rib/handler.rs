#[cfg(target_os = "macos")]
use super::os::macos::spawn_routing_socket;
use super::os::message::{OsChannel, OsLink, OsMessage};
#[cfg(target_os = "linux")]
use super::os::netlink::spawn_netlink;
use std::collections::BTreeMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Default, Debug)]
pub struct Link {
    index: u32,
    name: String,
    mtu: u32,
}

#[derive(Default, Debug)]
pub struct LinkAddr {
    index: u32,
    secondary: bool,
}

impl Link {
    pub fn from(link: OsLink) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
        }
    }
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

    pub fn link_add(&mut self, oslink: OsLink) {
        let link = Link::from(oslink);
        println!("AddX: {:?}", link);
        self.links.insert(link.index, link);
    }

    pub fn link_delete(&mut self, oslink: OsLink) {
        println!("Del: {:?}", oslink);
        self.links.remove(&oslink.index);
    }

    pub async fn event_loop(&mut self) {
        #[cfg(target_os = "linux")]
        spawn_netlink(self.os.tx.clone()).await.unwrap();

        #[cfg(target_os = "macos")]
        spawn_routing_socket(self.os.tx.clone()).await.unwrap();

        loop {
            tokio::select! {
                Some(msg) = self.os.rx.recv() => {
                    match msg  {
                        OsMessage::NewLink(link) => {
                            self.link_add(link);
                        }
                        OsMessage::DelLink(link) => {
                            self.link_delete(link);
                        }
                        OsMessage::NewRoute(_route) => {
                            //
                        }
                        OsMessage::DelRoute(_route) => {
                            //
                        }
                        OsMessage::NewAddress(_addr) => {
                            //
                        }
                        OsMessage::DelAddress(_addr) => {

                        }
                    }
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
