use super::os::message::{OsChannel, OsLink, OsMessage};
use super::os::spawn_os_dump;
use crate::config::{ConfigChannel, ShowChannel};
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
    pub cm: ConfigChannel,
    pub show: ShowChannel,
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
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
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

    fn process_os_message(&mut self, msg: OsMessage) {
        match msg {
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
            OsMessage::DelAddress(_addr) => {}
        }
    }

    fn process_cm_message(&self, msg: String) {
        println!("CM: {}", msg);
    }

    pub async fn event_loop(&mut self) {
        spawn_os_dump(self.os.tx.clone()).await.unwrap();

        loop {
            tokio::select! {
                Some(msg) = self.os.rx.recv() => {
                    self.process_os_message(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_message(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    // self.process_show_message(msg);
            msg.resp.send("line1\n".to_string()).await.unwrap();
            msg.resp.send("line2\n".to_string()).await.unwrap();
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
