use super::os::message::{OsChannel, OsLink, OsMessage};
use super::os::spawn_os_dump;
use super::Link;
use crate::config::{ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel};
use std::collections::BTreeMap;
//use std::fmt::Write;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

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
            tx,
            rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            os: OsChannel::new(),
            links: BTreeMap::new(),
        }
    }

    pub fn link_add(&mut self, oslink: OsLink) {
        let link = Link::from(oslink);
        self.links.insert(link.index, link);
    }

    pub fn link_delete(&mut self, oslink: OsLink) {
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
            OsMessage::NewAddress(_addr) => {
                //
            }
            OsMessage::DelAddress(_addr) => {
                //
            }
            OsMessage::NewRoute(_route) => {
                //
            }
            OsMessage::DelRoute(_route) => {
                //
            }
        }
    }

    fn process_cm_message(&self, _msg: ConfigRequest) {
        // println!("CM: {}", msg);
    }

    async fn process_show_message(&self, msg: DisplayRequest) {
        println!("S: {}", msg.line);
        self.link_show(msg.resp.clone()).await;
        // let mut buffer = String::new();
        // for (_, link) in self.links.iter() {
        //     write!(&mut buffer, "Interface: {}\n", link.name).unwrap();
        //     write!(
        //         &mut buffer,
        //         "  index {} metric {} mtu {}\n",
        //         link.index, link.metric, link.mtu
        //     )
        //     .unwrap();
        // }
        // msg.resp.send(buffer).await.unwrap();
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
                    self.process_show_message(msg).await;
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
