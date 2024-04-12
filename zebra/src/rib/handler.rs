use super::link::{link_show, LinkAddr};
use super::os::message::{OsAddr, OsChannel, OsLink, OsMessage};
use super::os::spawn_os_dump;
use super::Link;
use crate::config::{yang_path, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel};
use std::collections::{BTreeMap, HashMap};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

type Callback = fn(&Rib, Vec<String>) -> String;

#[derive(Debug)]
pub struct Rib {
    pub tx: UnboundedSender<String>,
    pub rx: UnboundedReceiver<String>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub os: OsChannel,
    pub links: BTreeMap<u32, Link>,
    //pub rib: prefix_trie::PrefixMap<Ipv4Net, u32>,
    pub callbacks: HashMap<String, Callback>,
}

pub fn rib_show(_rib: &Rib, _args: Vec<String>) -> String {
    "this is show ip route output".to_string()
}

impl Rib {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut rib = Rib {
            tx,
            rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            os: OsChannel::new(),
            links: BTreeMap::new(),
            callbacks: HashMap::new(),
        };
        rib.callback_build();
        rib
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/show/interfaces", link_show);
        self.callback_add("/show/ip/route", rib_show);
    }

    pub fn link_add(&mut self, oslink: OsLink) {
        let link = Link::from(oslink);
        self.links.insert(link.index, link);
    }

    pub fn link_delete(&mut self, oslink: OsLink) {
        self.links.remove(&oslink.index);
    }

    pub fn addr_add(&mut self, os_addr: OsAddr) {
        let addr = LinkAddr::from(os_addr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            if addr.is_v4() {
                link.addr4.push(addr);
            } else {
                link.addr6.push(addr);
            }
        }
    }

    pub fn addr_del(&mut self, addr: OsAddr) {
        if let Some(_link) = self.links.get_mut(&addr.link_index) {
            //link.addr.push(addr);
        }
    }

    fn process_os_message(&mut self, msg: OsMessage) {
        match msg {
            OsMessage::NewLink(link) => {
                self.link_add(link);
            }
            OsMessage::DelLink(link) => {
                self.link_delete(link);
            }
            OsMessage::NewAddress(addr) => {
                self.addr_add(addr);
            }
            OsMessage::DelAddress(addr) => {
                self.addr_del(addr);
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
        let (path, _args) = yang_path(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            let output = f(self, Vec::new());
            msg.resp.send(output).await.unwrap();
        }
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
