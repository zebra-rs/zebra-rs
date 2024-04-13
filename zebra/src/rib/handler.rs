use super::link::{link_show, LinkAddr};
use super::os::message::{OsAddr, OsChannel, OsLink, OsMessage};
use super::os::os_dump_spawn;
use super::Link;
use crate::config::{
    yang_path, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel,
};
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

pub fn link_addr_update(link: &mut Link, addr: LinkAddr) {
    if addr.is_v4() {
        for a in link.addr4.iter() {
            if a.addr == addr.addr {
                return;
            }
        }
        link.addr4.push(addr);
    } else {
        for a in link.addr6.iter() {
            if a.addr == addr.addr {
                return;
            }
        }
        link.addr6.push(addr);
    }
}

pub fn link_addr_del(link: &mut Link, addr: LinkAddr) {
    if addr.is_v4() {
        if let Some(remove_index) = link.addr4.iter().position(|x| x.addr == addr.addr) {
            link.addr4.remove(remove_index);
        }
    } else if let Some(remove_index) = link.addr6.iter().position(|x| x.addr == addr.addr) {
        link.addr6.remove(remove_index);
    }
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

    pub fn link_by_name(&self, link_name: &str) -> Option<&Link> {
        if let Some((_, value)) = self.links.iter().find(|(_, v)| &v.name == link_name) {
            Some(value)
        } else {
            None
        }
    }

    pub fn link_comps(&self) -> Vec<String> {
        self.links.values().map(|link| link.name.clone()).collect()
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

    pub fn addr_add(&mut self, osaddr: OsAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            link_addr_update(link, addr);
        }
    }

    pub fn addr_del(&mut self, osaddr: OsAddr) {
        let addr = LinkAddr::from(osaddr);
        if let Some(link) = self.links.get_mut(&addr.link_index) {
            link_addr_del(link, addr);
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

    fn process_cm_message(&self, msg: ConfigRequest) {
        if msg.op == ConfigOp::Completion {
            msg.resp.unwrap().send(self.link_comps()).unwrap();
        }
    }

    async fn process_show_message(&self, msg: DisplayRequest) {
        let (path, args) = yang_path(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            let output = f(self, args);
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn event_loop(&mut self) {
        os_dump_spawn(self.os.tx.clone()).await.unwrap();

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
