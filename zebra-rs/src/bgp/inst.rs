use super::peer::{fsm, Event, Peer};
use super::route::Route;
use crate::bgp::peer::accept;
use crate::bgp::task::Task;
use crate::config::{
    path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel,
};
use crate::policy::com_list::CommunityListMap;
use crate::rib::api::{RibRxChannel, RibTx};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

#[allow(dead_code)]
#[derive(Debug)]
pub enum Message {
    Event(IpAddr, Event),
    Accept(TcpStream, SocketAddr),
    Show(Sender<String>),
}

pub type Callback = fn(&mut Bgp, Args, ConfigOp) -> Option<()>;
pub type PCallback = fn(&mut CommunityListMap, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Bgp, Args, bool) -> String;

#[allow(dead_code)]
pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: BTreeMap<IpAddr, Peer>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub rib: UnboundedSender<RibTx>,
    pub redist: RibRxChannel,
    pub callbacks: HashMap<String, Callback>,
    pub pcallbacks: HashMap<String, PCallback>,
    pub ptree: PrefixMap<Ipv4Net, Vec<Route>>,
    pub listen_task: Option<Task<()>>,
    pub listen_err: Option<anyhow::Error>,
    pub clist: CommunityListMap,
}

impl Bgp {
    pub fn new(rib: UnboundedSender<RibTx>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            ptree: PrefixMap::<Ipv4Net, Vec<Route>>::new(),
            rib,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            redist: RibRxChannel::new(),
            callbacks: HashMap::new(),
            pcallbacks: HashMap::new(),
            listen_task: None,
            listen_err: None,
            clist: CommunityListMap::new(),
        };
        bgp.callback_build();
        bgp.show_build();
        bgp
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn pcallback_add(&mut self, path: &str, cb: PCallback) {
        self.pcallbacks.insert(path.to_string(), cb);
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Event(peer, event) => {
                println!("Message::Event: {:?}", event);
                fsm(self, peer, event);
            }
            Message::Accept(socket, sockaddr) => {
                println!("Accept: {:?}", sockaddr);
                accept(self, socket, sockaddr);
            }
            Message::Show(tx) => {
                self.tx.send(Message::Show(tx)).unwrap();
            }
        }
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        } else if let Some(f) = self.pcallbacks.get(&path) {
            f(&mut self.clist, args, msg.op);
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args, msg.json);
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind("0.0.0.0:179").await?;
        let tx = self.tx.clone();

        let listen_task = Task::spawn(async move {
            loop {
                let (socket, sockaddr) = listener.accept().await.unwrap();
                tx.send(Message::Accept(socket, sockaddr)).unwrap();
            }
        });
        self.listen_task = Some(listen_task);
        Ok(())
    }

    pub async fn event_loop(&mut self) {
        if let Err(err) = self.listen().await {
            self.listen_err = Some(err);
        }
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

pub fn serve(mut bgp: Bgp) {
    tokio::spawn(async move {
        bgp.event_loop().await;
    });
}
