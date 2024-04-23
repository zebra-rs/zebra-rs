use super::peer::{fsm, Event, Peer};
use super::route::Route;
use crate::bgp::task::Task;
use crate::config::{
    path_from_command, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel,
};
use crate::rib::api::{RibRxChannel, RibTx};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum Message {
    Event(Ipv4Addr, Event),
    Show(Sender<String>),
}

pub type Callback = fn(&mut Bgp, Vec<String>, ConfigOp);
pub type ShowCallback = fn(&Bgp, Vec<String>) -> String;

pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub peers: BTreeMap<Ipv4Addr, Peer>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub rib: Sender<RibTx>,
    pub redist: RibRxChannel,
    pub callbacks: HashMap<String, Callback>,
    pub ptree: PrefixMap<Ipv4Net, Vec<Route>>,
    pub listen_task: Option<Task<()>>,
}

impl Bgp {
    pub fn new(rib: Sender<RibTx>) -> Self {
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
            listen_task: None,
        };
        bgp.callback_build();
        bgp.show_build();
        bgp
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Event(peer, event) => {
                println!("Message::Event: {:?}", event);
                fsm(self, peer, event);
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
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args);
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind("0.0.0.0:179").await?;
        println!("listener is created");

        println!("start accept");
        let tx = self.tx.clone();
        let listen_task = Task::spawn(async move {
            loop {
                let (_socket, sockaddr) = listener.accept().await.unwrap();
                println!("end accept {:?}", sockaddr);
                // tx.send();
            }
        });
        self.listen_task = Some(listen_task);
        // process_socket(socket).await;
        Ok(())
    }

    pub async fn event_loop(&mut self) {
        self.listen().await.unwrap();
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
