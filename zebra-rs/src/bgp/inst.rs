use super::peer::{Event, Peer, fsm};
use super::route::{BgpLocalRibOrig, BgpRoute, LocalRib, Route};
use crate::bgp::debug::BgpDebugFlags;
use crate::bgp::peer::accept;
use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::Task;
use crate::policy::com_list::CommunityListMap;
use crate::rib;
use crate::rib::api::{RibRx, RibRxChannel, RibTx};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

/// Create an IPv6-only TCP listener to avoid conflicts with IPv4 binding
fn create_ipv6_listener() -> Result<TcpListener, std::io::Error> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

    // Set IPV6_V6ONLY to true to prevent binding to IPv4 as well
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;

    let addr = "[::]:179".parse::<SocketAddr>().unwrap();
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    // Convert socket2::Socket to std::net::TcpListener, then to tokio::net::TcpListener
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Message {
    Event(IpAddr, Event),
    Accept(TcpStream, SocketAddr),
    Show(Sender<String>),
}

pub type Callback = fn(&mut Bgp, Args, ConfigOp) -> Option<()>;
pub type PCallback = fn(&mut CommunityListMap, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Bgp, Args, bool) -> std::result::Result<String, std::fmt::Error>;

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
    pub rib_tx: UnboundedSender<rib::Message>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub redist: RibRxChannel,
    pub callbacks: HashMap<String, Callback>,
    pub pcallbacks: HashMap<String, PCallback>,
    /// BGP Local RIB (Loc-RIB) for best path selection
    pub local_rib: BgpLocalRibOrig,
    pub lrib: LocalRib,
    pub listen_task: Option<Task<()>>,
    pub listen_task6: Option<Task<()>>,
    pub listen_err: Option<anyhow::Error>,
    pub clist: CommunityListMap,
    /// Debug configuration flags
    pub debug_flags: BgpDebugFlags,
}

impl Bgp {
    pub fn new(rib_tx: UnboundedSender<rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            proto: "isis".into(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);

        let (tx, rx) = mpsc::unbounded_channel();
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            local_rib: BgpLocalRibOrig::new(),
            lrib: LocalRib::default(),
            rib_tx,
            rib_rx: chan.rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            redist: RibRxChannel::new(),
            callbacks: HashMap::new(),
            pcallbacks: HashMap::new(),
            listen_task: None,
            listen_task6: None,
            listen_err: None,
            clist: CommunityListMap::new(),
            debug_flags: BgpDebugFlags::default(),
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
                match event {
                    Event::BGPOpen(ref msg) => {
                        println!("{}", msg);
                    }
                    Event::UpdateMsg(ref msg) => {
                        println!("{:#?}", msg);
                    }
                    Event::KeepAliveMsg => {
                        println!("KeepAlive:");
                    }
                    _ => {
                        println!("Message::Event: {:?}", event);
                    }
                }
                fsm(self, peer, event);
            }
            Message::Accept(socket, sockaddr) => {
                // println!("Accept: {:?}", sockaddr);
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
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let tx = self.tx.clone();
        let tx_clone = tx.clone();

        // Try to bind to both IPv4 and IPv6
        let mut ipv4_bound = false;
        let mut ipv6_bound = false;

        // Check if we can bind to IPv4
        match TcpListener::bind("0.0.0.0:179").await {
            Ok(listener) => {
                ipv4_bound = true;
                // println!("Successfully bound to IPv4 0.0.0.0:179");
                let tx_ipv4 = tx.clone();
                self.listen_task = Some(Task::spawn(async move {
                    // println!("BGP listening on 0.0.0.0:179");
                    loop {
                        match listener.accept().await {
                            Ok((socket, sockaddr)) => {
                                // println!("IPv4 connection accepted from: {}", sockaddr);
                                if let Err(e) = tx_ipv4.send(Message::Accept(socket, sockaddr)) {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv4 accept error: {}", e);
                            }
                        }
                    }
                }));
            }
            Err(e) => {
                eprintln!("Failed to bind to IPv4 0.0.0.0:179: {}", e);
            }
        }

        // Check if we can bind to IPv6 with IPv6-only socket
        match create_ipv6_listener() {
            Ok(listener) => {
                ipv6_bound = true;
                // println!("Successfully bound to IPv6 [::]:179");
                let tx_ipv6 = tx_clone;
                self.listen_task6 = Some(Task::spawn(async move {
                    // println!("BGP listening on [::]:179");
                    loop {
                        match listener.accept().await {
                            Ok((socket, sockaddr)) => {
                                println!("IPv6 connection accepted from: {}", sockaddr);
                                if let Err(e) = tx_ipv6.send(Message::Accept(socket, sockaddr)) {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv6 accept error: {}", e);
                            }
                        }
                    }
                }));
            }
            Err(e) => {
                eprintln!("Failed to bind to IPv6 [::]:179: {}", e);
            }
        }

        if !ipv4_bound && !ipv6_bound {
            return Err(anyhow::anyhow!(
                "Failed to bind to any address (both IPv4 and IPv6)"
            ));
        }

        // Log which protocols are bound
        // match (ipv4_bound, ipv6_bound) {
        //     (true, true) => println!("BGP dual-stack: listening on both IPv4 and IPv6"),
        //     (true, false) => println!("BGP IPv4-only: listening on 0.0.0.0:179"),
        //     (false, true) => println!("BGP IPv6-only: listening on [::]:179"),
        //     (false, false) => unreachable!(),
        // }

        Ok(())
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(link) => {
                //self.link_add(link);
            }
            RibRx::AddrAdd(addr) => {
                // isis_info!("Isis::AddrAdd {}", addr.addr);
                // self.addr_add(addr);
            }
            RibRx::AddrDel(addr) => {
                // isis_info!("Isis::AddrDel {}", addr.addr);
                // self.addr_del(addr);
            }
            _ => {
                //
            }
        }
    }

    pub async fn event_loop(&mut self) {
        if let Err(err) = self.listen().await {
            self.listen_err = Some(err);
        }
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => break,
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        loop {
            tokio::select! {
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
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
