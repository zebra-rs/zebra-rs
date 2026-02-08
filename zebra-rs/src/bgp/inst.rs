use super::BgpAttrStore;
use super::peer::{Event, Peer, fsm};
use super::route::LocalRib;
use crate::bgp::debug::BgpDebugFlags;
use crate::bgp::peer::accept;
use crate::bgp::{InOut, peer};
use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::Task;
use crate::isis::link::LinkType;
use crate::policy::com_list::CommunityListMap;
use crate::policy::{self, PolicyRxChannel};
use crate::rib;
use crate::rib::api::{RibRx, RibRxChannel};
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
    /// Bounded channel for BGP events (capacity: 8192)
    pub tx: mpsc::Sender<Message>,
    pub rx: mpsc::Receiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub rib_tx: UnboundedSender<rib::Message>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub redist: RibRxChannel,
    pub callbacks: HashMap<String, Callback>,
    pub pcallbacks: HashMap<String, PCallback>,
    /// BGP Local RIB (Loc-RIB) for best path selection
    pub local_rib: LocalRib,
    pub listen_task: Option<Task<()>>,
    pub listen_task6: Option<Task<()>>,
    pub listen_err: Option<anyhow::Error>,
    /// Debug configuration flags
    pub debug_flags: BgpDebugFlags,
    pub policy_tx: UnboundedSender<policy::Message>,
    pub policy_rx: UnboundedReceiver<policy::PolicyRx>,
    // BgpAttr shared storage.
    pub attr_store: BgpAttrStore,
}

impl Bgp {
    pub fn new(
        rib_tx: UnboundedSender<rib::Message>,
        policy_tx: UnboundedSender<policy::Message>,
    ) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            proto: "bgp".into(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);

        let policy_chan = PolicyRxChannel::new();
        let msg = policy::Message::Subscribe {
            proto: "bgp".into(),
            tx: policy_chan.tx.clone(),
        };
        let _ = policy_tx.send(msg);

        let (tx, rx) = mpsc::channel(8192);
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            peers: BTreeMap::new(),
            tx,
            rx,
            local_rib: LocalRib::default(),
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
            debug_flags: BgpDebugFlags::default(),
            policy_tx,
            policy_rx: policy_chan.rx,
            attr_store: BgpAttrStore::new(),
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
                        // tracing::info!("Open from: {}", peer);
                    }
                    Event::UpdateMsg(ref msg) => {
                        // tracing::info!("Update from: {}", peer);
                    }
                    Event::KeepAliveMsg => {
                        // tracing::info!("Keepalive from: {}", peer);
                    }
                    Event::KeepaliveTimerExpires => {
                        // tracing::info!("KeepaliveTimerExpires for {}", peer);
                    }
                    _ => {
                        // tracing::info!("Other Event: {:?} for {}", event, peer);
                    }
                }
                fsm(self, peer, event);
            }
            Message::Accept(socket, sockaddr) => {
                // println!("Accept: {:?}", sockaddr);
                accept(self, socket, sockaddr);
            }
            Message::Show(tx) => {
                let _ = self.tx.try_send(Message::Show(tx));
            }
        }
    }

    pub fn peer_comps(&self) -> Vec<String> {
        self.peers
            .keys()
            .map(|addr| addr.to_string().clone())
            .collect()
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if let Some(f) = self.callbacks.get(&path) {
                    f(self, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                //
            }
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.peer_comps()).unwrap();
            }
            ConfigOp::Clear => {
                let (path, mut args) = path_from_command(&msg.paths);
                match path.as_str() {
                    "/clear/ip/bgp/neighbors" => {
                        peer::clear(self, &mut args);
                    }
                    "/clear/ip/bgp/keepalive" => {
                        peer::clear_keepalive(self, &mut args);
                    }
                    "/clear/ip/bgp/keepalive-recv" => {
                        peer::clear_keepalive_recv(self, &mut args);
                    }
                    _ => {
                        //
                    }
                }
            }
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
                                if let Err(e) =
                                    tx_ipv4.send(Message::Accept(socket, sockaddr)).await
                                {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv4 accept error: {}", e);
                                // Backoff on accept errors to prevent tight loop on FD exhaustion
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                                if let Err(e) =
                                    tx_ipv6.send(Message::Accept(socket, sockaddr)).await
                                {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv6 accept error: {}", e);
                                // Backoff on accept errors to prevent tight loop on FD exhaustion
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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

        Ok(())
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(_link) => {
                //self.link_add(link);
            }
            RibRx::AddrAdd(_addr) => {
                // isis_info!("Isis::AddrAdd {}", addr.addr);
                // self.addr_add(addr);
            }
            RibRx::AddrDel(_addr) => {
                // isis_info!("Isis::AddrDel {}", addr.addr);
                // self.addr_del(addr);
            }
            _ => {
                //
            }
        }
    }

    pub async fn process_policy_msg(&mut self, msg: policy::PolicyRx) {
        match msg {
            policy::PolicyRx::PrefixSet {
                name: _,
                ident,
                policy_type,
                prefix_set,
            } => {
                let Some(peer) = self.peers.get_mut(&ident) else {
                    return;
                };
                if policy_type == policy::PolicyType::PrefixSetIn {
                    let config = peer.prefix_set.get_mut(&InOut::Input);
                    config.prefix_set = prefix_set;
                } else if policy_type == policy::PolicyType::PrefixSetOut {
                    let config = peer.prefix_set.get_mut(&InOut::Output);
                    config.prefix_set = prefix_set;
                }
            }
            policy::PolicyRx::PolicyList {
                name,
                ident,
                policy_type,
                policy_list,
            } => {
                let Some(peer) = self.peers.get_mut(&ident) else {
                    return;
                };
                match policy_type {
                    policy::PolicyType::PolicyListIn => {
                        let config = peer.policy_list.get_mut(&InOut::Input);
                        config.policy_list = policy_list;
                    }
                    policy::PolicyType::PolicyListOut => {
                        let config = peer.policy_list.get_mut(&InOut::Output);
                        config.policy_list = policy_list;
                    }
                    _ => {
                        //
                    }
                }
            }
        }
    }

    pub async fn event_loop(&mut self) {
        if let Err(err) = self.listen().await {
            self.listen_err = Some(err);
        }
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => {
                    // tracing::info!("BGP: Received EoR, entering main event loop");
                    break;
                }
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        // tracing::info!(
        //     "BGP: Main event loop started with {} peers",
        //     self.peers.len()
        // );
        let mut event_count: u64 = 0;
        let mut last_report = std::time::Instant::now();
        loop {
            tokio::select! {
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.rx.recv() => {
                    // Decrement queue depth for events from timers
                    event_count += 1;
                    // Report every 10 seconds
                    if last_report.elapsed().as_secs() >= 10 {
                        // tracing::info!("Event loop: processed {} events in last 10s", event_count);
                        event_count = 0;
                        last_report = std::time::Instant::now();
                    }
                    self.process_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.policy_rx.recv() => {
                    self.process_policy_msg(msg).await;
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
