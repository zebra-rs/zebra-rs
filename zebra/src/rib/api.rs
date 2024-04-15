use tokio::sync::mpsc::{self, Receiver, Sender};

#[derive(Debug)]
pub struct RibTxChannel {
    pub tx: Sender<RibTx>,
    pub rx: Receiver<RibTx>,
}

impl RibTxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(4);
        Self { tx, rx }
    }
}

// Message from protocol module to rib.
pub enum RibTx {
    RouteAdd(),
    RouteDel(),
    NexthopResgister(),
    NexthopUnresgister(),
}

pub struct RibRxChannel {
    pub tx: Sender<RibRx>,
    pub rx: Receiver<RibRx>,
}

impl RibRxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(4);
        Self { tx, rx }
    }
}

// Message from rib to protocol module.
pub enum RibRx {
    RedistAdd(),
    RedistDel(),
    Link(),
    Nexthop(),
}
