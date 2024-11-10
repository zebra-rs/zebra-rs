use std::collections::HashMap;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::rib::api::RibRx;
use crate::{
    config::{path_from_command, Args, ConfigChannel, ConfigOp, ConfigRequest},
    context::Context,
    rib::RibRxChannel,
};

use super::link::OspfLink;

pub type Callback = fn(&mut Ospf, Args, ConfigOp) -> Option<()>;

pub struct Ospf {
    ctx: Context,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback>,
    pub rx: UnboundedReceiver<RibRx>,
    pub links: HashMap<u32, OspfLink>,
}

impl Ospf {
    pub fn new(ctx: Context, rib_tx: UnboundedSender<crate::rib::Message>) -> Self {
        let chan = RibRxChannel::new();
        let msg = crate::rib::Message::Subscribe {
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);
        Self {
            ctx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rx: chan.rx,
            links: HashMap::new(),
        }
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        println!("path: {}", path);
        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        }
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::Link(link) => {
                //
            }
            _ => {
                //
            }
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.rx.recv() => {
                    self.process_rib_msg(msg);
                    println!("OSPF: RIB message received")
                }
            }
        }
    }
}

pub fn serve(mut ospf: Ospf) {
    tokio::spawn(async move {
        ospf.event_loop().await;
    });
}
