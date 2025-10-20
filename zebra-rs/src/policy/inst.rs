use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

use anyhow::{Error, Result};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};

use super::{PolicyConfig, PrefixSet, PrefixSetConfig};

pub type ShowCallback = fn(&Policy, Args, bool) -> Result<String, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyType {
    PrefixSetIn,
    PrefixSetOut,
    PolicyListIn,
    PolicyListOut,
}

#[derive(Debug)]
pub enum Message {
    Subscribe {
        proto: String,
        tx: UnboundedSender<PolicyRx>,
    },
    Register {
        proto: String,
        name: String,
        ident: IpAddr,
        policy_type: PolicyType,
    },
    Unregister {
        proto: String,
        name: String,
        ident: IpAddr,
        policy_type: PolicyType,
    },
}

pub struct Subscription {
    pub tx: UnboundedSender<PolicyRx>,
}

// Message from rib to protocol module.
#[derive(Debug, PartialEq)]
pub enum PolicyRx {
    PrefixSet {
        name: String,
        ident: IpAddr,
        policy_type: PolicyType,
        prefix: Option<PrefixSet>,
    },
}

#[allow(dead_code)]
pub struct PolicyRxChannel {
    pub tx: UnboundedSender<PolicyRx>,
    pub rx: UnboundedReceiver<PolicyRx>,
}

impl PolicyRxChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

pub trait Syncer {
    fn prefix_set_remove(&self, name: &String);
}

impl Syncer for Policy {
    fn prefix_set_remove(&self, name: &String) {
        // Notify all watchers of this prefix-set
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

impl Syncer for &Policy {
    fn prefix_set_remove(&self, name: &String) {
        // Notify all watchers of this prefix-set
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

impl Syncer for &mut Policy {
    fn prefix_set_remove(&self, name: &String) {
        // Notify all watchers of this prefix-set
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

pub struct Policy {
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub policy_config: PolicyConfig,
    pub prefix_set: PrefixSetConfig,
    pub clients: BTreeMap<String, UnboundedSender<PolicyRx>>,
    pub watch_prefix: BTreeMap<String, Vec<PolicyWatch>>,
    pub watch_policy: BTreeMap<String, Vec<PolicyWatch>>,
}

#[derive(Debug)]
pub struct PolicyWatch {
    pub proto: String,
    pub ident: IpAddr,
    pub policy_type: PolicyType,
}

impl Policy {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut policy = Self {
            tx,
            rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            policy_config: PolicyConfig::new(),
            prefix_set: PrefixSetConfig::new(),
            clients: BTreeMap::new(),
            watch_prefix: BTreeMap::new(),
            watch_policy: BTreeMap::new(),
        };
        policy.show_build();
        policy
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Subscribe { proto, tx } => {
                self.clients.insert(proto, tx);
            }
            Message::Register {
                proto,
                name,
                ident,
                policy_type,
            } => {
                match policy_type {
                    PolicyType::PrefixSetIn => {
                        //
                    }
                    PolicyType::PrefixSetOut => {
                        // We need to lookup corresponding prefix-set.
                        if let Some(prefix) = self.prefix_set.config.get(&name) {
                            // Advertise.
                            if let Some(tx) = self.clients.get(&proto) {
                                let msg = PolicyRx::PrefixSet {
                                    name: name.clone(),
                                    ident,
                                    policy_type,
                                    prefix: Some(prefix.clone()),
                                };
                                let _ = tx.send(msg);
                            }
                        }
                        let watch = PolicyWatch {
                            proto,
                            ident,
                            policy_type,
                        };
                        self.watch_prefix.entry(name).or_default().push(watch);
                    }
                    PolicyType::PolicyListIn => {
                        println!("policy in");
                    }
                    PolicyType::PolicyListOut => {
                        println!("policy in");
                    }
                }
            }
            Message::Unregister {
                proto,
                name,
                ident,
                policy_type,
            } => {
                //
            }
        }
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if path.as_str().starts_with("/policy-options") {
                    self.policy_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/prefix-set") {
                    self.prefix_set.exec(path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                // Commit prefix-set changes manually to avoid double borrow
                while let Some((name, s)) = self.prefix_set.cache.pop_first() {
                    if s.delete {
                        // Notify subscribed entity for prefix-set removal
                        self.prefix_set_remove(&name);
                        self.prefix_set.config.remove(&name);
                    } else {
                        self.prefix_set.config.insert(name, s);
                    }
                }
                self.policy_config.commit();
            }
            _ => {}
        }
    }

    async fn process_show_msg(&mut self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("{}", e),
            };
            msg.resp.send(output).await;
        }
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

pub fn serve(mut policy: Policy) {
    tokio::spawn(async move {
        policy.event_loop().await;
    });
}
