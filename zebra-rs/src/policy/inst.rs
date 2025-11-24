use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

use anyhow::{Error, Result};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};

use super::{CommunitySetConfig, PolicyConfig, PolicyList, PrefixSet, PrefixSetConfig};

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
        prefix_set: Option<PrefixSet>,
    },
    PolicyList {
        name: String,
        ident: IpAddr,
        policy_type: PolicyType,
        policy_list: Option<PolicyList>,
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
    fn prefix_set_update(&self, name: &String, prefix_set: &PrefixSet);
    fn prefix_set_remove(&self, name: &String);
}

pub struct PolicySyncer<'a> {
    watch_prefix: &'a BTreeMap<String, Vec<PolicyWatch>>,
    clients: &'a BTreeMap<String, UnboundedSender<PolicyRx>>,
}

impl<'a> Syncer for PolicySyncer<'a> {
    fn prefix_set_update(&self, name: &String, prefix_set: &PrefixSet) {
        // Notify all watchers of this prefix-set update
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix_set: Some(prefix_set.clone()),
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }

    fn prefix_set_remove(&self, name: &String) {
        // Notify all watchers of this prefix-set
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix_set: None,
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

impl Syncer for &mut Policy {
    fn prefix_set_update(&self, name: &String, prefix_set: &PrefixSet) {
        // Notify all watchers of this prefix-set update
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix_set: Some(prefix_set.clone()),
                    };
                    let _ = tx.send(msg);
                }
            }
        }
    }

    fn prefix_set_remove(&self, name: &String) {
        // Notify all watchers of this prefix-set
        if let Some(watches) = self.watch_prefix.get(name) {
            for watch in watches {
                if let Some(tx) = self.clients.get(&watch.proto) {
                    let msg = PolicyRx::PrefixSet {
                        name: name.clone(),
                        ident: watch.ident,
                        policy_type: watch.policy_type,
                        prefix_set: None,
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
    pub prefix_config: PrefixSetConfig,
    pub community_config: CommunitySetConfig,
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
            prefix_config: PrefixSetConfig::new(),
            community_config: CommunitySetConfig::new(),
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
                    PolicyType::PrefixSetIn | PolicyType::PrefixSetOut => {
                        if let Some(prefix_set) = self.prefix_config.config.get(&name) {
                            // Advertise.
                            if let Some(tx) = self.clients.get(&proto) {
                                let msg = PolicyRx::PrefixSet {
                                    name: name.clone(),
                                    ident,
                                    policy_type,
                                    prefix_set: Some(prefix_set.clone()),
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
                    PolicyType::PolicyListIn | PolicyType::PolicyListOut => {
                        if let Some(policy_list) = self.policy_config.config.get(&name) {
                            if let Some(tx) = self.clients.get(&proto) {
                                let msg = PolicyRx::PolicyList {
                                    name: name.clone(),
                                    ident,
                                    policy_type,
                                    policy_list: Some(policy_list.clone()),
                                };
                                let _ = tx.send(msg);
                            }
                        }
                    }
                }
            }
            Message::Unregister {
                proto: _,
                name: _,
                ident: _,
                policy_type: _,
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
                    self.prefix_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/community-set") {
                    self.community_config.exec(path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                // Create a syncer struct to avoid borrowing issues
                let syncer = PolicySyncer {
                    watch_prefix: &self.watch_prefix,
                    clients: &self.clients,
                };
                PrefixSetConfig::commit(
                    &mut self.prefix_config.config,
                    &mut self.prefix_config.cache,
                    syncer,
                );
                self.policy_config.commit();

                // No need of sync with protocol.
                self.community_config.commit();
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
