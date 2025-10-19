use std::collections::HashMap;

use anyhow::{Error, Result};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};

use super::{PolicyConfig, PrefixSetConfig};

pub type ShowCallback = fn(&Policy, Args, bool) -> Result<String, Error>;

pub struct Message {
    //
}

pub struct Policy {
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub policy_config: PolicyConfig,
    pub prefix_set: PrefixSetConfig,
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
        };
        policy.show_build();
        policy
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
                self.prefix_set.commit();
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
