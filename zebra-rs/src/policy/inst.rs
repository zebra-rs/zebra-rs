use std::collections::HashMap;

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};

use super::{PrefixListIpv4Map, prefix_ipv4_commit, prefix_ipv4_exec};

pub type ShowCallback = fn(&Policy, Args, bool) -> std::result::Result<String, std::fmt::Error>;

pub struct Policy {
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub plist_v4: PrefixListIpv4Map,
}

impl Policy {
    pub fn new() -> Self {
        let mut policy = Self {
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            plist_v4: PrefixListIpv4Map::default(),
        };
        policy.show_build();
        policy
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                prefix_ipv4_exec(self, path, args, msg.op);
            }
            ConfigOp::CommitEnd => {
                prefix_ipv4_commit(&mut self.plist_v4.plist, &mut self.plist_v4.cache);
            }
            _ => {}
        }
    }

    async fn process_show_msg(&mut self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
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
