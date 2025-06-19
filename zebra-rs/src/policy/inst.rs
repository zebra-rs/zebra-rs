use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, path_from_command};

use super::{PrefixListIpv4Map, prefix_ipv4_commit, prefix_ipv4_exec};

pub struct Policy {
    pub cm: ConfigChannel,
    pub plist_v4: PrefixListIpv4Map,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            cm: ConfigChannel::new(),
            plist_v4: PrefixListIpv4Map::default(),
        }
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

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
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
