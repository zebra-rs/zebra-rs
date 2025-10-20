use std::collections::BTreeMap;
use tokio::sync::mpsc::UnboundedSender;

use super::Bridge;
use crate::config::{Args, ConfigOp};
use crate::rib::Message;

pub struct ConfigBuilder {
    //
}

pub struct BridgeConfig {
    pub config: BTreeMap<String, Bridge>,
    pub cache: BTreeMap<String, Bridge>,
    builder: ConfigBuilder,
}

impl BridgeConfig {
    pub fn new() -> Self {
        BridgeConfig {
            config: BTreeMap::new(),
            cache: BTreeMap::new(),
            builder: ConfigBuilder {},
        }
    }

    pub async fn exec(&mut self, _path: String, _args: Args, _op: ConfigOp) {
        // TODO: Implement bridge configuration
    }

    pub fn commit(&mut self, _tx: UnboundedSender<Message>) {
        // TODO: Implement bridge configuration commit
    }
}
