/// BGP debug configuration flags for selective logging
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BgpDebugFlags {
    /// Debug BGP events (connect, disconnect, state changes)
    pub event: bool,
    /// Debug BGP UPDATE messages
    pub update: bool,
    /// Debug BGP OPEN messages
    pub open: bool,
    /// Debug BGP NOTIFICATION messages
    pub notification: bool,
    /// Debug BGP KEEPALIVE messages
    pub keepalive: bool,
    /// Debug BGP Finite State Machine transitions
    pub fsm: bool,
    /// Debug BGP graceful restart operations
    pub graceful_restart: bool,
    /// Debug BGP route processing
    pub route: bool,
    /// Debug BGP policy application
    pub policy: bool,
    /// Debug BGP packet dump (hex)
    pub packet_dump: bool,
}

impl BgpDebugFlags {
    /// Check if a specific debug category is enabled
    pub fn is_enabled(&self, category: &str) -> bool {
        match category {
            "event" => self.event,
            "update" => self.update,
            "open" => self.open,
            "notification" => self.notification,
            "keepalive" => self.keepalive,
            "fsm" => self.fsm,
            "graceful_restart" => self.graceful_restart,
            "route" => self.route,
            "policy" => self.policy,
            "packet_dump" => self.packet_dump,
            _ => false,
        }
    }

    /// Enable all debug categories
    pub fn enable_all(&mut self) {
        self.event = true;
        self.update = true;
        self.open = true;
        self.notification = true;
        self.keepalive = true;
        self.fsm = true;
        self.graceful_restart = true;
        self.route = true;
        self.policy = true;
        self.packet_dump = true;
    }

    /// Disable all debug categories
    pub fn disable_all(&mut self) {
        *self = Self::default();
    }
}
