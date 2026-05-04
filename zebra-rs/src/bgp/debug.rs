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
