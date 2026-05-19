// The client-subscription API (subscribe / unsubscribe / ClientReq)
// is only exercised by tests until PR 5b wires BGP through it; the
// timer / session machinery similarly waits for PR 6+ production
// callers. One module-wide allow is cleaner than peppering
// individual files — the lint returns naturally as the protocol
// integrations land.
#![allow(dead_code)]

pub mod config;
pub mod fsm;
pub mod inst;
pub mod network;
pub mod session;
pub mod socket;
pub mod timer;

#[cfg(test)]
mod integration;
