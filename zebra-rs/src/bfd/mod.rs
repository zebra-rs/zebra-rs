// Several surfaces remain unexercised by production until later
// PRs: the admin-shutdown FSM events (`AdminDown` / `AdminUp` —
// pending a "shutdown" config callback path), `TimerCmd::ResetDetect`
// (currently subsumed by `Update`), the `Stats` counters and
// `local_addr` (pending show-command wiring), and a handful of
// SessionTable helpers used only by tests. One module-wide allow is
// cleaner than peppering individual files; the lint returns
// naturally as those production callers land.
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
