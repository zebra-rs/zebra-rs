// Several surfaces remain unexercised by production until later
// PRs: the admin-shutdown FSM events (`AdminDown` / `AdminUp` —
// pending a "shutdown" config callback path), `TimerCmd::ResetDetect`
// (currently subsumed by `Update`), `local_addr` (used only by tests
// that bind ephemeral ports), and a handful of SessionTable helpers
// used only by tests. (`Stats` is now read by `show bfd counters`.)
// One module-wide allow is cleaner than peppering individual files;
// the lint returns naturally as those production callers land.
#![allow(dead_code)]

pub mod config;
pub mod fsm;
pub mod inst;
pub mod network;
pub mod reflector;
pub mod session;
pub mod show;
pub mod socket;
pub mod timer;
pub(crate) mod trace;

#[cfg(test)]
mod integration;
