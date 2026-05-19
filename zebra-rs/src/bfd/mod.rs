// PR 3b stages the timer engine, outbound packet path, and the
// `Bfd::add_session` API; the runtime spawn point that consumes them
// (config-driven session creation) arrives in PR 4. Until then a
// number of items are only reached from the integration test, so
// the bin-only compilation surface them as `dead_code`. Suppress
// module-wide rather than peppering individual files — the lint
// returns naturally as PR 4 wires the production callers.
#![allow(dead_code)]

pub mod fsm;
pub mod inst;
pub mod network;
pub mod session;
pub mod socket;
pub mod timer;

#[cfg(test)]
mod integration;
