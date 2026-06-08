//! BFD session defaults.
//!
//! BFD has almost no configuration of its own: sessions are configured
//! per-protocol (`neighbor X bfd`, `ip ospf bfd`, `isis bfd`) and created /
//! torn down by those modules through [`super::inst::ClientReq::Subscribe`] /
//! `Unsubscribe`. The BFD task is spawned eagerly by the first such protocol
//! (see [`crate::config::manager`]). The one top-level leaf it owns is
//! `bfd { tracing }` (the conditional-tracing toggle, see [`super::trace`]),
//! handled directly in [`super::inst::Bfd::process_cm_msg`] rather than through
//! a callback table.
//!
//! The constants here are the FRR-aligned defaults every protocol-driven
//! session starts with — see [`super::session::SessionParams::default`].

/// FRR-aligned session defaults (compatible with the RFC 5880 §6.8.1
/// recommendations). These back [`super::session::SessionParams::default`] —
/// the parameters every protocol-driven session is created with.
pub const DEFAULT_DETECT_MULT: u8 = 3;
pub const DEFAULT_TRANSMIT_INTERVAL_MS: u32 = 300;
pub const DEFAULT_RECEIVE_INTERVAL_MS: u32 = 300;
pub const DEFAULT_MINIMUM_TTL: u8 = 254;
