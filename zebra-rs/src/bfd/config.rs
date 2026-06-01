//! BFD configuration model and per-leaf callback dispatcher (empty).
//!
//! The top-level `bfd` keyword is an FRR-style enable anchor: its
//! presence spawns the BFD task (see [`crate::config::manager`]), but
//! it has no configuration leaves of its own. BFD sessions are
//! configured per-protocol (`neighbor X bfd`, `ip ospf bfd`,
//! `isis bfd`) and created / torn down by those modules through
//! `ClientReq::Subscribe` / `Unsubscribe`.
//!
//! The dispatch plumbing (the `cm` channel, [`BfdConfig`], the callback
//! table, and [`Bfd::process_cm_msg`]) is kept as an empty shell so a
//! future `/bfd/*` leaf can register a handler without re-wiring the
//! instance.

use crate::config::{Args, ConfigOp};

use super::inst::Bfd;

pub type Callback = fn(&mut Bfd, Args, ConfigOp) -> Option<()>;

/// FRR-aligned session defaults (compatible with the RFC 5880 §6.8.1
/// recommendations). These back [`super::session::SessionParams::default`]
/// — the parameters every protocol-driven session is created with —
/// not any `/bfd` config leaf.
pub const DEFAULT_DETECT_MULT: u8 = 3;
pub const DEFAULT_TRANSMIT_INTERVAL_MS: u32 = 300;
pub const DEFAULT_RECEIVE_INTERVAL_MS: u32 = 300;
pub const DEFAULT_MINIMUM_TTL: u8 = 254;

/// In-memory mirror of the `container bfd` subtree of the committed
/// config. Currently empty — the container has no leaves — but kept so
/// the config-dispatch plumbing stays wired for any future `/bfd` leaf.
#[derive(Debug, Default, Clone)]
pub struct BfdConfig {}

impl Bfd {
    const BFD: &str = "/bfd";

    #[allow(dead_code)]
    fn config_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(format!("{}{}", Self::BFD, path), cb);
    }

    /// Register `/bfd/*` leaf callbacks. The container has no leaves
    /// today, so this is empty; it stays as the wiring point for any
    /// future BFD config.
    pub fn callback_build(&mut self) {}
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::bfd::inst::Bfd;
    use crate::context::ProtoContext;

    fn fresh_bfd() -> Bfd {
        Bfd::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("bind loopback")
    }

    /// The `bfd` container has no config leaves: no `/bfd/*` callbacks
    /// are registered. Per-peer and per-profile BFD config were removed;
    /// sessions are driven by the protocol modules via
    /// `ClientReq::Subscribe`.
    #[tokio::test]
    async fn no_bfd_config_callbacks_registered() {
        let bfd = fresh_bfd();
        assert!(
            bfd.callbacks.is_empty(),
            "the bfd container has no config leaves",
        );
    }
}
