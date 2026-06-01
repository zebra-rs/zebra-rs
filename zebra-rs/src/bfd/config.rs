//! BFD configuration model and per-leaf callback dispatcher.
//!
//! Mirrors the pattern used by [`crate::ospf::config`] and
//! [`crate::isis::config`]: each YANG leaf under `/bfd/profile`
//! registers a callback function. The config manager dispatches
//! incoming `ConfigRequest`s by path; the callback consumes its key /
//! value args and mutates the in-memory [`BfdConfig`] held by the
//! [`super::inst::Bfd`] instance.
//!
//! Only named profiles are configured here. There is no standalone
//! `bfd { peer }` config: live BFD sessions are created and torn down
//! by the protocol modules (BGP / OSPF / IS-IS) through
//! `ClientReq::Subscribe` / `Unsubscribe`.

use std::collections::BTreeMap;

use crate::config::{Args, ConfigOp};

use super::inst::Bfd;

pub type Callback = fn(&mut Bfd, Args, ConfigOp) -> Option<()>;

/// Defaults aligned with FRR (compatible with RFC 5880 §6.8.1
/// recommendations). Used when neither the peer-level override nor a
/// referenced profile supplies a value.
pub const DEFAULT_DETECT_MULT: u8 = 3;
pub const DEFAULT_TRANSMIT_INTERVAL_MS: u32 = 300;
pub const DEFAULT_RECEIVE_INTERVAL_MS: u32 = 300;
pub const DEFAULT_PASSIVE_MODE: bool = false;
pub const DEFAULT_SHUTDOWN: bool = false;
pub const DEFAULT_MINIMUM_TTL: u8 = 254;

/// A named bundle of session parameters. Peers reference profiles by
/// name; absence of a referenced profile is *not* an error here —
/// peer-level overrides may have set every relevant leaf already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileConfig {
    pub detect_multiplier: u8,
    pub transmit_interval_ms: u32,
    pub receive_interval_ms: u32,
    pub passive_mode: bool,
    pub shutdown: bool,
    pub minimum_ttl: u8,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            detect_multiplier: DEFAULT_DETECT_MULT,
            transmit_interval_ms: DEFAULT_TRANSMIT_INTERVAL_MS,
            receive_interval_ms: DEFAULT_RECEIVE_INTERVAL_MS,
            passive_mode: DEFAULT_PASSIVE_MODE,
            shutdown: DEFAULT_SHUTDOWN,
            minimum_ttl: DEFAULT_MINIMUM_TTL,
        }
    }
}

/// In-memory mirror of the `container bfd` subtree of the committed
/// config. Holds the named [`ProfileConfig`] bundles; per-peer BFD
/// sessions are driven entirely by the protocol modules (BGP / OSPF /
/// IS-IS) via `ClientReq::Subscribe`, so there is no standalone
/// `bfd { peer }` config here.
#[derive(Debug, Default, Clone)]
pub struct BfdConfig {
    pub profiles: BTreeMap<String, ProfileConfig>,
}

impl Bfd {
    const BFD: &str = "/bfd";

    fn config_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(format!("{}{}", Self::BFD, path), cb);
    }

    pub fn callback_build(&mut self) {
        // Profile leaves
        self.config_add("/profile/detect-multiplier", profile_detect_multiplier);
        self.config_add("/profile/transmit-interval", profile_transmit_interval);
        self.config_add("/profile/receive-interval", profile_receive_interval);
        self.config_add("/profile/passive-mode", profile_passive_mode);
        self.config_add("/profile/shutdown", profile_shutdown);
        self.config_add("/profile/minimum-ttl", profile_minimum_ttl);
    }
}

// -----------------------------------------------------------------------
// Profile callbacks
// -----------------------------------------------------------------------

/// Get-or-create-on-set, remove-on-delete-and-empty.
fn profile_mut<'a>(
    cfg: &'a mut BfdConfig,
    name: &str,
    op: ConfigOp,
) -> Option<&'a mut ProfileConfig> {
    if op.is_set() {
        Some(cfg.profiles.entry(name.to_string()).or_default())
    } else {
        cfg.profiles.get_mut(name)
    }
}

fn profile_detect_multiplier(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let v = args.u8()?;
    let p = profile_mut(&mut bfd.config, &name, op)?;
    p.detect_multiplier = if op.is_set() { v } else { DEFAULT_DETECT_MULT };
    Some(())
}

fn profile_transmit_interval(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let v = args.u32()?;
    let p = profile_mut(&mut bfd.config, &name, op)?;
    p.transmit_interval_ms = if op.is_set() {
        v
    } else {
        DEFAULT_TRANSMIT_INTERVAL_MS
    };
    Some(())
}

fn profile_receive_interval(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let v = args.u32()?;
    let p = profile_mut(&mut bfd.config, &name, op)?;
    p.receive_interval_ms = if op.is_set() {
        v
    } else {
        DEFAULT_RECEIVE_INTERVAL_MS
    };
    Some(())
}

fn profile_passive_mode(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let v = args.boolean()?;
    let p = profile_mut(&mut bfd.config, &name, op)?;
    p.passive_mode = op.is_set() && v;
    Some(())
}

fn profile_shutdown(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let v = args.boolean()?;
    let p = profile_mut(&mut bfd.config, &name, op)?;
    p.shutdown = op.is_set() && v;
    Some(())
}

fn profile_minimum_ttl(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let v = args.u8()?;
    let p = profile_mut(&mut bfd.config, &name, op)?;
    p.minimum_ttl = if op.is_set() { v } else { DEFAULT_MINIMUM_TTL };
    Some(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use crate::bfd::inst::Bfd;
    use crate::context::ProtoContext;

    fn fresh_bfd() -> Bfd {
        Bfd::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("bind loopback")
    }

    fn args(parts: &[&str]) -> Args {
        Args(
            parts
                .iter()
                .map(|s| (*s).to_string())
                .collect::<VecDeque<_>>(),
        )
    }

    /// A configured profile lands in `bfd.config.profiles` with its
    /// non-default leaves applied, and the unset leaves take their
    /// documented defaults.
    #[tokio::test]
    async fn profile_set_then_read_back() {
        let mut bfd = fresh_bfd();
        profile_detect_multiplier(&mut bfd, args(&["FAST", "5"]), ConfigOp::Set);
        profile_transmit_interval(&mut bfd, args(&["FAST", "50"]), ConfigOp::Set);
        profile_receive_interval(&mut bfd, args(&["FAST", "75"]), ConfigOp::Set);

        let p = bfd
            .config
            .profiles
            .get("FAST")
            .expect("profile inserted on first leaf");
        assert_eq!(p.detect_multiplier, 5);
        assert_eq!(p.transmit_interval_ms, 50);
        assert_eq!(p.receive_interval_ms, 75);
        // Unset leaves take ProfileConfig::default()'s values.
        assert!(!p.passive_mode);
        assert!(!p.shutdown);
        assert_eq!(p.minimum_ttl, DEFAULT_MINIMUM_TTL);
    }

    /// Deleting a leaf resets it to its default value (the profile
    /// itself stays in the map — empty-profile cleanup is the
    /// config tree's job, not the callback's).
    #[tokio::test]
    async fn profile_delete_resets_leaf_to_default() {
        let mut bfd = fresh_bfd();
        profile_detect_multiplier(&mut bfd, args(&["CORE", "7"]), ConfigOp::Set);
        assert_eq!(bfd.config.profiles["CORE"].detect_multiplier, 7);

        profile_detect_multiplier(&mut bfd, args(&["CORE", "7"]), ConfigOp::Delete);
        assert_eq!(
            bfd.config.profiles["CORE"].detect_multiplier,
            DEFAULT_DETECT_MULT,
        );
    }

    /// `callback_build` registers exactly the profile leaves we expect
    /// — a missing path here means a CLI verb won't reach the storage
    /// dispatcher at runtime. Per-peer BFD config was removed; sessions
    /// are driven by the protocol modules via `ClientReq::Subscribe`.
    #[tokio::test]
    async fn callback_table_covers_every_leaf() {
        let bfd = fresh_bfd();
        let expected = [
            "/bfd/profile/detect-multiplier",
            "/bfd/profile/transmit-interval",
            "/bfd/profile/receive-interval",
            "/bfd/profile/passive-mode",
            "/bfd/profile/shutdown",
            "/bfd/profile/minimum-ttl",
        ];
        for path in expected {
            assert!(
                bfd.callbacks.contains_key(path),
                "callback for {path} not registered",
            );
        }
        // No `/bfd/peer/*` callbacks remain.
        assert!(
            !bfd.callbacks.keys().any(|k| k.starts_with("/bfd/peer/")),
            "peer config callbacks must be gone",
        );
    }
}
