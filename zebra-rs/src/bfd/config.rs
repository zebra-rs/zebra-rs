//! BFD configuration model and per-leaf callback dispatcher.
//!
//! Mirrors the pattern used by [`crate::ospf::config`] and
//! [`crate::isis::config`]: each YANG leaf under `/bfd` registers a
//! callback function. The config manager dispatches incoming
//! `ConfigRequest`s by path; the callback consumes its key /
//! value args and mutates the in-memory [`BfdConfig`] held by the
//! [`super::inst::Bfd`] instance.
//!
//! PR 4 wires the storage and the callback table. The PR-5 work that
//! turns committed peer config into live sessions calls
//! [`crate::bfd::inst::Bfd::add_session`] from `CommitEnd` once the
//! candidate has been folded into [`BfdConfig`].

use std::collections::BTreeMap;
use std::net::IpAddr;

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

/// A configured peer. All non-key leaves are `Option` so an unset
/// leaf cleanly delegates to the referenced [`ProfileConfig`] (and
/// onward to the profile defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub remote_address: IpAddr,
    pub multihop: bool,
    pub local_address: Option<IpAddr>,
    pub interface: Option<String>,
    pub profile: Option<String>,
    pub detect_multiplier: Option<u8>,
    pub transmit_interval_ms: Option<u32>,
    pub receive_interval_ms: Option<u32>,
    pub passive_mode: Option<bool>,
    pub shutdown: Option<bool>,
    pub minimum_ttl: Option<u8>,
}

impl PeerConfig {
    fn new(remote: IpAddr) -> Self {
        Self {
            remote_address: remote,
            multihop: false,
            local_address: None,
            interface: None,
            profile: None,
            detect_multiplier: None,
            transmit_interval_ms: None,
            receive_interval_ms: None,
            passive_mode: None,
            shutdown: None,
            minimum_ttl: None,
        }
    }
}

/// In-memory mirror of the `container bfd` subtree of the committed
/// config. Updated by [`Callback`] invocations; the live session
/// lifecycle reads from here on CommitEnd (PR 5+).
#[derive(Debug, Default, Clone)]
pub struct BfdConfig {
    pub profiles: BTreeMap<String, ProfileConfig>,
    pub peers: BTreeMap<IpAddr, PeerConfig>,
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

        // Peer leaves
        self.config_add("/peer/multihop", peer_multihop);
        self.config_add("/peer/local-address", peer_local_address);
        self.config_add("/peer/interface", peer_interface);
        self.config_add("/peer/profile", peer_profile);
        self.config_add("/peer/detect-multiplier", peer_detect_multiplier);
        self.config_add("/peer/transmit-interval", peer_transmit_interval);
        self.config_add("/peer/receive-interval", peer_receive_interval);
        self.config_add("/peer/passive-mode", peer_passive_mode);
        self.config_add("/peer/shutdown", peer_shutdown);
        self.config_add("/peer/minimum-ttl", peer_minimum_ttl);
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

// -----------------------------------------------------------------------
// Peer callbacks
// -----------------------------------------------------------------------

fn peer_mut(cfg: &mut BfdConfig, remote: IpAddr, op: ConfigOp) -> Option<&mut PeerConfig> {
    if op.is_set() {
        Some(
            cfg.peers
                .entry(remote)
                .or_insert_with(|| PeerConfig::new(remote)),
        )
    } else {
        cfg.peers.get_mut(&remote)
    }
}

fn peer_remote(args: &mut Args) -> Option<IpAddr> {
    // The peer's key leaf accepts either an IPv4 or IPv6 literal —
    // tried in turn until one parses.
    if let Some(v4) = args.v4addr() {
        return Some(IpAddr::V4(v4));
    }
    args.v6addr().map(IpAddr::V6)
}

fn peer_multihop(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.boolean()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.multihop = op.is_set() && v;
    Some(())
}

fn peer_local_address(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = peer_remote(&mut args)?; // reuse the address parser for local-address
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.local_address = op.is_set().then_some(v);
    Some(())
}

fn peer_interface(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.string()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.interface = op.is_set().then_some(v);
    Some(())
}

fn peer_profile(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.string()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.profile = op.is_set().then_some(v);
    Some(())
}

fn peer_detect_multiplier(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.u8()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.detect_multiplier = op.is_set().then_some(v);
    Some(())
}

fn peer_transmit_interval(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.u32()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.transmit_interval_ms = op.is_set().then_some(v);
    Some(())
}

fn peer_receive_interval(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.u32()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.receive_interval_ms = op.is_set().then_some(v);
    Some(())
}

fn peer_passive_mode(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.boolean()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.passive_mode = op.is_set().then_some(v);
    Some(())
}

fn peer_shutdown(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.boolean()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.shutdown = op.is_set().then_some(v);
    Some(())
}

fn peer_minimum_ttl(bfd: &mut Bfd, mut args: Args, op: ConfigOp) -> Option<()> {
    let remote = peer_remote(&mut args)?;
    let v = args.u8()?;
    let p = peer_mut(&mut bfd.config, remote, op)?;
    p.minimum_ttl = op.is_set().then_some(v);
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

    /// Peer leaves are stored as Option so unset cleanly delegates
    /// to the profile (or the profile default) at session-creation
    /// time. Setting the peer-level multiplier marks it Some(_).
    #[tokio::test]
    async fn peer_overrides_are_stored_as_options() {
        let mut bfd = fresh_bfd();
        peer_multihop(&mut bfd, args(&["10.0.0.2", "true"]), ConfigOp::Set);
        peer_detect_multiplier(&mut bfd, args(&["10.0.0.2", "9"]), ConfigOp::Set);
        peer_transmit_interval(&mut bfd, args(&["10.0.0.2", "100"]), ConfigOp::Set);

        let p = bfd
            .config
            .peers
            .get(&std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .expect("peer inserted");
        assert!(p.multihop);
        assert_eq!(p.detect_multiplier, Some(9));
        assert_eq!(p.transmit_interval_ms, Some(100));
        assert_eq!(p.receive_interval_ms, None);
        assert_eq!(p.profile, None);
    }

    /// Linking a peer to a profile by name stores the reference;
    /// resolving the reference into effective parameters is the job
    /// of the session-spawn path (PR 5).
    #[tokio::test]
    async fn peer_profile_reference_stored() {
        let mut bfd = fresh_bfd();
        peer_profile(&mut bfd, args(&["10.0.0.3", "FAST"]), ConfigOp::Set);
        let p = bfd
            .config
            .peers
            .get(&std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
            .expect("peer inserted");
        assert_eq!(p.profile.as_deref(), Some("FAST"));
    }

    /// `callback_build` registers exactly the leaves we expect — a
    /// missing path here means a CLI verb won't reach the storage
    /// dispatcher at runtime.
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
            "/bfd/peer/multihop",
            "/bfd/peer/local-address",
            "/bfd/peer/interface",
            "/bfd/peer/profile",
            "/bfd/peer/detect-multiplier",
            "/bfd/peer/transmit-interval",
            "/bfd/peer/receive-interval",
            "/bfd/peer/passive-mode",
            "/bfd/peer/shutdown",
            "/bfd/peer/minimum-ttl",
        ];
        for path in expected {
            assert!(
                bfd.callbacks.contains_key(path),
                "callback for {path} not registered",
            );
        }
    }
}
