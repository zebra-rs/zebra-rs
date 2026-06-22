//! Embedded Lua scripting engine.
//!
//! Gated behind the `lua` Cargo feature. Provides a per-thread sandboxed
//! Lua VM, a global script registry with a generation counter for lazy
//! hot-reload, and the `RM_*` / [`Action`] return contract — plus a
//! feature-off no-op path so default builds compile and pay nothing.
//!
//! PR2 marshals `prefix` / `attributes` / `peer` into the script (read
//! only) and exposes the [`loc_rib_import`] entry the BGP ingest path
//! calls after inbound policy. Attribute write-back and the withdraw
//! hook land in later PRs; see `docs/design/lua-scripting-policy.md`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock, RwLock};

use bgp_packet::BgpAttr;
use ipnet::IpNet;

#[cfg(feature = "lua")]
mod engine;
#[cfg(feature = "lua")]
mod marshal;
#[cfg(feature = "lua")]
pub mod sideeffect;

/// Outcome of a script hook, mirroring FRR's route-map result constants.
///
/// The four variants are passed *into* a script as the `RM_FAILURE`,
/// `RM_NOMATCH`, `RM_MATCH` and `RM_MATCH_AND_CHANGE` arguments, and read
/// back from the `{ action = ... }` table the script returns. The integer
/// discriminants are the wire values shared with Lua.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Deny — drop the route before it reaches the Loc-RIB.
    Failure = 0,
    /// No opinion — admit the route unchanged.
    NoMatch = 1,
    /// Explicit match, no attribute edits — admit unchanged.
    Match = 2,
    /// Admit with the script's mutated attributes (write-back: later PR).
    MatchAndChange = 3,
}

impl Action {
    /// Map a Lua-supplied integer back to an [`Action`]; `None` for an
    /// out-of-range value (treated as a script error by callers).
    pub fn from_i64(v: i64) -> Option<Action> {
        match v {
            0 => Some(Action::Failure),
            1 => Some(Action::NoMatch),
            2 => Some(Action::Match),
            3 => Some(Action::MatchAndChange),
            _ => None,
        }
    }
}

/// Result of an import hook: the [`Action`] plus, for
/// [`Action::MatchAndChange`], the attributes the script mutated (already
/// folded onto the original `BgpAttr`, so unmarshalled fields are
/// preserved). `attr` is `None` for every other action.
#[derive(Debug, Clone)]
pub struct ImportOutcome {
    pub action: Action,
    pub attr: Option<BgpAttr>,
}

impl ImportOutcome {
    /// Admit unchanged — the fail-safe / unbound / feature-off result.
    pub fn nomatch() -> Self {
        ImportOutcome {
            action: Action::NoMatch,
            attr: None,
        }
    }
}

/// A flattened, read-only view of the sending `Peer`, marshalled into the
/// Lua `peer` table. The BGP module fills this from its `Peer` before
/// invoking a hook, which keeps this module decoupled from BGP internals.
#[derive(Debug, Clone)]
pub struct PeerView {
    pub remote_as: u32,
    pub local_as: u32,
    pub remote_id: Ipv4Addr,
    pub local_id: Ipv4Addr,
    pub remote_address: IpAddr,
    pub state: String,
    pub is_ibgp: bool,
}

/// Immutable snapshot of the bound script sources, tagged with a
/// monotonic `generation`. A reload installs a fresh `Scripts` with
/// `generation + 1`; per-thread VMs compare generations and lazily
/// recompile (see [`engine`]). Snapshots are shared by `Arc`, so a
/// reload never disturbs a hook mid-evaluation.
#[derive(Debug)]
pub struct Scripts {
    pub generation: u64,
    pub sources: BTreeMap<String, String>,
}

impl Scripts {
    fn empty() -> Self {
        Scripts {
            generation: 0,
            sources: BTreeMap::new(),
        }
    }
}

static REGISTRY: OnceLock<RwLock<Arc<Scripts>>> = OnceLock::new();

fn registry() -> &'static RwLock<Arc<Scripts>> {
    REGISTRY.get_or_init(|| RwLock::new(Arc::new(Scripts::empty())))
}

/// Install a new set of script sources (name → Lua source), bumping the
/// generation so live per-thread VMs recompile on their next call.
/// Called by config wiring in a later PR; exercised directly by tests.
pub fn install(sources: BTreeMap<String, String>) {
    let mut guard = registry().write().unwrap();
    let generation = guard.generation + 1;
    *guard = Arc::new(Scripts {
        generation,
        sources,
    });
}

/// Insert or remove a single named script source, bumping the
/// generation so live per-thread VMs recompile on their next call.
/// `Some(src)` installs/replaces; `None` removes. This is the
/// incremental form used by config (one `lua-script` at a time);
/// [`install`] replaces the whole set at once.
pub fn set_source(name: &str, source: Option<String>) {
    let mut guard = registry().write().unwrap();
    let mut sources = guard.sources.clone();
    match source {
        Some(src) => {
            sources.insert(name.to_string(), src);
        }
        None => {
            sources.remove(name);
        }
    }
    let generation = guard.generation + 1;
    *guard = Arc::new(Scripts {
        generation,
        sources,
    });
}

/// Current script snapshot (cheap `Arc` clone of the registry contents).
pub fn current() -> Arc<Scripts> {
    registry().read().unwrap().clone()
}

/// The script name bound to the IPv4-unicast Adj-RIB-In → Loc-RIB import
/// hook, or `None` when unbound. Kept separate from [`Scripts`] so
/// changing the binding does not force every VM to recompile.
static BINDING_V4: OnceLock<RwLock<Option<String>>> = OnceLock::new();

fn binding_v4() -> &'static RwLock<Option<String>> {
    BINDING_V4.get_or_init(|| RwLock::new(None))
}

/// Bind (or, with `None`, unbind) the IPv4-unicast import hook to a named
/// script. Called by BGP config.
pub fn set_import_binding_v4(name: Option<String>) {
    *binding_v4().write().unwrap() = name;
}

/// Run the IPv4-unicast import hook against the currently-bound script.
/// Returns an [`ImportOutcome::nomatch`] (admit unchanged) when nothing
/// is bound or the feature is off — so the BGP ingest path can call this
/// unconditionally and act on the returned [`Action`].
#[cfg(feature = "lua")]
pub fn loc_rib_import_v4(prefix: IpNet, attr: &BgpAttr, peer: &PeerView) -> ImportOutcome {
    match binding_v4().read().unwrap().clone() {
        Some(name) => engine::loc_rib_import(&name, prefix, attr, peer),
        None => ImportOutcome::nomatch(),
    }
}

/// Feature-off no-op.
#[cfg(not(feature = "lua"))]
pub fn loc_rib_import_v4(_prefix: IpNet, _attr: &BgpAttr, _peer: &PeerView) -> ImportOutcome {
    ImportOutcome::nomatch()
}

/// The script name bound to the IPv4-unicast Loc-RIB **withdraw** hook,
/// or `None` when unbound.
static WITHDRAW_BINDING_V4: OnceLock<RwLock<Option<String>>> = OnceLock::new();

fn withdraw_binding_v4() -> &'static RwLock<Option<String>> {
    WITHDRAW_BINDING_V4.get_or_init(|| RwLock::new(None))
}

/// Bind (or, with `None`, unbind) the IPv4-unicast withdraw hook.
pub fn set_withdraw_binding_v4(name: Option<String>) {
    *withdraw_binding_v4().write().unwrap() = name;
}

/// Run the IPv4-unicast withdraw hook against the currently-bound script.
///
/// Fires when a path leaves the Loc-RIB; `attr` is the **stored Loc-RIB
/// attributes of the path being removed** (a wire withdraw carries only
/// the NLRI), so a script can recover e.g. the GBP tag to tear down a
/// side-effect. The hook is observe-only — its return value is ignored —
/// and fail-safe. No-op when unbound or the feature is off.
#[cfg(feature = "lua")]
pub fn loc_rib_withdraw_v4(prefix: IpNet, attr: &BgpAttr, peer: &PeerView) {
    if let Some(name) = withdraw_binding_v4().read().unwrap().clone() {
        engine::loc_rib_withdraw(&name, prefix, attr, peer);
    }
}

/// Feature-off no-op.
#[cfg(not(feature = "lua"))]
pub fn loc_rib_withdraw_v4(_prefix: IpNet, _attr: &BgpAttr, _peer: &PeerView) {}

/// Config-seeded lookup tables exposed to scripts as `map.get(ns, key)`.
/// This is the non-blocking replacement for FRR's blocking HTTP GET: a
/// background process can refresh a namespace out of band while the hook
/// does a synchronous in-memory read on the hot path. Each namespace is a
/// flat key→value string table (e.g. `"sgt"` → MAC → tag).
static MAP: OnceLock<RwLock<BTreeMap<String, BTreeMap<String, String>>>> = OnceLock::new();

fn map() -> &'static RwLock<BTreeMap<String, BTreeMap<String, String>>> {
    MAP.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// Replace a whole namespace's entries (config load).
pub fn map_set_namespace(namespace: &str, entries: BTreeMap<String, String>) {
    map()
        .write()
        .unwrap()
        .insert(namespace.to_string(), entries);
}

/// Drop a namespace (config delete / load error).
pub fn map_clear_namespace(namespace: &str) {
    map().write().unwrap().remove(namespace);
}

/// Look up `key` in `namespace`; `None` if either is absent.
pub fn map_get(namespace: &str, key: &str) -> Option<String> {
    map()
        .read()
        .unwrap()
        .get(namespace)
        .and_then(|entries| entries.get(key).cloned())
}

/// Run the bound script's
/// `loc_rib_import(prefix, attributes, peer, RM_*)` and return its
/// [`Action`].
///
/// **Fail-safe:** any error — no such script, missing function, runtime
/// error, or a malformed return — is logged and mapped to
/// [`Action::NoMatch`] (admit unchanged) so a broken script can never
/// silently blackhole routes.
///
/// On [`Action::MatchAndChange`] the script's mutated `attributes` table
/// is read back and folded onto `attr` (see [`ImportOutcome`]). The
/// caller treats `Failure` as deny, `MatchAndChange` as
/// admit-with-new-attrs, and everything else as admit-unchanged.
#[cfg(feature = "lua")]
pub fn loc_rib_import(name: &str, prefix: IpNet, attr: &BgpAttr, peer: &PeerView) -> ImportOutcome {
    engine::loc_rib_import(name, prefix, attr, peer)
}

/// Feature-off no-op: always admit unchanged.
#[cfg(not(feature = "lua"))]
pub fn loc_rib_import(
    _name: &str,
    _prefix: IpNet,
    _attr: &BgpAttr,
    _peer: &PeerView,
) -> ImportOutcome {
    ImportOutcome::nomatch()
}
