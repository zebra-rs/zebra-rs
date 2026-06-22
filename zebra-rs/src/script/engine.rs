//! Per-thread Lua VM, sandbox, and script loading (feature = "lua").
//!
//! Each worker thread owns one [`Engine`] (a sandboxed `mlua::Lua` plus
//! the per-script environment tables). The Loc-RIB hooks call
//! synchronously from whatever thread owns the route — the sharded
//! Loc-RIB means that can be any shard worker — so a thread-local VM
//! avoids cross-thread sharing of the `!Sync` `Lua` and keeps the hot
//! path lock-free. A reload is picked up lazily: the first call on each
//! thread after a generation bump rebuilds that thread's VM.

use std::cell::RefCell;
use std::collections::BTreeMap;

use bgp_packet::BgpAttr;
use ipnet::IpNet;
use mlua::{Function, Lua, Table, Value};

use super::{Action, ImportOutcome, PeerView, Scripts, current, marshal};

thread_local! {
    static ENGINE: RefCell<Engine> = RefCell::new(Engine::new());
}

/// Per-thread compiled state: one sandboxed VM plus the per-script
/// environment tables that hold each script's hook functions.
/// `generation` records which registry snapshot this VM was built from;
/// a mismatch triggers a lazy rebuild in [`Engine::sync`].
struct Engine {
    lua: Lua,
    generation: u64,
    envs: BTreeMap<String, Table>,
}

/// Safe standard-library symbols copied into each script's environment.
/// Everything else — `os`, `io`, `package`, `require`, `load*`,
/// `dofile`, `debug`, `print` — is intentionally absent (sandbox). The
/// non-blocking host helpers (`zlog`, `ecom`, `sideeffect`, `map`) are
/// added by [`install_host_helpers`].
const SAFE_GLOBALS: &[&str] = &[
    "string",
    "table",
    "math",
    "tostring",
    "tonumber",
    "type",
    "pairs",
    "ipairs",
    "next",
    "select",
    "pcall",
    "xpcall",
    "error",
    "assert",
    "rawget",
    "rawset",
    "rawequal",
    "rawlen",
    "setmetatable",
    "getmetatable",
];

/// Dangerous globals stripped from the VM itself, as defence-in-depth on
/// top of the per-script environment (a script's `_ENV` already excludes
/// these, but dropping them from the VM closes any leak path).
const STRIPPED_GLOBALS: &[&str] = &[
    "os",
    "io",
    "package",
    "require",
    "dofile",
    "loadfile",
    "load",
    "loadstring",
    "debug",
    "collectgarbage",
    "print",
];

impl Engine {
    fn new() -> Self {
        // Start at u64::MAX so the first call on this thread always syncs
        // against the registry (whose initial generation is 0).
        Engine {
            lua: Lua::new(),
            generation: u64::MAX,
            envs: BTreeMap::new(),
        }
    }

    /// Recompile against `scripts` if our generation is stale. A fresh VM
    /// is built so old script state and functions are fully dropped. A
    /// script that fails to load is logged and skipped (its hooks then
    /// fail-safe to `NoMatch`); the generation still advances so we do
    /// not retry-compile on every call.
    fn sync(&mut self, scripts: &Scripts) {
        if self.generation == scripts.generation {
            return;
        }
        let lua = Lua::new();
        let globals = lua.globals();
        for &sym in STRIPPED_GLOBALS {
            let _ = globals.set(sym, Value::Nil);
        }
        let mut envs = BTreeMap::new();
        for (name, src) in &scripts.sources {
            match load_script(&lua, name, src) {
                Ok(env) => {
                    envs.insert(name.clone(), env);
                }
                Err(err) => {
                    tracing::warn!("lua: script '{name}' failed to load: {err}");
                }
            }
        }
        self.lua = lua;
        self.envs = envs;
        self.generation = scripts.generation;
    }

    fn run_import(
        &self,
        name: &str,
        prefix: IpNet,
        attr: &BgpAttr,
        peer: &PeerView,
    ) -> mlua::Result<ImportOutcome> {
        let env = self
            .envs
            .get(name)
            .ok_or_else(|| mlua::Error::RuntimeError(format!("no loaded script '{name}'")))?;
        let func: Function = env.get("loc_rib_import")?;
        let prefix_t = marshal::prefix_table(&self.lua, prefix)?;
        let attr_t = marshal::attr_table(&self.lua, attr)?;
        let peer_t = marshal::peer_table(&self.lua, peer)?;
        let ret: Value = func.call((
            prefix_t,
            attr_t,
            peer_t,
            Action::Failure as i64,
            Action::NoMatch as i64,
            Action::Match as i64,
            Action::MatchAndChange as i64,
        ))?;
        let Value::Table(table) = ret else {
            return Err(mlua::Error::RuntimeError(
                "script must return a table { action = ... }".into(),
            ));
        };
        let action_i: i64 = table.get("action")?;
        let action = Action::from_i64(action_i)
            .ok_or_else(|| mlua::Error::RuntimeError(format!("unknown action {action_i}")))?;
        // Fold a mutated `attributes` table back onto the input attr only
        // on MATCH_AND_CHANGE; a missing `attributes` field means "no
        // change" (admit with the original).
        let new_attr = if action == Action::MatchAndChange {
            match table.get::<Option<Table>>("attributes")? {
                Some(attrs) => Some(marshal::read_attr(&attrs, attr)?),
                None => None,
            }
        } else {
            None
        };
        Ok(ImportOutcome {
            action,
            attr: new_attr,
        })
    }

    /// Run the script's `loc_rib_withdraw(prefix, attributes, peer, RM_*)`.
    /// Observe-only: the return value is ignored (the route is already
    /// gone), so there is no attribute write-back. A script that defines
    /// no `loc_rib_withdraw` is a silent no-op (a script may bind only the
    /// import hook).
    fn run_withdraw(
        &self,
        name: &str,
        prefix: IpNet,
        attr: &BgpAttr,
        peer: &PeerView,
    ) -> mlua::Result<()> {
        let env = self
            .envs
            .get(name)
            .ok_or_else(|| mlua::Error::RuntimeError(format!("no loaded script '{name}'")))?;
        let Some(func) = env.get::<Option<Function>>("loc_rib_withdraw")? else {
            return Ok(());
        };
        let prefix_t = marshal::prefix_table(&self.lua, prefix)?;
        let attr_t = marshal::attr_table(&self.lua, attr)?;
        let peer_t = marshal::peer_table(&self.lua, peer)?;
        let _: Value = func.call((
            prefix_t,
            attr_t,
            peer_t,
            Action::Failure as i64,
            Action::NoMatch as i64,
            Action::Match as i64,
            Action::MatchAndChange as i64,
        ))?;
        Ok(())
    }
}

/// Load one script source into its own sandboxed environment table and
/// return that table. The chunk's `_ENV` is the env table, so the script
/// sees only [`SAFE_GLOBALS`] and its own definitions — no cross-script
/// global collisions. After `exec`, the env holds the script's
/// `loc_rib_import` / `loc_rib_withdraw` functions.
fn load_script(lua: &Lua, name: &str, src: &str) -> mlua::Result<Table> {
    let env = lua.create_table()?;
    let globals = lua.globals();
    for &sym in SAFE_GLOBALS {
        let value: Value = globals.get(sym)?;
        if value != Value::Nil {
            env.set(sym, value)?;
        }
    }
    install_host_helpers(lua, &env)?;
    lua.load(src)
        .set_name(name)
        .set_environment(env.clone())
        .exec()?;
    Ok(env)
}

/// Register the non-blocking host helpers exposed to scripts: `zlog`
/// (logging) and the `ecom` typed Group-Policy-ID helpers
/// (draft-wlin-bess, type 0x03, sub-type 0x17). `map` / `sideeffect`
/// (the non-blocking side-effect channel) follow in a later PR.
fn install_host_helpers(lua: &Lua, env: &Table) -> mlua::Result<()> {
    let zlog = lua.create_table()?;
    zlog.set(
        "info",
        lua.create_function(|_, msg: String| {
            tracing::info!("lua: {msg}");
            Ok(())
        })?,
    )?;
    zlog.set(
        "warn",
        lua.create_function(|_, msg: String| {
            tracing::warn!("lua: {msg}");
            Ok(())
        })?,
    )?;
    zlog.set(
        "error",
        lua.create_function(|_, msg: String| {
            tracing::error!("lua: {msg}");
            Ok(())
        })?,
    )?;
    env.set("zlog", zlog)?;

    let ecom = lua.create_table()?;
    // ecom.gpi(tag) -> 8-octet GPI extended-community value.
    ecom.set(
        "gpi",
        lua.create_function(|lua, tag: u16| {
            let mut bytes = [0u8; 8];
            bytes[0] = 0x03;
            bytes[1] = 0x17;
            bytes[6] = (tag >> 8) as u8;
            bytes[7] = (tag & 0xff) as u8;
            lua.create_string(&bytes[..])
        })?,
    )?;
    // ecom.parse_gpi(value) -> tag, or nil if not a GPI ext-community.
    ecom.set(
        "parse_gpi",
        lua.create_function(|_, value: mlua::String| {
            let bytes = value.as_bytes();
            Ok(
                if bytes.len() == 8 && bytes[0] == 0x03 && bytes[1] == 0x17 {
                    Some(u16::from_be_bytes([bytes[6], bytes[7]]))
                } else {
                    None
                },
            )
        })?,
    )?;
    env.set("ecom", ecom)?;

    // sideeffect.nft{op=, table=, set=, elem=} enqueues a non-blocking
    // nftables mutation onto the background drainer (the route path never
    // runs `nft` inline).
    let sideeffect = lua.create_table()?;
    sideeffect.set(
        "nft",
        lua.create_function(|_, opts: Table| {
            let op: String = opts.get("op")?;
            super::sideeffect::enqueue(super::sideeffect::NftOp {
                add: op == "add",
                table: opts.get("table")?,
                set: opts.get("set")?,
                elem: opts.get("elem")?,
            });
            Ok(())
        })?,
    )?;
    env.set("sideeffect", sideeffect)?;

    // map.get(namespace, key) → value string, or nil. A synchronous,
    // non-blocking read of a config-seeded lookup table (the non-blocking
    // replacement for FRR's blocking HTTP GET).
    let map = lua.create_table()?;
    map.set(
        "get",
        lua.create_function(|_, (namespace, key): (String, String)| {
            Ok(super::map_get(&namespace, &key))
        })?,
    )?;
    env.set("map", map)?;
    Ok(())
}

/// Thread-local entry point used by [`super::loc_rib_import`]. Fail-safe:
/// sync/run errors are logged and mapped to [`ImportOutcome::nomatch`].
pub fn loc_rib_import(name: &str, prefix: IpNet, attr: &BgpAttr, peer: &PeerView) -> ImportOutcome {
    let scripts = current();
    ENGINE.with(|cell| {
        let mut engine = cell.borrow_mut();
        engine.sync(&scripts);
        match engine.run_import(name, prefix, attr, peer) {
            Ok(outcome) => outcome,
            Err(err) => {
                tracing::warn!("lua: import hook '{name}' error: {err}");
                ImportOutcome::nomatch()
            }
        }
    })
}

/// Thread-local entry point used by [`super::loc_rib_withdraw_v4`].
/// Observe-only; fail-safe (errors are logged, nothing else happens).
pub fn loc_rib_withdraw(name: &str, prefix: IpNet, attr: &BgpAttr, peer: &PeerView) {
    let scripts = current();
    ENGINE.with(|cell| {
        let mut engine = cell.borrow_mut();
        engine.sync(&scripts);
        if let Err(err) = engine.run_withdraw(name, prefix, attr, peer) {
            tracing::warn!("lua: withdraw hook '{name}' error: {err}");
        }
    });
}

/// Test-only: run the withdraw hook and surface the `Result` (the public
/// entry swallows errors by design), so a test can assert the script ran
/// and saw the stored attributes.
#[cfg(test)]
fn run_withdraw_test(
    name: &str,
    prefix: IpNet,
    attr: &BgpAttr,
    peer: &PeerView,
) -> mlua::Result<()> {
    let scripts = current();
    ENGINE.with(|cell| {
        let mut engine = cell.borrow_mut();
        engine.sync(&scripts);
        engine.run_withdraw(name, prefix, attr, peer)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::{ExtCommunity, ExtCommunityValue};
    use std::collections::BTreeMap;
    use std::sync::{Mutex, MutexGuard};

    // The registry and per-thread VMs are process-global, so tests must
    // not install concurrently. Each test holds this lock for its whole
    // body; `into_inner` ignores poisoning so one panicking test does not
    // cascade-fail the rest.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn install_one(name: &str, src: &str) -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut map = BTreeMap::new();
        map.insert(name.to_string(), src.to_string());
        crate::script::install(map);
        guard
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn peer() -> PeerView {
        PeerView {
            remote_as: 65001,
            local_as: 65000,
            remote_id: "2.2.2.2".parse().unwrap(),
            local_id: "1.1.1.1".parse().unwrap(),
            remote_address: "10.0.0.2".parse().unwrap(),
            state: "Established".into(),
            is_ibgp: false,
        }
    }

    fn import(name: &str, prefix: &str, attr: &BgpAttr) -> Action {
        loc_rib_import(name, net(prefix), attr, &peer()).action
    }

    #[test]
    fn import_returns_nomatch() {
        let _g = install_one(
            "t",
            r#"
            function loc_rib_import(prefix, attributes, peer,
                                    RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
                return { action = RM_NOMATCH }
            end
        "#,
        );
        assert_eq!(
            import("t", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn prefix_and_peer_are_marshalled() {
        let _g = install_one(
            "t2",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                if prefix.network == "1.1.1.0/24"
                   and prefix.afi == "ipv4"
                   and peer.remote_as == 65001 then
                    return { action = FAIL }
                end
                return { action = NOMATCH }
            end
        "#,
        );
        assert_eq!(
            import("t2", "1.1.1.0/24", &BgpAttr::default()),
            Action::Failure
        );
        assert_eq!(
            import("t2", "2.2.2.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn reads_gpi_ext_community() {
        // GPI ext-community (draft-wlin-bess): type 0x03, sub-type 0x17,
        // scope=0, reserved=0, tag=300 (0x012c). The script extracts the
        // tag with FRR's `string.unpack(">BBHHH", ...)` idiom.
        let ecom = ExtCommunity::from([ExtCommunityValue {
            high_type: 0x03,
            low_type: 0x17,
            val: [0x00, 0x00, 0x00, 0x00, 0x01, 0x2c],
        }]);
        let attr = BgpAttr {
            ecom: Some(ecom),
            ..Default::default()
        };
        let _g = install_one(
            "gbp",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                for _, ec in ipairs(attributes.ext_community) do
                    local ht, lt, scope, resv, tag = string.unpack(">BBHHH", ec)
                    if ht == 0x03 and lt == 0x17 and tag == 300 then
                        return { action = FAIL }
                    end
                end
                return { action = NOMATCH }
            end
        "#,
        );
        assert_eq!(import("gbp", "10.0.0.0/24", &attr), Action::Failure);
        // No ext-community → loop is empty → NoMatch.
        assert_eq!(
            import("gbp", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn sandbox_blocks_os() {
        // `os` is absent from the script env, so referencing it raises a
        // runtime error, which fail-safes to NoMatch.
        let _g = install_one(
            "t3",
            r#"
            function loc_rib_import(prefix, a, p, FAIL, NOMATCH, MATCH, CHANGE)
                local _ = os.time()
                return { action = MATCH }
            end
        "#,
        );
        assert_eq!(
            import("t3", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn missing_function_failsafe() {
        let _g = install_one("t4", "x = 1\n");
        assert_eq!(
            import("t4", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn unknown_script_failsafe() {
        let _g = install_one("t5", "function loc_rib_import() return { action = 1 } end");
        assert_eq!(
            import("nope", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn bad_return_failsafe() {
        let _g = install_one(
            "t6",
            "function loc_rib_import(prefix, a, p, F, N, M, C) return 42 end",
        );
        assert_eq!(
            import("t6", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }

    #[test]
    fn import_v4_binding_dispatch() {
        let _g = install_one(
            "bind",
            r#"
            function loc_rib_import(prefix, a, p, FAIL, NOMATCH, MATCH, CHANGE)
                if prefix.network == "9.9.9.0/24" then return { action = FAIL } end
                return { action = NOMATCH }
            end
        "#,
        );
        // Unbound → NoMatch regardless of the route.
        assert_eq!(
            crate::script::loc_rib_import_v4(net("9.9.9.0/24"), &BgpAttr::default(), &peer())
                .action,
            Action::NoMatch
        );
        // Bound → the script decides.
        crate::script::set_import_binding_v4(Some("bind".to_string()));
        assert_eq!(
            crate::script::loc_rib_import_v4(net("9.9.9.0/24"), &BgpAttr::default(), &peer())
                .action,
            Action::Failure
        );
        assert_eq!(
            crate::script::loc_rib_import_v4(net("8.8.8.0/24"), &BgpAttr::default(), &peer())
                .action,
            Action::NoMatch
        );
        // Unbind → NoMatch again (clean up the global for other tests).
        crate::script::set_import_binding_v4(None);
        assert_eq!(
            crate::script::loc_rib_import_v4(net("9.9.9.0/24"), &BgpAttr::default(), &peer())
                .action,
            Action::NoMatch
        );
    }

    #[test]
    fn write_back_med_and_local_pref() {
        let _g = install_one(
            "wb",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                attributes.med = 222
                attributes.local_pref = 333
                return { action = CHANGE, attributes = attributes }
            end
        "#,
        );
        let out = loc_rib_import("wb", net("10.0.0.0/24"), &BgpAttr::default(), &peer());
        assert_eq!(out.action, Action::MatchAndChange);
        let attr = out.attr.expect("MATCH_AND_CHANGE carries attributes");
        assert_eq!(attr.med.map(|m| m.med), Some(222));
        assert_eq!(attr.local_pref.map(|l| l.local_pref), Some(333));
    }

    #[test]
    fn write_back_appends_gpi_ext_community() {
        // The GBP origination move: append a GPI ext-community via the
        // typed `ecom.gpi` helper, then read it back on the Rust side.
        let _g = install_one(
            "gpi",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                table.insert(attributes.ext_community, ecom.gpi(300))
                return { action = CHANGE, attributes = attributes }
            end
        "#,
        );
        let out = loc_rib_import("gpi", net("10.0.0.0/24"), &BgpAttr::default(), &peer());
        assert_eq!(out.action, Action::MatchAndChange);
        let attr = out.attr.expect("attributes present");
        let ecom = attr.ecom.expect("ext-community installed");
        let gpi = ecom
            .0
            .iter()
            .find(|v| v.high_type == 0x03 && v.low_type == 0x17)
            .expect("GPI ext-community present");
        assert_eq!(u16::from_be_bytes([gpi.val[4], gpi.val[5]]), 300);
    }

    #[test]
    fn write_back_clears_med_on_nil() {
        let _g = install_one(
            "clr",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                attributes.med = nil
                return { action = CHANGE, attributes = attributes }
            end
        "#,
        );
        let base = BgpAttr {
            med: Some(bgp_packet::Med::new(100)),
            ..Default::default()
        };
        let out = loc_rib_import("clr", net("10.0.0.0/24"), &base, &peer());
        assert_eq!(out.action, Action::MatchAndChange);
        assert_eq!(out.attr.expect("attributes present").med, None);
    }

    #[test]
    fn nomatch_does_not_change_attrs() {
        // Mutating then returning NOMATCH must not fold anything back.
        let _g = install_one(
            "nm",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                attributes.med = 999
                return { action = NOMATCH }
            end
        "#,
        );
        let out = loc_rib_import("nm", net("10.0.0.0/24"), &BgpAttr::default(), &peer());
        assert_eq!(out.action, Action::NoMatch);
        assert!(out.attr.is_none());
    }

    #[test]
    fn withdraw_sees_stored_attrs() {
        // The headline capability FRR lacks: on withdraw the script gets
        // the *stored* attributes of the removed path, so it can recover
        // the GBP tag. The script `error()`s when it sees tag 300, which
        // the test surfaces as Err.
        let _g = install_one(
            "wd",
            r#"
            function loc_rib_withdraw(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                for _, ec in ipairs(attributes.ext_community) do
                    if ecom.parse_gpi(ec) == 300 then
                        error("saw gpi 300")
                    end
                end
            end
        "#,
        );
        let ecom = ExtCommunity::from([ExtCommunityValue {
            high_type: 0x03,
            low_type: 0x17,
            val: [0x00, 0x00, 0x00, 0x00, 0x01, 0x2c],
        }]);
        let attr = BgpAttr {
            ecom: Some(ecom),
            ..Default::default()
        };
        assert!(run_withdraw_test("wd", net("10.0.0.0/24"), &attr, &peer()).is_err());
        // No ext-community on the removed path → loop empty → Ok.
        assert!(run_withdraw_test("wd", net("10.0.0.0/24"), &BgpAttr::default(), &peer()).is_ok());
    }

    #[test]
    fn withdraw_missing_function_is_noop() {
        // A script that binds only the import hook is a silent no-op for
        // withdraw (not a logged error every time).
        let _g = install_one("wd2", "function loc_rib_import() return { action = 1 } end");
        assert!(run_withdraw_test("wd2", net("10.0.0.0/24"), &BgpAttr::default(), &peer()).is_ok());
    }

    #[test]
    fn withdraw_v4_binding_smoke() {
        // Exercise the public dispatch: unbound → no-op, bound → runs.
        let _g = install_one("wb", "function loc_rib_withdraw(p, a, pe, F, N, M, C) end");
        crate::script::loc_rib_withdraw_v4(net("10.0.0.0/24"), &BgpAttr::default(), &peer());
        crate::script::set_withdraw_binding_v4(Some("wb".to_string()));
        crate::script::loc_rib_withdraw_v4(net("10.0.0.0/24"), &BgpAttr::default(), &peer());
        crate::script::set_withdraw_binding_v4(None);
    }

    #[test]
    fn sideeffect_nft_enqueues() {
        // A hook calling sideeffect.nft{...} enqueues an NftOp for the
        // background drainer (the GBP teardown move) without blocking.
        let _g = install_one(
            "se",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                sideeffect.nft{ op = "add", table = "bridge gbp_filter",
                                set = "tag_100", elem = "aa:bb:cc:dd:ee:01" }
                return { action = NOMATCH }
            end
        "#,
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        crate::script::sideeffect::set_sender(tx);
        let _ = loc_rib_import("se", net("10.0.0.0/24"), &BgpAttr::default(), &peer());
        let op = rx.try_recv().expect("nft op enqueued");
        assert!(op.add);
        assert_eq!(op.table, "bridge gbp_filter");
        assert_eq!(op.set, "tag_100");
        assert_eq!(op.elem, "aa:bb:cc:dd:ee:01");
    }

    #[test]
    fn map_get_lookup() {
        // The GBP origination move: a script resolves a MAC → tag from a
        // config-seeded table via `map.get` (no blocking HTTP).
        let _g = install_one(
            "m",
            r#"
            function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
                if map.get("sgt", "aa:bb:cc:dd:ee:01") == "100" then
                    return { action = FAIL }
                end
                return { action = NOMATCH }
            end
        "#,
        );
        let mut entries = std::collections::BTreeMap::new();
        entries.insert("aa:bb:cc:dd:ee:01".to_string(), "100".to_string());
        crate::script::map_set_namespace("sgt", entries);
        assert_eq!(
            import("m", "10.0.0.0/24", &BgpAttr::default()),
            Action::Failure
        );
        // Cleared namespace → nil → no match (and cleans up the global).
        crate::script::map_clear_namespace("sgt");
        assert_eq!(
            import("m", "10.0.0.0/24", &BgpAttr::default()),
            Action::NoMatch
        );
    }
}
