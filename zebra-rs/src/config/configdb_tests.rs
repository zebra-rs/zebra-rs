//! CONFIG_DB into the `sonic` subtree (`config::configdb`), on the
//! models of `testdata/sonic`.

use super::super::sonic::graft;
use super::test_support::{candidate, commit, edit, run, running};
use super::*;

const MODELS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/testdata/sonic");
const YANG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/yang");

/// A daemon as it is anywhere but on a SONiC device: no feature, no
/// models.
fn plain(name: &str) -> ConfigManager {
    let path =
        std::env::temp_dir().join(format!("zebra-rs-configdb-{name}-{}", std::process::id()));
    test_support::manager(&path, Vec::new(), Default::default())
}

/// A daemon started with `--feature sonic`, with the test models as its
/// `sonic` subtree.
fn manager(name: &str) -> ConfigManager {
    let path =
        std::env::temp_dir().join(format!("zebra-rs-configdb-{name}-{}", std::process::id()));
    let cm = test_support::manager(&path, vec!["sonic".to_string()], Default::default());
    let (sonic, _) = super::super::sonic::sonic_entry(YANG, Path::new(MODELS));
    graft(
        &cm.modes.get("configure").expect("configure mode").entry,
        &sonic,
    );
    // As `init` says it of a daemon that found the models.
    cm.sonic_mirror.set(true);
    cm
}

/// The same models where `sonic` is no copy of anything: configuration
/// like the rest, to read a document into.
fn unmirrored(name: &str) -> ConfigManager {
    let cm = manager(name);
    cm.sonic_mirror.set(false);
    cm
}

/// Give the manager CONFIG_DB as the sync process does.
fn import(cm: &ConfigManager, tables: serde_json::Value) -> DeployResponse {
    cm.deploy(&serde_json::json!({ "CONFIG_DB": tables }).to_string())
}

fn translate(cm: &ConfigManager, tables: serde_json::Value) -> super::super::configdb::Translation {
    let configure = &cm.modes.get("configure").expect("configure mode").entry;
    let sonic = super::super::sonic::grafted(configure).expect("sonic");
    super::super::configdb::translate(&sonic, tables.as_object().unwrap(), |line| {
        cm.paths(line.to_string()).is_some()
    })
}

fn tables() -> serde_json::Value {
    serde_json::json!({
        "PORT": {
            "Ethernet0": {"lanes": "1,2,3,4", "admin_status": "up", "mtu": "9100",
                          "description": "uplink to spine 1"},
            "Ethernet4": {"lanes": "5,6,7,8"},
        },
        "INTERFACE": {
            "Ethernet0": {"NULL": "NULL"},
            "Ethernet0|10.0.0.0/31": {},
            "Ethernet0|2001:db8::/64": {"scope": "global"},
        },
        "DEVICE_METADATA": {
            "localhost": {"hostname": "sonic1", "bgp_asn": "65100"},
        },
        "TELEMETRY_CLIENT": {
            "Global": {"retry_interval": "30"},
            "Subscription|s1": {"dst_group": "g1"},
        },
    })
}

const IMPORTED: &str = "\
sonic DEVICE_METADATA localhost bgp_asn 65100
sonic DEVICE_METADATA localhost hostname sonic1
sonic INTERFACE Ethernet0
sonic INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31
sonic INTERFACE_IPPREFIX Ethernet0 2001:db8::/64
sonic INTERFACE_IPPREFIX Ethernet0 2001:db8::/64 scope global
sonic PORT Ethernet0
sonic PORT Ethernet0 admin_status up
sonic PORT Ethernet0 description uplink to spine 1
sonic PORT Ethernet0 lanes 1,2,3,4
sonic PORT Ethernet0 mtu 9100
sonic PORT Ethernet4
sonic PORT Ethernet4 lanes 5,6,7,8
sonic TELEMETRY_CLIENT Global retry_interval 30
sonic TELEMETRY_CLIENT TELEMETRY_CLIENT_LIST Subscription s1
sonic TELEMETRY_CLIENT TELEMETRY_CLIENT_LIST Subscription s1 dst_group g1
";

/// Each row is under the list or the container of its table that its
/// key says, and each field is a leaf of it.
#[test]
fn config_db_is_copied_under_sonic() {
    let cm = manager("copy");
    let reply = import(&cm, tables());
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(running(&cm), IMPORTED);
    let t = translate(&cm, tables());
    assert_eq!((t.tables, t.rows), (4, 8));
    assert_eq!(t.problems, Vec::<String>::new());
    assert_eq!(t.unmodelled, Vec::<String>::new());
}

/// The subtree is the copy, whole: what CONFIG_DB no longer has is gone
/// from it, and the same CONFIG_DB again changes nothing.
#[test]
fn an_import_replaces_the_subtree() {
    let cm = manager("replace");
    import(&cm, tables());
    import(&cm, tables());
    assert_eq!(running(&cm), IMPORTED);

    let mut less = tables();
    less["PORT"].as_object_mut().unwrap().remove("Ethernet4");
    less["PORT"]["Ethernet0"]["mtu"] = "1500".into();
    less.as_object_mut().unwrap().remove("TELEMETRY_CLIENT");
    import(&cm, less);
    let now = running(&cm);
    assert!(!now.contains("Ethernet4"), "{now}");
    assert!(!now.contains("TELEMETRY_CLIENT"), "{now}");
    assert!(now.contains("sonic PORT Ethernet0 mtu 1500\n"), "{now}");

    import(&cm, serde_json::json!({}));
    assert_eq!(running(&cm), "");
}

/// Nothing else of the configuration is touched, and an import is not a
/// commit of the history: it is a copy of what was changed elsewhere.
#[test]
fn an_import_leaves_the_rest_and_the_history() {
    let cm = manager("rest");
    commit(&cm, &["set system hostname r1"]);
    assert_eq!(cm.history.len(), 1);
    import(&cm, tables());
    assert_eq!(running(&cm), format!("{IMPORTED}system hostname r1\n"));
    assert_eq!(cm.history.len(), 1);
    import(&cm, serde_json::json!({}));
    assert_eq!(running(&cm), "system hostname r1\n");
}

/// An operator's uncommitted edits are neither committed by an import
/// nor lost to it.
#[test]
fn an_import_keeps_uncommitted_edits() {
    let cm = manager("edits");
    import(&cm, tables());
    edit(&cm, "set system hostname pending");
    let mut more = tables();
    more["PORT"]["Ethernet8"] = serde_json::json!({"lanes": "9,10,11,12"});
    import(&cm, more);
    assert!(!running(&cm).contains("system hostname"));
    assert!(running(&cm).contains("sonic PORT Ethernet8 lanes 9,10,11,12\n"));
    let pending = candidate(&cm);
    assert!(pending.contains("system hostname pending\n"), "{pending}");
    assert!(pending.contains("sonic PORT Ethernet8\n"), "{pending}");
}

/// A leaf-list is a field named with `@` and its values joined by
/// commas, or an array; a row with as many keys as two lists have goes
/// to the one whose key types take them.
#[test]
fn leaf_lists_and_lists_with_as_many_keys() {
    let cm = manager("lists");
    let reply = import(
        &cm,
        serde_json::json!({"STATIC_ROUTE": {
            "192.0.2.0/24": {"nexthop": "10.0.0.1"},
            "default|198.51.100.0/24": {"nexthop": "10.0.0.2", "ifname@": "Ethernet0,Ethernet4"},
            "Vrf-red|203.0.113.0/24": {"ifname": ["Ethernet8"]},
            "Ethernet0|10.9.0.0/16": {},
        }}),
    );
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(
        running(&cm),
        "\
sonic STATIC_ROUTE Vrf-red 203.0.113.0/24
sonic STATIC_ROUTE Vrf-red 203.0.113.0/24 ifname Ethernet8
sonic STATIC_ROUTE default 198.51.100.0/24
sonic STATIC_ROUTE default 198.51.100.0/24 ifname Ethernet0
sonic STATIC_ROUTE default 198.51.100.0/24 ifname Ethernet4
sonic STATIC_ROUTE default 198.51.100.0/24 nexthop 10.0.0.2
sonic STATIC_ROUTE_IFACE Ethernet0 10.9.0.0/16
sonic STATIC_ROUTE_TEMPLATE 192.0.2.0/24
sonic STATIC_ROUTE_TEMPLATE 192.0.2.0/24 nexthop 10.0.0.1
"
    );
}

/// What cannot be copied is said and left out, and everything else is
/// copied: one row does not stop the import.
#[test]
fn what_cannot_be_copied_is_left_out() {
    let cm = manager("problems");
    let db = serde_json::json!({
        "NO_SUCH_TABLE": {"x": {"a": "b"}},
        "PORT": {
            "Ethernet0": {"lanes": "1,2,3,4", "no_such_field": "1", "description": "",
                          "admin_status": "sideways"},
            "Ethernet0|extra": {"lanes": "1"},
            "not-a-port": {"lanes": "1"},
        },
        "DEVICE_METADATA": {"localhost": {"hostname": "two\nlines", "bgp_asn": 65100}},
    });
    let t = translate(&cm, db.clone());
    assert_eq!(t.unmodelled, ["NO_SUCH_TABLE"]);
    assert_eq!(
        t.problems,
        [
            "PORT|Ethernet0: no field `no_such_field` in the model",
            "PORT|Ethernet0: the value of `description` is empty",
            "PORT|Ethernet0|extra: no list of the table takes this key",
            "DEVICE_METADATA|localhost: the value of `hostname` has more than one line",
        ]
    );
    let reply = import(&cm, db);
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    // The enumeration and the key's pattern are the model's: those two
    // lines are refused when they are run, and left out with the rest.
    assert_eq!(
        running(&cm),
        "sonic DEVICE_METADATA localhost bgp_asn 65100\n\
         sonic PORT Ethernet0\n\
         sonic PORT Ethernet0 lanes 1,2,3,4\n"
    );
}

/// A row the model calls incomplete is copied all the same: CONFIG_DB
/// is what the device is configured with. Typed by an operator, the
/// same row is refused at commit.
#[test]
fn an_incomplete_row_is_copied() {
    let cm = manager("incomplete");
    let reply = import(
        &cm,
        serde_json::json!({"PORT": {"Ethernet0": {"mtu": "9100"}}}),
    );
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(
        running(&cm),
        "sonic PORT Ethernet0\nsonic PORT Ethernet0 mtu 9100\n"
    );
}

/// Only a document in the wrapper is CONFIG_DB. The same tables without
/// it are a configuration in JSON, as before, and are refused as one.
#[test]
fn only_the_wrapped_document_is_config_db() {
    use super::super::configdb::document;
    assert!(document(r#"{"CONFIG_DB": {"PORT": {}}}"#).is_some());
    assert!(document(r#"  {"CONFIG_DB": {}}"#).is_some());
    for other in [
        r#"{"PORT": {}}"#,
        r#"{"CONFIG_DB": {}, "PORT": {}}"#,
        r#"{"CONFIG_DB": []}"#,
        "set sonic PORT Ethernet0",
        "",
    ] {
        assert!(document(other).is_none(), "{other}");
    }
    let cm = manager("wrapper");
    let reply = cm.deploy(r#"{"PORT": {"Ethernet0": {"lanes": "1"}}}"#);
    assert_eq!(reply.apply_code, ApplyCode::ParseError);
    assert_eq!(running(&cm), "");
}

/// Anywhere but on a SONiC device, none of this is there. A document
/// in the wrapper is a configuration with a key the schema does not
/// have, `sonic` and `compare config-db` are not commands, and a commit
/// asks nothing of a writer, should one be waiting.
#[tokio::test]
async fn without_the_feature_nothing_here_is_there() {
    let mut cm = plain("no-feature");
    let reply = import(&cm, tables());
    assert_eq!(reply.apply_code, ApplyCode::ParseError);
    assert!(
        reply.cmd.contains("unknown key `CONFIG_DB`"),
        "{}",
        reply.cmd
    );

    let mode = cm.modes.get("configure").expect("configure mode");
    for line in [
        "set sonic PORT Ethernet0 mtu 9100",
        "delete sonic",
        "compare config-db",
    ] {
        let (code, output, _) = cm.execute(mode, line);
        assert_eq!((code, output.as_str()), (ExecCode::Nomatch, ""), "`{line}`");
    }

    let orders = writer(&cm, shared(tables()), None);
    tokio::task::yield_now().await;
    edit(&cm, "set system hostname r1");
    assert_eq!(
        session(&mut cm, "compare formal").await,
        "+system hostname r1\n"
    );
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(running(&cm), "system hostname r1\n");
    assert_eq!(cm.history.len(), 1);
    // `save` writes all of it, and `rollback` reads all of it back.
    commit(&cm, &["set system hostname r2"]);
    assert!(run(&cm, "save formal").starts_with("Configuration saved"));
    assert_eq!(
        std::fs::read_to_string(&cm.config_path).unwrap(),
        "set system hostname r2\n"
    );
    let _ = std::fs::remove_file(&cm.config_path);
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(candidate(&cm), "system hostname r1\n");
}

/// With the feature and no models there is no `sonic` either: CONFIG_DB
/// is refused, and the patch has nothing to be of.
#[test]
fn with_the_feature_and_no_models() {
    let path = std::env::temp_dir().join(format!(
        "zebra-rs-configdb-no-models-{}",
        std::process::id()
    ));
    let cm = test_support::manager(&path, vec!["sonic".to_string()], Default::default());
    let reply = import(&cm, tables());
    assert_eq!(reply.apply_code, ApplyCode::ParseError);
    let mode = cm.modes.get("configure").expect("configure mode");
    let (code, why, _) = cm.execute(mode, "compare config-db");
    assert_eq!(code, ExecCode::Nomatch);
    assert!(why.contains("No SONiC models are loaded"), "{why}");
}

const READ_ONLY: &str = "% `sonic` is a copy of CONFIG_DB and is changed there: \
     give `compare config-db` to SONiC's `config apply-patch`, or `discard`";

/// The patch `compare config-db` prints.
fn pending_patch(cm: &ConfigManager) -> serde_json::Value {
    serde_json::from_str(&run(cm, "compare config-db")).expect("a JSON Patch")
}

/// Apply a JSON Patch of the three operations `compare config-db` uses
/// to `tables`, as SONiC's `config apply-patch` does to CONFIG_DB.
fn apply_patch(tables: &mut serde_json::Value, patch: &serde_json::Value) {
    for step in patch.as_array().expect("an array of steps") {
        let path: Vec<String> = step["path"]
            .as_str()
            .unwrap()
            .split('/')
            .skip(1)
            .map(|s| s.replace("~1", "/").replace("~0", "~"))
            .collect();
        let (last, parents) = path.split_last().unwrap();
        let mut at = &mut *tables;
        for step in parents {
            at = at
                .get_mut(step)
                .unwrap_or_else(|| panic!("no {step} in {path:?}"));
        }
        let object = at.as_object_mut().expect("an object");
        match step["op"].as_str().unwrap() {
            "remove" => {
                object
                    .remove(last)
                    .unwrap_or_else(|| panic!("nothing at {path:?}"));
            }
            "replace" => {
                assert!(object.contains_key(last), "nothing to replace at {path:?}");
                object.insert(last.clone(), step["value"].clone());
            }
            "add" => {
                object.insert(last.clone(), step["value"].clone());
            }
            other => panic!("op {other}"),
        }
    }
}

/// The copy is edited in the candidate like the rest of the
/// configuration. A commit of such an edit is refused: the subtree is
/// changed in CONFIG_DB, and the refusal says how.
#[test]
fn a_commit_does_not_change_the_copy() {
    let cm = manager("read-only");
    import(&cm, tables());
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    edit(&cm, "delete sonic PORT Ethernet4");
    assert_eq!(run(&cm, "commit"), READ_ONLY);
    assert_eq!(running(&cm), IMPORTED);
    // The edits are still there to be given to CONFIG_DB, or dropped.
    assert_ne!(run(&cm, "compare"), "");
    run(&cm, "discard");
    assert_eq!(candidate(&cm), IMPORTED);
    // Everything else is committed as ever, and the import still copies.
    commit(&cm, &["set system hostname r1"]);
    let mut more = tables();
    more["PORT"]["Ethernet0"]["mtu"] = "1500".into();
    import(&cm, more);
    assert!(running(&cm).contains("sonic PORT Ethernet0 mtu 1500\n"));
}

/// Nor does a document given to `vtyctl apply`, in any format: only the
/// one that says it is CONFIG_DB.
#[test]
fn a_document_does_not_change_the_copy() {
    let cm = manager("read-only-apply");
    import(&cm, tables());
    for document in [
        "set sonic PORT Ethernet0 mtu 1500\n",
        "set system hostname r1\nset sonic PORT Ethernet0 mtu 1500\n",
        "delete sonic PORT Ethernet4\n",
    ] {
        let reply = cm.deploy(document);
        assert_ne!(reply.apply_code, ApplyCode::Applied, "{document}");
        assert_eq!(reply.cmd, READ_ONLY, "{document}");
    }
    assert_eq!(running(&cm), IMPORTED);
    assert_eq!(candidate(&cm), IMPORTED);
}

/// The subtree stands for the tables it was copied from: what is
/// exported is what was imported, values as the strings CONFIG_DB holds.
#[test]
fn the_subtree_exports_as_the_tables_it_was_copied_from() {
    let cm = manager("export");
    let db = serde_json::json!({
        "PORT": {
            "Ethernet0": {"lanes": "1,2,3,4", "admin_status": "up", "mtu": "9100",
                          "description": "uplink to spine 1"},
            "Ethernet4": {"lanes": "5,6,7,8"},
        },
        "INTERFACE": {
            "Ethernet0": {},
            "Ethernet0|10.0.0.0/31": {},
            "Ethernet0|2001:db8::/64": {"scope": "global"},
        },
        "DEVICE_METADATA": {"localhost": {"hostname": "sonic1", "bgp_asn": "65100"}},
        "TELEMETRY_CLIENT": {
            "Global": {"retry_interval": "30"},
            "Subscription|s1": {"dst_group": "g1"},
        },
        "STATIC_ROUTE": {
            "192.0.2.0/24": {"nexthop": "10.0.0.1"},
            "default|198.51.100.0/24": {"ifname": ["Ethernet0", "Ethernet4"]},
        },
    });
    import(&cm, db.clone());
    let configure = &cm.modes.get("configure").expect("configure mode").entry;
    let schema = super::super::sonic::grafted(configure).expect("sonic");
    let sonic = cm.store.running.borrow().lookup(&"sonic".to_string());
    let exported = super::super::configdb::export(&schema, sonic.as_ref());
    assert_eq!(exported.unplaced, Vec::<String>::new());
    assert_eq!(serde_json::Value::Object(exported.tables), db);
    // With nothing pending there is nothing to patch.
    assert_eq!(pending_patch(&cm), serde_json::json!([]));
}

/// `compare config-db` is the pending edits of `sonic` as a JSON Patch
/// of CONFIG_DB: one step for each field, row or table that differs.
#[test]
fn compare_config_db_is_a_patch() {
    let cm = manager("patch");
    import(&cm, tables());
    for line in [
        "set sonic PORT Ethernet0 mtu 1500",
        "set sonic PORT Ethernet0 description to spine 2",
        "delete sonic PORT Ethernet0 admin_status",
        "delete sonic PORT Ethernet4",
        "set sonic PORT Ethernet8 lanes 9,10,11,12",
        "set sonic INTERFACE_IPPREFIX Ethernet0 192.0.2.1/24",
        "delete sonic TELEMETRY_CLIENT",
        "set sonic STATIC_ROUTE default 198.51.100.0/24 ifname Ethernet0",
        // Not `sonic`: no part of the patch.
        "set system hostname r1",
    ] {
        edit(&cm, line);
    }
    assert_eq!(
        pending_patch(&cm),
        serde_json::json!([
            {"op": "add", "path": "/INTERFACE/Ethernet0|192.0.2.1~124", "value": {}},
            {"op": "remove", "path": "/PORT/Ethernet0/admin_status"},
            {"op": "replace", "path": "/PORT/Ethernet0/description", "value": "to spine 2"},
            {"op": "replace", "path": "/PORT/Ethernet0/mtu", "value": "1500"},
            {"op": "remove", "path": "/PORT/Ethernet4"},
            {"op": "add", "path": "/PORT/Ethernet8", "value": {"lanes": "9,10,11,12"}},
            {"op": "add", "path": "/STATIC_ROUTE",
             "value": {"default|198.51.100.0/24": {"ifname": ["Ethernet0"]}}},
            {"op": "remove", "path": "/TELEMETRY_CLIENT"},
        ])
    );
}

/// The patch is the change: applied to CONFIG_DB and copied back, the
/// subtree is what the candidate had, and nothing of `sonic` is pending.
/// What is pending besides is still pending.
#[test]
fn the_patch_applied_is_the_candidate() {
    let cm = manager("patch-applied");
    let mut db = tables();
    import(&cm, db.clone());
    for line in [
        "set sonic PORT Ethernet0 mtu 1500",
        "delete sonic PORT Ethernet4",
        "set sonic PORT Ethernet8 lanes 9,10,11,12",
        "set sonic INTERFACE_IPPREFIX Ethernet0 192.0.2.1/24",
        "delete sonic INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31",
        "delete sonic DEVICE_METADATA localhost bgp_asn",
        "set system hostname r1",
    ] {
        edit(&cm, line);
    }
    let wanted = candidate(&cm);
    apply_patch(&mut db, &pending_patch(&cm));
    import(&cm, db);

    assert_eq!(pending_patch(&cm), serde_json::json!([]));
    assert_eq!(candidate(&cm), wanted);
    assert_eq!(run(&cm, "compare formal"), "+system hostname r1\n");
    // And that is committed like any change that is not of `sonic`.
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), wanted);
}

// --- A commit that changes `sonic`: through the writer of CONFIG_DB ---

/// A line typed in a session, taken the way the daemon takes it: off
/// the manager's queue. `commit` waits for the writer there.
async fn session(cm: &mut ConfigManager, line: &str) -> String {
    let (tx, mut rx) = oneshot::channel();
    let request = super::super::api::ExecuteRequest::new("configure", line, tx);
    cm.process_message(Message::Execute(request)).await;
    // A commit parked for the writer is answered by a later message of
    // the manager's own queue, which the daemon's loop would take.
    loop {
        tokio::select! {
            reply = &mut rx => return reply.expect("a reply").output,
            Some(message) = cm.rx.recv() => cm.process_message(message).await,
        }
    }
}

/// A writer that applies each order to `db`, as SONiC's updater does to
/// CONFIG_DB, unless `refuse` says why not. It counts the orders.
fn writer(
    cm: &ConfigManager,
    db: std::sync::Arc<std::sync::Mutex<serde_json::Value>>,
    refuse: Option<&'static str>,
) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
    let hub = cm.config_db_writer.clone();
    let orders = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = orders.clone();
    tokio::spawn(async move {
        while let Some((id, patch)) = hub.wait(std::time::Duration::from_secs(5)).await {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let answer = match refuse {
                Some(why) => Err(why.to_string()),
                None => {
                    let patch: serde_json::Value = serde_json::from_str(&patch).unwrap();
                    apply_patch(&mut db.lock().unwrap(), &patch);
                    Ok(())
                }
            };
            hub.done(id, answer);
        }
    });
    orders
}

fn shared(tables: serde_json::Value) -> std::sync::Arc<std::sync::Mutex<serde_json::Value>> {
    std::sync::Arc::new(std::sync::Mutex::new(tables))
}

/// `commit` gives the change of `sonic` to the writer, and when the
/// writer has made it in CONFIG_DB the commit is made here: the edits
/// are running, with whatever else was pending, and are a commit of the
/// history. The copy of CONFIG_DB that follows changes nothing.
#[tokio::test]
async fn a_commit_writes_config_db_through_the_writer() {
    let mut cm = manager("writer");
    let db = shared(tables());
    import(&cm, tables());
    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;

    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    edit(&cm, "delete sonic PORT Ethernet4");
    edit(&cm, "set sonic INTERFACE_IPPREFIX Ethernet0 192.0.2.1/24");
    edit(&cm, "set system hostname r1");
    let wanted = candidate(&cm);
    assert_eq!(session(&mut cm, "commit").await, "");

    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(running(&cm), wanted);
    assert_eq!(cm.history.len(), 1);
    // CONFIG_DB has the change, and nothing but the change.
    let written = db.lock().unwrap().clone();
    assert_eq!(written["PORT"]["Ethernet0"]["mtu"], "1500");
    assert_eq!(written["PORT"]["Ethernet0"]["lanes"], "1,2,3,4");
    assert!(written["PORT"].get("Ethernet4").is_none());
    assert!(written["INTERFACE"].get("Ethernet0|192.0.2.1/24").is_some());

    // The mirror then copies what CONFIG_DB holds: the same.
    import(&cm, written);
    assert_eq!(running(&cm), wanted);
    assert_eq!(run(&cm, "compare"), "");
    assert_eq!(cm.history.len(), 1);
}

/// What the writer refuses is not committed, here or there, and the
/// reason is the answer. The edits stay to be corrected.
#[tokio::test]
async fn a_change_the_writer_refuses_is_not_committed() {
    let mut cm = manager("writer-refuses");
    let db = shared(tables());
    import(&cm, tables());
    let orders = writer(&cm, db.clone(), Some("Error: PORT Ethernet8 has no lanes"));
    tokio::task::yield_now().await;

    edit(&cm, "set sonic PORT Ethernet8 mtu 1500");
    edit(&cm, "set system hostname r1");
    let pending = candidate(&cm);
    assert_eq!(
        session(&mut cm, "commit").await,
        "% The change of CONFIG_DB failed, and nothing is committed here: \
         Error: PORT Ethernet8 has no lanes\n\
         % CONFIG_DB may have been changed in part: `compare` shows what is still pending\n"
    );
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(running(&cm), IMPORTED);
    assert_eq!(candidate(&cm), pending);
    assert_eq!(*db.lock().unwrap(), tables());
    assert_eq!(cm.history.len(), 0);
}

/// With no writer on the device the commit is refused at once and says
/// so.
#[tokio::test]
async fn without_a_writer_the_commit_is_refused() {
    let mut cm = manager("writer-absent");
    import(&cm, tables());
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    assert_eq!(
        session(&mut cm, "commit").await,
        "% CONFIG_DB was not changed, and nothing is committed: no writer of CONFIG_DB is connected\n"
    );
    assert_eq!(running(&cm), IMPORTED);
}

/// A commit that does not change `sonic` asks nothing of the writer,
/// and one that commit validation refuses is not written first.
#[tokio::test]
async fn the_writer_is_asked_only_for_a_change_of_config_db() {
    let mut cm = manager("writer-not-asked");
    let db = shared(tables());
    import(&cm, tables());
    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;

    edit(&cm, "set system hostname r1");
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(session(&mut cm, "compare").await, "");

    // `vni` is mandatory: this commit is refused, with or without the
    // change of `sonic` beside it.
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    edit(&cm, "set vxlan vx1 local-address 10.0.0.1");
    assert!(
        session(&mut cm, "commit")
            .await
            .contains("missing mandatory node")
    );
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(*db.lock().unwrap(), tables());
}

/// While a commit waits for the writer the manager serves everything
/// else: SONiC's updater asks for the running config before it writes,
/// and gets it. A second commit that would change CONFIG_DB is told to
/// wait.
#[tokio::test]
async fn the_manager_is_not_held_while_the_writer_works() {
    let mut cm = manager("writer-parked");
    import(&cm, tables());
    let hub = cm.config_db_writer.clone();
    // A writer that takes the order and holds it until told.
    let (release, held) = oneshot::channel::<()>();
    let taken = std::sync::Arc::new(tokio::sync::Notify::new());
    let took = taken.clone();
    tokio::spawn(async move {
        let (id, _) = hub
            .wait(std::time::Duration::from_secs(5))
            .await
            .expect("an order");
        took.notify_one();
        let _ = held.await;
        hub.done(id, Ok(()));
    });
    tokio::task::yield_now().await;

    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    let (tx, mut reply) = oneshot::channel();
    let request = super::super::api::ExecuteRequest::new("configure", "commit", tx);
    cm.process_message(Message::Execute(request)).await;
    taken.notified().await;
    assert!(reply.try_recv().is_err(), "answered before the writer was");

    // Asked meanwhile, as the updater asks.
    assert!(run(&cm, "show running-config formal").contains("sonic PORT Ethernet0 mtu 9100\n"));
    let (tx, second) = oneshot::channel();
    let request = super::super::api::ExecuteRequest::new("configure", "commit", tx);
    cm.process_message(Message::Execute(request)).await;
    assert_eq!(
        second.await.unwrap().output,
        "% Another commit is waiting for CONFIG_DB to be changed\n"
    );

    release.send(()).unwrap();
    let message = cm.rx.recv().await.expect("the writer's answer");
    cm.process_message(message).await;
    assert_eq!(reply.await.unwrap().output, "");
    assert!(running(&cm).contains("sonic PORT Ethernet0 mtu 1500\n"));
    // And the next commit is taken again.
    edit(&cm, "set system hostname r1");
    assert_eq!(session(&mut cm, "commit").await, "");
}

// --- What a patch has to know of CONFIG_DB besides the subtree ---

const NOT_COPIED: &str = "% CONFIG_DB has not been copied here yet, so what a change \
     of `sonic` changes in it cannot be told: try again when it has been\n";

/// What a configure-mode line is answered with, refused or not.
fn answer(cm: &ConfigManager, line: &str) -> String {
    let mode = cm.modes.get("configure").expect("configure mode");
    cm.execute(mode, line).1
}

/// Before CONFIG_DB has been copied once, the subtree is empty because
/// nothing is known of it. A row typed then would be patched in as the
/// first of its table, and the table CONFIG_DB has would be replaced:
/// there is no patch, and no commit.
#[tokio::test]
async fn before_the_first_copy_nothing_is_written() {
    let mut cm = manager("not-copied");
    let db = shared(tables());
    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;

    // What is not of `sonic` is committed as ever.
    edit(&cm, "set system hostname r1");
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(running(&cm), "system hostname r1\n");

    edit(&cm, "set sonic PORT Ethernet8 lanes 9,10,11,12");
    assert_eq!(answer(&cm, "compare config-db"), NOT_COPIED);
    assert_eq!(session(&mut cm, "commit").await, NOT_COPIED);
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(*db.lock().unwrap(), tables());
    assert_eq!(running(&cm), "system hostname r1\n");

    // Copied, the edit is a row added to the table CONFIG_DB has.
    import(&cm, tables());
    assert_eq!(
        pending_patch(&cm),
        serde_json::json!([
            {"op": "add", "path": "/PORT/Ethernet8", "value": {"lanes": "9,10,11,12"}},
        ])
    );
    assert_eq!(session(&mut cm, "commit").await, "");
    let written = db.lock().unwrap().clone();
    assert_eq!(written["PORT"]["Ethernet0"]["lanes"], "1,2,3,4");
    assert_eq!(written["PORT"]["Ethernet8"]["lanes"], "9,10,11,12");
}

/// An empty CONFIG_DB that was copied is known to be empty: the first
/// row of a table is then added with its table.
#[test]
fn an_empty_config_db_that_was_copied_is_empty() {
    let cm = manager("copied-empty");
    import(&cm, serde_json::json!({}));
    edit(&cm, "set sonic PORT Ethernet8 lanes 9,10,11,12");
    assert_eq!(
        pending_patch(&cm),
        serde_json::json!([
            {"op": "add", "path": "/PORT", "value": {"Ethernet8": {"lanes": "9,10,11,12"}}},
        ])
    );
}

/// CONFIG_DB as the copy takes only a part of it: rows no line can be
/// made of, beside rows of the same tables that are copied or not.
fn tables_left_out() -> serde_json::Value {
    serde_json::json!({
        // One row copied, and one whose key the model's pattern refuses.
        "PORT": {
            "Ethernet0": {"lanes": "1,2,3,4"},
            "not-a-port": {"lanes": "1"},
        },
        // No row copied: no list of the table has three keys.
        "INTERFACE": {"Ethernet0|10.0.0.0/31|extra": {}},
        // A row with a fixed key, and no field that can be held.
        "DEVICE_METADATA": {"localhost": {"hostname": "two\nlines"}},
    })
}

/// A table is added with its first row and removed with its last, and
/// which those are is CONFIG_DB's to say. Where the copy left a row out
/// the table is neither: added, it would replace the rows CONFIG_DB
/// has, and removed, take them with it. Nor is a row added that is
/// there with fields the copy could not hold.
#[tokio::test]
async fn a_table_the_copy_left_rows_out_of_is_neither_added_nor_removed() {
    let mut cm = manager("left-out");
    let db = shared(tables_left_out());
    import(&cm, tables_left_out());
    assert_eq!(
        running(&cm),
        "sonic PORT Ethernet0\nsonic PORT Ethernet0 lanes 1,2,3,4\n"
    );
    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;

    edit(&cm, "delete sonic PORT Ethernet0");
    edit(&cm, "set sonic INTERFACE Ethernet4");
    edit(&cm, "set sonic DEVICE_METADATA localhost bgp_asn 65100");
    assert_eq!(
        pending_patch(&cm),
        serde_json::json!([
            {"op": "add", "path": "/DEVICE_METADATA/localhost/bgp_asn", "value": "65100"},
            {"op": "add", "path": "/INTERFACE/Ethernet4", "value": {}},
            {"op": "remove", "path": "/PORT/Ethernet0"},
        ])
    );
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);

    // What the copy left out is all still there.
    let mut wanted = tables_left_out();
    wanted["PORT"].as_object_mut().unwrap().remove("Ethernet0");
    wanted["INTERFACE"]["Ethernet4"] = serde_json::json!({});
    wanted["DEVICE_METADATA"]["localhost"]["bgp_asn"] = "65100".into();
    assert_eq!(*db.lock().unwrap(), wanted);

    // The rows the copy left out are still CONFIG_DB's alone, before
    // the next copy as after it.
    for copied_again in [false, true] {
        if copied_again {
            import(&cm, wanted.clone());
        }
        edit(&cm, "delete sonic INTERFACE Ethernet4");
        edit(&cm, "set sonic PORT Ethernet8 lanes 9");
        assert_eq!(
            pending_patch(&cm),
            serde_json::json!([
                {"op": "remove", "path": "/INTERFACE/Ethernet4"},
                {"op": "add", "path": "/PORT/Ethernet8", "value": {"lanes": "9"}},
            ]),
            "copied again: {copied_again}"
        );
        run(&cm, "discard");
    }
}

/// A startup config with what a commit refuses and a startup tolerates:
/// one route with both discard keywords. It is running, and from then on
/// every commit of a candidate that has it is refused.
fn start_with_what_no_commit_takes(cm: &ConfigManager) {
    std::fs::write(
        &cm.config_path,
        "set router static ipv4 route 10.9.9.0/24 nexthop blackhole\n\
         set router static ipv4 route 10.9.9.0/24 nexthop unreachable\n",
    )
    .unwrap();
    cm.load_config();
    let _ = std::fs::remove_file(&cm.config_path);
    assert!(running(cm).contains("nexthop unreachable\n"));
}

/// A copy is not a commit and is held to none of a commit's checks:
/// CONFIG_DB is what the device is configured with. Where what is
/// running would not be committed again (a startup config is let off
/// what a commit is refused for), the copy is made all the same. Made
/// as a commit of the running config with the subtree replaced, it was
/// refused every time, and the subtree was never filled.
#[test]
fn a_copy_is_made_where_no_commit_would_be() {
    let cm = manager("copy-not-commit");
    start_with_what_no_commit_takes(&cm);
    let routes = running(&cm);
    let reply = import(&cm, tables());
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(running(&cm), format!("{routes}{IMPORTED}"));
    assert_eq!(candidate(&cm), running(&cm));
    // It is no commit of the history either, and a commit is refused as
    // it was before the copy.
    assert_eq!(cm.history.len(), 1);
    edit(&cm, "set system hostname r1");
    assert_eq!(run(&cm, "commit"), BOTH_DISCARDS);
}

/// A row the model calls incomplete is copied, and is then in every
/// candidate. It is CONFIG_DB's, and refuses no commit made here: of
/// something else, or of another row through the writer.
#[tokio::test]
async fn an_incomplete_row_that_was_copied_refuses_no_commit() {
    let mut cm = manager("incomplete-commit");
    // `lanes` is mandatory.
    let config_db = serde_json::json!({"PORT": {"Ethernet0": {"mtu": "9100"}}});
    let db = shared(config_db.clone());
    import(&cm, config_db);
    commit(&cm, &["set system hostname r1"]);
    assert!(running(&cm).contains("system hostname r1\n"));

    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;
    edit(&cm, "set sonic PORT Ethernet4 lanes 5,6,7,8");
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(running(&cm).contains("sonic PORT Ethernet4 lanes 5,6,7,8\n"));
}

/// The subscribers of the running configuration are told what a copy
/// changed, line by line, as they are told what a commit did.
#[test]
fn a_copy_is_told_to_the_subscribers_of_the_running_config() {
    let cm = manager("copy-subscribers");
    let (tx, mut events) = mpsc::channel(8);
    cm.config_subscribers.borrow_mut().push(ConfigSubscriber {
        format: config_pb::Format::Path,
        path: vec!["sonic".to_string(), "PORT".to_string()],
        tx,
    });
    let told = |events: &mut mpsc::Receiver<config_pb::ConfigEvent>| {
        let mut lines = Vec::new();
        while let Ok(event) = events.try_recv() {
            for change in event.changes {
                let op = if change.op == config_pb::Op::Set as i32 {
                    "set"
                } else {
                    "delete"
                };
                lines.push(format!("{op} {}", change.path.join(" ")));
            }
        }
        lines
    };

    import(&cm, tables());
    assert_eq!(
        told(&mut events),
        [
            "set sonic PORT Ethernet0",
            "set sonic PORT Ethernet0 admin_status up",
            "set sonic PORT Ethernet0 description uplink to spine 1",
            "set sonic PORT Ethernet0 lanes 1,2,3,4",
            "set sonic PORT Ethernet0 mtu 9100",
            "set sonic PORT Ethernet4",
            "set sonic PORT Ethernet4 lanes 5,6,7,8",
        ]
    );
    let mut changed = tables();
    changed["PORT"]["Ethernet0"]["mtu"] = "1500".into();
    changed["PORT"].as_object_mut().unwrap().remove("Ethernet4");
    import(&cm, changed.clone());
    assert_eq!(
        told(&mut events),
        [
            "delete sonic PORT Ethernet0 mtu 9100",
            "delete sonic PORT Ethernet4",
            "delete sonic PORT Ethernet4 lanes 5,6,7,8",
            "set sonic PORT Ethernet0 mtu 1500",
        ]
    );
    // The same again changes nothing, and nothing is told.
    import(&cm, changed);
    assert_eq!(told(&mut events), Vec::<String>::new());
}

/// The document that was copied last is not read again: the process
/// that copies CONFIG_DB may give the same one on a timer. Shown here by
/// what a second reading would do, which is to put the subtree back as
/// the document has it. A commit that writes CONFIG_DB changes the
/// subtree, and the document is then read again: it is no longer what
/// is running.
#[tokio::test]
async fn a_document_that_was_copied_is_not_read_again() {
    let mut cm = manager("copy-seen");
    import(&cm, tables());
    assert_eq!(running(&cm), IMPORTED);

    // The subtree changed behind the manager's back, as nothing does.
    let line = cm
        .paths("sonic PORT Ethernet0 mtu 1500".to_string())
        .expect("a line of the model");
    super::super::configs::set(line, cm.store.running.borrow().clone());
    let touched = IMPORTED.replace("mtu 9100", "mtu 1500");
    assert_eq!(running(&cm), touched);
    import(&cm, tables());
    assert_eq!(running(&cm), touched, "the same document was read again");
    // Another document is read, and then the first one again.
    let mut other = tables();
    other["PORT"]["Ethernet0"]["mtu"] = "9000".into();
    import(&cm, other);
    assert_eq!(running(&cm), IMPORTED.replace("mtu 9100", "mtu 9000"));
    import(&cm, tables());
    assert_eq!(running(&cm), IMPORTED);

    // A commit through the writer: the subtree is what was written.
    let orders = writer(&cm, shared(tables()), None);
    tokio::task::yield_now().await;
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(running(&cm), touched);
    // The document from before the commit, late: read, as any document
    // is that is not known to be what is running.
    import(&cm, tables());
    assert_eq!(running(&cm), IMPORTED);
}

/// A copy says what it could not copy, and what it copied incomplete,
/// once: the copy after it says only what is new.
#[test]
fn a_copy_says_only_what_the_one_before_it_did_not() {
    let cm = manager("copy-said");
    let said = |problems: &[&str]| {
        cm.config_db_said_anew(problems.iter().map(|p| p.to_string()).collect())
    };
    assert_eq!(said(&["a", "b"]), ["a", "b"]);
    assert_eq!(said(&["a", "b"]), Vec::<String>::new());
    assert_eq!(said(&["b", "c"]), ["c"]);
    // Gone and back is new again.
    assert_eq!(said(&["a", "b", "c"]), ["a"]);
}

// --- What a copy and a whole document leave alone ---

/// A startup config whose commit was refused stays in the candidate,
/// for a session to complete. A copy of CONFIG_DB is not that session:
/// it is committed by itself, and the file's lines are still there
/// afterwards, on the copy, to be completed. Run on that candidate, the
/// copy was refused with the file, every time, and dropped it.
#[test]
fn a_copy_leaves_a_refused_startup_config_to_be_completed() {
    let cm = manager("refused-startup");
    // `vni` is mandatory.
    std::fs::write(
        &cm.config_path,
        "set vxlan vx1 local-address 10.0.0.1\nset system hostname r1\n",
    )
    .unwrap();
    cm.load_config();
    let _ = std::fs::remove_file(&cm.config_path);
    assert!(cm.store.refused_load.get());
    assert_eq!(running(&cm), "");
    let file = candidate(&cm);
    assert!(
        file.contains("vxlan vx1 local-address 10.0.0.1\n"),
        "{file}"
    );

    // The copy, and a second one that changes it.
    let mut more = tables();
    more["PORT"]["Ethernet0"]["mtu"] = "1500".into();
    for (tables, copied) in [
        (tables(), IMPORTED.to_string()),
        (more, IMPORTED.replace("mtu 9100", "mtu 1500")),
    ] {
        let reply = import(&cm, tables);
        assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
        assert_eq!(running(&cm), copied);
        // The file's lines and the copy's, in the order of the tree.
        let sorted = |text: &str| {
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            lines.sort();
            lines
        };
        assert_eq!(sorted(&candidate(&cm)), sorted(&format!("{copied}{file}")));
        assert!(
            cm.store.refused_load.get(),
            "still a refused startup config"
        );
    }

    // Completed, it is committed, with `sonic` as CONFIG_DB has it.
    edit(&cm, "set vxlan vx1 vni 100");
    assert_eq!(run(&cm, "commit"), "");
    assert!(!cm.store.refused_load.get());
    let now = running(&cm);
    assert!(now.contains("sonic PORT Ethernet0 mtu 1500\n"), "{now}");
    assert!(now.contains("system hostname r1\n"), "{now}");
    assert!(now.contains("vxlan vx1 vni 100\n"), "{now}");
}

/// Nor does a copy commit what a refused `load` left in the candidate
/// beside a session's edits: they are as pending after it as before.
#[test]
fn a_copy_does_not_commit_what_a_refused_load_left() {
    let cm = manager("refused-load");
    import(&cm, tables());
    edit(&cm, "set system hostname pending");
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    // `load` commits the candidate with the file's lines, and is refused
    // for the edit of `sonic`.
    std::fs::write(&cm.config_path, "set vxlan vx1 vni 100\n").unwrap();
    run(&cm, "load");
    let _ = std::fs::remove_file(&cm.config_path);
    assert!(cm.store.refused_load.get());
    assert_eq!(running(&cm), IMPORTED);
    let pending = run(&cm, "compare formal");

    let mut more = tables();
    more["PORT"]["Ethernet8"] = serde_json::json!({"lanes": "9,10,11,12"});
    let reply = import(&cm, more);
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    let now = running(&cm);
    assert!(
        now.contains("sonic PORT Ethernet8 lanes 9,10,11,12\n"),
        "{now}"
    );
    assert!(now.contains("sonic PORT Ethernet0 mtu 9100\n"), "{now}");
    assert!(!now.contains("system hostname"), "{now}");
    assert!(!now.contains("vxlan"), "{now}");
    assert_eq!(run(&cm, "compare formal"), pending);
    assert!(cm.store.refused_load.get());
}

/// A document that is all of the configuration does not have the copy:
/// `save` leaves it out. Applied, it replaces the configuration made
/// here and leaves `sonic` as it is running, in each of the formats
/// that are a whole configuration. Started from nothing, every such
/// document was a commit that deletes `sonic`, and was refused.
#[test]
fn a_whole_config_document_leaves_the_copy_as_it_is() {
    let cm = manager("whole-config");
    import(&cm, tables());
    commit(&cm, &["set system hostname r1", "set vxlan vx1 vni 100"]);
    let with = |hostname: &str| {
        format!("vxlan vx1\nvxlan vx1 vni 100\n{IMPORTED}system hostname {hostname}\n")
    };
    assert_eq!(running(&cm), with("r1"));
    for format in ["cli", "json", "yaml"] {
        assert!(run(&cm, &format!("save {format}")).starts_with("Configuration saved"));
        let saved = std::fs::read_to_string(&cm.config_path).unwrap();
        assert!(!saved.contains("sonic"), "{format}: {saved}");
        // What was saved, again: nothing changes.
        let reply = cm.deploy(&saved);
        assert_eq!(
            reply.apply_code,
            ApplyCode::Applied,
            "{format}: {}",
            reply.cmd
        );
        assert_eq!(running(&cm), with("r1"), "{format}");
        // With a change, and without what it does not have any more.
        let changed = saved.replace("r1", "r2");
        let reply = cm.deploy(&changed);
        assert_eq!(
            reply.apply_code,
            ApplyCode::Applied,
            "{format}: {}",
            reply.cmd
        );
        assert_eq!(running(&cm), with("r2"), "{format}");
        let reply = cm.deploy(&saved);
        assert_eq!(
            reply.apply_code,
            ApplyCode::Applied,
            "{format}: {}",
            reply.cmd
        );
    }
    let _ = std::fs::remove_file(&cm.config_path);

    // A document with the copy in it, as `show running-config json`
    // prints it, says of `sonic` what is running: applied. One that
    // says something else is refused, as any other change of it by a
    // document is.
    let whole = run(&cm, "show running-config json");
    let reply = cm.deploy(&whole);
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(running(&cm), with("r1"));
    let reply = cm.deploy(&whole.replace("9100", "1500"));
    assert_ne!(reply.apply_code, ApplyCode::Applied);
    assert_eq!(reply.cmd, READ_ONLY);
    assert_eq!(running(&cm), with("r1"));
    assert_eq!(candidate(&cm), with("r1"));
}

/// A member of a leaf-list is one word. One that is not would be read
/// as a member for each of its words, so the leaf-list is said and left
/// out, whole: copied in part, the first edit of it would write it back
/// without the members the copy could not hold.
#[test]
fn a_leaf_list_with_a_member_of_several_words_is_left_out() {
    let cm = manager("leaf-list-words");
    let db = serde_json::json!({"STATIC_ROUTE": {
        "default|198.51.100.0/24": {"nexthop": "10.0.0.2", "ifname@": "Ethernet 0,Ethernet4"},
        "default|203.0.113.0/24": {"ifname": ["Ethernet8", "to spine"]},
        "Vrf-red|203.0.113.0/24": {"ifname": ["Ethernet8", ""]},
        "Vrf-red|198.51.100.0/24": {"ifname@": "Ethernet0,Ethernet4"},
    }});
    let mut problems = translate(&cm, db.clone()).problems;
    problems.sort();
    assert_eq!(
        problems,
        [
            "STATIC_ROUTE|Vrf-red|203.0.113.0/24: a member of `ifname` is empty",
            "STATIC_ROUTE|default|198.51.100.0/24: a member of `ifname` is not one word",
            "STATIC_ROUTE|default|203.0.113.0/24: a member of `ifname` is not one word",
        ]
    );
    let reply = import(&cm, db);
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(
        running(&cm),
        "\
sonic STATIC_ROUTE Vrf-red 198.51.100.0/24
sonic STATIC_ROUTE Vrf-red 198.51.100.0/24 ifname Ethernet0
sonic STATIC_ROUTE Vrf-red 198.51.100.0/24 ifname Ethernet4
sonic STATIC_ROUTE Vrf-red 203.0.113.0/24
sonic STATIC_ROUTE default 198.51.100.0/24
sonic STATIC_ROUTE default 198.51.100.0/24 nexthop 10.0.0.2
sonic STATIC_ROUTE default 203.0.113.0/24
"
    );
    // What is left out is not touched by an edit of the row beside it.
    edit(
        &cm,
        "set sonic STATIC_ROUTE default 198.51.100.0/24 nexthop 10.0.0.9",
    );
    assert_eq!(
        pending_patch(&cm),
        serde_json::json!([
            {"op": "replace", "path": "/STATIC_ROUTE/default|198.51.100.0~124/nexthop",
             "value": "10.0.0.9"},
        ])
    );
}

/// Free text copied from CONFIG_DB is whatever CONFIG_DB holds: quotes,
/// backslashes, and what looks like a number and is not one. The JSON
/// and YAML renderings of a configuration with it are still documents,
/// and read back as the same configuration.
#[test]
fn free_text_from_config_db_is_rendered_as_json() {
    let cm = manager("json-text");
    let db = serde_json::json!({"PORT": {"Ethernet0": {
        "lanes": "1,2,3,4",
        "description": "rack \"A\", row \\7",
    }}, "DEVICE_METADATA": {"localhost": {"hostname": "007", "bgp_asn": "65100"}}});
    let reply = import(&cm, db);
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    let want = running(&cm);
    assert!(
        want.contains("sonic PORT Ethernet0 description rack \"A\", row \\7\n"),
        "{want}"
    );
    assert!(
        want.contains("sonic DEVICE_METADATA localhost hostname 007\n"),
        "{want}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&run(&cm, "show running-config json")).expect("JSON");
    let port = &json["sonic"]["PORT"][0];
    assert_eq!(port["description"], "rack \"A\", row \\7");
    assert_eq!(
        json["sonic"]["DEVICE_METADATA"]["localhost"]["hostname"],
        "007"
    );
    assert_eq!(
        json["sonic"]["DEVICE_METADATA"]["localhost"]["bgp_asn"],
        65100
    );
    let yaml = run(&cm, "show running-config yaml");
    assert!(!yaml.contains("failed"), "{yaml}");

    for format in [" json", " yaml"] {
        let document = run(&cm, &format!("show running-config{format}"));
        let fresh = unmirrored("json-text-fresh");
        let reply = fresh.deploy(&document);
        assert_eq!(
            reply.apply_code,
            ApplyCode::Applied,
            "`{format}`: {}",
            reply.cmd
        );
        assert_eq!(running(&fresh), want, "`{format}`");
    }
}

// --- Maps, and what CONFIG_DB has no form for ---

fn maps() -> serde_json::Value {
    serde_json::json!({
        "DSCP_TO_TC_MAP": {"AZURE": {"0": "1", "8": "0", "46": "5"}},
        "PORT": {"Ethernet0": {"lanes": "1,2,3,4"}},
    })
}

/// A map is a row whose fields are the entries of the list its model
/// has inside it: the field's name is the entry's key and its value the
/// entry's leaf. It is copied so, exported so, and patched field by
/// field.
#[test]
fn a_map_is_a_row_whose_fields_are_entries() {
    let cm = manager("map");
    let t = translate(&cm, maps());
    assert_eq!(t.problems, Vec::<String>::new());
    let reply = import(&cm, maps());
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(
        running(&cm),
        "\
sonic DSCP_TO_TC_MAP AZURE
sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 0
sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 0 tc 1
sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 8
sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 8 tc 0
sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 46
sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 46 tc 5
sonic PORT Ethernet0
sonic PORT Ethernet0 lanes 1,2,3,4
"
    );
    let configure = &cm.modes.get("configure").expect("configure mode").entry;
    let schema = super::super::sonic::grafted(configure).expect("sonic");
    let sonic = cm.store.running.borrow().lookup(&"sonic".to_string());
    let exported = super::super::configdb::export(&schema, sonic.as_ref());
    assert_eq!(exported.unplaced, Vec::<String>::new());
    assert_eq!(serde_json::Value::Object(exported.tables), maps());

    for line in [
        "set sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 8 tc 2",
        "set sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 3 tc 3",
        "delete sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 46",
        "set sonic DSCP_TO_TC_MAP EDGE DSCP_TO_TC_MAP 0 tc 7",
    ] {
        edit(&cm, line);
    }
    let patch = pending_patch(&cm);
    assert_eq!(
        patch,
        serde_json::json!([
            {"op": "add", "path": "/DSCP_TO_TC_MAP/AZURE/3", "value": "3"},
            {"op": "remove", "path": "/DSCP_TO_TC_MAP/AZURE/46"},
            {"op": "replace", "path": "/DSCP_TO_TC_MAP/AZURE/8", "value": "2"},
            {"op": "add", "path": "/DSCP_TO_TC_MAP/EDGE", "value": {"0": "7"}},
        ])
    );
    // Applied and copied back, it is the candidate.
    let wanted = candidate(&cm);
    let mut db = maps();
    apply_patch(&mut db, &patch);
    import(&cm, db);
    assert_eq!(running(&cm), wanted);
    assert_eq!(pending_patch(&cm), serde_json::json!([]));
}

/// A field of a map that cannot be an entry of it is said and left out,
/// as any field that cannot be copied is.
#[test]
fn a_field_of_a_map_that_is_no_entry_is_left_out() {
    let cm = manager("map-problems");
    let db = serde_json::json!({
        "DSCP_TO_TC_MAP": {"AZURE": {"0": "1", "two words": "1", "9": "", "64": "1", "7": "9"}},
    });
    assert_eq!(
        translate(&cm, db.clone()).problems,
        [
            "DSCP_TO_TC_MAP|AZURE: `two words` is not one word",
            "DSCP_TO_TC_MAP|AZURE: the value of `9` is empty",
        ]
    );
    // The key's pattern and the leaf's are the model's: refused when the
    // line is read.
    import(&cm, db);
    assert_eq!(
        running(&cm),
        "sonic DSCP_TO_TC_MAP AZURE\n\
         sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 0\n\
         sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 0 tc 1\n"
    );
}

/// What is typed under `sonic` and is no row and no field of one has no
/// form in CONFIG_DB: an entry of a map with no value, a leaf with none,
/// a container in a row. A patch does not say it, so there is none, and
/// the commit that would make it running here is refused with nothing
/// written: the lines are named, to be completed or deleted.
#[tokio::test]
async fn what_config_db_has_no_form_for_is_not_committed() {
    let mut cm = manager("unplaced");
    let db = shared(maps());
    import(&cm, maps());
    let before = running(&cm);
    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;

    // Beside an edit there is a patch of.
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    for (line, named) in [
        (
            "set sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 5",
            "%   set sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 5\n",
        ),
        ("set sonic ODD o1 flag", "%   set sonic ODD o1 flag\n"),
        (
            "set sonic ODD o1 inside depth 2",
            "%   set sonic ODD o1 inside depth 2\n",
        ),
    ] {
        edit(&cm, line);
        let refused = format!(
            "% CONFIG_DB has no form for what these lines say, so it cannot be changed to it:\n\
             {named}% Complete or `delete` them\n"
        );
        assert_eq!(answer(&cm, "compare config-db"), refused, "`{line}`");
        assert_eq!(session(&mut cm, "commit").await, refused, "`{line}`");
        assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(running(&cm), before, "`{line}`");
        edit(&cm, &line.replacen("set", "delete", 1));
    }
    assert_eq!(*db.lock().unwrap(), maps());

    // Completed, the entry is a field, and the commit is written.
    edit(&cm, "set sonic DSCP_TO_TC_MAP AZURE DSCP_TO_TC_MAP 5 tc 2");
    edit(&cm, "set sonic ODD o1 size 3");
    assert_eq!(session(&mut cm, "commit").await, "");
    let written = db.lock().unwrap().clone();
    assert_eq!(written["DSCP_TO_TC_MAP"]["AZURE"]["5"], "2");
    assert_eq!(written["PORT"]["Ethernet0"]["mtu"], "1500");
    assert_eq!(written["ODD"], serde_json::json!({"o1": {"size": "3"}}));
}

// --- What a parked commit is a commit of ---

/// A writer that takes one order, applies it to `db`, and holds its
/// answer until `release` is sent to. `taken` is told when CONFIG_DB
/// has the change.
fn holding_writer(
    cm: &ConfigManager,
    db: std::sync::Arc<std::sync::Mutex<serde_json::Value>>,
) -> (oneshot::Sender<()>, std::sync::Arc<tokio::sync::Notify>) {
    let hub = cm.config_db_writer.clone();
    let (release, held) = oneshot::channel::<()>();
    let taken = std::sync::Arc::new(tokio::sync::Notify::new());
    let took = taken.clone();
    tokio::spawn(async move {
        let (id, patch) = hub
            .wait(std::time::Duration::from_secs(5))
            .await
            .expect("an order");
        let patch: serde_json::Value = serde_json::from_str(&patch).unwrap();
        apply_patch(&mut db.lock().unwrap(), &patch);
        took.notify_one();
        let _ = held.await;
        hub.done(id, Ok(()));
    });
    (release, taken)
}

/// Type `commit` and return where its answer comes, without waiting for
/// it: the commit is parked for the writer.
async fn parked_commit(cm: &mut ConfigManager) -> oneshot::Receiver<ExecuteResponse> {
    let (tx, reply) = oneshot::channel();
    let request = super::super::api::ExecuteRequest::new("configure", "commit", tx);
    cm.process_message(Message::Execute(request)).await;
    reply
}

/// The writer's answer, taken off the manager's queue as the daemon's
/// loop takes it.
async fn writer_answers(cm: &mut ConfigManager) {
    let message = cm.rx.recv().await.expect("the writer's answer");
    cm.process_message(message).await;
}

/// A line typed in a session while a commit is parked: off the
/// manager's queue, and answered at once.
async fn typed(cm: &mut ConfigManager, line: &str) -> String {
    let (tx, rx) = oneshot::channel();
    let request = super::super::api::ExecuteRequest::new("configure", line, tx);
    cm.process_message(Message::Execute(request)).await;
    rx.await.expect("a reply").output
}

const HELD: &str = "% A commit is waiting for CONFIG_DB to be changed, and the \
     configuration is not edited meanwhile: try again when it is made\n";

/// The commit is made of the candidate when the writer has answered,
/// with `sonic` open to it because CONFIG_DB has the change. So the
/// candidate is not edited while the writer works: an edit of `sonic`
/// typed then would be running here and never have been in CONFIG_DB.
/// What only reads is answered as ever. So it is whether the copy of
/// CONFIG_DB lands before the writer's answer, as it usually does, or
/// after.
#[tokio::test]
async fn the_candidate_is_not_edited_while_the_writer_works() {
    for copy_lands_first in [false, true] {
        let mut cm = manager(&format!("writer-held-{copy_lands_first}"));
        let db = shared(tables());
        import(&cm, tables());
        commit(&cm, &["set system hostname r0"]);
        let (release, taken) = holding_writer(&cm, db.clone());
        tokio::task::yield_now().await;

        edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
        edit(&cm, "set system hostname r1");
        let wanted = candidate(&cm);
        let mut reply = parked_commit(&mut cm).await;
        taken.notified().await;
        assert!(reply.try_recv().is_err(), "answered before the writer was");

        for line in [
            "set sonic PORT Ethernet4 mtu 1500",
            "set system hostname r2",
            "delete sonic PORT Ethernet4",
            "delete system hostname",
            "discard",
            "rollback 1",
            "load",
        ] {
            assert_eq!(typed(&mut cm, line).await, HELD, "`{line}`");
            assert_eq!(candidate(&cm), wanted, "`{line}`");
        }
        assert_eq!(
            typed(&mut cm, "commit").await,
            "% Another commit is waiting for CONFIG_DB to be changed\n"
        );
        assert_eq!(
            typed(&mut cm, "compare formal").await,
            "-sonic PORT Ethernet0 mtu 9100\n+sonic PORT Ethernet0 mtu 1500\n\
             -system hostname r0\n+system hostname r1\n"
        );
        assert!(
            typed(&mut cm, "show running-config formal")
                .await
                .contains("set system hostname r0\n")
        );
        assert!(
            typed(&mut cm, "save")
                .await
                .starts_with("Configuration saved")
        );
        let _ = std::fs::remove_file(&cm.config_path);

        if copy_lands_first {
            let copy = db.lock().unwrap().clone();
            import(&cm, copy);
            assert!(running(&cm).contains("sonic PORT Ethernet0 mtu 1500\n"));
            assert!(running(&cm).contains("system hostname r0\n"));
        }
        release.send(()).unwrap();
        writer_answers(&mut cm).await;
        assert_eq!(reply.await.unwrap().output, "", "{copy_lands_first}");
        assert_eq!(running(&cm), wanted, "{copy_lands_first}");
        assert_eq!(candidate(&cm), wanted, "{copy_lands_first}");

        // Made, the candidate is edited again, and the next commit
        // writes what is typed now.
        let orders = writer(&cm, db.clone(), None);
        tokio::task::yield_now().await;
        assert_eq!(
            typed(&mut cm, "set sonic PORT Ethernet4 mtu 1500").await,
            ""
        );
        assert_eq!(session(&mut cm, "commit").await, "");
        assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(db.lock().unwrap()["PORT"]["Ethernet4"]["mtu"], "1500");
        assert!(running(&cm).contains("sonic PORT Ethernet4 mtu 1500\n"));
    }
}

/// A commit the writer refuses, or does not answer, lets go of the
/// candidate as one that is made does.
#[tokio::test]
async fn a_refused_write_lets_go_of_the_candidate() {
    let mut cm = manager("writer-held-refused");
    let db = shared(tables());
    import(&cm, tables());
    writer(&cm, db.clone(), Some("no"));
    tokio::task::yield_now().await;
    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    assert!(session(&mut cm, "commit").await.contains(": no\n"));
    assert_eq!(typed(&mut cm, "set system hostname r1").await, "");
    assert_eq!(typed(&mut cm, "discard").await, "");
    assert_eq!(candidate(&cm), IMPORTED);
}

const BOTH_DISCARDS: &str = "router static ipv4 route 10.9.9.0/24: nexthop blackhole cannot be \
     combined with nexthop unreachable; delete one or the other";

/// Everything that refuses a commit refuses it before CONFIG_DB is
/// changed for it, not only what `validate` finds: here a check commit
/// makes on the whole candidate.
#[tokio::test]
async fn a_commit_that_is_refused_is_refused_before_the_write() {
    let mut cm = manager("writer-checked");
    let db = shared(tables());
    import(&cm, tables());
    let orders = writer(&cm, db.clone(), None);
    tokio::task::yield_now().await;

    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    edit(
        &cm,
        "set router static ipv4 route 10.9.9.0/24 nexthop blackhole",
    );
    edit(
        &cm,
        "set router static ipv4 route 10.9.9.0/24 nexthop unreachable",
    );
    let pending = candidate(&cm);
    assert_eq!(session(&mut cm, "commit").await, BOTH_DISCARDS);
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(*db.lock().unwrap(), tables());
    assert_eq!(running(&cm), IMPORTED);
    assert_eq!(candidate(&cm), pending);

    // Corrected, it is written and committed.
    edit(
        &cm,
        "delete router static ipv4 route 10.9.9.0/24 nexthop blackhole",
    );
    assert_eq!(session(&mut cm, "commit").await, "");
    assert_eq!(orders.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(db.lock().unwrap()["PORT"]["Ethernet0"]["mtu"], "1500");
}

/// A commit that passed every check can still be refused when the
/// writer has answered: another writer committed meanwhile what it
/// cannot be beside. CONFIG_DB has its change of `sonic` by then, and
/// the refusal says so. Nothing is committed here, the copy of
/// CONFIG_DB brings `sonic`, and the rest stays pending.
#[tokio::test]
async fn a_commit_refused_after_the_write_says_config_db_has_the_change() {
    let mut cm = manager("writer-refused-after");
    let db = shared(tables());
    import(&cm, tables());
    let (release, taken) = holding_writer(&cm, db.clone());
    tokio::task::yield_now().await;

    edit(&cm, "set sonic PORT Ethernet0 mtu 1500");
    edit(
        &cm,
        "set router static ipv4 route 10.9.9.0/24 nexthop unreachable",
    );
    let reply = parked_commit(&mut cm).await;
    taken.notified().await;
    let applied = cm.deploy("set router static ipv4 route 10.9.9.0/24 nexthop blackhole\n");
    assert_eq!(applied.apply_code, ApplyCode::Applied, "{}", applied.cmd);
    let applied = running(&cm);

    release.send(()).unwrap();
    writer_answers(&mut cm).await;
    assert_eq!(
        reply.await.unwrap().output,
        format!(
            "% CONFIG_DB has the change of `sonic`, but the commit was then refused here:\n\
             {BOTH_DISCARDS}\n\
             % Nothing was committed here. `sonic` follows at the next copy of CONFIG_DB; \
             the rest is still pending\n"
        )
    );
    assert_eq!(running(&cm), applied);
    assert_eq!(db.lock().unwrap()["PORT"]["Ethernet0"]["mtu"], "1500");

    let copy = db.lock().unwrap().clone();
    import(&cm, copy);
    assert!(running(&cm).contains("sonic PORT Ethernet0 mtu 1500\n"));
    assert_eq!(pending_patch(&cm), serde_json::json!([]));
    assert_eq!(
        run(&cm, "compare formal"),
        "+router static ipv4 route 10.9.9.0/24 nexthop unreachable\n"
    );
}

/// Not a test of what is copied: how long a copy of a large CONFIG_DB
/// takes. `cargo test --release -p zebra-rs import_timing -- --ignored
/// --nocapture`.
#[test]
#[ignore = "timing, run by hand"]
fn import_timing() {
    let rows: usize = std::env::var("ROWS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(2000);
    let big = |mtu: &str| {
        let ports: serde_json::Map<String, serde_json::Value> = (0..rows)
            .map(|n| {
                (
                    format!("Ethernet{n}"),
                    serde_json::json!({"lanes": format!("{n}"), "admin_status": "up",
                                       "mtu": mtu, "description": format!("port {n} of the lot")}),
                )
            })
            .collect();
        serde_json::json!({ "PORT": ports })
    };
    let cm = manager("timing");
    let time = |what: &str, tables: serde_json::Value| {
        let start = std::time::Instant::now();
        let reply = import(&cm, tables);
        assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
        println!("{what}: {:?}", start.elapsed());
    };
    time("first copy", big("9100"));
    time("same again", big("9100"));
    let mut one = big("9100");
    one["PORT"]["Ethernet7"]["mtu"] = "1500".into();
    time("one leaf changed", one);
    time("every row changed", big("1500"));
    time("emptied", serde_json::json!({}));
    println!("lines: {}", rows * 5);
}

/// An earlier commit is the configuration made here as it was then. The
/// copy is not part of it: going back leaves `sonic` as CONFIG_DB has
/// it now, and `compare rollback` shows no change of it.
#[test]
fn rollback_leaves_the_copy_as_it_is_now() {
    let cm = manager("read-only-rollback");
    import(&cm, tables());
    commit(&cm, &["set system hostname r1"]);
    commit(&cm, &["set system hostname r2"]);
    // CONFIG_DB changes after the commit to go back to.
    let mut later = tables();
    later["PORT"]["Ethernet0"]["mtu"] = "1500".into();
    later["PORT"].as_object_mut().unwrap().remove("Ethernet4");
    import(&cm, later);
    let copy_now: String = running(&cm)
        .lines()
        .filter(|l| l.starts_with("sonic"))
        .map(|l| format!("{l}\n"))
        .collect();

    assert_eq!(
        run(&cm, "compare rollback 1"),
        " system {\n-  hostname r1;\n+  hostname r2;\n }\n"
    );
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(candidate(&cm), format!("{copy_now}system hostname r1\n"));
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), format!("{copy_now}system hostname r1\n"));
}

/// `save` writes the configuration made here. The copy is SONiC's to
/// save and is copied in again at start.
#[test]
fn save_leaves_the_copy_out() {
    let cm = manager("read-only-save");
    import(&cm, tables());
    commit(&cm, &["set system hostname r1"]);
    for format in ["formal", "cli", "json", "yaml"] {
        assert!(run(&cm, &format!("save {format}")).starts_with("Configuration saved"));
        let saved = std::fs::read_to_string(&cm.config_path).unwrap();
        assert!(saved.contains("hostname"), "{format}: {saved}");
        assert!(!saved.contains("sonic"), "{format}: {saved}");
        assert!(!saved.contains("Ethernet0"), "{format}: {saved}");
    }
    let _ = std::fs::remove_file(&cm.config_path);
    // What is running still has it.
    assert!(running(&cm).contains("sonic PORT Ethernet0\n"));
}
