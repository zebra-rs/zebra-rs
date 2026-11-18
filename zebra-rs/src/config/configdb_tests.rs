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
    assert_eq!(serde_json::Value::Object(exported), db);
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
