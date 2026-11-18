//! SONiC's models under `sonic` (`config::sonic`), on the small models
//! of `testdata/sonic`, which have the shapes SONiC's own have.

use super::super::sonic::{EXT_LIST, EXT_TABLE, graft, models_dir, sonic_entry};
use super::test_support::{candidate, edit, run, running};
use super::*;

const MODELS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/testdata/sonic");
const YANG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/yang");

fn sonic() -> (Rc<Entry>, Vec<String>) {
    sonic_entry(YANG, Path::new(MODELS))
}

fn manager(name: &str) -> ConfigManager {
    let path = std::env::temp_dir().join(format!("zebra-rs-sonic-{name}-{}", std::process::id()));
    let cm = test_support::manager(&path, Vec::new(), Default::default());
    let configure = &cm.modes.get("configure").expect("configure mode").entry;
    graft(configure, &sonic().0);
    // These tests type `set sonic …` to say what the schema takes. On a
    // device the subtree is a copy of CONFIG_DB and that is refused:
    // see configdb_tests.
    cm.sonic_read_only.set(false);
    cm
}

fn child(entry: &Rc<Entry>, name: &str) -> Rc<Entry> {
    entry
        .dir
        .borrow()
        .iter()
        .find(|e| e.name == name)
        .cloned()
        .unwrap_or_else(|| panic!("no `{name}` under `{}`", entry.name))
}

fn code(cm: &ConfigManager, line: &str) -> ExecCode {
    let mode = cm.modes.get("configure").expect("configure mode");
    cm.execute(mode, line).0
}

/// A list is a keyword under `sonic`, by its name without `_LIST`: the
/// module's container and the table's are not typed. A table with
/// containers is there as it is, and so is one with both.
#[test]
fn the_tables_under_sonic() {
    let (sonic, _) = sonic();
    let mut names: Vec<String> = sonic.dir.borrow().iter().map(|e| e.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "DEVICE_METADATA",
            "DSCP_TO_TC_MAP",
            "INTERFACE",
            "INTERFACE_IPPREFIX",
            "ODD",
            "PORT",
            "STATIC_ROUTE",
            "STATIC_ROUTE_IFACE",
            "STATIC_ROUTE_TEMPLATE",
            "TELEMETRY_CLIENT",
        ]
    );

    let port = child(&sonic, "PORT");
    assert!(port.is_list());
    assert_eq!(port.key, ["name"]);
    assert_eq!(port.extension[EXT_TABLE], "PORT");
    assert_eq!(port.extension[EXT_LIST], "PORT_LIST");

    // The two lists of one table are two keywords of the same table.
    let prefix = child(&sonic, "INTERFACE_IPPREFIX");
    assert_eq!(prefix.key, ["name", "ip-prefix"]);
    assert_eq!(prefix.extension[EXT_TABLE], "INTERFACE");
    assert_eq!(prefix.extension[EXT_LIST], "INTERFACE_IPPREFIX_LIST");
    assert_eq!(child(&sonic, "INTERFACE").extension[EXT_TABLE], "INTERFACE");

    // Rows with fixed keys: the table, then the row's container.
    let metadata = child(&sonic, "DEVICE_METADATA");
    assert!(!metadata.is_list());
    assert_eq!(metadata.extension[EXT_TABLE], "DEVICE_METADATA");
    assert!(!metadata.extension.contains_key(EXT_LIST));
    child(&metadata, "localhost");

    // A container and a list in one table: both under the table, the
    // list by its own name.
    let telemetry = child(&sonic, "TELEMETRY_CLIENT");
    child(&telemetry, "Global");
    assert_eq!(
        child(&telemetry, "TELEMETRY_CLIENT_LIST").key,
        ["prefix", "name"]
    );
}

/// What does not load, or is defined twice, is said and left out; the
/// rest is there. The events modules are not configuration.
#[test]
fn what_is_left_out_is_said() {
    let (sonic, problems) = sonic();
    assert_eq!(problems.len(), 2, "{problems:#?}");
    assert!(problems[0].starts_with("sonic-broken: "), "{problems:#?}");
    assert_eq!(
        problems[1],
        "sonic-zdup: `PORT` is already defined by sonic-port; left out"
    );
    // The first definition stands.
    assert_eq!(child(&sonic, "PORT").dir.borrow().len(), 5);
    assert!(sonic.dir.borrow().iter().all(|e| e.name != "disk-usage"));
}

/// A node's description is its help: the first sentence of it. A list
/// with none has its table's.
#[test]
fn a_description_is_the_help() {
    let (sonic, _) = sonic();
    let port = child(&sonic, "PORT");
    assert_eq!(port.extension["ext:help"], "PORT part of config_db.json");
    assert_eq!(child(&port, "name").extension["ext:help"], "Port name");
    assert_eq!(
        child(&port, "admin_status").extension["ext:help"],
        "Administrative state of the port"
    );
    assert!(!child(&port, "mtu").extension.contains_key("ext:help"));
    assert_eq!(
        child(&sonic, "INTERFACE").extension["ext:help"],
        "Layer 3 interfaces"
    );
    assert_eq!(
        child(
            &child(&child(&sonic, "DEVICE_METADATA"), "localhost"),
            "hostname"
        )
        .extension["ext:help"],
        "Host name of the device"
    );
}

/// The models are found in the directory `sonic` under the YANG path,
/// and only there: the daemon's own YANG directory has none.
#[test]
fn the_models_are_under_the_yang_path() {
    assert_eq!(models_dir(YANG), None);
    let testdata = concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/testdata");
    assert_eq!(
        models_dir(&format!("{YANG}:{testdata}")),
        Some(Path::new(MODELS).to_path_buf())
    );
}

/// `--feature sonic` is what puts `sonic` in the configuration. With no
/// feature there is none, whatever is under the YANG path; with the
/// feature and no models there is none either, and the daemon starts.
#[test]
fn the_feature_turns_sonic_on() {
    let testdata = concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/testdata");
    let start = |name: &str, yang_path: String, features: &[&str]| {
        let path =
            std::env::temp_dir().join(format!("zebra-rs-sonic-{name}-{}", std::process::id()));
        let (rib_tx, _rib_rx) = mpsc::unbounded_channel();
        let (rib_inbound_tx, _rib_inbound_rx) = mpsc::unbounded_channel();
        let (policy_tx, _policy_rx) = mpsc::unbounded_channel();
        ConfigManager::new(
            yang_path,
            features.iter().map(|f| f.to_string()).collect(),
            Some(path.to_string_lossy().into_owned()),
            rib_tx,
            rib_inbound_tx,
            policy_tx,
            Default::default(),
        )
        .expect("manager builds")
    };
    let with_models = format!("{YANG}:{testdata}");
    let line = "set sonic PORT Ethernet0 lanes 1,2,3,4";

    let on = start("feature-on", with_models.clone(), &["sonic"]);
    assert_eq!(code(&on, line), ExecCode::Show);
    let reply = on.deploy(r#"{"CONFIG_DB": {"PORT": {"Ethernet4": {"lanes": "5,6,7,8"}}}}"#);
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);

    let off = start("feature-off", with_models, &[]);
    assert_eq!(code(&off, line), ExecCode::Nomatch);
    let reply = off.deploy(r#"{"CONFIG_DB": {"PORT": {}}}"#);
    assert_eq!(reply.apply_code, ApplyCode::ParseError);
    // Without the feature the document is a configuration like any
    // other, with a key the schema does not have.
    assert!(
        reply.cmd.contains("unknown key `CONFIG_DB`"),
        "{}",
        reply.cmd
    );

    let no_models = start("feature-no-models", YANG.to_string(), &["sonic"]);
    assert_eq!(code(&no_models, line), ExecCode::Nomatch);
    // The daemon's own configuration is as ever.
    edit(&no_models, "set system hostname r1");
}

/// The commands of the design document, as they are typed.
#[test]
fn set_show_and_delete() {
    let cm = manager("set");
    for line in [
        "set sonic PORT Ethernet0 lanes 1,2,3,4",
        "set sonic PORT Ethernet0 admin_status up",
        "set sonic PORT Ethernet0 mtu 9100",
        "set sonic INTERFACE Ethernet0",
        "set sonic INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31",
        "set sonic INTERFACE_IPPREFIX Ethernet0 2001:db8::/64 scope global",
        "set sonic DEVICE_METADATA localhost hostname sonic1",
        "set sonic TELEMETRY_CLIENT Global retry_interval 30",
        "set sonic TELEMETRY_CLIENT TELEMETRY_CLIENT_LIST Subscription s1 dst_group g1",
    ] {
        edit(&cm, line);
    }
    assert_eq!(
        run(&cm, "show candidate-config"),
        "sonic {\n\
         \x20 DEVICE_METADATA {\n\
         \x20   localhost {\n\
         \x20     hostname sonic1;\n\
         \x20   }\n\
         \x20 }\n\
         \x20 INTERFACE Ethernet0;\n\
         \x20 INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31;\n\
         \x20 INTERFACE_IPPREFIX Ethernet0 2001:db8::/64 {\n\
         \x20   scope global;\n\
         \x20 }\n\
         \x20 PORT Ethernet0 {\n\
         \x20   admin_status up;\n\
         \x20   lanes 1,2,3,4;\n\
         \x20   mtu 9100;\n\
         \x20 }\n\
         \x20 TELEMETRY_CLIENT {\n\
         \x20   Global {\n\
         \x20     retry_interval 30;\n\
         \x20   }\n\
         \x20   TELEMETRY_CLIENT_LIST Subscription s1 {\n\
         \x20     dst_group g1;\n\
         \x20   }\n\
         \x20 }\n\
         }\n"
    );
    assert_eq!(run(&cm, "commit"), "");
    edit(&cm, "delete sonic INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31");
    edit(&cm, "delete sonic PORT Ethernet0 mtu");
    assert_eq!(
        run(&cm, "compare formal"),
        "-sonic INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31\n-sonic PORT Ethernet0 mtu 9100\n"
    );
}

/// What a leaf takes is the model's: its enumeration, its range, the
/// pattern of a key, a mandatory leaf at commit.
#[test]
fn the_model_says_what_is_valid() {
    let cm = manager("valid");
    for line in [
        "set sonic PORT Ethernet0 admin_status sideways",
        "set sonic PORT Ethernet0 mtu 20",
        "set sonic PORT Ethernet0 mtu 99999",
        "set sonic PORT ethernet0 mtu 9100",
        "set sonic DEVICE_METADATA localhost hostname not a name",
        "set sonic PORT Ethernet0 no_such_leaf 1",
        "set sonic NO_SUCH_TABLE x",
    ] {
        assert_eq!(code(&cm, line), ExecCode::Nomatch, "`{line}`");
    }
    edit(&cm, "set sonic PORT Ethernet0 mtu 9100");
    assert_eq!(
        run(&cm, "commit"),
        "'sonic PORT Ethernet0' missing mandatory node 'lanes'"
    );
}

/// A string leaf with no pattern is free text: the rest of the line,
/// whatever is in it. A key is one word.
#[test]
fn a_string_with_no_pattern_is_free_text() {
    let cm = manager("text");
    edit(&cm, "set sonic PORT Ethernet0 lanes 1,2,3,4");
    edit(
        &cm,
        "set sonic PORT Ethernet0 description uplink to spine-1 (rack 7), port #3",
    );
    edit(&cm, "set sonic INTERFACE Ethernet0 vrf_name Vrf red");
    let want = candidate(&cm);
    assert!(
        want.contains("sonic PORT Ethernet0 description uplink to spine-1 (rack 7), port #3\n"),
        "{want}"
    );
    assert!(want.contains("sonic INTERFACE Ethernet0 vrf_name Vrf red\n"));

    // It comes back from every rendering as it was typed.
    for format in ["", " formal", " json", " yaml"] {
        let document = run(&cm, &format!("show candidate-config{format}"));
        let fresh = manager("text-fresh");
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
