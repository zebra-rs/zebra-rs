//! Lists with more than one key (`key "vlan port"`).
//!
//! An entry is the node under the values of all its keys, each a key
//! node under the one before it. These tests go through everything
//! that reads or writes the tree: the command parser, the four
//! renderings, the document loaders, `delete`, commit validation and
//! the carrying of edits over an apply.
//!
//! None of the daemon's own models has such a list, so the schema of
//! `testdata/test-multikey.yang` is put under `set` and `delete` here.

use super::test_support::{candidate, commit, edit, run, running};
use super::*;

fn manager(name: &str) -> ConfigManager {
    let path =
        std::env::temp_dir().join(format!("zebra-rs-multikey-{name}-{}", std::process::id()));
    let cm = test_support::manager(&path, Vec::new(), Default::default());

    let mut yang = YangStore::new();
    yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/testdata"));
    yang.read_with_resolve("test-multikey")
        .expect("test-multikey parses");
    let module = yang.find_module("test-multikey").expect("module");
    let root = to_entry(&yang, module);
    let mk = root.dir.borrow()[0].clone();
    let configure = &cm.modes.get("configure").expect("configure mode").entry;
    for top in configure.dir.borrow().iter() {
        if top.name == "set" || top.name == "delete" {
            top.dir.borrow_mut().push(mk.clone());
        }
    }
    cm
}

/// The code a line is answered with, where it is not taken.
fn code(cm: &ConfigManager, line: &str) -> ExecCode {
    let mode = cm.modes.get("configure").expect("configure mode");
    cm.execute(mode, line).0
}

const MEMBERS: &[&str] = &[
    "set mk member Vlan100 Ethernet0 mode untagged",
    "set mk member Vlan100 Ethernet4 mode tagged",
    "set mk member Vlan100 Ethernet4 note uplink",
    "set mk member Vlan200 Ethernet0 mode tagged",
];

fn with_members(name: &str) -> ConfigManager {
    let cm = manager(name);
    for line in MEMBERS {
        edit(&cm, line);
    }
    cm
}

/// An entry is named by all its keys, and each of them is in every line
/// of it. There is no line for the first key alone: it is not an entry.
#[test]
fn an_entry_has_all_its_keys() {
    let cm = with_members("keys");
    assert_eq!(
        candidate(&cm),
        "mk member Vlan100 Ethernet0\n\
         mk member Vlan100 Ethernet0 mode untagged\n\
         mk member Vlan100 Ethernet4\n\
         mk member Vlan100 Ethernet4 mode tagged\n\
         mk member Vlan100 Ethernet4 note uplink\n\
         mk member Vlan200 Ethernet0\n\
         mk member Vlan200 Ethernet0 mode tagged\n"
    );
    assert_eq!(
        run(&cm, "show candidate-config"),
        "mk {\n\
         \x20 member Vlan100 Ethernet0 {\n\
         \x20   mode untagged;\n\
         \x20 }\n\
         \x20 member Vlan100 Ethernet4 {\n\
         \x20   mode tagged;\n\
         \x20   note uplink;\n\
         \x20 }\n\
         \x20 member Vlan200 Ethernet0 {\n\
         \x20   mode tagged;\n\
         \x20 }\n\
         }\n"
    );
}

/// In JSON and YAML an entry is one object with all its keys (RFC 7951
/// §5.4).
#[test]
fn an_entry_is_one_object() {
    let cm = with_members("json");
    let json: serde_json::Value =
        serde_json::from_str(&run(&cm, "show candidate-config json")).expect("valid JSON");
    assert_eq!(
        json,
        serde_json::json!({"mk": {"member": [
            {"vlan": "Vlan100", "port": "Ethernet0", "mode": "untagged"},
            {"vlan": "Vlan100", "port": "Ethernet4", "mode": "tagged", "note": "uplink"},
            {"vlan": "Vlan200", "port": "Ethernet0", "mode": "tagged"},
        ]}})
    );
    let yaml: serde_json::Value =
        serde_yaml::from_str(&run(&cm, "show candidate-config yaml")).expect("valid YAML");
    assert_eq!(yaml, json);
}

/// Every rendering of a configuration loads back as that configuration.
#[test]
fn every_rendering_loads_back() {
    let cm = with_members("roundtrip");
    edit(&cm, "set mk triple x 7 z v deep");
    edit(&cm, "set mk member Vlan100 Ethernet0 tag red");
    edit(&cm, "set mk member Vlan100 Ethernet0 tag blue");
    edit(&cm, "set mk member Vlan100 Ethernet0 inner 3 weight 9");
    edit(&cm, "set mk single Po1 mtu 9100");
    let want = candidate(&cm);
    for format in ["", " formal", " json", " yaml"] {
        let document = run(&cm, &format!("show candidate-config{format}"));
        let fresh = manager("roundtrip-fresh");
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

/// The keys of a JSON entry are found wherever they are in the object,
/// and an entry that lacks one is refused, naming it.
#[test]
fn a_document_entry_needs_all_its_keys() {
    let cm = manager("doc-keys");
    let reply = cm.deploy(
        r#"{"mk": {"member": [{"mode": "tagged", "port": "Ethernet0", "vlan": "Vlan100"}]}}"#,
    );
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(
        running(&cm),
        "mk member Vlan100 Ethernet0\nmk member Vlan100 Ethernet0 mode tagged\n"
    );

    let reply = cm.deploy(r#"{"mk": {"member": [{"vlan": "Vlan300", "mode": "tagged"}]}}"#);
    assert_eq!(reply.apply_code, ApplyCode::ParseError);
    assert!(
        reply.cmd.contains("list entry is missing its key `port`"),
        "{}",
        reply.cmd
    );
}

/// Three keys, and a key that is a number.
#[test]
fn three_keys() {
    let cm = manager("three");
    edit(&cm, "set mk triple x 7 z v one");
    edit(&cm, "set mk triple x 7 y v two");
    edit(&cm, "set mk triple x 8 z");
    assert_eq!(
        candidate(&cm),
        "mk triple x 7 y\nmk triple x 7 y v two\n\
         mk triple x 7 z\nmk triple x 7 z v one\n\
         mk triple x 8 z\n"
    );
    // The second key is a uint8.
    assert_eq!(code(&cm, "set mk triple x 700 z"), ExecCode::Nomatch);
}

/// A line that stops before the last key names no entry.
#[test]
fn a_line_without_all_the_keys_is_incomplete() {
    let cm = manager("incomplete");
    assert_eq!(code(&cm, "set mk member Vlan100"), ExecCode::Incomplete);
    assert_eq!(code(&cm, "set mk triple x 7"), ExecCode::Incomplete);
    assert_eq!(candidate(&cm), "");
}

/// Each key is checked against its own type: a pattern on the first, a
/// pattern with alternatives on the second.
#[test]
fn each_key_has_its_own_type() {
    let cm = manager("types");
    assert_eq!(
        code(&cm, "set mk member Vxlan100 Ethernet0"),
        ExecCode::Nomatch
    );
    edit(&cm, "set mk address eth0 10.0.0.0/31");
    edit(&cm, "set mk address eth0 10.0.0.2/3");
    assert_eq!(
        code(&cm, "set mk address eth0 10.0.0.0/33"),
        ExecCode::Nomatch
    );
    assert_eq!(code(&cm, "set mk address eth0 10.0.0.0"), ExecCode::Nomatch);
    assert_eq!(
        candidate(&cm),
        "mk address eth0 10.0.0.0/31\nmk address eth0 10.0.0.2/3\n"
    );
}

/// A list's mandatory leaf is each entry's, and the refusal names the
/// entry by all its keys.
#[test]
fn a_mandatory_leaf_is_each_entry_s() {
    let cm = manager("mandatory");
    edit(&cm, "set mk member Vlan100 Ethernet0 mode tagged");
    edit(&cm, "set mk member Vlan100 Ethernet4 note no-mode");
    assert_eq!(
        run(&cm, "commit"),
        "'mk member Vlan100 Ethernet4' missing mandatory node 'mode'"
    );
    edit(&cm, "set mk member Vlan100 Ethernet4 mode untagged");
    assert_eq!(run(&cm, "commit"), "");
    assert_eq!(running(&cm), candidate(&cm));
}

/// `delete` of an entry removes that entry. The node of the first key
/// goes with the last entry under it, and the list with its last entry.
#[test]
fn delete_removes_the_entry() {
    let cm = with_members("delete");
    edit(&cm, "delete mk member Vlan100 Ethernet4");
    assert_eq!(
        candidate(&cm),
        "mk member Vlan100 Ethernet0\n\
         mk member Vlan100 Ethernet0 mode untagged\n\
         mk member Vlan200 Ethernet0\n\
         mk member Vlan200 Ethernet0 mode tagged\n"
    );
    edit(&cm, "delete mk member Vlan200 Ethernet0");
    assert_eq!(
        candidate(&cm),
        "mk member Vlan100 Ethernet0\nmk member Vlan100 Ethernet0 mode untagged\n"
    );
    // The same keys set again are a new entry, not one found half there.
    edit(&cm, "set mk member Vlan200 Ethernet8 mode tagged");
    edit(&cm, "delete mk member Vlan200 Ethernet8");
    edit(&cm, "delete mk member Vlan100 Ethernet0");
    assert_eq!(candidate(&cm), "");
}

/// A leaf of an entry is deleted and the entry stays.
#[test]
fn delete_of_a_leaf_keeps_the_entry() {
    let cm = with_members("delete-leaf");
    edit(&cm, "delete mk member Vlan100 Ethernet4 note");
    assert!(!candidate(&cm).contains("note"));
    assert!(candidate(&cm).contains("mk member Vlan100 Ethernet4 mode tagged\n"));
}

/// `delete` names what is there: an entry that is not is refused, and
/// so is one named by the start of a key.
#[test]
fn delete_of_an_entry_that_is_not_there() {
    let cm = with_members("delete-missing");
    let before = candidate(&cm);
    for line in [
        "delete mk member Vlan100 Ethernet9",
        "delete mk member Vlan300 Ethernet0",
        "delete mk member Vlan1 Ethernet0",
    ] {
        assert_eq!(code(&cm, line), ExecCode::Nomatch, "`{line}`");
    }
    // The start of a key that two entries share names neither.
    assert_eq!(
        code(&cm, "delete mk member Vlan100 Ethernet"),
        ExecCode::Ambiguous
    );
    assert_eq!(candidate(&cm), before);
}

/// `delete` that stops at the first key removes every entry under it,
/// as `delete` of a list removes the list.
#[test]
fn delete_by_the_first_key() {
    let cm = with_members("delete-first");
    edit(&cm, "delete mk member Vlan100");
    assert_eq!(
        candidate(&cm),
        "mk member Vlan200 Ethernet0\nmk member Vlan200 Ethernet0 mode tagged\n"
    );
    edit(&cm, "delete mk member");
    assert_eq!(candidate(&cm), "");
}

/// A commit dispatches the lines of such a list and they are in the
/// history; `compare` and `rollback` read them back.
#[test]
fn commit_compare_and_rollback() {
    let cm = with_members("commit");
    assert_eq!(run(&cm, "commit"), "");
    let first = running(&cm);
    commit(&cm, &["set mk member Vlan100 Ethernet0 mode tagged"]);
    edit(&cm, "delete mk member Vlan200 Ethernet0");
    assert_eq!(
        run(&cm, "compare"),
        " mk {\n-  member Vlan200 Ethernet0 {\n-    mode tagged;\n-  }\n }\n"
    );
    assert_eq!(run(&cm, "rollback 1"), "");
    assert_eq!(candidate(&cm), first);
}

/// An operator's uncommitted edit of such a list is carried over an
/// apply by another writer, and the apply's entry over the edit.
#[test]
fn an_apply_carries_edits_of_a_multikey_list() {
    let cm = with_members("apply");
    assert_eq!(run(&cm, "commit"), "");
    edit(&cm, "set mk member Vlan100 Ethernet0 note mine");
    edit(&cm, "delete mk member Vlan200 Ethernet0");
    let reply = cm.deploy(
        "set mk member Vlan300 Ethernet8 mode tagged\ndelete mk member Vlan100 Ethernet4\n",
    );
    assert_eq!(reply.apply_code, ApplyCode::Applied, "{}", reply.cmd);
    assert_eq!(
        running(&cm),
        "mk member Vlan100 Ethernet0\n\
         mk member Vlan100 Ethernet0 mode untagged\n\
         mk member Vlan200 Ethernet0\n\
         mk member Vlan200 Ethernet0 mode tagged\n\
         mk member Vlan300 Ethernet8\n\
         mk member Vlan300 Ethernet8 mode tagged\n"
    );
    assert_eq!(
        candidate(&cm),
        "mk member Vlan100 Ethernet0\n\
         mk member Vlan100 Ethernet0 mode untagged\n\
         mk member Vlan100 Ethernet0 note mine\n\
         mk member Vlan300 Ethernet8\n\
         mk member Vlan300 Ethernet8 mode tagged\n"
    );
}

/// A list with one key beside them is as it was, and its patterned key
/// may be followed by a leaf.
#[test]
fn a_single_key_list_is_unchanged() {
    let cm = manager("single");
    edit(&cm, "set mk single Po1 mtu 9100");
    edit(&cm, "set mk single Po2");
    assert_eq!(code(&cm, "set mk single Eth1 mtu 9100"), ExecCode::Nomatch);
    assert_eq!(
        candidate(&cm),
        "mk single Po1\nmk single Po1 mtu 9100\nmk single Po2\n"
    );
    edit(&cm, "delete mk single Po1 mtu");
    edit(&cm, "delete mk single Po2");
    assert_eq!(candidate(&cm), "mk single Po1\n");
}
