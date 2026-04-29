// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::fs;

use bdd::netns;
use cucumber::{World, WriterExt, given, then, when, writer};
use serde_json::Value;
use tokio::process::Command;

#[derive(Debug, Default, World)]
pub struct BgpWorld {
    topology_running: bool,
    feature_tag: String,
}

#[given("a clean test environment")]
async fn clean_test_environment(_world: &mut BgpWorld) {
    // Clean up any existing test resources (ignore errors)
    // Kill any leftover zebra-rs processes before tearing down namespaces,
    // otherwise their open netlink sockets can keep the namespace alive.
    let _ = netns::killall_zebra_rs().await;

    // Delete veths first (must be done before namespaces are deleted)
    let _ = netns::delete_veth("z1").await;
    let _ = netns::delete_veth("z2").await;
    let _ = netns::delete_netns("z1").await;
    let _ = netns::delete_netns("z2").await;
    let _ = netns::delete_bridge("br0").await;

    println!("✓ Test environment cleaned");
}

#[when(expr = "I create bridge {string}")]
async fn create_bridge(_world: &mut BgpWorld, bridge_name: String) {
    netns::create_bridge(&bridge_name)
        .await
        .expect("Failed to create bridge");
    println!("✓ Bridge {} created and up", bridge_name);
}

#[when(expr = "I create namespace {string} with IP {string} on bridge {string}")]
async fn create_namespace_with_ip(
    _world: &mut BgpWorld,
    namespace: String,
    ip: String,
    bridge_name: String,
) {
    netns::create_netns(&namespace)
        .await
        .expect("Failed to create namespace");

    netns::connect_netns_to_bridge(&namespace, &bridge_name)
        .await
        .expect("Failed to connect namespace to bridge");

    println!(
        "✓ Namespace {} created with IP {} on bridge {}",
        namespace, ip, bridge_name
    );
}

#[when(
    expr = "I create namespace {string} with loopback and veth interface on the bridge {string}"
)]
async fn create_namespace_with_loopback(
    _world: &mut BgpWorld,
    namespace: String,
    bridge_name: String,
) {
    netns::create_netns(&namespace)
        .await
        .expect("Failed to create namespace");

    netns::connect_netns_to_bridge(&namespace, &bridge_name)
        .await
        .expect("Failed to connect namespace to bridge");

    println!(
        "✓ Namespace {} created with loopback and veth on bridge {}",
        namespace, bridge_name
    );
}

#[when(expr = "I bring link down in namespace {string}")]
async fn bring_link_down(_world: &mut BgpWorld, namespace: String) {
    netns::set_link_state(&namespace, false)
        .await
        .expect("Failed to bring link down");
    println!("✓ Link brought down in namespace {}", namespace);
}

#[when(expr = "I bring link up in namespace {string}")]
async fn bring_link_up(_world: &mut BgpWorld, namespace: String) {
    netns::set_link_state(&namespace, true)
        .await
        .expect("Failed to bring link up");
    println!("✓ Link brought up in namespace {}", namespace);
}

#[when(expr = "I wait {int} seconds")]
async fn wait_seconds(_world: &mut BgpWorld, seconds: u64) {
    tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
}

#[then(expr = "ping from {string} to {string} should succeed")]
async fn ping_should_succeed(_world: &mut BgpWorld, namespace: String, target: String) {
    let success = netns::ping6(&namespace, &target, 3, 2)
        .await
        .expect("ping6 failed to run");
    assert!(
        success,
        "ping from {} to {} did not succeed",
        namespace, target
    );
    println!("✓ ping from {} to {} succeeded", namespace, target);
}

#[then(expr = "ping from {string} to {string} should fail")]
async fn ping_should_fail(_world: &mut BgpWorld, namespace: String, target: String) {
    let success = netns::ping6(&namespace, &target, 1, 1)
        .await
        .expect("ping6 failed to run");
    assert!(
        !success,
        "ping from {} to {} unexpectedly succeeded",
        namespace, target
    );
    println!(
        "✓ ping from {} to {} failed (as expected)",
        namespace, target
    );
}

#[when(expr = "I start zebra-rs in namespace {string}")]
async fn start_zebra_rs(_world: &mut BgpWorld, namespace: String) {
    let log_file = format!("{}.log", namespace);

    let _child = netns::spawn_in_netns(
        &namespace,
        "zebra-rs",
        &["--log-output=file", &format!("--log-file={}", log_file)],
    )
    .await
    .expect("Failed to start zebra-rs");

    // Wait a moment for zebra-rs to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!("✓ zebra-rs started in namespace {}", namespace);
}

#[when(expr = "I stop zebra-rs in namespace {string}")]
async fn stop_zebra_rs(_world: &mut BgpWorld, namespace: String) {
    let _ = netns::exec_in_netns(&namespace, "pkill", &["-9", "zebra-rs"]).await;
    println!("✓ zebra-rs stopped in namespace {}", namespace);
}

#[when(expr = "I apply config {string} to namespace {string}")]
async fn apply_config(world: &mut BgpWorld, config_file: String, namespace: String) {
    let config_path = format!("tests/data/{}/{}", world.feature_tag, config_file);

    netns::exec_in_netns(&namespace, "vtyctl", &["apply", "-f", &config_path])
        .await
        .expect("Failed to apply config");

    println!(
        "✓ Config {} applied to namespace {}",
        config_file, namespace
    );
}

#[when(expr = "I wait {int} seconds for BGP to operate")]
async fn wait_for_bgp(_world: &mut BgpWorld, seconds: u64) {
    tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
    println!("✓ Waited {} seconds for BGP to operate", seconds);
}

#[when(expr = "I clear namespace {string} neighbor {string}")]
async fn clear_bgp_neighbor(_world: &mut BgpWorld, namespace: String, neighbor: String) {
    let cmd = format!("clear ip bgp neighbors {}", neighbor);
    netns::exec_in_netns(&namespace, "vtyctl", &["clear", &cmd])
        .await
        .expect("Failed to clear BGP neighbor");

    println!(
        "✓ Cleared BGP neighbor {} in namespace {}",
        neighbor, namespace
    );
}

#[when(expr = "I delete namespace {string}")]
async fn delete_namespace(_world: &mut BgpWorld, namespace: String) {
    // Delete veth on host side first
    // let _ = netns::delete_veth(&namespace).await;

    netns::delete_netns(&namespace)
        .await
        .expect("Failed to delete namespace");

    println!("✓ Namespace {} deleted", namespace);
}

#[when(expr = "I delete bridge {string}")]
async fn delete_bridge(_world: &mut BgpWorld, bridge_name: String) {
    netns::delete_bridge(&bridge_name)
        .await
        .expect("Failed to delete bridge");

    println!("✓ Bridge {} deleted", bridge_name);
}

#[then(expr = "BGP session in {string} to {string} should be {string}")]
async fn verify_bgp_session(
    _world: &mut BgpWorld,
    namespace: String,
    neighbor: String,
    expected_state: String,
) {
    let cmd = format!("show ip bgp neighbors {}", neighbor);
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns(&namespace, "vtyctl", &binding)
        .await
        .expect("Failed to get BGP neighbor state");

    let json: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");
    let state = json.get("state").and_then(|s| s.as_str()).unwrap_or("");

    assert!(
        state
            .to_lowercase()
            .contains(&expected_state.to_lowercase()),
        "BGP session {} -> {} is not {}, got: {}",
        namespace,
        neighbor,
        expected_state,
        output
    );

    println!(
        "✓ BGP session {} -> {} is {}",
        namespace, neighbor, expected_state
    );
}

#[then(expr = "BGP session in {string} to {string} should not be {string}")]
async fn verify_bgp_session_not(
    _world: &mut BgpWorld,
    namespace: String,
    neighbor: String,
    unexpected_state: String,
) {
    let cmd = format!("show ip bgp neighbors {}", neighbor);
    let binding = ["show", "-j", &cmd];
    let output = netns::exec_in_netns(&namespace, "vtyctl", &binding)
        .await
        .expect("Failed to get BGP neighbor state");

    let json: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");
    let state = json.get("state").and_then(|s| s.as_str()).unwrap_or("");

    assert!(
        state.to_lowercase() != unexpected_state.to_lowercase(),
        "BGP session {} -> {} should not be {}, got: {}",
        namespace,
        neighbor,
        unexpected_state,
        state
    );

    println!(
        "✓ BGP session {} -> {} is not {}",
        namespace, neighbor, unexpected_state
    );
}

#[then(expr = "BGP route in {string} has {string}")]
async fn verify_bgp_route(_world: &mut BgpWorld, namespace: String, expected_prefix: String) {
    let output = netns::exec_in_netns(&namespace, "vtyctl", &["show", "-j", "show ip bgp"])
        .await
        .expect("Failed to get BGP routes");

    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");

    let has_prefix = routes
        .as_array()
        .map(|arr| {
            arr.iter()
                .any(|route| route.get("prefix").and_then(|p| p.as_str()) == Some(&expected_prefix))
        })
        .unwrap_or(false);

    assert!(
        has_prefix,
        "BGP route {} not found in namespace {}, got: {}",
        expected_prefix, namespace, output
    );

    println!(
        "✓ BGP route {} found in namespace {}",
        expected_prefix, namespace
    );
}

#[then(expr = "BGP route in {string} does not have {string}")]
async fn verify_bgp_route_not(_world: &mut BgpWorld, namespace: String, unexpected_prefix: String) {
    let output = netns::exec_in_netns(&namespace, "vtyctl", &["show", "-j", "show ip bgp"])
        .await
        .expect("Failed to get BGP routes");

    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");

    let has_prefix = routes
        .as_array()
        .map(|arr| {
            arr.iter().any(|route| {
                route.get("prefix").and_then(|p| p.as_str()) == Some(&unexpected_prefix)
            })
        })
        .unwrap_or(false);

    assert!(
        !has_prefix,
        "BGP route {} should not be in namespace {}, got: {}",
        unexpected_prefix, namespace, output
    );

    println!(
        "✓ BGP route {} not found in namespace {}",
        unexpected_prefix, namespace
    );
}

#[then(expr = "BGP route in {string} has {string} with {string} value {string}")]
async fn verify_bgp_route_field(
    _world: &mut BgpWorld,
    namespace: String,
    expected_prefix: String,
    field_name: String,
    expected_value: String,
) {
    let output = netns::exec_in_netns(&namespace, "vtyctl", &["show", "-j", "show ip bgp"])
        .await
        .expect("Failed to get BGP routes");

    let routes: Value = serde_json::from_str(&output).expect("Failed to parse JSON output");

    let route = routes.as_array().and_then(|arr| {
        arr.iter()
            .find(|r| r.get("prefix").and_then(|p| p.as_str()) == Some(&expected_prefix))
    });

    let route = route.expect(&format!(
        "BGP route {} not found in namespace {}, got: {}",
        expected_prefix, namespace, output
    ));

    let actual_value = route.get(&field_name).expect(&format!(
        "Field {} not found in route {}",
        field_name, expected_prefix
    ));

    let actual_str = match actual_value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => actual_value.to_string(),
    };

    assert!(
        actual_str == expected_value,
        "BGP route {} field {} expected {}, got: {}",
        expected_prefix,
        field_name,
        expected_value,
        actual_str
    );

    println!(
        "✓ BGP route {} in namespace {} has {} = {}",
        expected_prefix, namespace, field_name, expected_value
    );
}

#[given("the test topology exists")]
async fn test_topology_exists(world: &mut BgpWorld) {
    world.topology_running = netns::netns_exists("z1").await.unwrap_or(false)
        && netns::netns_exists("z2").await.unwrap_or(false);
}

#[then("the test environment should be clean")]
async fn verify_clean_environment(_world: &mut BgpWorld) {
    let z1_exists = netns::netns_exists("z1").await.unwrap_or(false);
    let z2_exists = netns::netns_exists("z2").await.unwrap_or(false);

    assert!(!z1_exists, "Namespace z1 still exists");
    assert!(!z2_exists, "Namespace z2 still exists");

    let output = Command::new("sudo")
        .args(["ip", "link", "show", "br0"])
        .output()
        .await
        .expect("Failed to check bridge");

    assert!(!output.status.success(), "Bridge br0 still exists");

    println!("✓ Test environment is clean");
}

#[tokio::main]
async fn main() {
    let file = fs::File::create(format!("allure-results/results.json")).unwrap();
    BgpWorld::cucumber()
        .before(|feature, _rule, _scenario, world| {
            Box::pin(async move {
                // Get first feature tag (excluding special tags like @serial)
                world.feature_tag = feature
                    .tags
                    .iter()
                    .find(|t| *t != "serial" && *t != "allow.skipped")
                    .cloned()
                    .unwrap_or_default();
            })
        })
        .with_writer(
            writer::Basic::stdout()
                .summarized()
                .tee::<BgpWorld, _>(writer::Json::for_tee(file))
                .normalized(),
        )
        .run("tests/features")
        .await;
}
