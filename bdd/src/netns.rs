// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use anyhow::{Context, Result, bail};
use std::process::Stdio;
use tokio::process::Command;

/// Run a command and check for success
async fn run_cmd(args: &[&str], error_msg: &str) -> Result<()> {
    let output = Command::new("sudo")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| error_msg.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{}: {}", error_msg, stderr.trim())
    }
}

/// Execute a command in a network namespace
pub async fn exec_in_netns(netns: &str, cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg(netns)
        .arg(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("Failed to execute {} in netns {}", cmd, netns))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command failed in netns {}: {}", netns, stderr)
    }
}

/// Check if a network namespace exists
pub async fn netns_exists(netns: &str) -> Result<bool> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("list")
        .stdout(Stdio::piped())
        .output()
        .await
        .context("Failed to list network namespaces")?;

    let list = String::from_utf8_lossy(&output.stdout);
    Ok(list
        .lines()
        .any(|line| line.split_whitespace().next() == Some(netns)))
}

/// Create a network namespace
pub async fn create_netns(netns: &str) -> Result<()> {
    run_cmd(
        &["ip", "netns", "add", netns],
        &format!("Failed to create netns {}", netns),
    )
    .await?;

    // Bring up loopback
    exec_in_netns(netns, "ip", &["link", "set", "lo", "up"]).await?;
    Ok(())
}

/// Delete a network namespace
pub async fn delete_netns(netns: &str) -> Result<()> {
    run_cmd(
        &["ip", "netns", "del", netns],
        &format!("Failed to delete netns {}", netns),
    )
    .await
}

/// Create a bridge
pub async fn create_bridge(bridge_name: &str) -> Result<()> {
    run_cmd(
        &["ip", "link", "add", "name", bridge_name, "type", "bridge"],
        &format!("Failed to create bridge {}", bridge_name),
    )
    .await?;

    run_cmd(
        &["ip", "link", "set", bridge_name, "up"],
        &format!("Failed to bring up bridge {}", bridge_name),
    )
    .await
}

/// Delete a bridge
pub async fn delete_bridge(bridge_name: &str) -> Result<()> {
    run_cmd(
        &["ip", "link", "del", bridge_name],
        &format!("Failed to delete bridge {}", bridge_name),
    )
    .await
}

/// Create a veth pair and connect namespace to bridge with IP
pub async fn connect_netns_to_bridge(netns: &str, bridge_name: &str, ip: &str) -> Result<()> {
    let veth_host = format!("v{}", netns);
    let veth_ns = format!("v{}ns", netns);

    // Create veth pair
    run_cmd(
        &[
            "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
        ],
        &format!("Failed to create veth pair for {}", netns),
    )
    .await?;

    // Move veth to namespace
    run_cmd(
        &["ip", "link", "set", &veth_ns, "netns", netns],
        &format!("Failed to move veth to namespace {}", netns),
    )
    .await?;

    // Add host veth to bridge
    run_cmd(
        &["ip", "link", "set", &veth_host, "master", bridge_name],
        &format!("Failed to add veth to bridge {}", bridge_name),
    )
    .await?;

    // Bring up host veth
    run_cmd(
        &["ip", "link", "set", &veth_host, "up"],
        &format!("Failed to bring up host veth {}", veth_host),
    )
    .await?;

    // Bring up namespace veth
    exec_in_netns(netns, "ip", &["link", "set", &veth_ns, "up"]).await?;

    // Assign IP address
    exec_in_netns(netns, "ip", &["addr", "add", ip, "dev", &veth_ns]).await?;

    Ok(())
}

/// Delete the veth interface for a namespace (host side)
pub async fn delete_veth(netns: &str) -> Result<()> {
    let veth_host = format!("v{}", netns);
    // Ignore errors as the veth might not exist
    let _ = Command::new("sudo")
        .args(["ip", "link", "del", &veth_host])
        .status()
        .await;
    Ok(())
}

/// Spawn a process in a network namespace (non-blocking)
pub async fn spawn_in_netns(
    netns: &str,
    cmd: &str,
    args: &[&str],
) -> Result<tokio::process::Child> {
    Command::new("sudo")
        .arg("ip")
        .arg("netns")
        .arg("exec")
        .arg(netns)
        .arg(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to spawn {} in netns {}", cmd, netns))
}
