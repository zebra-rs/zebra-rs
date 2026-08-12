//! Minimal MCP (Model Context Protocol) client for `vtyctl mcp`.
//!
//! Each router in the playset runs zebra-rs inside its own network
//! namespace, listening on the abstract Unix socket `@zebra-rs/vty` —
//! which is network-namespaced, so the daemon is only reachable from
//! inside its namespace. This client therefore spawns
//! `ip netns exec <router> vtyctl mcp` per call and speaks the MCP
//! 2026-07-28 stateless revision over stdio: one `tools/call` request
//! line out, one response line back, no handshake.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const PROTOCOL_VERSION: &str = "2026-07-28";
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// How the MCP server process is launched for a given router.
#[derive(Clone, Debug)]
pub struct McpLauncher {
    /// Path to the vtyctl binary that provides `vtyctl mcp`.
    pub vtyctl: String,
    /// `--host` passed through to `vtyctl mcp` (the daemon's VTY gRPC
    /// endpoint as seen from inside the namespace).
    pub host: String,
    /// Per-call timeout.
    pub timeout: Duration,
}

impl McpLauncher {
    /// Build the command that runs `vtyctl mcp` inside `netns`. When not
    /// running as root, go through `sudo -n` — the same convention as the
    /// playset scripts, but non-interactive so a misconfigured sudo fails
    /// fast instead of hanging the HTTP request on a password prompt.
    fn command(&self, netns: &str) -> Command {
        let mut argv: Vec<&str> = Vec::new();
        if !is_root() {
            argv.extend(["sudo", "-n"]);
        }
        argv.extend(["ip", "netns", "exec", netns]);
        argv.push(&self.vtyctl);
        argv.extend(["mcp", "-H", &self.host]);

        let mut cmd = Command::new(argv[0]);
        cmd.args(&argv[1..]);
        cmd
    }

    /// Call one MCP tool on the router in `netns` and return the tool's
    /// text content parsed as JSON.
    pub async fn call_tool(&self, netns: &str, tool: &str, arguments: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    META_PROTOCOL_VERSION: PROTOCOL_VERSION,
                    META_CLIENT_CAPABILITIES: {},
                },
            },
        });

        let response = tokio::time::timeout(self.timeout, self.roundtrip(netns, &request))
            .await
            .map_err(|_| anyhow!("MCP call '{tool}' on '{netns}' timed out"))??;

        if let Some(error) = response.get("error") {
            bail!("MCP error from '{netns}': {error}");
        }
        let result = response
            .get("result")
            .ok_or_else(|| anyhow!("MCP response from '{netns}' has no result"))?;
        let text = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("MCP result from '{netns}' has no text content"))?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            bail!("MCP tool '{tool}' failed on '{netns}': {text}");
        }
        serde_json::from_str(text)
            .with_context(|| format!("MCP tool '{tool}' on '{netns}' returned non-JSON output"))
    }

    /// One stateless request/response exchange with a freshly spawned
    /// `vtyctl mcp` in `netns`.
    async fn roundtrip(&self, netns: &str, request: &Value) -> Result<Value> {
        let mut child = self
            .command(netns)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to spawn vtyctl mcp for '{netns}'"))?;

        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");

        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        stdin.write_all(line.as_bytes()).await?;
        // Closing stdin lets the server exit after answering, so the
        // process reaps itself once we have read the response.
        drop(stdin);

        let mut lines = BufReader::new(stdout).lines();
        let response = loop {
            match lines.next_line().await? {
                // Skip anything that is not a JSON object (stray log noise).
                Some(l) => match serde_json::from_str::<Value>(&l) {
                    Ok(v) if v.is_object() => break Some(v),
                    _ => continue,
                },
                None => break None,
            }
        };

        match response {
            Some(v) => {
                let _ = child.wait().await;
                Ok(v)
            }
            None => {
                // Server exited without answering — surface its stderr,
                // which is where sudo and connection errors land.
                let mut err = String::new();
                let _ = stderr.read_to_string(&mut err).await;
                let status = child.wait().await?;
                bail!(
                    "vtyctl mcp for '{netns}' exited ({status}) without a response: {}",
                    err.trim()
                );
            }
        }
    }
}

fn is_root() -> bool {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc_geteuid() == 0 }
}

unsafe fn libc_geteuid() -> u32 {
    // Avoid a libc dependency for one syscall wrapper: geteuid is
    // exported by glibc/musl under this exact name and signature.
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}
