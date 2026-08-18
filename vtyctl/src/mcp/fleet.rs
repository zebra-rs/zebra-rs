//! Fleet mode: one MCP server fronting many per-netns zebra-rs daemons.
//!
//! Each router of a playset runs zebra-rs in its own network namespace,
//! listening on the abstract Unix socket `@zebra-rs/vty` — and abstract
//! sockets are network-namespaced, so a daemon is only reachable from
//! inside its namespace. The fleet server therefore adds a `router`
//! argument to every tool and forwards each call to a one-shot
//! `ip netns exec <router> vtyctl mcp` child (this same binary), speaking
//! the MCP 2026-07-28 stateless revision over the child's stdio: one
//! `tools/call` line out, one response line back, no handshake.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const PROTOCOL_VERSION: &str = "2026-07-28";
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// Per-forwarded-call deadline. Generous — `show` on a large table plus
/// the netns process spawn stays well inside it.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The router roster and how to reach each member.
#[derive(Clone, Debug)]
pub struct Fleet {
    /// Router names in ontology order; by playset convention each name is
    /// also the router's network namespace.
    routers: Vec<String>,
    /// Daemon VTY endpoint as seen from inside each namespace.
    host: String,
}

impl Fleet {
    /// Build the roster from the ontology file: every entry's `name` is a
    /// router. Fails on an unreadable file or a malformed roster so fleet
    /// mode dies at server start, not at first call.
    pub fn new(ontology_path: &Path, host: &str) -> Result<Self> {
        let text = std::fs::read_to_string(ontology_path)
            .with_context(|| format!("cannot read fleet file {}", ontology_path.display()))?;
        let routers = roster_from_ontology(&text)
            .with_context(|| format!("fleet file {}", ontology_path.display()))?;
        Ok(Self::from_roster(routers, host))
    }

    pub fn from_roster(routers: Vec<String>, host: &str) -> Self {
        Self {
            routers,
            host: host.to_string(),
        }
    }

    pub fn routers(&self) -> &[String] {
        &self.routers
    }

    /// Forward one tool call to `router` and return the tool's text output.
    pub async fn call(&self, router: &str, tool: &str, arguments: Value) -> Result<String> {
        if !self.routers.iter().any(|r| r == router) {
            bail!(
                "unknown router '{}'; known routers: {}",
                router,
                self.routers.join(", ")
            );
        }

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

        let response = tokio::time::timeout(CALL_TIMEOUT, self.roundtrip(router, &request))
            .await
            .map_err(|_| anyhow!("call '{tool}' on router '{router}' timed out"))??;

        extract_tool_text(&response, router)
    }

    /// Build the command that runs this binary's own `mcp` server inside
    /// the router's namespace. When the fleet server itself is not root,
    /// go through `sudo -n` — non-interactive, so a misconfigured sudo
    /// fails fast instead of hanging the call on a password prompt.
    fn command(&self, netns: &str) -> Result<Command> {
        let exe = std::env::current_exe().context("cannot resolve own executable path")?;

        let mut argv: Vec<std::ffi::OsString> = Vec::new();
        if !is_root() {
            argv.extend(["sudo".into(), "-n".into()]);
        }
        argv.extend(["ip".into(), "netns".into(), "exec".into(), netns.into()]);
        argv.push(exe.into());
        argv.extend(["mcp".into(), "-H".into(), self.host.as_str().into()]);

        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        Ok(cmd)
    }

    /// One stateless request/response exchange with a freshly spawned
    /// per-router server.
    async fn roundtrip(&self, netns: &str, request: &Value) -> Result<Value> {
        let mut child = self
            .command(netns)?
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to spawn vtyctl mcp for router '{netns}'"))?;

        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");

        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        stdin.write_all(line.as_bytes()).await?;
        // Closing stdin lets the child exit after answering, so it reaps
        // itself once the response is read.
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
                // Child exited without answering — surface its stderr,
                // which is where sudo and connection errors land.
                let mut err = String::new();
                let _ = stderr.read_to_string(&mut err).await;
                let status = child.wait().await?;
                bail!(
                    "vtyctl mcp for router '{netns}' exited ({status}) without a response: {}",
                    err.trim()
                );
            }
        }
    }
}

/// Parse the ontology JSON into the router roster.
fn roster_from_ontology(text: &str) -> Result<Vec<String>> {
    let parsed: Value = serde_json::from_str(text).context("not valid JSON")?;
    let entries = parsed
        .as_array()
        .ok_or_else(|| anyhow!("must be a JSON array of router objects"))?;

    let mut routers = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            bail!("entry {i} has no 'name'");
        }
        if routers.iter().any(|r| r == name) {
            bail!("duplicate router name '{name}'");
        }
        routers.push(name.to_string());
    }
    if routers.is_empty() {
        bail!("names no routers");
    }
    Ok(routers)
}

/// Extract the text content from a forwarded `tools/call` response,
/// propagating both protocol errors and tool-level `isError` results.
fn extract_tool_text(response: &Value, router: &str) -> Result<String> {
    if let Some(error) = response.get("error") {
        bail!("MCP error from router '{router}': {error}");
    }
    let result = response
        .get("result")
        .ok_or_else(|| anyhow!("response from router '{router}' has no result"))?;
    let text = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("result from router '{router}' has no text content"))?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        // The child already spelled the error out (usually with an
        // "Error: " prefix the caller's own wrapper would duplicate).
        bail!("{}", text.strip_prefix("Error: ").unwrap_or(text));
    }
    Ok(text.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_parses_names_in_order() {
        let text = r#"[{"name":"tk","region":"AP"},{"name":"se","region":"US"}]"#;
        assert_eq!(roster_from_ontology(text).unwrap(), vec!["tk", "se"]);
    }

    #[test]
    fn roster_rejects_bad_shapes() {
        for (text, needle) in [
            ("{}", "JSON array"),
            ("[]", "no routers"),
            (r#"[{"region":"AP"}]"#, "no 'name'"),
            (r#"[{"name":""}]"#, "no 'name'"),
            (r#"[{"name":"tk"},{"name":"tk"}]"#, "duplicate"),
            ("not json", "not valid JSON"),
        ] {
            let err = roster_from_ontology(text).unwrap_err().to_string();
            assert!(err.contains(needle), "{text}: {err}");
        }
    }

    #[tokio::test]
    async fn call_rejects_unknown_router_before_spawning() {
        let fleet = Fleet::from_roster(vec!["tk".into(), "se".into()], "unix:zebra-rs/vty");
        let err = fleet
            .call("nowhere", "show", json!({}))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown router 'nowhere'"), "{err}");
        assert!(err.contains("tk, se"), "{err}");
    }

    #[test]
    fn extract_text_propagates_error_shapes() {
        let err = extract_tool_text(&json!({"error": {"code": -32601}}), "tk")
            .unwrap_err()
            .to_string();
        assert!(err.contains("MCP error from router 'tk'"), "{err}");

        let err = extract_tool_text(
            &json!({"result": {"content": [{"type":"text","text":"Error: apply failed"}], "isError": true}}),
            "tk",
        )
        .unwrap_err()
        .to_string();
        assert_eq!(err, "apply failed");

        let err = extract_tool_text(&json!({"result": {"content": []}}), "tk")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no text content"), "{err}");
    }

    #[test]
    fn extract_text_returns_success_payload() {
        let text = extract_tool_text(
            &json!({"result": {"content": [{"type":"text","text":"applied: 2 line(s) committed"}], "isError": false}}),
            "tk",
        )
        .unwrap();
        assert_eq!(text, "applied: 2 line(s) committed");
    }
}
