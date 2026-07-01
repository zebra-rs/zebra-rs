use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::mcp::client::ZebraClient;

/// Generic read-only `show` command tool.
///
/// Phase 0 is read-only: this tool runs the daemon `Show` RPC for any
/// operational `show` command and returns its output. Commands that do not
/// begin with `show` are rejected so the read-only contract is explicit.
#[derive(Clone)]
pub struct ShowTool {
    client: ZebraClient,
}

impl ShowTool {
    pub fn new(client: ZebraClient) -> Self {
        Self { client }
    }

    /// Execute a read-only `show` command against the daemon.
    pub async fn run(&self, args: HashMap<String, Value>) -> Result<String> {
        let command = args
            .get("command")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");

        if command.is_empty() {
            return Err(anyhow::anyhow!("Missing required 'command' argument"));
        }

        // Read-only contract: only `show` commands are permitted.
        if command.split_whitespace().next() != Some("show") {
            warn!("Rejected non-show command: {}", command);
            return Err(anyhow::anyhow!(
                "Only 'show' commands are permitted; got '{}'",
                command
            ));
        }

        let json = args.get("json").and_then(|v| v.as_bool()).unwrap_or(false);

        debug!("Executing show command: {} (json={})", command, json);
        let output = self.client.show_command(command, json).await?;

        if output.trim().is_empty() {
            Ok(String::from("(no output)"))
        } else {
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> ShowTool {
        ShowTool::new(ZebraClient::new("127.0.0.1".to_string(), 2650))
    }

    fn args(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[tokio::test]
    async fn rejects_missing_command() {
        let err = tool().run(args(&[])).await.unwrap_err().to_string();
        assert!(err.contains("Missing required 'command'"), "{err}");
    }

    #[tokio::test]
    async fn rejects_empty_command() {
        let err = tool()
            .run(args(&[("command", Value::String("   ".to_string()))]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Missing required 'command'"), "{err}");
    }

    #[tokio::test]
    async fn rejects_non_show_command() {
        for cmd in [
            "configure terminal",
            "clear bgp ipv4 neighbor *",
            "showtime",
        ] {
            let err = tool()
                .run(args(&[("command", Value::String(cmd.to_string()))]))
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("Only 'show' commands are permitted"),
                "{cmd}: {err}"
            );
        }
    }
}
