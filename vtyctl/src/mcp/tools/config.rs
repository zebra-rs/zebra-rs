use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use crate::mcp::client::ZebraClient;

/// Serializations `get-config` can return. `formal` leads because it is the
/// round-trip format: the same `set ...` line syntax `apply-config` consumes.
const FORMATS: &[&str] = &["formal", "cli", "json", "yaml"];

/// Configuration tools: read the running configuration and apply changes.
///
/// `apply-config` is the MCP server's only write surface. It forwards
/// explicit `set` / `delete` lines to the daemon's Apply service, which
/// validates and commits them as one transaction — on any error the whole
/// candidate is discarded and nothing is applied. The service also accepts
/// whole YAML/JSON documents, but those REPLACE the entire running
/// configuration, so this tool refuses anything that is not a set/delete
/// line rather than let a stray document line trigger a full replace.
#[derive(Clone)]
pub struct ConfigTools {
    client: ZebraClient,
}

impl ConfigTools {
    pub fn new(client: ZebraClient) -> Self {
        Self { client }
    }

    /// `get-config`: the running configuration in the requested
    /// serialization (default `formal`).
    pub async fn get_config(&self, args: HashMap<String, Value>) -> Result<String> {
        let format = match args.get("format") {
            None => "formal",
            Some(v) => v
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("'format' must be a string"))?,
        };
        if !FORMATS.contains(&format) {
            return Err(anyhow::anyhow!(
                "'format' must be one of formal, cli, json, yaml; got '{}'",
                format
            ));
        }

        // The bare command is the CLI-block rendering; the other formats
        // are selected by a trailing keyword.
        let command = if format == "cli" {
            String::from("show running-config")
        } else {
            format!("show running-config {}", format)
        };

        debug!("Fetching running config: {}", command);
        let output = self.client.show_command(&command, false).await?;
        if output.trim().is_empty() {
            Ok(String::from("(empty configuration)"))
        } else {
            Ok(output)
        }
    }

    /// `apply-config`: validate the line shape client-side, then hand the
    /// lines to the daemon's transactional Apply service.
    pub async fn apply_config(&self, args: HashMap<String, Value>) -> Result<String> {
        let lines = parse_config_lines(args.get("commands"))?;
        debug!("Applying {} config line(s)", lines.len());
        self.client.apply_config(&lines).await
    }
}

/// Validate the `commands` argument: a non-empty array of strings, each a
/// single `set ...` or `delete ...` line. Anything else is rejected here,
/// before it reaches the daemon's format sniffer (see the type-level
/// comment for why that matters).
fn parse_config_lines(value: Option<&Value>) -> Result<Vec<String>> {
    let items = value.and_then(|v| v.as_array()).ok_or_else(|| {
        anyhow::anyhow!("Missing required 'commands' argument (an array of strings)")
    })?;
    if items.is_empty() {
        return Err(anyhow::anyhow!("'commands' must not be empty"));
    }

    let mut lines = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let line = item.as_str().map(str::trim).unwrap_or("");
        if line.is_empty() {
            return Err(anyhow::anyhow!(
                "commands[{}] must be a non-empty string",
                i
            ));
        }
        if line.contains('\n') {
            return Err(anyhow::anyhow!(
                "commands[{}] contains a newline; pass one command per array element",
                i
            ));
        }
        let mut tokens = line.split_whitespace();
        let verb = tokens.next().unwrap_or("");
        if !(verb == "set" || verb == "delete") || tokens.next().is_none() {
            return Err(anyhow::anyhow!(
                "commands[{}] must be a 'set ...' or 'delete ...' line; got '{}'",
                i,
                line
            ));
        }
        lines.push(line.to_string());
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool() -> ConfigTools {
        ConfigTools::new(ZebraClient::new("127.0.0.1".to_string(), 2650))
    }

    fn args(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[tokio::test]
    async fn get_config_rejects_unknown_format() {
        let err = tool()
            .get_config(args(&[("format", json!("xml"))]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be one of"), "{err}");
    }

    #[tokio::test]
    async fn get_config_rejects_non_string_format() {
        let err = tool()
            .get_config(args(&[("format", json!(42))]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be a string"), "{err}");
    }

    #[test]
    fn accepts_set_and_delete_lines() {
        let lines = parse_config_lines(Some(&json!([
            "set routing isis net 49.0000.0000.0001.00",
            "  delete interface lo shutdown  ",
        ])))
        .unwrap();
        assert_eq!(
            lines,
            vec![
                "set routing isis net 49.0000.0000.0001.00".to_string(),
                "delete interface lo shutdown".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_missing_or_empty_commands() {
        for value in [None, Some(json!("set x y")), Some(json!({}))] {
            let err = parse_config_lines(value.as_ref()).unwrap_err().to_string();
            assert!(err.contains("array of strings"), "{value:?}: {err}");
        }
        let err = parse_config_lines(Some(&json!([])))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn rejects_lines_that_are_not_set_or_delete() {
        for bad in [
            "configure terminal",
            "interface: {}",
            "settle down",
            "set",
            "delete",
            "show running-config",
        ] {
            let err = parse_config_lines(Some(&json!([bad])))
                .unwrap_err()
                .to_string();
            assert!(err.contains("'set ...' or 'delete ...'"), "{bad}: {err}");
        }
    }

    #[test]
    fn rejects_non_string_and_blank_elements() {
        for bad in [json!([42]), json!([""]), json!(["   "]), json!([null])] {
            let err = parse_config_lines(Some(&bad)).unwrap_err().to_string();
            assert!(err.contains("non-empty string"), "{bad}: {err}");
        }
    }

    #[test]
    fn rejects_embedded_newlines() {
        let err = parse_config_lines(Some(&json!(["set system hostname x\nkey: value"])))
            .unwrap_err()
            .to_string();
        assert!(err.contains("one command per array element"), "{err}");
    }
}
