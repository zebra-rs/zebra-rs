use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};

use super::client::ZebraClient;
use super::tools::commands::CommandsTool;
use super::tools::isis::IsisTools;
use super::tools::show::ShowTool;

/// Protocol revisions the `initialize` handshake can negotiate, newest first.
/// 2025-03-26 is deliberately absent: it is the only revision that requires
/// JSON-RPC batching, which this newline-delimited server does not accept.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2024-11-05"];

/// Wrap tool output in the MCP `tools/call` result shape.
fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "isError": is_error
    })
}

pub struct ZmcpServer {
    zebra_client: ZebraClient,
    isis_tools: IsisTools,
    show_tool: ShowTool,
    commands_tool: CommandsTool,
}

impl ZmcpServer {
    pub fn new(base_url: String, port: u32) -> Self {
        let zebra_client = ZebraClient::new(base_url, port);
        let isis_tools = IsisTools::new(zebra_client.clone());
        let show_tool = ShowTool::new(zebra_client.clone());
        let commands_tool = CommandsTool::new(zebra_client.clone());

        Self {
            zebra_client,
            isis_tools,
            show_tool,
            commands_tool,
        }
    }

    pub fn zebra_client(&self) -> &ZebraClient {
        &self.zebra_client
    }

    pub async fn handle_request(&self, request: Value) -> Option<Value> {
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let id = request.get("id").cloned();

        debug!("Handling request: method={}, id={:?}", method, id);

        let result = match method {
            "initialize" => {
                debug!("MCP initialize request");

                let client_version = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Echo a supported requested version; otherwise offer our
                // latest and let the client decide whether to continue.
                let negotiated = if SUPPORTED_PROTOCOL_VERSIONS.contains(&client_version) {
                    client_version
                } else {
                    warn!(
                        "Unsupported client protocol version {:?}, offering {}",
                        client_version, SUPPORTED_PROTOCOL_VERSIONS[0]
                    );
                    SUPPORTED_PROTOCOL_VERSIONS[0]
                };

                json!({
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "vtyctl-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })
            }
            "tools/list" => {
                debug!("Listing available tools");
                json!({
                    "tools": [
                        {
                            "name": "list-show-commands",
                            "description": "List every available read-only `show` command with a one-line explanation of each, generated live from the daemon's command grammar. Call this first to discover what `show` can do.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "show",
                            "description": "Run a read-only zebra-rs operational `show` command and return its output. The command must begin with 'show' (e.g. 'show ip route', 'show bgp summary', 'show isis neighbor'). Use 'list-show-commands' to discover the available commands.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {
                                        "type": "string",
                                        "description": "Full show command to execute, beginning with 'show'."
                                    },
                                    "json": {
                                        "type": "boolean",
                                        "description": "Return JSON-formatted output when the command supports it (default false)."
                                    }
                                },
                                "required": ["command"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "get-isis-graph",
                            "description": "Get IS-IS topology graph data for network visualization and analysis",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "level": {
                                        "type": "string",
                                        "enum": ["L1", "L2", "both"],
                                        "description": "IS-IS level to retrieve (L1, L2, or both)"
                                    }
                                },
                                "additionalProperties": false
                            }
                        }
                    ]
                })
            }
            "tools/call" => self.handle_tool_call(params).await,
            "ping" => json!({}),
            _ => {
                warn!("Unknown method: {}", method);
                // For unknown methods, return error only if request has an ID
                if let Some(id) = id {
                    return Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": "Method not found",
                            "data": format!("Unknown method: {}", method)
                        }
                    }));
                } else {
                    // For notifications (no ID), don't send response
                    return None;
                }
            }
        };

        // Build response with id if present (notifications with no ID don't get responses)
        id.map(|id| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        })
    }

    pub async fn handle_tool_call(&self, params: Value) -> Value {
        let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let arguments = params
            .get("arguments")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Value>>()
            })
            .unwrap_or_default();

        debug!("Calling tool: {}", tool_name);

        let result = match tool_name {
            "list-show-commands" => self.commands_tool.list_show_commands().await,
            "show" => self.show_tool.run(arguments).await,
            "get-isis-graph" => self.isis_tools.get_isis_graph(arguments).await,
            _ => {
                warn!("Unknown tool requested: {}", tool_name);
                return tool_result(format!("Unknown tool: {}", tool_name), true);
            }
        };

        match result {
            Ok(text) => tool_result(text, false),
            Err(e) => {
                error!("Tool execution failed: {}", e);
                tool_result(format!("Error: {}", e), true)
            }
        }
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut reader = BufReader::new(stdin).lines();

        debug!("MCP server ready, listening on stdin/stdout");

        while let Some(line) = reader.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            debug!("Received: {}", line);

            match serde_json::from_str::<Value>(&line) {
                Ok(request) => {
                    if let Some(response) = self.handle_request(request).await {
                        let response_str = serde_json::to_string(&response)?;

                        debug!("Sending: {}", response_str);
                        stdout.write_all(response_str.as_bytes()).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    } else {
                        debug!("No response for notification request");
                    }
                }
                Err(e) => {
                    error!("Failed to parse JSON request: {}", e);
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": "Parse error",
                            "data": format!("Invalid JSON: {}", e)
                        },
                        "id": null
                    });
                    let response_str = serde_json::to_string(&error_response)?;
                    stdout.write_all(response_str.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
            }
        }

        debug!("MCP server shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> ZmcpServer {
        ZmcpServer::new("127.0.0.1".to_string(), 2650)
    }

    #[tokio::test]
    async fn tools_list_advertises_expected_tools() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = server().handle_request(req).await.expect("response");
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for expected in ["list-show-commands", "show", "get-isis-graph"] {
            assert!(
                names.contains(&expected),
                "missing {expected}; tools: {names:?}"
            );
        }
    }

    async fn negotiate(requested: Option<&str>) -> Value {
        let params = match requested {
            Some(v) => json!({"protocolVersion": v}),
            None => json!({}),
        };
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params});
        let resp = server().handle_request(req).await.expect("response");
        resp["result"]["protocolVersion"].clone()
    }

    #[tokio::test]
    async fn initialize_echoes_supported_versions() {
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            assert_eq!(negotiate(Some(version)).await, json!(version));
        }
    }

    #[tokio::test]
    async fn initialize_offers_latest_for_unsupported_version() {
        for requested in [Some("2025-03-26"), Some("1999-01-01"), None] {
            assert_eq!(
                negotiate(requested).await,
                json!(SUPPORTED_PROTOCOL_VERSIONS[0])
            );
        }
    }

    #[tokio::test]
    async fn ping_returns_empty_result() {
        let req = json!({"jsonrpc": "2.0", "id": 3, "method": "ping"});
        let resp = server().handle_request(req).await.expect("response");
        assert_eq!(resp["result"], json!({}));
    }

    #[tokio::test]
    async fn unknown_tool_call_is_error() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "configure", "arguments": {}}
        });
        let resp = server().handle_request(req).await.expect("response");
        assert_eq!(resp["result"]["isError"], json!(true));
    }
}
