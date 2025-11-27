use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};

use super::client::ZebraClient;
use super::tools::isis::IsisTools;

pub struct ZmcpServer {
    zebra_client: ZebraClient,
    isis_tools: IsisTools,
}

impl ZmcpServer {
    pub fn new(base_url: String, port: u32) -> Self {
        let zebra_client = ZebraClient::new(base_url, port);
        let isis_tools = IsisTools::new(zebra_client.clone());

        Self {
            zebra_client,
            isis_tools,
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

                // Validate client protocol version
                let client_version = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if !client_version.is_empty() && client_version != "2024-11-05" {
                    warn!(
                        "Client protocol version mismatch: expected 2024-11-05, got {}",
                        client_version
                    );
                }

                json!({
                    "protocolVersion": "2024-11-05",
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
        if let Some(id) = id {
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            }))
        } else {
            // For notifications (requests without ID), don't send a response
            None
        }
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

        match tool_name {
            "get-isis-graph" => match self.isis_tools.get_isis_graph(arguments).await {
                Ok(result) => json!({
                    "content": [
                        {
                            "type": "text",
                            "text": result
                        }
                    ],
                    "isError": false
                }),
                Err(e) => {
                    error!("Tool execution failed: {}", e);
                    json!({
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Error: {}", e)
                            }
                        ],
                        "isError": true
                    })
                }
            },
            _ => {
                warn!("Unknown tool requested: {}", tool_name);
                json!({
                    "content": [
                        {
                            "type": "text",
                            "text": format!("Unknown tool: {}", tool_name)
                        }
                    ],
                    "isError": true
                })
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
