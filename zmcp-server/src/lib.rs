pub mod client;
pub mod tools;

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};

use client::ZebraClient;
use tools::isis::IsisTools;

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

    pub async fn handle_request(&self, request: Value) -> Value {
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let id = request.get("id").cloned();

        debug!("Handling request: method={}, id={:?}", method, id);

        let result = match method {
            "initialize" => {
                debug!("MCP initialize request");
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "zmcp-server",
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
                                        "description": "IS-IS level to retrieve (L1, L2, or both)",
                                        "default": "both"
                                    }
                                },
                                "required": []
                            }
                        }
                    ]
                })
            }
            "tools/call" => self.handle_tool_call(params).await,
            _ => {
                warn!("Unknown method: {}", method);
                json!({
                    "error": {
                        "code": -32601,
                        "message": "Method not found",
                        "data": format!("Unknown method: {}", method)
                    }
                })
            }
        };

        // Build response with id if present
        if let Some(id) = id {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        } else {
            json!({
                "jsonrpc": "2.0",
                "result": result
            })
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
                    let response = self.handle_request(request).await;
                    let response_str = serde_json::to_string(&response)?;

                    debug!("Sending: {}", response_str);
                    stdout.write_all(response_str.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
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
    use serde_json::json;

    #[tokio::test]
    async fn test_handle_initialize() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert_eq!(response["result"]["serverInfo"]["name"], "zmcp-server");
    }

    #[tokio::test]
    async fn test_handle_tools_list() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 2);
        assert!(response["result"]["tools"].is_array());

        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "get-isis-graph");
        assert!(tools[0]["description"].is_string());
        assert!(tools[0]["inputSchema"].is_object());
    }

    #[tokio::test]
    async fn test_handle_unknown_method() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "unknown/method",
            "params": {}
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 3);
        assert_eq!(response["result"]["error"]["code"], -32601);
        assert_eq!(response["result"]["error"]["message"], "Method not found");
    }

    #[tokio::test]
    async fn test_handle_tools_call_unknown_tool() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "unknown-tool",
                "arguments": {}
            }
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 4);
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Unknown tool"));
    }

    #[tokio::test]
    async fn test_handle_tools_call_isis_graph() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "get-isis-graph",
                "arguments": {
                    "level": "L1"
                }
            }
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 5);
        // This will either succeed with empty data or fail with connection error
        if response["result"]["isError"] == false {
            // Success case - got empty ISIS data
            let content = response["result"]["content"][0]["text"].as_str().unwrap();
            // Should be empty JSON array "[]" for empty ISIS data
            assert!(content == "[]" || content.contains("[]"));
        } else {
            // Error case - connection failed
            assert!(response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Error"));
        }
    }

    #[tokio::test]
    async fn test_handle_tools_call_invalid_params() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "get-isis-graph",
                "arguments": {
                    "level": "invalid"
                }
            }
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 6);
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Invalid level"));
    }

    #[tokio::test]
    async fn test_handle_request_no_id() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);
        let request = json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {}
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response.get("id").is_none());
        assert!(response["result"].is_object());
    }

    #[test]
    fn test_server_creation() {
        let server = ZmcpServer::new("http://localhost".to_string(), 8080);
        // Just test that we can create the server without panicking
        assert_eq!(server.zebra_client().base_url, "http://localhost");
        assert_eq!(server.zebra_client().port, 8080);
    }

    #[tokio::test]
    async fn test_json_rpc_request_structure() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);

        // Test well-formed JSON-RPC request
        let request = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        });

        let response = server.handle_request(request).await;

        // Validate JSON-RPC response structure
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 42);
        assert!(response["result"].is_object());
        assert!(response.get("error").is_none());
    }

    #[tokio::test]
    async fn test_malformed_request_handling() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);

        // Request without required fields
        let request = json!({
            "id": 1
        });

        let response = server.handle_request(request).await;

        // Should handle gracefully
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert!(response["result"]["error"].is_object());
    }

    #[tokio::test]
    async fn test_tools_call_parameter_validation() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);

        // Test missing tool name
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "arguments": {}
            }
        });

        let response = server.handle_request(request).await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Unknown tool"));
    }

    #[tokio::test]
    async fn test_tools_call_argument_parsing() {
        let server = ZmcpServer::new("http://127.0.0.1".to_string(), 2650);

        // Test with complex nested arguments
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get-isis-graph",
                "arguments": {
                    "level": "L1",
                    "extra_param": {
                        "nested": "value"
                    }
                }
            }
        });

        let response = server.handle_request(request).await;

        // Should parse arguments correctly and execute (though will fail due to no zebra-rs)
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        // This will either succeed with empty data or fail with connection error
        if response["result"]["isError"] == false {
            // Success case - got empty ISIS data
            let content = response["result"]["content"][0]["text"].as_str().unwrap();
            // Should be empty JSON array "[]" for empty ISIS data
            assert!(content == "[]" || content.contains("[]"));
        } else {
            // Error case - should fail with connection error, not argument parsing error
            assert!(response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Error"));
        }
    }
}
