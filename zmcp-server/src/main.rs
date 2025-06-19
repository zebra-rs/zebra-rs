use anyhow::Result;
use clap::Parser;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};
use tracing_subscriber;

mod tools;
mod client;

use tools::isis::IsisTools;
use client::ZebraClient;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, help = "Base URL of zebra-rs server", default_value = "http://127.0.0.1")]
    base: String,

    #[arg(short, long, help = "Show server port", default_value = "2650")]
    port: u32,

    #[arg(short, long, help = "Enable debug logging")]
    debug: bool,
}

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

    async fn handle_request(&self, request: Value) -> Value {
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
            "tools/call" => {
                self.handle_tool_call(params).await
            }
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

    async fn handle_tool_call(&self, params: Value) -> Value {
        let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let arguments = params.get("arguments")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Value>>()
            })
            .unwrap_or_default();

        debug!("Calling tool: {}", tool_name);

        match tool_name {
            "get-isis-graph" => {
                match self.isis_tools.get_isis_graph(arguments).await {
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
                }
            }
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

    async fn run(&self) -> Result<()> {
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(if cli.debug {
            "debug"
        } else {
            "warn"
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    debug!("Starting zmcp-server v{}", env!("CARGO_PKG_VERSION"));
    debug!("Connecting to zebra-rs at {}:{}", cli.base, cli.port);

    let server = ZmcpServer::new(cli.base, cli.port);

    // Test connection to zebra-rs
    if let Err(e) = server.zebra_client.test_connection().await {
        error!("Failed to connect to zebra-rs: {}", e);
        error!("Make sure zebra-rs is running on the specified address");
        return Err(e);
    }

    debug!("Successfully connected to zebra-rs");

    server.run().await?;

    Ok(())
}