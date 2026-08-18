use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};

use super::client::ZebraClient;
use super::tools::commands::CommandsTool;
use super::tools::config::ConfigTools;
use super::tools::isis::IsisTools;
use super::tools::ontology::OntologyTool;
use super::tools::ospf::OspfTools;
use super::tools::show::ShowTool;

/// Handshake revisions the legacy `initialize` path can negotiate, newest
/// first. 2025-03-26 is deliberately absent: it is the only revision that
/// requires JSON-RPC batching, which this newline-delimited server does not
/// accept.
const LEGACY_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2024-11-05"];

/// Stateless revisions served from per-request `_meta`; 2026-07-28 and later
/// carry the protocol version on every request instead of negotiating it in
/// an `initialize` handshake.
const MODERN_PROTOCOL_VERSIONS: &[&str] = &["2026-07-28"];

const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// Freshness hint for cacheable results: the tool list is fixed for the
/// lifetime of the process.
const CACHE_TTL_MS: u64 = 3_600_000;

fn supported_versions() -> Vec<&'static str> {
    let mut versions = MODERN_PROTOCOL_VERSIONS.to_vec();
    versions.extend_from_slice(LEGACY_PROTOCOL_VERSIONS);
    versions
}

fn server_info() -> Value {
    json!({
        "name": "vtyctl-mcp",
        "version": env!("CARGO_PKG_VERSION")
    })
}

fn method_not_found(method: &str) -> Value {
    warn!("Unknown method: {}", method);
    json!({
        "code": -32601,
        "message": "Method not found",
        "data": format!("Unknown method: {}", method)
    })
}

/// Stamp the fields the 2026-07-28 revision requires on every result
/// (`resultType`, server identity in `_meta`); legacy clients ignore them.
fn stamp_result(result: &mut Value) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    obj.entry("resultType").or_insert_with(|| json!("complete"));
    if let Some(meta) = obj
        .entry("_meta")
        .or_insert_with(|| json!({}))
        .as_object_mut()
    {
        meta.insert(META_SERVER_INFO.to_string(), server_info());
    }
}

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
    ospf_tools: OspfTools,
    show_tool: ShowTool,
    commands_tool: CommandsTool,
    config_tools: ConfigTools,
    /// Present only when the server was started with `--ontology <path>`;
    /// the `get-ontology` tool is registered iff this is set.
    ontology_tool: Option<OntologyTool>,
}

impl ZmcpServer {
    pub fn new(base_url: String, port: u32, ontology_tool: Option<OntologyTool>) -> Self {
        let zebra_client = ZebraClient::new(base_url, port);
        let isis_tools = IsisTools::new(zebra_client.clone());
        let ospf_tools = OspfTools::new(zebra_client.clone());
        let show_tool = ShowTool::new(zebra_client.clone());
        let commands_tool = CommandsTool::new(zebra_client.clone());
        let config_tools = ConfigTools::new(zebra_client.clone());

        Self {
            zebra_client,
            isis_tools,
            ospf_tools,
            show_tool,
            commands_tool,
            config_tools,
            ontology_tool,
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

        let meta_version = params
            .get("_meta")
            .and_then(|m| m.get(META_PROTOCOL_VERSION))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        // `server/discover` doubles as the era/version probe, so answer it
        // regardless of the requested version.
        let outcome = if method == "server/discover" {
            Ok(self.discover_result())
        } else if let Some(version) = meta_version {
            self.handle_modern(method, &version, params).await
        } else {
            self.handle_legacy(method, params).await
        };

        // Notifications (no ID) never get responses.
        let id = id?;
        Some(match outcome {
            Ok(mut result) => {
                stamp_result(&mut result);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                })
            }
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": error
            }),
        })
    }

    /// Serve a request that declared its protocol version per-request
    /// (2026-07-28 stateless semantics).
    async fn handle_modern(
        &self,
        method: &str,
        version: &str,
        params: Value,
    ) -> Result<Value, Value> {
        if !MODERN_PROTOCOL_VERSIONS.contains(&version) {
            return Err(json!({
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {
                    "supported": supported_versions(),
                    "requested": version
                }
            }));
        }

        // Required on every stateless request; a request missing it is
        // malformed under the 2026-07-28 revision.
        if params
            .get("_meta")
            .and_then(|m| m.get(META_CLIENT_CAPABILITIES))
            .is_none()
        {
            return Err(json!({
                "code": -32602,
                "message": "Invalid params",
                "data": format!("missing required _meta field {}", META_CLIENT_CAPABILITIES)
            }));
        }

        match method {
            "tools/list" => Ok(self.tools_list()),
            "tools/call" => Ok(self.handle_tool_call(params).await),
            _ => Err(method_not_found(method)),
        }
    }

    /// Serve a request under the pre-2026 handshake-based semantics.
    async fn handle_legacy(&self, method: &str, params: Value) -> Result<Value, Value> {
        match method {
            "initialize" => {
                debug!("MCP initialize request");

                let client_version = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Echo a supported requested version; otherwise offer our
                // latest and let the client decide whether to continue.
                let negotiated = if LEGACY_PROTOCOL_VERSIONS.contains(&client_version) {
                    client_version
                } else {
                    warn!(
                        "Unsupported client protocol version {:?}, offering {}",
                        client_version, LEGACY_PROTOCOL_VERSIONS[0]
                    );
                    LEGACY_PROTOCOL_VERSIONS[0]
                };

                Ok(json!({
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": server_info()
                }))
            }
            "tools/list" => Ok(self.tools_list()),
            "tools/call" => Ok(self.handle_tool_call(params).await),
            "ping" => Ok(json!({})),
            _ => Err(method_not_found(method)),
        }
    }

    fn discover_result(&self) -> Value {
        json!({
            "supportedVersions": supported_versions(),
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "instructions": "Interface to a zebra-rs routing daemon. Call list-show-commands to discover the read-only show commands and run them with the show tool. Read the configuration with get-config (format 'formal' is set-line syntax) and change it with apply-config, which validates and commits set/delete lines as one atomic transaction.",
            "ttlMs": CACHE_TTL_MS,
            "cacheScope": "private"
        })
    }

    fn tools_list(&self) -> Value {
        debug!("Listing available tools");
        let mut extra_tools = vec![
            json!({
                "name": "get-config",
                "description": "Get the daemon's running configuration. Format 'formal' (the default) returns one 'set ...' line per node — the same syntax apply-config consumes; 'cli' returns indented configuration blocks; 'json' and 'yaml' return the configuration tree in those serializations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["formal", "cli", "json", "yaml"],
                            "description": "Serialization of the configuration (default 'formal')."
                        }
                    },
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "apply-config",
                "description": "Apply configuration changes and commit them atomically. Each element of 'commands' must be a single 'set ...' or 'delete ...' line in the syntax shown by get-config format 'formal'. The daemon validates and commits all lines as one transaction: on any error nothing is applied and the error detail (including the offending line) is returned, so a failed call is safe to correct and retry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "commands": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                            "description": "Configuration lines, each beginning with 'set ' or 'delete '."
                        }
                    },
                    "required": ["commands"],
                    "additionalProperties": false
                }
            }),
        ];
        if self.ontology_tool.is_some() {
            extra_tools.push(json!({
                "name": "get-ontology",
                "description": "Get the operator-provided network ontology as JSON: semantic metadata about the routers (short name, full name, region, ...) that the routing protocols do not carry. Use it to map intent expressed in business terms — regions, sites, jurisdictions — onto the topology.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }
            }));
        }
        let mut result = json!({
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
                    "description": "Get IS-IS topology graph data for network visualization and analysis. Without 'algorithm' this is the unpruned LSDB graph; with a Flex-Algorithm number (128-255) it is that algorithm's constraint-pruned graph.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "level": {
                                "type": "string",
                                "enum": ["L1", "L2", "both"],
                                "description": "IS-IS level to retrieve (L1, L2, or both)"
                            },
                            "algorithm": {
                                "type": "integer",
                                "minimum": 128,
                                "maximum": 255,
                                "description": "Flex-Algorithm number (128-255). Omit for the plain algorithm-0 graph."
                            }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "get-isis-spf",
                    "description": "Get IS-IS SPF (shortest path first) results as JSON: per-destination cost, nexthops, and the full hop-by-hop paths from this router. Without 'algorithm' this is the plain algorithm-0 SPF; with a Flex-Algorithm number (128-255) it is that algorithm's constrained SPF.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "algorithm": {
                                "type": "integer",
                                "minimum": 128,
                                "maximum": 255,
                                "description": "Flex-Algorithm number (128-255). Omit for the plain algorithm-0 SPF."
                            }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "get-isis-flex-algo",
                    "description": "Get IS-IS Flexible Algorithm (RFC 9350) state as JSON: locally configured algorithms with their constraints, and per-level peer FAD advertisements and algorithm participation.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                },
                {
                    "name": "get-ospf-graph",
                    "description": "Get OSPF topology graph data for network visualization and analysis: the area's SPF graph with router names and per-link costs, built from the LSDB. 'version' selects OSPFv2 (2, the default) or OSPFv3 (3).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "version": {
                                "type": "integer",
                                "enum": [2, 3],
                                "description": "OSPF version: 2 (OSPFv2, default) or 3 (OSPFv3)."
                            }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "get-ospf-spf",
                    "description": "Get OSPF SPF (shortest path first) results as JSON: per-vertex cost and first hops from this router. 'version' selects OSPFv2 (2, the default) or OSPFv3 (3). Unlike IS-IS, OSPF's SPF result carries no hop-by-hop path lists; join vertex ids against get-ospf-graph for names and links.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "version": {
                                "type": "integer",
                                "enum": [2, 3],
                                "description": "OSPF version: 2 (OSPFv2, default) or 3 (OSPFv3)."
                            }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "get-ospf-flex-algo",
                    "description": "Get OSPF Flexible Algorithm (RFC 9350) state as JSON: each configured algorithm's definition and constraints, its per-algorithm SPF status, and per-algorithm routes. 'version' selects OSPFv2 (2, the default) or OSPFv3 (3).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "version": {
                                "type": "integer",
                                "enum": [2, 3],
                                "description": "OSPF version: 2 (OSPFv2, default) or 3 (OSPFv3)."
                            }
                        },
                        "additionalProperties": false
                    }
                }
            ],
            "ttlMs": CACHE_TTL_MS,
            "cacheScope": "private"
        });
        result["tools"]
            .as_array_mut()
            .expect("tools is an array")
            .extend(extra_tools);
        result
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
            "get-isis-spf" => self.isis_tools.get_isis_spf(arguments).await,
            "get-isis-flex-algo" => self.isis_tools.get_isis_flex_algo(arguments).await,
            "get-ospf-graph" => self.ospf_tools.get_ospf_graph(arguments).await,
            "get-ospf-spf" => self.ospf_tools.get_ospf_spf(arguments).await,
            "get-ospf-flex-algo" => self.ospf_tools.get_ospf_flex_algo(arguments).await,
            "get-config" => self.config_tools.get_config(arguments).await,
            "apply-config" => self.config_tools.apply_config(arguments).await,
            "get-ontology" => match &self.ontology_tool {
                Some(tool) => tool.read(),
                None => Err(anyhow::anyhow!(
                    "no ontology configured; start the server with 'vtyctl mcp --ontology <path>'"
                )),
            },
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
        ZmcpServer::new("127.0.0.1".to_string(), 2650, None)
    }

    /// A server with the ontology tool wired to a real temp file.
    fn server_with_ontology() -> (ZmcpServer, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "vtyctl-server-ontology-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"[{"name":"tk","region":"AP"}]"#).unwrap();
        let tool = OntologyTool::new(&path).unwrap();
        (
            ZmcpServer::new("127.0.0.1".to_string(), 2650, Some(tool)),
            path,
        )
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
        for expected in [
            "list-show-commands",
            "show",
            "get-isis-graph",
            "get-isis-spf",
            "get-isis-flex-algo",
            "get-ospf-graph",
            "get-ospf-spf",
            "get-ospf-flex-algo",
            "get-config",
            "apply-config",
        ] {
            assert!(
                names.contains(&expected),
                "missing {expected}; tools: {names:?}"
            );
        }
        // get-ontology is registered only when --ontology names a file.
        assert!(!names.contains(&"get-ontology"), "tools: {names:?}");
    }

    #[tokio::test]
    async fn ontology_tool_is_listed_and_served_when_configured() {
        let (server, path) = server_with_ontology();
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = server.handle_request(req).await.expect("response");
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"get-ontology"), "tools: {names:?}");

        let result = server
            .handle_tool_call(json!({"name": "get-ontology", "arguments": {}}))
            .await;
        std::fs::remove_file(&path).unwrap();
        assert_eq!(result["isError"], json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"region\": \"AP\""), "{text}");
    }

    #[tokio::test]
    async fn ontology_tool_errors_when_unconfigured() {
        let result = server()
            .handle_tool_call(json!({"name": "get-ontology", "arguments": {}}))
            .await;
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("--ontology"), "{text}");
    }

    #[tokio::test]
    async fn apply_config_rejects_bad_lines_before_dialing() {
        // Client-side validation runs before any gRPC dial, so these fail
        // fast even with no daemon listening.
        let result = server()
            .handle_tool_call(json!({
                "name": "apply-config",
                "arguments": {"commands": ["configure terminal"]}
            }))
            .await;
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("'set ...' or 'delete ...'"), "{text}");
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
        for version in LEGACY_PROTOCOL_VERSIONS {
            assert_eq!(negotiate(Some(version)).await, json!(version));
        }
    }

    #[tokio::test]
    async fn initialize_offers_latest_for_unsupported_version() {
        for requested in [Some("2025-03-26"), Some("1999-01-01"), None] {
            assert_eq!(
                negotiate(requested).await,
                json!(LEGACY_PROTOCOL_VERSIONS[0])
            );
        }
    }

    /// Build a stateless 2026-07-28 request carrying the required `_meta`
    /// fields, spelled out literally to pin the wire format.
    fn modern_request(method: &str, mut params: Value) -> Value {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
    }

    #[tokio::test]
    async fn server_discover_answers_without_meta() {
        let req = json!({"jsonrpc": "2.0", "id": 5, "method": "server/discover"});
        let resp = server().handle_request(req).await.expect("response");
        let result = &resp["result"];
        assert_eq!(result["resultType"], json!("complete"));
        assert_eq!(
            result["supportedVersions"],
            json!(["2026-07-28", "2025-06-18", "2024-11-05"])
        );
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            json!("vtyctl-mcp")
        );
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn modern_tools_list_needs_no_handshake() {
        let resp = server()
            .handle_request(modern_request("tools/list", json!({})))
            .await
            .expect("response");
        let result = &resp["result"];
        assert!(result["tools"].as_array().is_some_and(|t| t.len() == 10));
        assert_eq!(result["resultType"], json!("complete"));
        assert_eq!(result["cacheScope"], json!("private"));
        assert!(result["ttlMs"].is_u64());
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            json!("vtyctl-mcp")
        );
    }

    #[tokio::test]
    async fn modern_unsupported_version_is_32022() {
        let mut req = modern_request("tools/list", json!({}));
        req["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
        let resp = server().handle_request(req).await.expect("response");
        assert_eq!(resp["error"]["code"], json!(-32022));
        assert_eq!(resp["error"]["data"]["requested"], json!("2099-01-01"));
        assert!(
            resp["error"]["data"]["supported"]
                .as_array()
                .is_some_and(|v| v.contains(&json!("2026-07-28")))
        );
    }

    #[tokio::test]
    async fn modern_request_requires_client_capabilities() {
        let mut req = modern_request("tools/list", json!({}));
        req["params"]["_meta"]
            .as_object_mut()
            .expect("meta object")
            .remove("io.modelcontextprotocol/clientCapabilities");
        let resp = server().handle_request(req).await.expect("response");
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[tokio::test]
    async fn ping_is_legacy_only() {
        let req = json!({"jsonrpc": "2.0", "id": 3, "method": "ping"});
        let resp = server().handle_request(req).await.expect("response");
        assert_eq!(resp["result"]["resultType"], json!("complete"));

        // 2026-07-28 removed ping from the protocol.
        let resp = server()
            .handle_request(modern_request("ping", json!({})))
            .await
            .expect("response");
        assert_eq!(resp["error"]["code"], json!(-32601));
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
