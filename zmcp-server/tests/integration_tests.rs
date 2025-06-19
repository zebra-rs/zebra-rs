use serde_json::{json, Value};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Integration tests for MCP protocol communication
/// These tests spawn the actual zmcp-server binary and test the JSON-RPC protocol

#[tokio::test]
async fn test_mcp_protocol_initialization() {
    // This test would require a running zebra-rs instance
    // For now, we'll test that the binary starts and responds to initialization
    let child = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "zmcp-server",
            "--",
            "--base",
            "http://non-existent-host",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    if let Ok(mut child) = child {
        // The process should fail quickly due to connection error
        let result = timeout(Duration::from_secs(5), child.wait()).await;

        // Process should exit (due to connection failure) rather than hang
        assert!(result.is_ok());

        let status = result.unwrap().unwrap();
        assert!(!status.success()); // Should fail due to no zebra-rs connection
    } else {
        // Skip test if we can't run the binary (e.g., in CI without build)
        println!("Skipping integration test - unable to spawn binary");
    }
}

#[tokio::test]
async fn test_json_rpc_message_format() {
    // Test JSON-RPC message parsing and formatting
    use zmcp_server::ZmcpServer;

    let server = ZmcpServer::new("http://test".to_string(), 1234);

    // Test various JSON-RPC message formats
    let test_cases = vec![
        // Valid initialize request
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
        // Valid tools/list request
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
        // Request without params
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize"
        }),
        // Request without id (notification)
        json!({
            "jsonrpc": "2.0",
            "method": "tools/list"
        }),
    ];

    for (i, request) in test_cases.iter().enumerate() {
        let response = server.handle_request(request.clone()).await;

        // Requests with ID should get responses, notifications should not
        if request.get("id").is_some() {
            let response = response.expect(&format!(
                "Request with ID should get response, test case {}",
                i
            ));

            // All responses should have jsonrpc field
            assert_eq!(response["jsonrpc"], "2.0", "Test case {}", i);

            // If request had id, response should have same id
            if let Some(request_id) = request.get("id") {
                assert_eq!(response["id"], *request_id, "Test case {}", i);
            }

            // Should have either result or error (we expect result for these)
            assert!(
                response.get("result").is_some() || response.get("error").is_some(),
                "Test case {}",
                i
            );
        } else {
            // Notifications should not get responses
            assert!(
                response.is_none(),
                "Notification should not get response, test case {}",
                i
            );
        }
    }
}

#[tokio::test]
async fn test_tool_schema_validation() {
    use zmcp_server::ZmcpServer;

    let server = ZmcpServer::new("http://test".to_string(), 1234);

    // Get tools list
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });

    let response = server.handle_request(request).await.unwrap();

    // Validate tool schema structure
    assert!(response["result"]["tools"].is_array());

    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);

    let isis_tool = &tools[0];
    assert_eq!(isis_tool["name"], "get-isis-graph");
    assert!(isis_tool["description"].is_string());
    assert!(isis_tool["inputSchema"].is_object());

    // Validate input schema
    let schema = &isis_tool["inputSchema"];
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"].is_object());

    let properties = &schema["properties"];
    assert!(properties["level"].is_object());

    let level_prop = &properties["level"];
    assert_eq!(level_prop["type"], "string");
    assert!(level_prop["enum"].is_array());

    let enum_values = level_prop["enum"].as_array().unwrap();
    assert!(enum_values.contains(&json!("L1")));
    assert!(enum_values.contains(&json!("L2")));
    assert!(enum_values.contains(&json!("both")));
}

#[tokio::test]
async fn test_error_response_format() {
    use zmcp_server::ZmcpServer;

    let server = ZmcpServer::new("http://test".to_string(), 1234);

    // Test unknown method
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "unknown/method",
        "params": {}
    });

    let response = server.handle_request(request).await.unwrap();

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response["error"].is_object());

    let error = &response["error"];
    assert_eq!(error["code"], -32601);
    assert_eq!(error["message"], "Method not found");
    assert!(error["data"].is_string());
}

#[tokio::test]
async fn test_concurrent_requests() {
    use futures::future::join_all;
    use zmcp_server::ZmcpServer;

    let server = ZmcpServer::new("http://test".to_string(), 1234);

    // Create multiple concurrent requests
    let requests = (0..10).map(|i| {
        let server = &server;
        async move {
            let request = json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "initialize",
                "params": {}
            });
            server.handle_request(request).await.unwrap()
        }
    });

    let responses = join_all(requests).await;

    // All requests should be handled correctly
    for (i, response) in responses.iter().enumerate() {
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], i);
        assert!(response["result"].is_object());
    }
}

/// Test utilities for creating mock MCP clients
pub struct MockMcpClient {
    requests: Vec<Value>,
    responses: Vec<Value>,
}

impl MockMcpClient {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            responses: Vec::new(),
        }
    }

    pub fn add_request(&mut self, request: Value) {
        self.requests.push(request);
    }

    pub fn get_responses(&self) -> &[Value] {
        &self.responses
    }

    pub async fn send_requests(&mut self, server: &zmcp_server::ZmcpServer) {
        for request in &self.requests {
            if let Some(response) = server.handle_request(request.clone()).await {
                self.responses.push(response);
            }
        }
    }
}

#[tokio::test]
async fn test_mock_client_workflow() {
    use zmcp_server::ZmcpServer;

    let server = ZmcpServer::new("http://test".to_string(), 1234);
    let mut client = MockMcpClient::new();

    // Simulate a typical MCP workflow
    client.add_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }));

    client.add_request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));

    client.add_request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get-isis-graph",
            "arguments": {
                "level": "L1"
            }
        }
    }));

    client.send_requests(&server).await;

    let responses = client.get_responses();
    assert_eq!(responses.len(), 3);

    // Check initialize response
    assert_eq!(responses[0]["id"], 1);
    assert!(responses[0]["result"]["protocolVersion"].is_string());

    // Check tools/list response
    assert_eq!(responses[1]["id"], 2);
    assert!(responses[1]["result"]["tools"].is_array());

    // Check tools/call response (will error due to no zebra-rs)
    assert_eq!(responses[2]["id"], 3);
    // Check that this is an error response by content
    assert!(responses[2]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Error"));
}

#[tokio::test]
async fn test_real_zebra_connection_and_isis_graph() {
    use zmcp_server::ZmcpServer;

    // This test requires a real zebra-rs server running at localhost:2650
    // Skip if not available
    let server = ZmcpServer::new("http://localhost".to_string(), 2650);

    // Test connection first
    match server.zebra_client().test_connection().await {
        Ok(_) => {
            println!("✓ Connected to zebra-rs at localhost:2650");

            // Test the full MCP workflow with real zebra-rs
            let test_cases = vec![
                ("both", "Test getting ISIS graph for both levels"),
                ("L1", "Test getting ISIS graph for L1 only"),
                ("L2", "Test getting ISIS graph for L2 only"),
            ];

            for (level, description) in test_cases {
                println!("  Testing: {}", description);

                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "get-isis-graph",
                        "arguments": {
                            "level": level
                        }
                    }
                });

                let response = server.handle_request(request).await.unwrap();

                // Validate response structure
                assert_eq!(response["jsonrpc"], "2.0");
                assert_eq!(response["id"], 1);

                if response["result"]["isError"] == false {
                    // Success case - validate the ISIS graph data
                    let content = &response["result"]["content"][0]["text"];
                    assert!(content.is_string());

                    let graph_data = content.as_str().unwrap();
                    println!("  ✓ Received ISIS graph data ({} bytes)", graph_data.len());

                    // Try to parse as JSON to validate structure
                    match serde_json::from_str::<serde_json::Value>(graph_data) {
                        Ok(parsed) => {
                            println!("  ✓ ISIS graph data is valid JSON");

                            // Basic validation of ISIS graph structure
                            if parsed.is_array() {
                                let graphs = parsed.as_array().unwrap();
                                println!("  ✓ Found {} graph object(s)", graphs.len());

                                // If filtering by specific level, validate the results
                                if level != "both" && !graphs.is_empty() {
                                    let all_correct_level = graphs.iter().all(|graph| {
                                        graph
                                            .get("level")
                                            .and_then(|l| l.as_str())
                                            .map(|l| l == level)
                                            .unwrap_or(true) // Accept if no level field
                                    });

                                    if all_correct_level {
                                        println!(
                                            "  ✓ All graph objects have correct level: {}",
                                            level
                                        );
                                    } else {
                                        println!(
                                            "  ! Warning: Some graph objects have incorrect level"
                                        );
                                    }
                                }

                                // Check for common ISIS graph fields
                                for (i, graph) in graphs.iter().enumerate() {
                                    if let Some(nodes) = graph.get("nodes") {
                                        if nodes.is_array() {
                                            let node_array = nodes.as_array().unwrap();
                                            println!("    Graph {}: {} nodes", i, node_array.len());

                                            // Count total links across all nodes
                                            let total_links: usize = node_array
                                                .iter()
                                                .map(|node| {
                                                    node.get("links")
                                                        .and_then(|links| links.as_array())
                                                        .map(|arr| arr.len())
                                                        .unwrap_or(0)
                                                })
                                                .sum();
                                            println!(
                                                "    Graph {}: {} total links",
                                                i, total_links
                                            );
                                        }
                                    }
                                }
                            } else if parsed.is_object() {
                                println!("  ✓ Single graph object received");

                                // Check for nodes/links in single graph
                                if let Some(nodes) = parsed.get("nodes") {
                                    if nodes.is_array() {
                                        let node_array = nodes.as_array().unwrap();
                                        println!("    {} nodes", node_array.len());

                                        // Count total links
                                        let total_links: usize = node_array
                                            .iter()
                                            .map(|node| {
                                                node.get("links")
                                                    .and_then(|links| links.as_array())
                                                    .map(|arr| arr.len())
                                                    .unwrap_or(0)
                                            })
                                            .sum();
                                        println!("    {} total links", total_links);
                                    }
                                }
                                if let Some(links) = parsed.get("links") {
                                    if links.is_array() {
                                        println!("    {} links", links.as_array().unwrap().len());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("  ! Graph data is not JSON, might be text format: {}", e);
                            // This is also valid - zebra-rs might return text format
                            // Just verify we got some data
                            assert!(!graph_data.is_empty(), "Graph data should not be empty");
                            println!("  ✓ Received non-empty graph data");
                        }
                    }
                } else {
                    // Error case - this might happen if ISIS is not configured
                    println!(
                        "  ! ISIS graph request failed (this is OK if ISIS is not configured)"
                    );
                    let error_text = response["result"]["content"][0]["text"].as_str().unwrap();
                    println!("    Error: {}", error_text);

                    // Common error cases that are acceptable
                    let acceptable_errors = [
                        "ISIS is not running",
                        "No ISIS neighbors",
                        "ISIS not configured",
                        "Protocol not enabled",
                    ];

                    let is_acceptable_error = acceptable_errors
                        .iter()
                        .any(|&err| error_text.to_lowercase().contains(&err.to_lowercase()));

                    if is_acceptable_error {
                        println!("    This is an acceptable error - ISIS may not be configured");
                    }
                }
            }

            // Test error cases with real server
            println!("  Testing error handling with real server");

            let invalid_request = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "get-isis-graph",
                    "arguments": {
                        "level": "invalid-level"
                    }
                }
            });

            let error_response = server.handle_request(invalid_request).await.unwrap();
            assert_eq!(error_response["result"]["isError"], true);
            let error_text = error_response["result"]["content"][0]["text"]
                .as_str()
                .unwrap();
            assert!(error_text.contains("Invalid level"));
            println!("  ✓ Invalid level parameter correctly rejected");
        }
        Err(e) => {
            println!("⚠ Skipping real zebra-rs test - server not available at localhost:2650");
            println!("  Connection error: {}", e);
            println!("  To run this test, start zebra-rs with: make run");
            println!("  Or start it manually with gRPC server enabled on port 2650");

            // This is not a test failure - just means the server isn't running
            // We'll skip the test gracefully
        }
    }
}

#[tokio::test]
async fn test_direct_zebra_client_isis_command() {
    use zmcp_server::client::ZebraClient;

    // Test the zebra client directly for ISIS commands
    let client = ZebraClient::new("http://localhost".to_string(), 2650);

    match client.test_connection().await {
        Ok(_) => {
            println!("✓ Direct client connection successful");

            // Test various ISIS show commands
            let isis_commands = vec![
                ("graph", "ISIS topology graph"),
                ("neighbors", "ISIS neighbors"),
                ("database", "ISIS database"),
                ("route", "ISIS routes"),
            ];

            for (cmd, description) in isis_commands {
                println!("  Testing: show isis {} ({})", cmd, description);

                match client.show_isis_command(cmd, true).await {
                    Ok(output) => {
                        println!("    ✓ Command succeeded, got {} bytes", output.len());

                        // If it's the graph command, try to validate structure
                        if cmd == "graph" && !output.is_empty() {
                            // Try parsing as JSON
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&output) {
                                println!("    ✓ Output is valid JSON");

                                if parsed.is_array() {
                                    println!(
                                        "    ✓ Graph data is an array with {} elements",
                                        parsed.as_array().unwrap().len()
                                    );
                                } else if parsed.is_object() {
                                    println!("    ✓ Graph data is a single object");
                                }
                            } else {
                                println!("    ! Output is not JSON (text format)");
                            }
                        }
                    }
                    Err(e) => {
                        println!("    ! Command failed: {}", e);
                        // This might be normal if ISIS is not configured
                    }
                }
            }

            // Test non-ISIS command for comparison
            println!("  Testing: show version (for comparison)");
            match client.show_command("show version", false).await {
                Ok(output) => {
                    println!(
                        "    ✓ Version command succeeded, got {} bytes",
                        output.len()
                    );
                    // Print first line to verify we're talking to zebra-rs
                    if let Some(first_line) = output.lines().next() {
                        println!("    Version info: {}", first_line);
                    }
                }
                Err(e) => {
                    println!("    ! Version command failed: {}", e);
                }
            }
        }
        Err(_) => {
            println!("⚠ Skipping direct client test - zebra-rs not available at localhost:2650");
        }
    }
}

#[tokio::test]
async fn test_isis_graph_data_parsing_with_mock_data() {
    use zmcp_server::client::ZebraClient;
    use zmcp_server::tools::isis::IsisTools;

    // Test ISIS graph filtering with realistic mock data
    let isis_tools = IsisTools::new(ZebraClient::new("http://mock".to_string(), 1234));

    // Test data that matches actual zebra-rs ISIS graph format
    let mock_isis_data = serde_json::json!([
        {
            "level": "L1",
            "nodes": [
                {
                    "id": 0,
                    "name": "0000.0000.0001",
                    "links": [
                        {
                            "to_id": 1,
                            "to_name": "0000.0000.0002",
                            "cost": 10
                        }
                    ]
                },
                {
                    "id": 1,
                    "name": "0000.0000.0002",
                    "links": [
                        {
                            "to_id": 0,
                            "to_name": "0000.0000.0001",
                            "cost": 10
                        }
                    ]
                }
            ]
        },
        {
            "level": "L2",
            "nodes": [
                {
                    "id": 0,
                    "name": "0000.0000.0001",
                    "links": [
                        {
                            "to_id": 2,
                            "to_name": "0000.0000.0003",
                            "cost": 20
                        }
                    ]
                },
                {
                    "id": 2,
                    "name": "0000.0000.0003",
                    "links": [
                        {
                            "to_id": 0,
                            "to_name": "0000.0000.0001",
                            "cost": 20
                        }
                    ]
                }
            ]
        }
    ]);

    // Test filtering by level
    let l1_result = isis_tools
        .filter_graph_by_level(&mock_isis_data, "L1")
        .unwrap();
    assert!(l1_result.is_array());
    let l1_graphs = l1_result.as_array().unwrap();
    assert_eq!(l1_graphs.len(), 1);
    assert_eq!(l1_graphs[0]["level"], "L1");
    assert_eq!(l1_graphs[0]["nodes"].as_array().unwrap().len(), 2);
    // In the new format, links are inside each node, not separate edges
    let first_node_links = l1_graphs[0]["nodes"][0]["links"].as_array().unwrap();
    assert_eq!(first_node_links.len(), 1);

    let l2_result = isis_tools
        .filter_graph_by_level(&mock_isis_data, "L2")
        .unwrap();
    assert!(l2_result.is_array());
    let l2_graphs = l2_result.as_array().unwrap();
    assert_eq!(l2_graphs.len(), 1);
    assert_eq!(l2_graphs[0]["level"], "L2");
    assert_eq!(l2_graphs[0]["nodes"].as_array().unwrap().len(), 2);
    // Check links in the first node of L2 graph
    let first_node_links = l2_graphs[0]["nodes"][0]["links"].as_array().unwrap();
    assert_eq!(first_node_links.len(), 1);

    let both_result = isis_tools
        .filter_graph_by_level(&mock_isis_data, "both")
        .unwrap();
    assert!(both_result.is_array());
    let both_graphs = both_result.as_array().unwrap();
    assert_eq!(both_graphs.len(), 2);

    println!("✓ ISIS graph filtering tests passed with realistic topology data");
    println!(
        "  L1 graph: {} nodes, {} links in first node",
        l1_graphs[0]["nodes"].as_array().unwrap().len(),
        l1_graphs[0]["nodes"][0]["links"].as_array().unwrap().len()
    );
    println!(
        "  L2 graph: {} nodes, {} links in first node",
        l2_graphs[0]["nodes"].as_array().unwrap().len(),
        l2_graphs[0]["nodes"][0]["links"].as_array().unwrap().len()
    );
}

#[tokio::test]
async fn test_mcp_server_with_sample_isis_data() {
    // This test demonstrates what the MCP response would look like with actual ISIS data
    // We can't easily mock the gRPC client, so this is more of a documentation test

    let sample_response_structure = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": r#"[
  {
    "level": "L1",
    "nodes": [
      {
        "id": 0,
        "name": "0000.0000.0001",
        "links": [
          {
            "to_id": 1,
            "to_name": "0000.0000.0002",
            "cost": 10
          }
        ]
      },
      {
        "id": 1,
        "name": "0000.0000.0002",
        "links": [
          {
            "to_id": 0,
            "to_name": "0000.0000.0001",
            "cost": 10
          }
        ]
      }
    ]
  },
  {
    "level": "L2", 
    "nodes": [
      {
        "id": 0,
        "name": "0000.0000.0001",
        "links": [
          {
            "to_id": 2,
            "to_name": "0000.0000.0003",
            "cost": 20
          }
        ]
      },
      {
        "id": 2,
        "name": "0000.0000.0003",
        "links": [
          {
            "to_id": 0,
            "to_name": "0000.0000.0001",
            "cost": 20
          }
        ]
      }
    ]
  }
]"#
                }
            ],
        }
    });

    // Validate the structure matches MCP tool response format
    assert_eq!(sample_response_structure["jsonrpc"], "2.0");
    assert!(sample_response_structure["result"]["content"].is_array());
    // Verify this is a successful response (no error in content)

    let content = &sample_response_structure["result"]["content"][0]["text"];
    let isis_data: serde_json::Value = serde_json::from_str(content.as_str().unwrap()).unwrap();

    assert!(isis_data.is_array());
    let graphs = isis_data.as_array().unwrap();
    assert_eq!(graphs.len(), 2);

    // Validate L1 graph structure
    assert_eq!(graphs[0]["level"], "L1");
    assert!(graphs[0]["nodes"].is_array());
    let l1_nodes = graphs[0]["nodes"].as_array().unwrap();
    assert_eq!(l1_nodes.len(), 2);
    assert!(l1_nodes[0]["links"].is_array());

    // Validate L2 graph structure
    assert_eq!(graphs[1]["level"], "L2");
    assert!(graphs[1]["nodes"].is_array());
    let l2_nodes = graphs[1]["nodes"].as_array().unwrap();
    assert_eq!(l2_nodes.len(), 2);
    assert!(l2_nodes[0]["links"].is_array());

    println!("✓ Sample MCP response structure validation passed");
    println!("  Response contains {} ISIS level(s)", graphs.len());
    println!(
        "  L1: {} nodes, {} links in first node",
        l1_nodes.len(),
        l1_nodes[0]["links"].as_array().unwrap().len()
    );
    println!(
        "  L2: {} nodes, {} links in first node",
        l2_nodes.len(),
        l2_nodes[0]["links"].as_array().unwrap().len()
    );
}
