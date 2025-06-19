use zmcp_server::client::ZebraClient;

#[tokio::test]
async fn test_show_isis_graph_only() {
    println!("=== Testing ONLY 'show isis graph' ===");

    let client = ZebraClient::new("http://localhost".to_string(), 2650);

    println!("Connecting to localhost:2650...");

    match client.test_connection().await {
        Ok(_) => {
            println!("✓ Connection successful!");

            println!("\nExecuting: 'show isis graph' with JSON=true");
            match client.show_isis_command("graph", true).await {
                Ok(output) => {
                    println!("✓ Command executed successfully!");
                    println!("Response details:");
                    println!("  - Length: {} bytes", output.len());

                    if output.is_empty() {
                        println!("  - Content: EMPTY (ISIS not configured or no topology data)");
                    } else {
                        println!(
                            "  - Content preview: {}",
                            if output.len() > 100 {
                                format!("{}...", &output[..100])
                            } else {
                                output.clone()
                            }
                        );

                        // Try parsing as JSON
                        match serde_json::from_str::<serde_json::Value>(&output) {
                            Ok(json_data) => {
                                println!("  - Format: Valid JSON ✓");
                                match json_data {
                                    serde_json::Value::Array(arr) => {
                                        println!(
                                            "  - Structure: JSON Array with {} elements",
                                            arr.len()
                                        );
                                        for (i, item) in arr.iter().enumerate().take(3) {
                                            if let Some(level) = item.get("level") {
                                                println!("    Element {}: level = {}", i, level);
                                            }
                                        }
                                    }
                                    serde_json::Value::Object(obj) => {
                                        println!(
                                            "  - Structure: JSON Object with {} keys",
                                            obj.len()
                                        );
                                        if let Some(level) = obj.get("level") {
                                            println!("    Level: {}", level);
                                        }
                                    }
                                    _ => {
                                        println!("  - Structure: JSON Primitive: {}", json_data);
                                    }
                                }
                            }
                            Err(parse_error) => {
                                println!("  - Format: Not JSON ({})", parse_error);
                                println!("  - Raw content: '{}'", output);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("✗ Command failed: {}", e);
                    println!("  This could indicate:");
                    println!("  - Network/connection issues");
                    println!("  - gRPC communication problems");
                    println!("  - zebra-rs internal errors");
                }
            }
        }
        Err(e) => {
            println!("✗ Connection failed: {}", e);
            println!("  Make sure zebra-rs is running at localhost:2650");
        }
    }
}
