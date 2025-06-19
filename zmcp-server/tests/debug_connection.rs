use zmcp_server::client::ZebraClient;

#[tokio::test]
async fn debug_real_connection() {
    println!("=== Debug Connection Test ===");

    let client = ZebraClient::new("http://localhost".to_string(), 2650);

    println!("Testing connection to localhost:2650...");

    match client.test_connection().await {
        Ok(_) => {
            println!("✓ Connection successful!");

            // Try to get version info
            println!("\nTesting 'show version' command...");
            match client.show_command("show version", false).await {
                Ok(version_output) => {
                    println!("✓ Version command successful!");
                    println!("Response length: {} bytes", version_output.len());
                    if !version_output.is_empty() {
                        println!("Response content:");
                        for (i, line) in version_output.lines().take(5).enumerate() {
                            println!("  {}: {}", i + 1, line);
                        }
                        if version_output.lines().count() > 5 {
                            println!("  ... ({} total lines)", version_output.lines().count());
                        }
                    } else {
                        println!("Response is empty");
                    }
                }
                Err(e) => {
                    println!("✗ Version command failed: {}", e);
                }
            }

            // Try ISIS graph command with detailed logging
            println!("\nTesting 'show isis graph' command...");
            match client.show_isis_command("graph", true).await {
                Ok(isis_output) => {
                    println!("✓ ISIS graph command successful!");
                    println!("Response length: {} bytes", isis_output.len());

                    if isis_output.is_empty() {
                        println!("Response is empty (ISIS likely not configured)");
                    } else {
                        println!("Response content preview:");
                        let preview = if isis_output.len() > 200 {
                            format!("{}...", &isis_output[..200])
                        } else {
                            isis_output.clone()
                        };
                        println!("  {}", preview);

                        // Try to parse as JSON
                        match serde_json::from_str::<serde_json::Value>(&isis_output) {
                            Ok(json_data) => {
                                println!("✓ Response is valid JSON");
                                if json_data.is_array() {
                                    println!(
                                        "  JSON array with {} elements",
                                        json_data.as_array().unwrap().len()
                                    );
                                } else if json_data.is_object() {
                                    println!(
                                        "  JSON object with {} keys",
                                        json_data.as_object().unwrap().len()
                                    );
                                } else {
                                    println!("  JSON primitive: {}", json_data);
                                }
                            }
                            Err(e) => {
                                println!("  Response is not JSON: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("✗ ISIS graph command failed: {}", e);
                }
            }

            // Test BGP commands (which should have data based on config)
            let bgp_commands = ["summary", "neighbor"];
            for cmd in bgp_commands {
                println!("\nTesting 'show bgp {}' command...", cmd);
                let bgp_cmd = format!("show bgp {}", cmd);
                match client.show_command(&bgp_cmd, true).await {
                    Ok(output) => {
                        println!("✓ BGP command successful! ({} bytes)", output.len());
                        if !output.is_empty() {
                            if output.len() < 200 {
                                println!("  Content: {}", output.replace('\n', " "));
                            } else {
                                println!(
                                    "  Content preview: {}...",
                                    output[..100].replace('\n', " ")
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("✗ BGP command failed: {}", e);
                    }
                }
            }

            // Test basic commands that should always work
            let basic_commands = ["show interface", "show route", "show running-config"];
            for cmd in basic_commands {
                println!("\nTesting '{}' command...", cmd);
                match client.show_command(cmd, false).await {
                    Ok(output) => {
                        println!("✓ Command successful! ({} bytes)", output.len());
                        if !output.is_empty() {
                            if output.len() < 200 {
                                println!("  Content: {}", output.replace('\n', " "));
                            } else {
                                println!(
                                    "  Content preview: {}...",
                                    output[..100].replace('\n', " ")
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("✗ Command failed: {}", e);
                    }
                }
            }

            // Test other ISIS commands to confirm they're empty
            let isis_commands = ["neighbors", "database", "route", "interface"];
            for cmd in isis_commands {
                println!("\nTesting 'show isis {}' command...", cmd);
                match client.show_isis_command(cmd, true).await {
                    Ok(output) => {
                        println!("✓ Command successful! ({} bytes)", output.len());
                        if !output.is_empty() && output.len() < 100 {
                            println!("  Content: {}", output.replace('\n', " "));
                        }
                    }
                    Err(e) => {
                        println!("✗ Command failed: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Connection failed: {}", e);
            println!("Make sure zebra-rs is running with gRPC enabled on port 2650");
        }
    }
}
