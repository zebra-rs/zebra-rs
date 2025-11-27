use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::{debug, error, warn};

use crate::mcp::client::ZebraClient;

/// ISIS-specific tools for network topology analysis
#[derive(Clone)]
pub struct IsisTools {
    client: ZebraClient,
}

impl IsisTools {
    pub fn new(client: ZebraClient) -> Self {
        Self { client }
    }

    /// Get ISIS topology graph data
    pub async fn get_isis_graph(&self, args: HashMap<String, Value>) -> Result<String> {
        debug!("Getting ISIS graph with args: {:?}", args);

        // Parse the level parameter
        let level = args.get("level").and_then(|v| v.as_str()).unwrap_or("both");

        // Validate level parameter
        if !matches!(level, "L1" | "L2" | "both") {
            warn!("Invalid level parameter: {}", level);
            return Err(anyhow::anyhow!(
                "Invalid level '{}'. Must be 'L1', 'L2', or 'both'",
                level
            ));
        }

        // Execute the show isis graph command
        match self.client.show_isis_command("graph", true).await {
            Ok(json_output) => {
                debug!("Received ISIS graph data: {} bytes", json_output.len());

                // Handle empty response (ISIS not configured or no data)
                if json_output.trim().is_empty() {
                    warn!("ISIS graph command returned empty output");
                    return Ok("[]".to_string()); // Return empty JSON array
                }

                // Parse the JSON to validate it
                match serde_json::from_str::<Value>(&json_output) {
                    Ok(parsed_json) => {
                        // Filter by level if requested
                        let filtered_data = self.filter_graph_by_level(&parsed_json, level)?;

                        // Return the graph data as pretty-printed JSON
                        Ok(serde_json::to_string_pretty(&filtered_data)?)
                    }
                    Err(e) => {
                        error!("Failed to parse ISIS graph JSON: {}", e);
                        // If parsing fails but we have data, it might be text format
                        if !json_output.trim().is_empty() {
                            warn!("ISIS graph data is not JSON format, returning as-is");
                            Ok(json_output)
                        } else {
                            Err(anyhow::anyhow!("Error parsing ISIS graph data: {}", e))
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to get ISIS graph: {}", e);
                Err(anyhow::anyhow!("Error retrieving ISIS graph: {}", e))
            }
        }
    }

    /// Filter graph data by IS-IS level
    pub fn filter_graph_by_level(&self, data: &Value, level: &str) -> Result<Value> {
        if level == "both" {
            return Ok(data.clone());
        }

        // If data is an array of graph objects, filter by level
        if let Value::Array(graphs) = data {
            let filtered: Vec<Value> = graphs
                .iter()
                .filter(|graph| {
                    graph
                        .get("level")
                        .and_then(|l| l.as_str())
                        .map(|l| l == level)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();

            Ok(Value::Array(filtered))
        } else {
            // If it's a single graph object, check if it matches the level
            if let Some(graph_level) = data.get("level").and_then(|l| l.as_str()) {
                if graph_level == level {
                    Ok(data.clone())
                } else {
                    Ok(json!([]))
                }
            } else {
                // If no level information, return as-is
                Ok(data.clone())
            }
        }
    }
}
