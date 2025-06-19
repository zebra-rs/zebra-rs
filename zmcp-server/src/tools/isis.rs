use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{debug, error, warn};

use crate::client::ZebraClient;

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
        let level = args
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("both");

        // Validate level parameter
        if !matches!(level, "L1" | "L2" | "both") {
            warn!("Invalid level parameter: {}", level);
            return Err(anyhow::anyhow!(
                "Invalid level '{}'. Must be 'L1', 'L2', or 'both'", level
            ));
        }

        // Execute the show isis graph command
        match self.client.show_isis_command("graph", true).await {
            Ok(json_output) => {
                debug!("Received ISIS graph data: {} bytes", json_output.len());

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
                        Err(anyhow::anyhow!("Error parsing ISIS graph data: {}", e))
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
    fn filter_graph_by_level(&self, data: &Value, level: &str) -> Result<Value> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_filter_graph_by_level_both() {
        let isis_tools = IsisTools::new(ZebraClient::new("test".to_string(), 1234));
        let data = json!([
            {"level": "L1", "nodes": []},
            {"level": "L2", "nodes": []}
        ]);

        let result = isis_tools.filter_graph_by_level(&data, "both").unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_filter_graph_by_level_l1() {
        let isis_tools = IsisTools::new(ZebraClient::new("test".to_string(), 1234));
        let data = json!([
            {"level": "L1", "nodes": ["node1"]},
            {"level": "L2", "nodes": ["node2"]}
        ]);

        let result = isis_tools.filter_graph_by_level(&data, "L1").unwrap();
        let expected = json!([{"level": "L1", "nodes": ["node1"]}]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_filter_graph_by_level_l2() {
        let isis_tools = IsisTools::new(ZebraClient::new("test".to_string(), 1234));
        let data = json!([
            {"level": "L1", "nodes": ["node1"]},
            {"level": "L2", "nodes": ["node2"]}
        ]);

        let result = isis_tools.filter_graph_by_level(&data, "L2").unwrap();
        let expected = json!([{"level": "L2", "nodes": ["node2"]}]);
        assert_eq!(result, expected);
    }
}