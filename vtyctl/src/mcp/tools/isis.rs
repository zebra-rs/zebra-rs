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

/// Parse and validate the optional `algorithm` argument shared by the
/// IS-IS tools. Absent means algorithm 0 — the plain SPF topology;
/// present it must be a Flex-Algorithm number (RFC 9350: 128-255).
fn algorithm_arg(args: &HashMap<String, Value>) -> Result<Option<u8>> {
    let Some(value) = args.get("algorithm") else {
        return Ok(None);
    };
    let algo = value
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("'algorithm' must be an integer (128-255)"))?;
    if !(128..=255).contains(&algo) {
        return Err(anyhow::anyhow!(
            "Invalid algorithm {}. Flex-Algorithm numbers are 128-255",
            algo
        ));
    }
    Ok(Some(algo as u8))
}

impl IsisTools {
    pub fn new(client: ZebraClient) -> Self {
        Self { client }
    }

    /// Run an IS-IS show subcommand in JSON mode, validating that the
    /// output parses. `empty` is returned for a daemon with no data
    /// (protocol not configured yet), so callers always get valid JSON.
    async fn show_json(&self, subcommand: &str, empty: &str) -> Result<String> {
        match self.client.show_isis_command(subcommand, true).await {
            Ok(output) => {
                debug!(
                    "Received data for 'show isis {}': {} bytes",
                    subcommand,
                    output.len()
                );
                if output.trim().is_empty() {
                    warn!("'show isis {}' returned empty output", subcommand);
                    return Ok(empty.to_string());
                }
                match serde_json::from_str::<Value>(&output) {
                    Ok(parsed) => Ok(serde_json::to_string_pretty(&parsed)?),
                    Err(e) => {
                        error!("Failed to parse 'show isis {}' JSON: {}", subcommand, e);
                        // If parsing fails but we have data, it might be
                        // text format — return it rather than losing it.
                        warn!(
                            "'show isis {}' data is not JSON, returning as-is",
                            subcommand
                        );
                        Ok(output)
                    }
                }
            }
            Err(e) => {
                error!("Failed to run 'show isis {}': {}", subcommand, e);
                Err(anyhow::anyhow!("Error retrieving IS-IS data: {}", e))
            }
        }
    }

    /// Get ISIS topology graph data. Without `algorithm` this is the
    /// unpruned LSDB graph; with a Flex-Algorithm number it is that
    /// algorithm's constraint-pruned graph.
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

        let subcommand = match algorithm_arg(&args)? {
            Some(algo) => format!("flex-algo {} graph", algo),
            None => "graph".to_string(),
        };

        let output = self.show_json(&subcommand, "[]").await?;

        // Filter by level if requested (tolerate non-JSON text output).
        match serde_json::from_str::<Value>(&output) {
            Ok(parsed) => {
                let filtered = self.filter_graph_by_level(&parsed, level)?;
                Ok(serde_json::to_string_pretty(&filtered)?)
            }
            Err(_) => Ok(output),
        }
    }

    /// Get ISIS SPF results: per-destination cost, nexthops, and the
    /// full hop-by-hop paths, computed from this router's LSDB. Without
    /// `algorithm` this is the algorithm-0 SPF; with a Flex-Algorithm
    /// number it is that algorithm's constrained SPF.
    pub async fn get_isis_spf(&self, args: HashMap<String, Value>) -> Result<String> {
        debug!("Getting ISIS SPF with args: {:?}", args);
        let subcommand = match algorithm_arg(&args)? {
            Some(algo) => format!("flex-algo {} spf", algo),
            None => "spf".to_string(),
        };
        self.show_json(&subcommand, "{}").await
    }

    /// Get ISIS Flexible Algorithm state: locally configured algorithms
    /// with their constraints, and per-level peer FADs / participation.
    pub async fn get_isis_flex_algo(&self, args: HashMap<String, Value>) -> Result<String> {
        debug!("Getting ISIS flex-algo state with args: {:?}", args);
        self.show_json("flex-algo", "{}").await
    }

    /// Filter graph data by IS-IS level. Graph objects label their level
    /// as `L1`/`L2` (plain graph) or `L1 algo 128`-style (per-algorithm
    /// graph), so match on the leading level token.
    pub fn filter_graph_by_level(&self, data: &Value, level: &str) -> Result<Value> {
        if level == "both" {
            return Ok(data.clone());
        }

        let level_matches = |l: &str| l == level || l.starts_with(&format!("{} ", level));

        // If data is an array of graph objects, filter by level
        if let Value::Array(graphs) = data {
            let filtered: Vec<Value> = graphs
                .iter()
                .filter(|graph| {
                    graph
                        .get("level")
                        .and_then(|l| l.as_str())
                        .map(level_matches)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();

            Ok(Value::Array(filtered))
        } else {
            // If it's a single graph object, check if it matches the level
            if let Some(graph_level) = data.get("level").and_then(|l| l.as_str()) {
                if level_matches(graph_level) {
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

    fn tools() -> IsisTools {
        IsisTools::new(ZebraClient::new("127.0.0.1".to_string(), 2650))
    }

    fn args(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn algorithm_arg_absent_is_none() {
        assert_eq!(algorithm_arg(&args(&[])).unwrap(), None);
    }

    #[test]
    fn algorithm_arg_accepts_flex_algo_range() {
        for algo in [128u64, 200, 255] {
            assert_eq!(
                algorithm_arg(&args(&[("algorithm", json!(algo))])).unwrap(),
                Some(algo as u8)
            );
        }
    }

    #[test]
    fn algorithm_arg_rejects_out_of_range_and_non_integer() {
        for bad in [json!(0), json!(127), json!(256), json!("128"), json!(-1)] {
            assert!(
                algorithm_arg(&args(&[("algorithm", bad.clone())])).is_err(),
                "expected error for {bad}"
            );
        }
    }

    #[test]
    fn level_filter_matches_plain_and_algo_labels() {
        let data = json!([
            {"level": "L1", "nodes": []},
            {"level": "L2", "nodes": []},
            {"level": "L2 algo 128", "nodes": []},
        ]);
        let filtered = tools().filter_graph_by_level(&data, "L2").unwrap();
        let levels: Vec<&str> = filtered
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["level"].as_str().unwrap())
            .collect();
        assert_eq!(levels, vec!["L2", "L2 algo 128"]);
    }

    #[tokio::test]
    async fn graph_rejects_invalid_algorithm() {
        let err = tools()
            .get_isis_graph(args(&[("algorithm", json!(1))]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("128-255"), "{err}");
    }

    #[tokio::test]
    async fn spf_rejects_invalid_algorithm() {
        let err = tools()
            .get_isis_spf(args(&[("algorithm", json!("igp"))]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("integer"), "{err}");
    }
}
