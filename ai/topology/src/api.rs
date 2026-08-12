//! The three JSON APIs behind the viewer, assembled from MCP tool calls
//! against the selected source router:
//!
//! - `/api/routers`    — the ontology (no MCP).
//! - `/api/algorithms` — `get-isis-flex-algo` → algorithm choices.
//! - `/api/topology`   — `get-isis-graph` + `get-isis-spf` → nodes,
//!   connectivity edges, and hop-by-hop paths from the source router.

use std::collections::BTreeSet;

use anyhow::Result;
use serde_json::{Value, json};

use crate::mcp::McpLauncher;
use crate::ontology::Router;

pub struct App {
    pub routers: Vec<Router>,
    pub launcher: McpLauncher,
}

impl App {
    pub fn router(&self, name: &str) -> Option<&Router> {
        self.routers.iter().find(|r| r.name == name)
    }

    pub fn api_routers(&self) -> Value {
        json!({ "routers": self.routers })
    }

    /// Algorithm choices for the source router: algorithm 0 always, plus
    /// every locally configured Flex-Algorithm with a human label built
    /// from its constraints.
    pub async fn api_algorithms(&self, source: &str) -> Result<Value> {
        let flex = self
            .launcher
            .call_tool(source, "get-isis-flex-algo", json!({}))
            .await?;
        Ok(json!({ "algorithms": algorithm_choices(&flex) }))
    }

    /// The graph and SPF view from `source`, optionally constrained to
    /// one Flex-Algorithm and filtered to one destination.
    pub async fn api_topology(
        &self,
        source: &str,
        algorithm: u8,
        destination: Option<&str>,
    ) -> Result<Value> {
        let mut graph_args = json!({ "level": "both" });
        let mut spf_args = json!({});
        if algorithm != 0 {
            graph_args["algorithm"] = json!(algorithm);
            spf_args["algorithm"] = json!(algorithm);
        }

        let (graph, spf) = tokio::try_join!(
            self.launcher
                .call_tool(source, "get-isis-graph", graph_args),
            self.launcher.call_tool(source, "get-isis-spf", spf_args),
        )?;

        let active = graph_node_names(&graph);
        let edges = graph_edges(&graph);
        let paths = spf_paths(&spf, source, destination);

        // Every ontology router, marked active when the graph knows it —
        // plus any graph node the ontology does not know (no coordinates,
        // so the frontend lists it without plotting it).
        let mut nodes: Vec<Value> = Vec::new();
        for r in &self.routers {
            let mut n = serde_json::to_value(r)?;
            n["active"] = json!(active.contains(&r.name));
            nodes.push(n);
        }
        for name in &active {
            if self.router(name).is_none() {
                nodes.push(json!({
                    "name": name,
                    "fullName": name,
                    "region": "unknown",
                    "active": true,
                }));
            }
        }

        Ok(json!({
            "source": source,
            "algorithm": algorithm,
            "nodes": nodes,
            "edges": edges,
            "paths": paths,
        }))
    }
}

/// Flatten `get-isis-flex-algo` output into dropdown choices. Algorithm 0
/// is always present — it is IS-IS's unconstrained SPF, not a FAD.
fn algorithm_choices(flex: &Value) -> Vec<Value> {
    let mut choices = vec![json!({
        "algo": 0,
        "label": "0 — shortest path (unconstrained SPF)",
    })];
    let Some(locals) = flex.get("local_algorithms").and_then(Value::as_array) else {
        return choices;
    };
    for entry in locals {
        let Some(algo) = entry.get("algorithm").and_then(Value::as_u64) else {
            continue;
        };
        let mut constraints = Vec::new();
        for key in ["exclude_any", "include_any", "include_all"] {
            if let Some(list) = entry.get(key).and_then(Value::as_array)
                && !list.is_empty()
            {
                let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
                constraints.push(format!("{}: {}", key.replace('_', "-"), names.join(", ")));
            }
        }
        let label = if constraints.is_empty() {
            format!("{} — flex-algo", algo)
        } else {
            format!("{} — {}", algo, constraints.join("; "))
        };
        choices.push(json!({ "algo": algo, "label": label }));
    }
    choices
}

/// All node names present in a `get-isis-graph` result (any level).
fn graph_node_names(graph: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for level in graph.as_array().into_iter().flatten() {
        for node in level
            .get("nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(name) = node.get("name").and_then(Value::as_str) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

/// Undirected connectivity edges from a `get-isis-graph` result: each
/// node's outgoing links, deduplicated so `a->b` and `b->a` (and the
/// same pair on another level) become one edge.
fn graph_edges(graph: &Value) -> Vec<Value> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut edges = Vec::new();
    for level in graph.as_array().into_iter().flatten() {
        for node in level
            .get("nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(from) = node.get("name").and_then(Value::as_str) else {
                continue;
            };
            for link in node
                .get("olinks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(to) = link.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if from == to {
                    continue;
                }
                let key = if from < to {
                    (from.to_string(), to.to_string())
                } else {
                    (to.to_string(), from.to_string())
                };
                if !seen.insert(key) {
                    continue;
                }
                edges.push(json!({
                    "source": from,
                    "target": to,
                    "cost": link.get("cost").and_then(Value::as_u64).unwrap_or(0),
                }));
            }
        }
    }
    edges
}

/// Hop-by-hop paths from a `get-isis-spf` result. The daemon's path
/// vertex lists start at the first hop, so the source is prepended to
/// make each path a complete node walk. Paths are deduplicated across
/// topologies (e.g. MT0 and MT2 computing the identical path).
fn spf_paths(spf: &Value, source: &str, destination: Option<&str>) -> Vec<Value> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut paths = Vec::new();
    let Some(topologies) = spf.get("topologies").and_then(Value::as_object) else {
        return paths;
    };
    for topology in topologies.values() {
        let destinations = topology.get("destinations").and_then(Value::as_array);
        for dest in destinations.into_iter().flatten() {
            let Some(dest_name) = dest.get("name").and_then(Value::as_str) else {
                continue;
            };
            if dest_name == source {
                continue;
            }
            if let Some(filter) = destination
                && dest_name != filter
            {
                continue;
            }
            let cost = dest.get("cost").and_then(Value::as_u64).unwrap_or(0);
            for path in dest
                .get("paths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let mut hops = vec![source.to_string()];
                for vertex in path.as_array().into_iter().flatten() {
                    if let Some(name) = vertex.get("name").and_then(Value::as_str) {
                        hops.push(name.to_string());
                    }
                }
                if hops.len() < 2 {
                    continue;
                }
                let key = hops.join(">");
                if !seen.insert(key) {
                    continue;
                }
                // The outgoing interface for this path is the one toward
                // its first hop.
                let interface = dest
                    .get("nexthops")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|nh| nh.get("name").and_then(Value::as_str) == Some(&hops[1]))
                    .and_then(|nh| nh.get("interface").and_then(Value::as_str))
                    .unwrap_or("");
                paths.push(json!({
                    "index": paths.len(),
                    "destination": dest_name,
                    "cost": cost,
                    "hops": hops,
                    "interface": interface,
                }));
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-level slice of `get-isis-graph` output shaped like the
    /// daemon's `GraphJson` (see zebra-rs/src/isis/show.rs).
    fn graph_fixture() -> Value {
        json!([
            {
                "level": "L2",
                "nodes": [
                    {
                        "id": 0,
                        "name": "se",
                        "sys_id": "0000.0000.0001",
                        "olinks": [
                            {"id": 1, "name": "sj", "cost": 10},
                            {"id": 2, "name": "sg", "cost": 10},
                        ],
                        "ilinks": [
                            {"id": 1, "name": "sj", "cost": 10},
                        ],
                    },
                    {
                        "id": 1,
                        "name": "sj",
                        "sys_id": "0000.0000.0002",
                        "olinks": [
                            {"id": 0, "name": "se", "cost": 10},
                        ],
                        "ilinks": [],
                    },
                ],
            }
        ])
    }

    /// A slice of `get-isis-spf` output shaped like the daemon's
    /// `SpfResultJson`, from source `tk`.
    fn spf_fixture() -> Value {
        json!({
            "ti_lfa_enabled": false,
            "sr_mpls_enabled": true,
            "sr_srv6_enabled": false,
            "detail": false,
            "topologies": {
                "L2 (algorithm 128)": {
                    "destinations": [
                        {
                            "vertex_id": 0,
                            "name": "tk",
                            "cost": 0,
                            "nexthops": [],
                            "paths": [],
                        },
                        {
                            "vertex_id": 1,
                            "name": "se",
                            "cost": 60,
                            "nexthops": [
                                {"vertex_id": 9, "name": "sg", "interface": "tk-sg"},
                            ],
                            "paths": [
                                [
                                    {"vertex_id": 9, "name": "sg"},
                                    {"vertex_id": 8, "name": "fr"},
                                    {"vertex_id": 7, "name": "ln"},
                                    {"vertex_id": 3, "name": "ch"},
                                    {"vertex_id": 1, "name": "se"},
                                ],
                            ],
                        },
                        {
                            "vertex_id": 4,
                            "name": "da",
                            "cost": 60,
                            "nexthops": [
                                {"vertex_id": 9, "name": "sg", "interface": "tk-sg"},
                            ],
                            "paths": [
                                [
                                    {"vertex_id": 9, "name": "sg"},
                                    {"vertex_id": 4, "name": "da"},
                                ],
                                [
                                    {"vertex_id": 9, "name": "sg"},
                                    {"vertex_id": 4, "name": "da"},
                                ],
                            ],
                        },
                    ],
                },
            },
        })
    }

    #[test]
    fn node_names_cover_all_levels() {
        let names = graph_node_names(&graph_fixture());
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            vec!["se".to_string(), "sj".to_string()]
        );
    }

    #[test]
    fn edges_are_undirected_and_deduplicated() {
        let edges = graph_edges(&graph_fixture());
        // se->sj and sj->se collapse; se->sg survives even though sg has
        // no node entry of its own in this slice.
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0]["source"], "se");
        assert_eq!(edges[0]["cost"], 10);
        let pairs: Vec<(String, String)> = edges
            .iter()
            .map(|e| {
                (
                    e["source"].as_str().unwrap().to_string(),
                    e["target"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert!(pairs.contains(&("se".to_string(), "sj".to_string())));
        assert!(pairs.contains(&("se".to_string(), "sg".to_string())));
    }

    #[test]
    fn paths_prepend_source_skip_self_and_dedup() {
        let paths = spf_paths(&spf_fixture(), "tk", None);
        // 1 path to se + 1 to da (the duplicate ECMP entry dedups).
        assert_eq!(paths.len(), 2);
        let se = &paths[0];
        assert_eq!(se["destination"], "se");
        assert_eq!(se["cost"], 60);
        assert_eq!(se["interface"], "tk-sg");
        let hops: Vec<&str> = se["hops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap())
            .collect();
        assert_eq!(hops, vec!["tk", "sg", "fr", "ln", "ch", "se"]);
    }

    #[test]
    fn paths_filter_by_destination() {
        let paths = spf_paths(&spf_fixture(), "tk", Some("da"));
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0]["destination"], "da");
    }

    #[test]
    fn algorithm_choices_always_include_zero() {
        let flex = json!({
            "area": "49.0000",
            "local_algorithms": [
                {
                    "algorithm": 128,
                    "metric_type": "igp",
                    "advertise_definition": false,
                    "include_any": [],
                    "include_all": [],
                    "exclude_any": ["trans-pacific"],
                    "srlg_exclude": [],
                },
            ],
        });
        let choices = algorithm_choices(&flex);
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0]["algo"], 0);
        assert_eq!(choices[1]["algo"], 128);
        assert_eq!(choices[1]["label"], "128 — exclude-any: trans-pacific");

        // No flex-algo configured still offers algorithm 0.
        assert_eq!(algorithm_choices(&json!({})).len(), 1);
    }
}
