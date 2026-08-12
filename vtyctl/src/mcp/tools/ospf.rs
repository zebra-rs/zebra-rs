use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use crate::mcp::client::ZebraClient;

/// OSPF-specific tools for network topology analysis — the OSPFv2/v3
/// siblings of the IS-IS tool family. One tool set serves both
/// versions: the `version` argument (2, the default, or 3) selects
/// between the `show ospf …` and `show ospfv3 …` command families.
#[derive(Clone)]
pub struct OspfTools {
    client: ZebraClient,
}

/// Parse the optional `version` argument shared by the OSPF tools and
/// return the show-command base for it: absent or 2 means OSPFv2
/// (`show ospf …`), 3 means OSPFv3 (`show ospfv3 …`).
fn version_base(args: &HashMap<String, Value>) -> Result<&'static str> {
    match args.get("version") {
        None => Ok("ospf"),
        Some(value) => match value.as_u64() {
            Some(2) => Ok("ospf"),
            Some(3) => Ok("ospfv3"),
            _ => Err(anyhow::anyhow!(
                "'version' must be 2 (OSPFv2) or 3 (OSPFv3)"
            )),
        },
    }
}

impl OspfTools {
    pub fn new(client: ZebraClient) -> Self {
        Self { client }
    }

    /// Get the OSPF topology graph: the area's SPF graph with router
    /// names and per-link costs, as built from the LSDB.
    pub async fn get_ospf_graph(&self, args: HashMap<String, Value>) -> Result<String> {
        debug!("Getting OSPF graph with args: {:?}", args);
        let base = version_base(&args)?;
        // OSPFv2 renders a single graph object, OSPFv3 a vertex array —
        // match each version's empty shape.
        let empty = if base == "ospf" { "{}" } else { "[]" };
        self.client
            .show_json(&format!("show {} graph", base), empty)
            .await
    }

    /// Get the OSPF SPF tree: per-vertex cost and first hops from this
    /// router. Unlike IS-IS, OSPF's primary SPF does not retain full
    /// hop-by-hop vertex chains, so the result carries no `paths` list.
    pub async fn get_ospf_spf(&self, args: HashMap<String, Value>) -> Result<String> {
        debug!("Getting OSPF SPF with args: {:?}", args);
        let base = version_base(&args)?;
        self.client
            .show_json(&format!("show {} spf", base), "[]")
            .await
    }

    /// Get the OSPF Flexible Algorithm state: each configured
    /// algorithm's definition and constraints, its per-algorithm SPF
    /// status, and the per-algorithm routes.
    pub async fn get_ospf_flex_algo(&self, args: HashMap<String, Value>) -> Result<String> {
        debug!("Getting OSPF flex-algo state with args: {:?}", args);
        let base = version_base(&args)?;
        self.client
            .show_json(&format!("show {} flex-algo", base), "[]")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn version_base_defaults_to_v2() {
        assert_eq!(version_base(&args(&[])).unwrap(), "ospf");
    }

    #[test]
    fn version_base_selects_command_family() {
        assert_eq!(
            version_base(&args(&[("version", json!(2))])).unwrap(),
            "ospf"
        );
        assert_eq!(
            version_base(&args(&[("version", json!(3))])).unwrap(),
            "ospfv3"
        );
    }

    #[test]
    fn version_base_rejects_other_values() {
        for bad in [json!(1), json!(4), json!(0), json!("3"), json!(-3)] {
            assert!(
                version_base(&args(&[("version", bad.clone())])).is_err(),
                "expected error for {bad}"
            );
        }
    }

    #[tokio::test]
    async fn tools_reject_invalid_version() {
        let tools = OspfTools::new(ZebraClient::new("127.0.0.1".to_string(), 2650));
        for call in ["graph", "spf", "flex-algo"] {
            let a = args(&[("version", json!(9))]);
            let err = match call {
                "graph" => tools.get_ospf_graph(a).await.unwrap_err(),
                "spf" => tools.get_ospf_spf(a).await.unwrap_err(),
                _ => tools.get_ospf_flex_algo(a).await.unwrap_err(),
            };
            assert!(err.to_string().contains("must be 2"), "{call}: {err}");
        }
    }
}
