//! Static snapshot export: the same frontend the live server embeds,
//! plus every API response pre-fetched into `data/` files, laid out so
//! the site works from any static host (GitHub Pages included).
//!
//! The export is all-or-nothing behind a convergence guard: every
//! ontology router must be active in every algorithm's graph and every
//! source must have a path to every other router, retried until a
//! deadline — a half-converged lab is never written to disk.
//!
//! Layout under `--out`:
//!
//! ```text
//! index.html
//! static/app.js, static/style.css
//! data/manifest.js                  — window.ZEBRA_SNAPSHOT = {...}
//! data/routers.json                 — /api/routers
//! data/algorithms-<src>.json        — /api/algorithms?source=<src>
//! data/topology-<src>-<algo>.json   — /api/topology?...&destination=__all__
//! ```
//!
//! The frontend filters by destination client-side, so one `__all__`
//! topology per (source, algorithm) covers every destination choice.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::api::App;

/// One fully collected, validated lab state, ready to write.
struct Snapshot {
    /// Per source router: the `/api/algorithms` response.
    algorithms: Vec<(String, Value)>,
    /// Per (source, algorithm): the all-destinations `/api/topology`
    /// response.
    topologies: Vec<(String, u8, Value)>,
}

pub async fn run(app: &App, out: &Path, settle: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + settle;
    let snapshot = loop {
        match collect(app).await {
            Ok(s) => break s,
            Err(e) if tokio::time::Instant::now() < deadline => {
                eprintln!("lab not ready: {e:#}; retrying...");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Err(e) => {
                return Err(e.context(format!(
                    "lab did not converge within {}s; refusing to export a partial snapshot",
                    settle.as_secs()
                )));
            }
        }
    };

    write(app, out, &snapshot)?;
    println!(
        "snapshot: {} — {} routers, {} topology file(s)",
        out.display(),
        snapshot.algorithms.len(),
        snapshot.topologies.len()
    );
    Ok(())
}

/// Query every router and validate completeness. Any hole (router not
/// yet in a graph, destination not yet reachable, flex-algo not yet
/// advertised) is an error, so the caller can retry until convergence.
async fn collect(app: &App) -> Result<Snapshot> {
    let names: BTreeSet<&str> = app.routers.iter().map(|r| r.name.as_str()).collect();
    let mut snapshot = Snapshot {
        algorithms: Vec::new(),
        topologies: Vec::new(),
    };
    let mut flex_seen = false;

    for router in &app.routers {
        let source = router.name.as_str();
        let algorithms = app.api_algorithms(source).await?;
        let ids = algorithm_ids(&algorithms);
        flex_seen |= ids.iter().any(|a| *a != 0);

        for algo in &ids {
            let topology = app.api_topology(source, *algo, None).await?;
            validate_topology(&names, source, *algo, &topology)?;
            snapshot
                .topologies
                .push((source.to_string(), *algo, topology));
        }
        println!("  {source}: algorithms {ids:?} ok");
        snapshot.algorithms.push((source.to_string(), algorithms));
    }

    // This playset exists to show Flex-Algorithm; a lab where no router
    // advertises one yet has not finished loading its configuration.
    if !flex_seen {
        bail!("no router advertises a Flex-Algorithm yet");
    }
    Ok(snapshot)
}

/// The algorithm numbers in an `/api/algorithms` response (0 always
/// included by construction).
fn algorithm_ids(algorithms: &Value) -> Vec<u8> {
    algorithms
        .get("algorithms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| a.get("algo").and_then(Value::as_u64))
        .filter_map(|a| u8::try_from(a).ok())
        .collect()
}

/// A topology is complete when every ontology router is active in its
/// graph and every other router is reachable from the source.
fn validate_topology(
    names: &BTreeSet<&str>,
    source: &str,
    algo: u8,
    topology: &Value,
) -> Result<()> {
    let active: BTreeSet<&str> = topology
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|n| n.get("active").and_then(Value::as_bool) == Some(true))
        .filter_map(|n| n.get("name").and_then(Value::as_str))
        .collect();
    let reachable: BTreeSet<&str> = topology
        .get("paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|p| p.get("destination").and_then(Value::as_str))
        .collect();

    for name in names {
        if !active.contains(name) {
            bail!("algorithm {algo} from {source}: {name} not in the IS-IS graph");
        }
        if *name != source && !reachable.contains(name) {
            bail!("algorithm {algo} from {source}: no path to {name}");
        }
    }
    Ok(())
}

fn write(app: &App, out: &Path, snapshot: &Snapshot) -> Result<()> {
    let data = out.join("data");
    let assets = out.join("static");
    std::fs::create_dir_all(&data)
        .with_context(|| format!("failed to create {}", data.display()))?;
    std::fs::create_dir_all(&assets)
        .with_context(|| format!("failed to create {}", assets.display()))?;

    // The frontend embedded in this binary — the deployed site always
    // matches the code that produced its data.
    write_file(&out.join("index.html"), crate::INDEX_HTML)?;
    write_file(&assets.join("app.js"), crate::APP_JS)?;
    write_file(&assets.join("style.css"), crate::STYLE_CSS)?;

    write_json(&data.join("routers.json"), &app.api_routers())?;
    for (source, algorithms) in &snapshot.algorithms {
        write_json(&data.join(format!("algorithms-{source}.json")), algorithms)?;
    }
    for (source, algo, topology) in &snapshot.topologies {
        write_json(
            &data.join(format!("topology-{source}-{algo}.json")),
            topology,
        )?;
    }

    let generated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is past the epoch")
        .as_secs();
    let manifest = json!({
        "generatedAtEpoch": generated,
        "playset": "isis-flexalgo",
        "routers": snapshot.algorithms.len(),
        "topologies": snapshot.topologies.len(),
    });
    write_file(
        &data.join("manifest.js"),
        &format!("window.ZEBRA_SNAPSHOT = {manifest};\n"),
    )
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    write_file(path, &text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> BTreeSet<&'static str> {
        BTreeSet::from(["tk", "sg", "se"])
    }

    /// A complete topology from `tk`: everyone active, everyone reached.
    fn topology_fixture() -> Value {
        json!({
            "source": "tk",
            "algorithm": 0,
            "nodes": [
                {"name": "tk", "active": true},
                {"name": "sg", "active": true},
                {"name": "se", "active": true},
            ],
            "edges": [],
            "paths": [
                {"destination": "sg", "hops": ["tk", "sg"]},
                {"destination": "se", "hops": ["tk", "se"]},
            ],
        })
    }

    #[test]
    fn complete_topology_validates() {
        validate_topology(&names(), "tk", 0, &topology_fixture()).expect("complete");
    }

    #[test]
    fn inactive_router_is_rejected() {
        let mut topology = topology_fixture();
        topology["nodes"][2]["active"] = json!(false);
        let err = validate_topology(&names(), "tk", 128, &topology).unwrap_err();
        assert!(
            err.to_string().contains("se not in the IS-IS graph"),
            "{err}"
        );
    }

    #[test]
    fn unreached_destination_is_rejected() {
        let mut topology = topology_fixture();
        topology["paths"].as_array_mut().unwrap().pop();
        let err = validate_topology(&names(), "tk", 0, &topology).unwrap_err();
        assert!(err.to_string().contains("no path to se"), "{err}");
    }

    #[test]
    fn algorithm_ids_flatten_the_choices() {
        let algorithms = json!({
            "algorithms": [
                {"algo": 0, "label": "0 — shortest path"},
                {"algo": 128, "label": "128 — exclude-any: trans-pacific"},
            ],
        });
        assert_eq!(algorithm_ids(&algorithms), vec![0, 128]);
        assert!(algorithm_ids(&json!({})).is_empty());
    }
}
