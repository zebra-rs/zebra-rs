//! Router ontology: the playset's `ontology.json` (name, full name,
//! region per router) joined with a built-in city gazetteer that supplies
//! the coordinates the 3D globe needs. `ontology.json` is the source of
//! truth for which routers exist and where they are; the gazetteer only
//! turns its city names into latitude/longitude.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct OntologyEntry {
    name: String,
    #[serde(rename = "full-name")]
    full_name: String,
    region: String,
}

/// One router as served to the frontend.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Router {
    /// Short name — the IS-IS hostname and the network namespace name.
    pub name: String,
    pub full_name: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lat: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lng: Option<f64>,
}

/// City-name → (lat, lng) gazetteer for the ontology's `full-name`
/// values. A city missing here still renders in lists; it just cannot be
/// placed on the globe.
const CITY_GEO: &[(&str, f64, f64)] = &[
    ("Seattle", 47.6062, -122.3321),
    ("San Jose", 37.3382, -121.8863),
    ("Chicago", 41.8781, -87.6298),
    ("Dallas", 32.7767, -96.7970),
    // The ontology's "Virginia" is the Ashburn, VA datacenter corridor.
    ("Virginia", 39.0438, -77.4874),
    ("Atlanta", 33.7490, -84.3880),
    ("London", 51.5074, -0.1278),
    ("Frankfurt", 50.1109, 8.6821),
    ("Singapore", 1.3521, 103.8198),
    ("Sydney", -33.8688, 151.2093),
    ("Tokyo", 35.6762, 139.6503),
];

fn geocode(full_name: &str) -> Option<(f64, f64)> {
    CITY_GEO
        .iter()
        .find(|(city, _, _)| city.eq_ignore_ascii_case(full_name))
        .map(|(_, lat, lng)| (*lat, *lng))
}

/// Load `ontology.json` and geocode each entry.
pub fn load(path: &Path) -> Result<Vec<Router>> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read ontology {}", path.display()))?;
    let entries: Vec<OntologyEntry> = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse ontology {}", path.display()))?;
    Ok(entries
        .into_iter()
        .map(|e| {
            let geo = geocode(&e.full_name);
            Router {
                name: e.name,
                full_name: e.full_name,
                region: e.region,
                lat: geo.map(|(lat, _)| lat),
                lng: geo.map(|(_, lng)| lng),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_playset_ontology() {
        // The playset file this app is built around; keep the test
        // hermetic against layout changes by resolving from the crate.
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../playset/isis-flexalgo/ontology.json");
        let routers = load(&path).expect("ontology loads");
        assert_eq!(routers.len(), 11);
        assert!(
            routers.iter().all(|r| r.lat.is_some() && r.lng.is_some()),
            "every playset city must geocode"
        );
        let tk = routers.iter().find(|r| r.name == "tk").expect("tk exists");
        assert_eq!(tk.full_name, "Tokyo");
        assert_eq!(tk.region, "AP");
    }

    #[test]
    fn geocode_is_case_insensitive_and_total_for_known_cities() {
        assert!(geocode("tokyo").is_some());
        assert!(geocode("Nowhere City").is_none());
    }
}
