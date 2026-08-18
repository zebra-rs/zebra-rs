use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Serves the operator-provided network ontology file to MCP clients:
/// semantic metadata about the routers (short name, full name, region,
/// coordinates, ...) that the routing protocols do not carry. Only
/// registered when `vtyctl mcp --ontology <path>` names a file.
#[derive(Clone, Debug)]
pub struct OntologyTool {
    path: PathBuf,
}

impl OntologyTool {
    /// Validate the file up front (readable, valid JSON) so a bad path
    /// fails at server start rather than at the first tool call.
    pub fn new(path: &Path) -> Result<Self> {
        let tool = Self {
            path: path.to_path_buf(),
        };
        tool.read()?;
        Ok(tool)
    }

    /// Read the ontology fresh on every call, so edits to the file are
    /// visible without restarting the server.
    pub fn read(&self) -> Result<String> {
        let text = std::fs::read_to_string(&self.path)
            .with_context(|| format!("cannot read ontology file {}", self.path.display()))?;
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("ontology file {} is not valid JSON", self.path.display()))?;
        Ok(serde_json::to_string_pretty(&parsed)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vtyctl-ontology-{}-{}.json",
            name,
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn round_trips_valid_json() {
        let path = temp_file("valid", r#"[{"name":"tk","region":"AP"}]"#);
        let tool = OntologyTool::new(&path).unwrap();
        let text = tool.read().unwrap();
        std::fs::remove_file(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed[0]["region"], serde_json::json!("AP"));
    }

    #[test]
    fn rejects_missing_file_at_construction() {
        let err = OntologyTool::new(Path::new("/nonexistent/ontology.json"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot read ontology file"), "{err}");
    }

    #[test]
    fn rejects_invalid_json_at_construction() {
        let path = temp_file("invalid", "name: tk\nregion: AP\n");
        let err = OntologyTool::new(&path).unwrap_err().to_string();
        std::fs::remove_file(&path).unwrap();
        assert!(err.contains("not valid JSON"), "{err}");
    }
}
