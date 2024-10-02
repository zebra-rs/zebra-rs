pub fn yaml_parse(str: &str) -> String {
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(str).unwrap();
    let json_str = serde_json::to_string(&yaml_value).unwrap();
    json_str
}
