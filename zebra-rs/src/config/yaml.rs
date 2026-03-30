// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

pub fn yaml_parse(str: &str) -> String {
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(str).unwrap();
    serde_json::to_string(&yaml_value).unwrap()
}
