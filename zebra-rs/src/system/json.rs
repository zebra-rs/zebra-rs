//! Serde helpers shared by the system backends that consume config
//! subtrees as JSON batches (`ConfigManager::subscribe_json`).
//!
//! Shapes of `Config::json()` output to know: scalars that look
//! numeric are emitted as JSON numbers (see `format_json_value`), so
//! every user-string field is a [`Flex`]; `type empty` leaves arrive
//! as `"name": null`, handled by [`de_presence`]; YANG lists are
//! arrays of objects with the key leaf inline; leaf-lists are arrays
//! (a scalar is tolerated defensively by [`de_flex_vec`]).

use std::fmt;

use serde::{Deserialize, Deserializer};

/// A config scalar: the JSON marshaler emits `80` for `port 80` but
/// `"https"` for `port https`, so any value-position field must accept
/// both.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Flex {
    Num(serde_json::Number),
    Str(String),
    Bool(bool),
}

impl fmt::Display for Flex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Flex::Num(n) => write!(f, "{n}"),
            Flex::Str(s) => write!(f, "{s}"),
            Flex::Bool(b) => write!(f, "{b}"),
        }
    }
}

/// `type empty` leaf: present-as-null means set. `deserialize_with`
/// runs only when the key exists, so any payload (null, `{}`) counts
/// as presence; a missing key takes the `default` (false).
pub fn de_presence<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(d)?;
    Ok(true)
}

/// Leaf-list: normally an array, but tolerate a bare scalar and null.
pub fn de_flex_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Flex>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    let one = |val: serde_json::Value| -> Option<Flex> {
        match val {
            serde_json::Value::Number(n) => Some(Flex::Num(n)),
            serde_json::Value::String(s) => Some(Flex::Str(s)),
            serde_json::Value::Bool(b) => Some(Flex::Bool(b)),
            _ => None,
        }
    };
    Ok(match v {
        serde_json::Value::Array(items) => items.into_iter().filter_map(one).collect(),
        serde_json::Value::Null => Vec::new(),
        other => one(other).into_iter().collect(),
    })
}
