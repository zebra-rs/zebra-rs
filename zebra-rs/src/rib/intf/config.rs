// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;

use anyhow::Result;
use ipnet::Ipv4Net;

use crate::config::{Args, ConfigOp};

pub struct LinkConfig {
    pub name: String,
    pub ipv4addr: Vec<Ipv4Net>,
}

pub struct InterfaceConfig {
    pub config: BTreeMap<String, LinkConfig>,
    pub cache: BTreeMap<String, LinkConfig>,
    builder: ConfigBuilder,
}

#[derive(Default)]
struct ConfigBuilder {
    path: String,
    pub map: BTreeMap<(String, ConfigOp), Handler>,
}

type Handler = fn(
    config: &mut BTreeMap<String, LinkConfig>,
    cache: &mut BTreeMap<String, LinkConfig>,
    args: &mut Args,
) -> Result<()>;
