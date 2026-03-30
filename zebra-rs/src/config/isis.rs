// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use crate::context::Context;
use crate::isis::inst;

use super::ConfigManager;

pub fn spawn_isis(config: &ConfigManager) {
    let ctx = Context::default();
    let isis = inst::Isis::new(ctx, config.rib_tx.clone());
    config.subscribe("isis", isis.cm.tx.clone());
    config.subscribe_show("isis", isis.show.tx.clone());
    inst::serve(isis);
}
