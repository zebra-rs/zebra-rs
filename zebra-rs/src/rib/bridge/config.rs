// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use crate::rib::AddrGenMode;

#[derive(Default, Debug, Clone)]
pub struct BridgeConfig {
    // Bridge configuration structure
    pub delete: bool,

    // Address generation mode.
    pub addr_gen_mode: Option<AddrGenMode>,
}
