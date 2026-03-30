// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use isis_packet::IsisSysId;

pub use crate::spf::label_block::{LabelBlock, LabelConfig, LabelMap};

pub type IsisLabelMap = LabelMap<IsisSysId>;
