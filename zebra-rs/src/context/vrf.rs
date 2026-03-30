// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

pub struct Vrf {
    pub name: String,
    pub id: u32,
}

impl Vrf {
    pub fn new(name: impl Into<String>, id: u32) -> Self {
        Self {
            name: name.into(),
            id,
        }
    }
}
