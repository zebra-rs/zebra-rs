// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

pub enum SidType {
    Prefix,
    Adjacency,
}

pub struct Sid {
    pub label: u32,
    pub typ: SidType,
    pub index: Option<u32>,
}
