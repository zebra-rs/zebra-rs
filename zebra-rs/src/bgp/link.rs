// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

#[derive(Debug, Default)]
pub struct BgpLink {
    pub ifindex: u32,
    pub name: String,
}
