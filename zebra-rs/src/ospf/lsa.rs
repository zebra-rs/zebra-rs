// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use ospf_packet::*;

pub fn ospf_ls_rquest_new(lsah: &OspfLsaHeader) -> OspfLsRequestEntry {
    OspfLsRequestEntry::new(lsah.ls_type, lsah.ls_id, lsah.adv_router)
}
