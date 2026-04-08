// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use bytes::{BufMut, BytesMut};

pub use packet_utils::{ParseBe, TlvEmitter, u32_u8_3, write_hold_time};

/// Emit sub-TLVs with a back-patched length byte.
///
/// Writes a placeholder `0u8`, calls `emit_fn` to write sub-TLV data, then
/// patches the placeholder with the actual length (capped to 255).
pub fn emit_sub_tlvs(buf: &mut BytesMut, emit_fn: impl FnOnce(&mut BytesMut)) {
    buf.put_u8(0);
    let pp = buf.len();
    emit_fn(buf);
    buf[pp - 1] = (buf.len() - pp).min(255) as u8;
}
