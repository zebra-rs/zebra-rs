// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use nom::{Err, IResult, Needed};

/// Split `input` at position `len`, returning `(remaining, head)` as an `IResult`.
/// Returns `Err::Incomplete` if `input.len() < len`.
pub fn safe_split_at(input: &[u8], len: usize) -> IResult<&[u8], &[u8]> {
    if input.len() < len {
        return Err(Err::Incomplete(Needed::new(len)));
    }
    let (head, tail) = input.split_at(len);
    Ok((tail, head))
}
