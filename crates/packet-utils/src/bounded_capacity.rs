/// Cap a wire-supplied element count before using it as a `Vec::with_capacity`
/// argument, so a forged count field cannot trigger a huge eager allocation.
///
/// A parser that reads an element count from the packet and then pre-allocates
/// `Vec::with_capacity(count)` is exposed to a denial-of-service: a tiny packet
/// can declare a 4-billion element count and force a multi-gigabyte reservation
/// before the parse loop ever runs. Since each element occupies at least
/// `min_entry` bytes on the wire, an input with `remaining` bytes left can hold
/// at most `remaining / min_entry` elements; any larger `count` is clamped to
/// that bound. Well-formed packets keep their exact-fit pre-allocation (their
/// count never exceeds the bound); a hostile count only reserves what the packet
/// could actually contain.
pub fn bounded_capacity(count: usize, remaining: usize, min_entry: usize) -> usize {
    count.min(remaining / min_entry.max(1))
}

#[cfg(test)]
mod tests {
    use super::bounded_capacity;

    #[test]
    fn keeps_legitimate_count() {
        // 3 elements, 30 bytes remaining, 4-byte minimum entry -> plenty of room.
        assert_eq!(bounded_capacity(3, 30, 4), 3);
    }

    #[test]
    fn clamps_hostile_count() {
        // A forged u32 count with a near-empty body clamps to what fits.
        assert_eq!(bounded_capacity(0xFFFF_FFFF, 8, 4), 2);
        assert_eq!(bounded_capacity(0xFFFF_FFFF, 0, 20), 0);
    }

    #[test]
    fn min_entry_zero_does_not_divide_by_zero() {
        assert_eq!(bounded_capacity(5, 40, 0), 5);
    }
}
