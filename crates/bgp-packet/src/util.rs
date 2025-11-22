pub fn u32_u24(value: u32) -> [u8; 3] {
    // Extract the three least significant bytes as big-endian
    [
        (value >> 16) as u8, // Most significant byte of the remaining 3 bytes
        (value >> 8) as u8,  // Middle byte
        value as u8,         // Least significant byte
    ]
}
