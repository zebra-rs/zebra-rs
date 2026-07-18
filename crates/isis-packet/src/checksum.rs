pub fn is_valid_checksum(input: &[u8]) -> bool {
    if input.len() < 12 {
        return false;
    }
    fletcher::calc_fletcher16(&input[12..]) == 0
}

pub fn checksum_calc(data: &[u8]) -> [u8; 2] {
    // The IS-IS LSP checksum is the offset-12 specialization of the shared
    // Fletcher helper (checksum field at bytes 12-13 of the checksummed span).
    packet_utils::fletcher_lsa_checksum(data, 12).to_be_bytes()
}
