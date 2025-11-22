pub fn is_valid_checksum(input: &[u8]) -> bool {
    fletcher::calc_fletcher16(&input[12..]) == 0
}

pub fn checksum_calc(data: &[u8]) -> [u8; 2] {
    let checksum = fletcher::calc_fletcher16(data);
    let mut c0 = (checksum & 0x00FF) as i32;
    let mut c1 = ((checksum >> 8) & 0x00FF) as i32;

    let sop = data.len() as u16 - 13;
    let mut x = (sop as i32 * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    c1 = 510 - c0 - x;
    if c1 > 255 {
        c1 -= 255;
    }
    c0 = x;
    [c0 as u8, c1 as u8]
}
