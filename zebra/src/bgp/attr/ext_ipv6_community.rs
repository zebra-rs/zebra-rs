struct ExtIpv6Community {
    typ: u8,
    sub_typ: u8,
    global: Ipv6Addr,
    local: u16,
}
