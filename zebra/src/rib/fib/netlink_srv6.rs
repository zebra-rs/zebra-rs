use netlink_packet_route::route::RouteLwEnCapType;

pub fn srv6_encap() {
    println!("srv6_encap {}", RouteLwEnCapType::Seg6);
}
