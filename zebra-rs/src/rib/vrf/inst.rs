/// Applied state for one VRF instance.
///
/// Created when `Message::VrfAdd { name }` is handled by the RIB —
/// the allocator hands out a fresh table ID, the netlink layer creates
/// the kernel `vrf` master interface, and the result is recorded here.
/// `ifindex` is the kernel-assigned ifindex of the VRF master device;
/// callers enslave member interfaces to it via `IFLA_MASTER`.
#[derive(Debug, Clone)]
pub struct Vrf {
    pub name: String,
    pub table_id: u32,
    pub ifindex: u32,
}
