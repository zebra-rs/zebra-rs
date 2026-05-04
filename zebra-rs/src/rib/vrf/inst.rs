/// Applied state for one VRF instance.
///
/// Created when `Message::VrfAdd { name }` is handled by the RIB —
/// the allocator hands out a fresh table ID, the netlink layer creates
/// the kernel `vrf` master interface, and the result is recorded here.
/// `ifindex` is filled in opportunistically when the kernel emits the
/// resulting `NewLink`; until then it stays `None`.
#[derive(Debug, Clone)]
pub struct Vrf {
    pub name: String,
    pub table_id: u32,
}
