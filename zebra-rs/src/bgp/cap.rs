// Capability for sent and received.

use std::collections::HashMap;

use bgp_packet::{cap::CapMultiProtocol, Afi, AfiSafi, Safi};

#[derive(Default)]
struct SendRecv {
    pub send: bool,
    pub recv: bool,
}

#[derive(Default)]
struct CapAfiMap {
    pub entries: HashMap<CapMultiProtocol, SendRecv>,
}

impl CapAfiMap {
    pub fn new() -> Self {
        let mp4uni = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
        let mp4vpn = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsVpn);
        let mp6uni = CapMultiProtocol::new(&Afi::Ip6, &Safi::Unicast);
        let mpevpn = CapMultiProtocol::new(&Afi::L2vpn, &Safi::Evpn);

        let mut cmap = Self::default();
        cmap.entries.insert(mp4uni, SendRecv::default());
        cmap.entries.insert(mp4vpn, SendRecv::default());
        cmap.entries.insert(mp6uni, SendRecv::default());
        cmap.entries.insert(mpevpn, SendRecv::default());
        cmap
    }

    pub fn get(&self, mp: &CapMultiProtocol) -> Option<&SendRecv> {
        self.entries.get(mp)
    }
}
