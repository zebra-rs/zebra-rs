// Capability for sent and received.

use std::collections::HashMap;

use bgp_packet::{cap::CapabilityPacket, Afi, AfiSafi, CapMultiProtocol, Safi};
use serde::Serialize;

#[derive(Default, Debug, Serialize, Clone)]
pub struct SendRecv {
    pub send: bool,
    pub recv: bool,
}

impl SendRecv {
    pub fn desc(&self) -> &str {
        match (self.send, self.recv) {
            (true, true) => "advertised and received",
            (true, false) => "advertised",
            (false, true) => "received",
            (false, false) => "",
        }
    }
}
#[derive(Default, Debug, Serialize, Clone)]
pub struct CapAfiMap {
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

    pub fn get_mut(&mut self, mp: &CapMultiProtocol) -> Option<&mut SendRecv> {
        self.entries.get_mut(mp)
    }
}

pub fn cap_register_send(caps: &[CapabilityPacket], cap_map: &mut CapAfiMap) {
    for cap in caps {
        if let CapabilityPacket::MultiProtocol(ref mp) = cap {
            if let Some(entry) = cap_map.get_mut(mp) {
                entry.send = true;
            }
        }
    }
}

pub fn cap_register_recv(caps: &[CapabilityPacket], cap_map: &mut CapAfiMap) {
    for cap in caps {
        if let CapabilityPacket::MultiProtocol(ref mp) = cap {
            if let Some(entry) = cap_map.get_mut(mp) {
                entry.recv = true;
            }
        }
    }
}
