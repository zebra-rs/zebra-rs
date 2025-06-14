// Capability for sent and received.

use bgp_packet::{Afi, Safi};

struct CapAfi {
    pub afi: Afi,
    pub safi: Safi,
    pub sent: bool,
    pub rcvd: bool,
}

#[derive(Default)]
struct CapAfiMap {
    pub entries: Vec<CapAfi>,
}

impl CapAfiMap {
    pub fn new() -> Self {
        let mut cmap = Self::default();
        cmap.entries.push(CapAfi {
            afi: Afi::Ip,
            safi: Safi::Unicast,
            sent: false,
            rcvd: false,
        });
        cmap
    }
    
    pub fn get_mut(&mut self, afi: Afi, safi: Safi) -> Option<&mut CapAfi> {
        self.entries.iter_mut().find(|e| e.afi == afi && e.safi == safi)
    }
    
    pub fn get(&self, afi: Afi, safi: Safi) -> Option<&CapAfi> {
        self.entries.iter().find(|e| e.afi == afi && e.safi == safi)
    }
}
