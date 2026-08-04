//! System-level config consumers — subsystems that translate committed
//! config subtrees into kernel or system-daemon state rather than
//! running a routing protocol. Residents: the VyOS-compatible
//! firewall → nftables backend and the VyOS-compatible IPsec →
//! strongSwan (swanctl) backend.

pub mod firewall;
pub mod ipsec;
mod json;
pub mod vici;

pub use firewall::Firewall;
pub use ipsec::Ipsec;

pub fn serve(firewall: Firewall, ipsec: Ipsec) {
    tokio::spawn(async move {
        firewall.event_loop().await;
    });
    tokio::spawn(async move {
        ipsec.event_loop().await;
    });
}
