//! System-level config consumers — subsystems that translate committed
//! config subtrees into kernel state rather than running a routing
//! protocol. First resident: the VyOS-compatible firewall → nftables
//! backend.

pub mod firewall;

pub use firewall::Firewall;

pub fn serve(firewall: Firewall) {
    tokio::spawn(async move {
        firewall.event_loop().await;
    });
}
