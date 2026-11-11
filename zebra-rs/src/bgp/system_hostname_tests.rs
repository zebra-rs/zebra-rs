//! `system hostname` as the name BGP's FQDN capability carries when BGP
//! has no hostname of its own (docs/design/system-hostname.md §7).
//!
//! The RIB reports the name (`RibRx::HostnameUpdate`). A peer advertises
//! the snapshot it holds (`Peer::local_hostname`) in its next OPEN, so the
//! snapshots have to follow the name; a session that is up keeps the name
//! its OPEN carried, as with `router bgp global hostname`.

use super::*;
use crate::bgp::peer::Peer;
use crate::rib::api::RibRx;
use std::net::IpAddr;
use tokio::sync::mpsc;

fn fresh_bgp() -> Bgp {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    Box::leak(Box::new(inbound_rx));
    let ctx = crate::context::ProtoContext::default_table(client);
    let (rib_tx, rib_out_rx) = mpsc::unbounded_channel();
    let (rib_inbound_tx, sub_inbound_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_out_rx));
    Box::leak(Box::new(sub_inbound_rx));
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(policy_rx));
    Bgp::new(
        ctx,
        rib_rx,
        subscriber,
        policy_tx,
        None,
        None,
        mpsc::channel(1).0,
    )
}

/// A neighbor at `addr`, created as the config path creates one: with the
/// hostname BGP resolves at that moment.
fn add_peer(bgp: &mut Bgp, addr: &str) -> IpAddr {
    let ip: IpAddr = addr.parse().unwrap();
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let peer = Peer::new(
        0,
        65000,
        bgp.router_id,
        65000,
        ip,
        bgp.hostname(),
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    bgp.peers.insert(ip, peer);
    ip
}

/// The hostname the next OPEN to `addr` advertises.
fn next_open(bgp: &mut Bgp, addr: &IpAddr) -> Option<String> {
    bgp.peers.get_mut(addr).unwrap().local_hostname.clone()
}

fn os_name() -> Option<String> {
    hostname::get()
        .ok()
        .and_then(|s| s.into_string().ok())
        .filter(|s| !s.is_empty())
}

fn told(bgp: &mut Bgp, hostname: Option<&str>) {
    bgp.process_rib_msg(RibRx::HostnameUpdate(hostname.map(str::to_string)));
}

#[tokio::test]
async fn router_bgp_hostname_wins_then_system_hostname_then_the_os_name() {
    let mut bgp = fresh_bgp();
    assert_eq!(bgp.hostname(), os_name());
    told(&mut bgp, Some("r1"));
    assert_eq!(bgp.hostname().as_deref(), Some("r1"));
    bgp.config_set_hostname(Some("bgp-r1".to_string()));
    assert_eq!(bgp.hostname().as_deref(), Some("bgp-r1"));
    told(&mut bgp, None);
    assert_eq!(bgp.hostname().as_deref(), Some("bgp-r1"));
    bgp.config_set_hostname(None);
    assert_eq!(bgp.hostname(), os_name());
}

/// The name reaches the neighbors that exist, for their next OPEN, and a
/// neighbor created afterwards starts with it.
#[tokio::test]
async fn a_system_hostname_reaches_every_neighbors_next_open() {
    let mut bgp = fresh_bgp();
    let before = add_peer(&mut bgp, "10.0.0.2");
    assert_eq!(next_open(&mut bgp, &before), os_name());

    told(&mut bgp, Some("r1"));
    assert_eq!(next_open(&mut bgp, &before).as_deref(), Some("r1"));
    let after = add_peer(&mut bgp, "10.0.0.3");
    assert_eq!(next_open(&mut bgp, &after).as_deref(), Some("r1"));

    told(&mut bgp, Some("r2"));
    assert_eq!(next_open(&mut bgp, &before).as_deref(), Some("r2"));
    assert_eq!(next_open(&mut bgp, &after).as_deref(), Some("r2"));

    // Deleted: back to the OS name.
    told(&mut bgp, None);
    assert_eq!(next_open(&mut bgp, &before), os_name());
}

/// `router bgp global hostname` is BGP's own: the system hostname comes
/// and goes under it, and takes over when it is deleted.
#[tokio::test]
async fn router_bgp_hostname_is_not_replaced_by_the_system_hostname() {
    let mut bgp = fresh_bgp();
    bgp.config_set_hostname(Some("bgp-r1".to_string()));
    let peer = add_peer(&mut bgp, "10.0.0.2");

    told(&mut bgp, Some("r1"));
    assert_eq!(next_open(&mut bgp, &peer).as_deref(), Some("bgp-r1"));

    bgp.config_set_hostname(None);
    assert_eq!(next_open(&mut bgp, &peer).as_deref(), Some("r1"));
}

/// With neither name configured a neighbor's snapshot holds the OS name
/// as it was when the snapshot was taken. When the system is renamed
/// (`--feature insomnia`) the RIB sends the system hostname again,
/// unchanged, and the snapshot is taken again.
#[tokio::test]
async fn a_renamed_system_refreshes_a_snapshot_of_the_os_name() {
    let mut bgp = fresh_bgp();
    let peer = add_peer(&mut bgp, "10.0.0.2");
    // What the system was called when the neighbor was created.
    bgp.peers.get_mut(&peer).unwrap().local_hostname = Some("the-name-before".to_string());

    told(&mut bgp, None);
    assert_eq!(next_open(&mut bgp, &peer), os_name());
}
