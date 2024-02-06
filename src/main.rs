use bgpd::*;
use std::error::Error;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

const CHANNEL_SIZE: usize = 1024;

async fn bgp_global_set_asn(bgp: BgpInstance, asn_str: String) {
    let mut bgp = bgp.write().await;
    bgp.asn = asn_str.parse().unwrap();
}

async fn bgp_global_set_router_id(bgp: BgpInstance, router_id_str: String) {
    let mut bgp = bgp.write().await;
    bgp.router_id = router_id_str.parse().unwrap();
}

async fn bgp_peer_push(bgp: BgpInstance, peer: Peer) {
    let mut bgp = bgp.write().await;
    bgp.peers.push(peer);
}

async fn bgp_peer_add(bgp: BgpInstance, address: String, asn_str: String) {
    let addr: Ipv4Addr = address.parse().unwrap();
    let asn: u32 = asn_str.parse().unwrap();
    let peer = Peer::new(bgp.clone(), asn, addr);
    bgp_peer_push(bgp.clone(), peer).await;
}

async fn bgp_config_set(bgp: BgpInstance, conf: &str) {
    let paths: Vec<&str> = conf.split('/').collect();
    if paths.len() < 5 {
        return;
    }
    match paths[2] {
        "global" => match paths[3] {
            "as" => {
                bgp_global_set_asn(bgp, paths[4].to_string()).await;
            }
            "router-id" => {
                bgp_global_set_router_id(bgp, paths[4].to_string()).await;
            }
            _ => {}
        },
        "neighbors" => {
            if paths.len() < 7 {
                return;
            }
            bgp_peer_add(bgp, paths[4].to_string(), paths[6].to_string()).await;
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (tx, mut rx) = mpsc::channel::<&str>(CHANNEL_SIZE);

    tx.send("/bgp/global/as/1").await?;
    tx.send("/bgp/global/router-id/10.211.65.2").await?;
    tx.send("/bgp/neighbors/address/10.211.55.65/peer-as/100")
        .await?;

    let bgp = Bgp::new_instance().clone();

    tokio::spawn(async move {
        loop {
            let conf = rx.recv().await;
            if let Some(conf) = conf {
                bgp_config_set(bgp.clone(), conf).await;
            }
        }
    })
    .await?;

    Ok(())
}
