#![feature(async_closure)]

use bgp_parser::*;
use bytes::BytesMut;
use nom::AsBytes;
use std::error::Error;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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

async fn bgp_peer_add(bgp: BgpInstance, address: String, _asn_str: String) {
    tokio::spawn(async move {
        let bgp = bgp.read().await;

        let mut stream = TcpStream::connect(address + ":179").await.unwrap();

        let header = BgpHeader::new(BgpPacketType::Open, BGP_PACKET_HEADER_LEN + 10);
        let open = OpenPacket::new(header, bgp.asn as u16, &bgp.router_id);

        let bytes: BytesMut = open.into();
        stream.write_all(&bytes[..]).await.unwrap();

        let keepalive = BgpHeader::new(BgpPacketType::Keepalive, BGP_PACKET_HEADER_LEN);
        let bytes: BytesMut = keepalive.into();
        stream.write_all(&bytes[..]).await.unwrap();

        // Keepalive timer.
        let _timer = Timer::new(Duration::new(3, 0), TimerType::Infinite, async || {
            println!("timer");
        });

        loop {
            let mut rx = [0u8; BGP_PACKET_MAX_LEN];
            let rx_len = stream.read(&mut rx).await.unwrap();
            if rx_len >= BGP_PACKET_HEADER_LEN as usize {
                let (_, p) = parse_bgp_packet(rx.as_bytes()).expect("error");
                println!("{:?}", p);
            }
        }
    });
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
