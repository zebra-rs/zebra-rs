use tokio::net::TcpSocket;

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

use super::Context;

impl Context {
    async fn connect<A: ToSocketAddrs>(addr: &str) -> io::Result<()> {
        let sock_addr = addr.parse::<SocketAddr>().unwrap();

        let socket = TcpSocket::new_v4()?;
        socket.bind_device(Some(b"vrf1"));

        let stream = socket.connect(sock_addr).await?;

        Ok(())
    }
}
