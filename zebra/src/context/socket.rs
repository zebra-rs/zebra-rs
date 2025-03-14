use tokio::net::TcpSocket;

use std::io;
use std::net::SocketAddr;

use super::Context;

impl Context {
    async fn connect(addr: &str) -> io::Result<()> {
        let sock_addr = addr.parse::<SocketAddr>().unwrap();

        let socket = TcpSocket::new_v4()?;
        let _ = socket.bind_device(Some(b"vrf1"));

        let _stream = socket.connect(sock_addr).await?;

        Ok(())
    }
}
