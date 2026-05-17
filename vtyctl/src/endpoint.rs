use anyhow::{Result, anyhow};
use tonic::transport::{Channel, Endpoint};

/// Normalize the `--host` flag into a full endpoint URI.
///
/// Accepts:
/// - bare hostname/IP (`127.0.0.1`) — becomes `http://127.0.0.1:2666`
/// - `unix:NAME`, `tcp://…`, `http://…`, `https://…` — used as-is
pub fn host_uri(host: &str) -> String {
    if host.starts_with("unix:") || host.contains("://") {
        host.to_string()
    } else {
        format!("http://{host}:2666")
    }
}

/// Connect to the zebra-rs VTY gRPC server.
///
/// Supported URI forms:
/// - `http://host:port` / `https://host:port` — TCP via tonic Endpoint
/// - `tcp://host:port` — alias for `http://host:port`
/// - `unix:NAME` — Linux abstract Unix socket (e.g. `unix:zebra-rs/vty`)
pub async fn connect(uri: &str) -> Result<Channel> {
    #[cfg(target_os = "linux")]
    if let Some(name) = uri.strip_prefix("unix:") {
        return connect_abstract(name).await;
    }
    let normalized = if let Some(rest) = uri.strip_prefix("tcp://") {
        format!("http://{rest}")
    } else {
        uri.to_string()
    };
    Endpoint::try_from(normalized.clone())
        .map_err(|e| anyhow!("invalid endpoint {normalized:?}: {e}"))?
        .connect()
        .await
        .map_err(|e| anyhow!("connect {normalized}: {e}"))
}

#[cfg(target_os = "linux")]
async fn connect_abstract(name: &str) -> Result<Channel> {
    use hyper_util::rt::TokioIo;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as StdSockAddr, UnixStream as StdUnixStream};
    use tokio::net::UnixStream;
    use tower::service_fn;

    let name = name.trim_start_matches('@').to_string();
    if name.is_empty() {
        return Err(anyhow!("unix name must be non-empty"));
    }
    let name_for_err = name.clone();
    // The endpoint URI is a placeholder; the connector ignores it and dials
    // the abstract Unix socket each time tonic calls it.
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let name = name.clone();
            async move {
                let addr = StdSockAddr::from_abstract_name(name.as_bytes())
                    .map_err(std::io::Error::other)?;
                let std = StdUnixStream::connect_addr(&addr)?;
                std.set_nonblocking(true)?;
                let stream = UnixStream::from_std(std)?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| anyhow!("connect unix:{name_for_err}: {e}"))
}
