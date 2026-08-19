use anyhow::{Result, anyhow};
use tonic::transport::{Channel, Endpoint};

/// Connect to the zebra-rs VTY gRPC server.
///
/// Supported URI forms:
/// - `http://host:port` / `https://host:port` — TCP via tonic Endpoint
/// - `tcp://host:port` — alias for `http://host:port`
/// - `unix:NAME` — Linux abstract Unix socket (e.g. `unix:zebra-rs/vty`)
/// - `unix:/PATH` — filesystem Unix socket (e.g. `unix:/tmp/zebra-rs`)
/// - `unix:@NAME` — explicitly abstract, even when NAME starts with `/`
pub async fn connect(uri: &str) -> Result<Channel> {
    #[cfg(target_os = "linux")]
    if let Some(name) = uri.strip_prefix("unix:") {
        return connect_unix(name).await;
    }
    // `tcp://HOST:PORT` and the daemon-style `tcp:HOST:PORT` both mean
    // plain-TCP gRPC, which tonic spells `http://`.
    let normalized = if let Some(rest) = uri.strip_prefix("tcp://") {
        format!("http://{rest}")
    } else if let Some(rest) = uri.strip_prefix("tcp:") {
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
async fn connect_unix(name: &str) -> Result<Channel> {
    use hyper_util::rt::TokioIo;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as StdSockAddr, UnixStream as StdUnixStream};
    use tokio::net::UnixStream;
    use tower::service_fn;

    // `@NAME` is explicitly abstract, `/PATH` is a filesystem socket, and
    // a bare NAME stays an abstract name (the historical default).
    let (is_path, name) = match name.strip_prefix('@') {
        Some(rest) => (false, rest.to_string()),
        None => (name.starts_with('/'), name.to_string()),
    };
    if name.is_empty() {
        return Err(anyhow!("unix name must be non-empty"));
    }
    let name_for_err = name.clone();
    // The endpoint URI is a placeholder; the connector ignores it and dials
    // the Unix socket each time tonic calls it.
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let name = name.clone();
            async move {
                let std = if is_path {
                    StdUnixStream::connect(&name)?
                } else {
                    let addr = StdSockAddr::from_abstract_name(name.as_bytes())
                        .map_err(std::io::Error::other)?;
                    StdUnixStream::connect_addr(&addr)?
                };
                std.set_nonblocking(true)?;
                let stream = UnixStream::from_std(std)?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| anyhow!("connect unix:{name_for_err}: {e}"))
}
