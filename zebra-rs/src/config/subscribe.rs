//! Running-config subscription over gRPC (`zebra.config.v1`).
//!
//! `Subscribe` opens a snapshot-then-deltas stream in either PATH
//! format (per-commit batch of set/delete path changes, the
//! `ConfigManager::subscribe` model) or JSON format (whole
//! post-commit subtree per touching commit — how the out-of-process
//! firewall/IPsec daemon consumes its subtrees).
//!
//! The service handler only mints a per-subscriber channel and hands
//! its sender to the manager's event loop
//! ([`Message::ConfigSubscribe`]); registration, the snapshot, and all
//! deliveries happen inside the manager (see
//! `ConfigManager::dispatch_config_subscribers`), which prunes a
//! subscriber whose channel is closed or full.

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Response;

use super::api::Message;

pub mod pb {
    tonic::include_proto!("zebra.config.v1");
}

pub use pb::config_service_server::ConfigServiceServer;

/// Per-subscriber buffer of undelivered events. Commits are rare and
/// delivery is one event per commit, so this only fills when a client
/// stops reading — at which point the manager drops the subscription
/// rather than buffering without bound toward a dead peer.
const EVENT_BUFFER: usize = 32;

/// A subscribe registration in flight from the gRPC handler to the
/// config manager's event loop.
#[derive(Debug)]
pub struct ConfigSubscribeRequest {
    pub format: pb::Format,
    /// Config-tree prefix to watch, one segment per element; empty
    /// watches the whole configuration.
    pub path: Vec<String>,
    pub tx: mpsc::Sender<pb::ConfigEvent>,
}

/// One registered subscriber row in the manager.
#[derive(Debug)]
pub struct ConfigSubscriber {
    pub format: pb::Format,
    pub path: Vec<String>,
    pub tx: mpsc::Sender<pb::ConfigEvent>,
}

/// Segment-wise prefix match, the same rule the in-process JSON batch
/// subscriptions use: every `prefix` segment equals the corresponding
/// leading `path` segment. An empty prefix matches everything.
pub fn path_has_prefix(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len() && prefix.iter().zip(path.iter()).all(|(pre, seg)| pre == seg)
}

#[derive(Debug)]
pub struct ConfigSubscribeService {
    pub tx: mpsc::Sender<Message>,
}

#[tonic::async_trait]
impl pb::config_service_server::ConfigService for ConfigSubscribeService {
    type SubscribeStream = ReceiverStream<Result<pb::ConfigEvent, tonic::Status>>;

    async fn subscribe(
        &self,
        request: tonic::Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, tonic::Status> {
        let request = request.into_inner();
        let format = pb::Format::try_from(request.format).map_err(|_| {
            tonic::Status::invalid_argument(format!("unknown format {}", request.format))
        })?;

        let (bus_tx, mut bus_rx) = mpsc::channel::<pb::ConfigEvent>(EVENT_BUFFER);
        let register = ConfigSubscribeRequest {
            format,
            path: request.path,
            tx: bus_tx,
        };
        self.tx
            .send(Message::ConfigSubscribe(register))
            .await
            .map_err(|_| tonic::Status::unavailable("config manager unavailable"))?;

        // Forward manager deliveries to the response stream. The
        // `closed()` arm tears the bus down promptly when the client
        // disconnects, so the manager notices (try_send error) on its
        // next delivery instead of buffering toward a dead peer.
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = bus_rx.recv() => match event {
                        Some(event) => {
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                    _ = tx.closed() => break,
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_prefix_matches_everything() {
        assert!(path_has_prefix(&segs(&["router", "bgp"]), &[]));
        assert!(path_has_prefix(&[], &[]));
    }

    #[test]
    fn prefix_matches_by_leading_segments() {
        let path = segs(&["interface", "eth0", "mtu", "9000"]);
        assert!(path_has_prefix(&path, &segs(&["interface"])));
        assert!(path_has_prefix(&path, &segs(&["interface", "eth0"])));
        assert!(!path_has_prefix(&path, &segs(&["interface", "eth1"])));
        assert!(!path_has_prefix(&path, &segs(&["router"])));
    }

    #[test]
    fn prefix_longer_than_path_does_not_match() {
        let path = segs(&["router", "bgp"]);
        assert!(!path_has_prefix(&path, &segs(&["router", "bgp", "65001"])));
    }
}
