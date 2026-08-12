//! External show providers over gRPC (`zebra.show.v1`).
//!
//! The reverse of the vty `Show` service: an out-of-process feature
//! daemon opens `Provide`, names the show trees it serves (the same
//! keys in-process daemons pass to `ConfigManager::subscribe_show`,
//! e.g. `"firewall"` / `"ipsec"`), and answers the vty's orders over
//! the stream. The bridge task below is the provider's in-process
//! stand-in: it owns a `DisplayRequest` channel registered in the
//! manager's show registry and translates requests into `ShowOrder`s
//! and chunks back into per-request responses.
//!
//! Lifecycle: registration replaces any previous provider of the same
//! name; when the stream ends the names are withdrawn (guarded by a
//! `same_channel` check so a replaced provider's exit cannot remove
//! its successor) and outstanding orders' response buses are dropped,
//! which the vty surfaces as an unanswered command instead of a hang.

use std::collections::HashMap;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Response;

use super::api::{DisplayRequest, Message};
use super::paths::path_from_command;

pub mod pb {
    tonic::include_proto!("zebra.show.v1");
}

pub use pb::show_provider_service_server::ShowProviderServiceServer;

/// Undelivered-order buffer toward one provider. Show traffic is
/// human-driven; this only fills when the provider stops reading.
const ORDER_BUFFER: usize = 16;

#[derive(Debug)]
pub struct ShowProviderBridge {
    pub tx: mpsc::Sender<Message>,
}

#[tonic::async_trait]
impl pb::show_provider_service_server::ShowProviderService for ShowProviderBridge {
    type ProvideStream = ReceiverStream<Result<pb::ShowOrder, tonic::Status>>;

    async fn provide(
        &self,
        request: tonic::Request<tonic::Streaming<pb::ProviderMessage>>,
    ) -> Result<Response<Self::ProvideStream>, tonic::Status> {
        let mut inbound = request.into_inner();

        // The stream must open with a Register naming the show trees.
        let names = match inbound.message().await? {
            Some(pb::ProviderMessage {
                msg: Some(pb::provider_message::Msg::Register(register)),
            }) => register.name,
            _ => {
                return Err(tonic::Status::invalid_argument(
                    "first provider message must be Register",
                ));
            }
        };
        if names.is_empty() {
            return Err(tonic::Status::invalid_argument(
                "Register must name at least one show tree",
            ));
        }

        let (display_tx, display_rx) = mpsc::unbounded_channel::<DisplayRequest>();
        for name in names.iter() {
            self.tx
                .send(Message::SubscribeShow {
                    name: name.clone(),
                    tx: display_tx.clone(),
                })
                .await
                .map_err(|_| tonic::Status::unavailable("config manager unavailable"))?;
        }
        tracing::info!(names = ?names, "show provider registered");

        let (orders_tx, orders_rx) = mpsc::channel(ORDER_BUFFER);
        tokio::spawn(bridge(
            display_rx,
            display_tx,
            inbound,
            orders_tx,
            names,
            self.tx.clone(),
        ));
        Ok(Response::new(ReceiverStream::new(orders_rx)))
    }
}

/// Per-provider pump: vty `DisplayRequest`s out as orders, provider
/// chunks back into the per-request response buses. Runs until the
/// provider stream ends (disconnect, error, or a protocol violation),
/// then withdraws the registrations.
async fn bridge(
    mut display_rx: mpsc::UnboundedReceiver<DisplayRequest>,
    display_tx: mpsc::UnboundedSender<DisplayRequest>,
    mut inbound: tonic::Streaming<pb::ProviderMessage>,
    orders_tx: mpsc::Sender<Result<pb::ShowOrder, tonic::Status>>,
    names: Vec<String>,
    manager_tx: mpsc::Sender<Message>,
) {
    let mut next_id: u64 = 0;
    // Response bus of each outstanding order. Dropping an entry closes
    // that request's stream; dropping the whole map at exit is what
    // turns provider death into per-command errors instead of hangs.
    let mut pending: HashMap<u64, mpsc::Sender<String>> = HashMap::new();
    loop {
        tokio::select! {
            req = display_rx.recv() => {
                // Unreachable in practice (we hold `display_tx`), but
                // a closed channel would make recv() a busy loop.
                let Some(req) = req else { break };
                next_id += 1;
                let (path, args) = path_from_command(&req.paths);
                pending.insert(next_id, req.resp);
                let order = pb::ShowOrder {
                    id: next_id,
                    path,
                    args: args.0.into(),
                    json: req.json,
                };
                if orders_tx.send(Ok(order)).await.is_err() {
                    break;
                }
            }
            msg = inbound.message() => {
                match msg {
                    Ok(Some(pb::ProviderMessage {
                        msg: Some(pb::provider_message::Msg::Chunk(chunk)),
                    })) => {
                        if let Some(resp) = pending.get(&chunk.id) {
                            let _ = resp.send(chunk.text).await;
                        }
                        if chunk.eof {
                            pending.remove(&chunk.id);
                        }
                    }
                    Ok(Some(pb::ProviderMessage {
                        msg: Some(pb::provider_message::Msg::Register(_)),
                    })) => {
                        tracing::warn!(
                            names = ?names,
                            "show provider sent a second Register; closing stream"
                        );
                        break;
                    }
                    Ok(Some(pb::ProviderMessage { msg: None })) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
    for name in names.iter() {
        let _ = manager_tx
            .send(Message::UnsubscribeShow {
                name: name.clone(),
                tx: display_tx.clone(),
            })
            .await;
    }
    tracing::info!(names = ?names, "show provider withdrawn");
}
