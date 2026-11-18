//! Handing a change of CONFIG_DB to the process that writes it.
//!
//! `proto/configdb.proto` has the why and the wire. This is the meeting
//! point between the two sides inside the daemon:
//!
//! - the config manager, whose `commit` has a patch to be written and
//!   waits for what became of it ([`WriterHub::write`]);
//! - the writer, a process on the device that asks for the next order
//!   and reports on it ([`WriterHub::wait`], [`WriterHub::done`]),
//!   through the gRPC service at the end of this file.
//!
//! The hub does not know what a patch is, nor who the writer is. It
//! knows whether one is there: a writer that is waiting, or was a
//! moment ago and is between two waits.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, oneshot};
use tonic::Response;

pub mod pb {
    tonic::include_proto!("zebra.configdb.v1");
}
pub use pb::writer_service_server::WriterServiceServer;

/// How long a writer may be between two waits and still be there: it
/// is applying an order, or calling again.
const PRESENT_FOR: Duration = Duration::from_secs(15);

/// Why a change is not written when no writer is there. The one refusal
/// after which CONFIG_DB is certainly as it was.
pub const NO_WRITER: &str = "no writer of CONFIG_DB is connected";

/// The wait of a writer that names none.
const DEFAULT_WAIT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct WriterHub {
    next_id: AtomicU64,
    /// Orders no writer has taken yet, oldest first.
    queue: Mutex<Vec<(u64, String)>>,
    /// Told when an order is queued.
    queued: Notify,
    /// Orders taken or queued, each with where its answer goes.
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<(), String>>>>,
    /// Writers waiting now, and when one last was.
    waiting: AtomicUsize,
    last_wait: Mutex<Option<Instant>>,
}

impl WriterHub {
    /// Whether a writer is there to take an order.
    pub fn present(&self) -> bool {
        self.waiting.load(Ordering::SeqCst) > 0
            || self
                .last_wait
                .lock()
                .unwrap()
                .is_some_and(|at| at.elapsed() < PRESENT_FOR)
    }

    /// Have `patch` written, and wait up to `timeout` for the answer.
    /// `Err` is why it was not written, for the operator.
    pub async fn write(&self, patch: String, timeout: Duration) -> Result<(), String> {
        if !self.present() {
            return Err(NO_WRITER.to_string());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        self.queue.lock().unwrap().push((id, patch));
        self.queued.notify_one();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err("the writer of CONFIG_DB went away".to_string()),
            Err(_) => {
                // Not waited for any longer: an answer that still comes
                // has nobody to go to, and an order not yet taken is
                // not to be.
                self.pending.lock().unwrap().remove(&id);
                self.queue
                    .lock()
                    .unwrap()
                    .retain(|(queued, _)| *queued != id);
                Err(format!(
                    "the writer of CONFIG_DB did not answer in {} seconds; \
                     CONFIG_DB may or may not have been changed",
                    timeout.as_secs()
                ))
            }
        }
    }

    /// The next order, waiting up to `timeout` for one.
    pub async fn wait(&self, timeout: Duration) -> Option<(u64, String)> {
        struct Waiting<'a>(&'a WriterHub);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                self.0.waiting.fetch_sub(1, Ordering::SeqCst);
                *self.0.last_wait.lock().unwrap() = Some(Instant::now());
            }
        }
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let _waiting = Waiting(self);

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Asked for before the queue is looked at: an order queued
            // between the look and the wait is not missed.
            let queued = self.queued.notified();
            {
                let mut queue = self.queue.lock().unwrap();
                if !queue.is_empty() {
                    return Some(queue.remove(0));
                }
            }
            if tokio::time::timeout_at(deadline, queued).await.is_err() {
                return None;
            }
        }
    }

    /// The writer's answer to order `id`. `false` when nobody waits for
    /// it: the commit gave up, or there was no such order.
    pub fn done(&self, id: u64, answer: Result<(), String>) -> bool {
        match self.pending.lock().unwrap().remove(&id) {
            Some(tx) => tx.send(answer).is_ok(),
            None => false,
        }
    }
}

/// `zebra.configdb.v1.WriterService`.
pub struct WriterBridge {
    pub hub: std::sync::Arc<WriterHub>,
}

#[tonic::async_trait]
impl pb::writer_service_server::WriterService for WriterBridge {
    async fn wait(
        &self,
        request: tonic::Request<pb::WaitRequest>,
    ) -> Result<Response<pb::Order>, tonic::Status> {
        let timeout = match request.get_ref().timeout_seconds {
            0 => DEFAULT_WAIT,
            seconds => Duration::from_secs(seconds.into()),
        };
        let order = match self.hub.wait(timeout).await {
            Some((id, patch)) => pb::Order { id, patch },
            None => pb::Order::default(),
        };
        Ok(Response::new(order))
    }

    async fn done(
        &self,
        request: tonic::Request<pb::Result>,
    ) -> Result<Response<pb::DoneReply>, tonic::Status> {
        let result = request.into_inner();
        let answer = if result.ok {
            Ok(())
        } else if result.message.trim().is_empty() {
            Err("the writer of CONFIG_DB refused the change".to_string())
        } else {
            Err(result.message)
        };
        if !self.hub.done(result.id, answer) {
            return Err(tonic::Status::not_found(format!(
                "no commit is waiting for order {}",
                result.id
            )));
        }
        Ok(Response::new(pb::DoneReply {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const SOON: Duration = Duration::from_secs(5);

    /// With no writer waiting, a change is refused at once.
    #[tokio::test]
    async fn no_writer_is_a_refusal() {
        let hub = WriterHub::default();
        assert!(!hub.present());
        assert_eq!(
            hub.write("[]".into(), SOON).await,
            Err("no writer of CONFIG_DB is connected".to_string())
        );
    }

    /// The writer takes the order and its answer is the commit's.
    #[tokio::test]
    async fn the_writer_s_answer_is_the_answer() {
        let hub = Arc::new(WriterHub::default());
        for (answer, expected) in [
            (Ok(()), Ok(())),
            (
                Err("no such port".to_string()),
                Err("no such port".to_string()),
            ),
        ] {
            let writer = {
                let hub = hub.clone();
                tokio::spawn(async move {
                    let (id, patch) = hub.wait(SOON).await.expect("an order");
                    assert_eq!(patch, r#"[{"op":"remove","path":"/VLAN"}]"#);
                    assert!(hub.done(id, answer));
                })
            };
            // Let the writer get to its wait.
            tokio::task::yield_now().await;
            assert!(hub.present());
            let got = hub
                .write(r#"[{"op":"remove","path":"/VLAN"}]"#.into(), SOON)
                .await;
            assert_eq!(got, expected);
            writer.await.unwrap();
        }
    }

    /// A writer between two waits is still there, and the order it
    /// finds at its next wait was queued meanwhile.
    #[tokio::test]
    async fn an_order_waits_for_the_writer_s_next_call() {
        let hub = Arc::new(WriterHub::default());
        assert_eq!(hub.wait(Duration::from_millis(1)).await, None);
        assert!(hub.present(), "just waited");
        let writer = {
            let hub = hub.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let (id, _) = hub.wait(SOON).await.expect("the queued order");
                hub.done(id, Ok(()));
            })
        };
        assert_eq!(hub.write("[]".into(), SOON).await, Ok(()));
        writer.await.unwrap();
    }

    /// No answer in time is a refusal that says CONFIG_DB may have been
    /// changed. An order never taken is withdrawn, and a late answer
    /// has nobody waiting.
    #[tokio::test(start_paused = true)]
    async fn no_answer_in_time() {
        let hub = Arc::new(WriterHub::default());
        assert_eq!(hub.wait(Duration::from_millis(1)).await, None);
        let refused = hub.write("[]".into(), Duration::from_secs(3)).await;
        assert!(refused.unwrap_err().contains("did not answer in 3 seconds"));
        assert_eq!(hub.wait(Duration::from_millis(1)).await, None, "withdrawn");

        // Taken, and answered too late.
        let taker = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.wait(Duration::from_secs(60)).await })
        };
        tokio::task::yield_now().await;
        assert!(
            hub.write("[]".into(), Duration::from_secs(3))
                .await
                .is_err()
        );
        let (id, _) = taker.await.unwrap().expect("taken");
        assert!(!hub.done(id, Ok(())));
        assert!(!hub.done(99, Ok(())));
    }

    /// A writer that has not called for a while is gone.
    #[tokio::test]
    async fn a_writer_that_stopped_calling_is_gone() {
        let hub = WriterHub::default();
        assert_eq!(hub.wait(Duration::from_millis(1)).await, None);
        assert!(hub.present());
        *hub.last_wait.lock().unwrap() =
            Some(Instant::now() - PRESENT_FOR - Duration::from_secs(1));
        assert!(!hub.present());
    }
}
