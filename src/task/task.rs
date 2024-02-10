use std::future::Future;
use tokio::sync::mpsc::{self, UnboundedSender};

#[derive(Debug)]
pub struct Task {
    pub tx: UnboundedSender<TaskMessage>,
}

#[derive(Debug)]
pub enum TaskMessage {
    Cancel,
}

impl Task {
    pub fn new<F, Fut>(mut cb: F) -> Task
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            tokio::select! {
                _ = (cb)() => {}
                message = rx.recv() => {
                }
            }
        });
        Task { tx }
    }
}
