#![allow(dead_code)]
use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task;

#[derive(Debug)]
pub struct Task<T> {
    join_handle: task::JoinHandle<T>,
    detached: bool,
}

impl<T> Task<T> {
    pub fn spawn<Fut>(future: Fut) -> Task<T>
    where
        Fut: Future<Output = T> + Send + 'static,
        Fut::Output: Send + 'static,
    {
        Task {
            join_handle: task::spawn(future),
            detached: false,
        }
    }

    pub fn detach(&mut self) {
        self.detached = true;
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if !self.detached {
            self.join_handle.abort();
        }
    }
}

#[derive(Debug)]
pub struct Timer {
    pub tx: UnboundedSender<TimerMessage>,
}

#[derive(Debug)]
pub enum TimerMessage {
    Refresh,
}

#[derive(PartialEq)]
pub enum TimerType {
    Once,
    Infinite,
}

impl Timer {
    pub fn new<F, Fut>(duration: Duration, typ: TimerType, mut cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(duration);
            _ = interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        (cb)().await;
                        if typ == TimerType::Once {
                            break;
                        }
                    }
                    message = rx.recv() => {
                        match message {
                            Some(TimerMessage::Refresh)=> {
                                interval = tokio::time::interval(duration);
                                _ = interval.tick().await;
                            }
                            None => break,
                        }
                    }
                }
            }
        });
        Timer { tx }
    }

    pub fn second(sec: u64) -> Duration {
        Duration::new(sec, 0)
    }

    pub fn refresh(&self) {
        let _ = self.tx.send(TimerMessage::Refresh);
    }
}
