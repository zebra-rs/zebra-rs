use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};

pub struct Timer {
    pub tx: UnboundedSender<TimerMessage>,
}

pub enum TimerMessage {
    Cancel,
    Reset,
}

#[derive(PartialEq)]
pub enum TimerType {
    Once,
    Infinite,
}

pub struct Task {
    pub tx: UnboundedSender<TimerMessage>,
}

impl Task {
    pub fn new<F, Fut>(duration: Duration, typ: TimerType, callback: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static + Copy,
        Fut: Future<Output = ()> + Send,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(duration);
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        (callback)().await;
                        if typ == TimerType::Once {
                            break;
                        }
                    }
                    msg = rx.recv() => {
                        match msg {
                            Some(TimerMessage::Cancel) => {
                                break;
                            }
                            Some(TimerMessage::Reset)=> {
                                timer = tokio::time::interval(duration);
                            }
                            None => break,
                        }
                    }
                }
            }
        });
        Task { tx }
    }
}

impl Timer {
    pub fn new<F, Fut>(duration: Duration, typ: TimerType, callback: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static + Copy,
        Fut: Future<Output = ()> + Send,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(duration);
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        (callback)().await;
                        if typ == TimerType::Once {
                            break;
                        }
                    }
                    msg = rx.recv() => {
                        match msg {
                            Some(TimerMessage::Cancel) => {
                                break;
                            }
                            Some(TimerMessage::Reset)=> {
                                timer = tokio::time::interval(duration);
                            }
                            None => break,
                        }
                    }
                }
            }
        });
        Timer { tx }
    }
}
