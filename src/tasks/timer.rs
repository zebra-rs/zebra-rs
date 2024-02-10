use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};

#[derive(Debug)]
pub struct Timer {
    pub tx: UnboundedSender<TimerMessage>,
}

#[derive(Debug)]
pub enum TimerMessage {
    Cancel,
    Reset,
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
                            Some(TimerMessage::Cancel) => {
                                break;
                            }
                            Some(TimerMessage::Reset)=> {
                                interval = tokio::time::interval(duration);
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
}
