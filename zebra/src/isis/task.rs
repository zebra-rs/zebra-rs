#![allow(dead_code)]
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
    tx: UnboundedSender<TimerMessage>,
    duration: Duration,              // Store the timer duration
    last_reset: Arc<Mutex<Instant>>, // Track the last reset time
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
    pub fn new<F, Fut>(sec: u64, typ: TimerType, mut cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        // println!("Timer create: duration {}", sec);
        let duration = Duration::new(sec, 0);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let last_reset = Arc::new(Mutex::new(Instant::now()));

        let last_reset_clone = last_reset.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(duration);
            _ = interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // println!("Timer expired {}", sec);
                        (cb)().await;
                        if typ == TimerType::Once {
                            break;
                        }
                    }
                    message = rx.recv() => {
                        match message {
                            Some(TimerMessage::Refresh)=> {
                                *last_reset_clone.lock().unwrap() = Instant::now();
                                interval = tokio::time::interval(duration);
                                _ = interval.tick().await;
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Timer {
            tx,
            duration,
            last_reset,
        }
    }

    pub fn once<F, Fut>(sec: u64, cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        Self::new(sec, TimerType::Once, cb)
    }

    /// Refresh the timer (resets the timer countdown)
    pub fn refresh(&self) {
        let _ = self.tx.send(TimerMessage::Refresh);
    }

    pub fn second(sec: u64) -> Duration {
        Duration::new(sec, 0)
    }

    /// Get the remaining seconds until the next tick
    pub fn rem_sec(&self) -> u64 {
        let elapsed = self.last_reset.lock().unwrap().elapsed();
        if elapsed >= self.duration {
            0
        } else {
            (self.duration - elapsed).as_secs()
        }
    }
}
