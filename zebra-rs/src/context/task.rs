use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task;

#[derive(Debug)]
pub struct Task<T> {
    join_handle: task::JoinHandle<T>,
}

impl<T> Task<T> {
    pub fn spawn<Fut>(future: Fut) -> Task<T>
    where
        Fut: Future<Output = T> + Send + 'static,
        Fut::Output: Send + 'static,
    {
        Task {
            join_handle: task::spawn(future),
        }
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

#[derive(Debug)]
pub struct Timer {
    tx: UnboundedSender<TimerMessage>,
    duration: Duration,              // Store the timer duration
    last_reset: Arc<Mutex<Instant>>, // Track the last reset time
    join_handle: task::JoinHandle<()>,
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

#[derive(Debug)]
pub enum TimerMessage {
    Refresh,
}

#[derive(PartialEq)]
pub enum TimerType {
    Once,
    Infinite,
    ImmediateRepeat,
}

impl Timer {
    pub fn new<F, Fut>(sec: u64, typ: TimerType, cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        // Make it sure sec is not zero.
        let sec = if sec == 0 { 1 } else { sec };
        Self::new_dur(Duration::new(sec, 0), typ, cb)
    }

    pub fn new_dur<F, Fut>(duration: Duration, typ: TimerType, mut cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let last_reset = Arc::new(Mutex::new(Instant::now()));

        let last_reset_clone = last_reset.clone();
        let join_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(duration);
            if typ != TimerType::ImmediateRepeat {
                _ = interval.tick().await;
            }
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // println!("Timer expired {}", sec);
                        // Update last_reset for repeating timers so rem_sec() works correctly
                        if typ != TimerType::Once {
                            *last_reset_clone.lock().unwrap() = Instant::now();
                        }
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
            join_handle,
        }
    }

    pub fn once<F, Fut>(sec: u64, cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        Self::new(sec, TimerType::Once, cb)
    }

    pub fn once_ms<F, Fut>(ms: u64, cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        Self::new_dur(Duration::from_millis(ms.max(1)), TimerType::Once, cb)
    }

    pub fn repeat<F, Fut>(sec: u64, cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        Self::new(sec, TimerType::Infinite, cb)
    }

    pub fn immediate_repeat<F, Fut>(sec: u64, cb: F) -> Timer
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        Self::new(sec, TimerType::ImmediateRepeat, cb)
    }

    /// Refresh the timer (resets the timer countdown)
    pub fn refresh(&self) {
        let _ = self.tx.send(TimerMessage::Refresh);
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

    /// Get the timer's full duration in seconds (the value it was set to)
    pub fn duration_sec(&self) -> u64 {
        self.duration.as_secs()
    }
}
