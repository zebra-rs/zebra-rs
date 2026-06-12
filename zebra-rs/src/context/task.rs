use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task;

#[derive(Debug)]
pub struct Task<T> {
    /// `None` after [`Task::detach`] — the abort-on-drop is disarmed
    /// and the spawned future runs to completion in the background.
    join_handle: Option<task::JoinHandle<T>>,
}

impl<T> Task<T> {
    pub fn spawn<Fut>(future: Fut) -> Task<T>
    where
        Fut: Future<Output = T> + Send + 'static,
        Fut::Output: Send + 'static,
    {
        Task {
            join_handle: Some(task::spawn(future)),
        }
    }

    /// Consume the handle without aborting the task: the spawned
    /// future keeps running to completion in the background (tokio
    /// detaches a task when its `JoinHandle` is dropped). Used where
    /// a teardown must let the task finish in-flight work — e.g. a
    /// BGP connection writer draining a queued NOTIFICATION onto the
    /// wire before the socket closes; aborting it there sent the FIN
    /// *instead of* the NOTIFICATION.
    pub fn detach(mut self) {
        let _ = self.join_handle.take();
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if let Some(join_handle) = &self.join_handle {
            join_handle.abort();
        }
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

    /// Time remaining until the next fire. `Once` timers count
    /// down from `duration` to zero and stay at zero after firing;
    /// `Infinite` / `ImmediateRepeat` reset on each tick (and on
    /// every `refresh()`) so this is "time until next tick".
    pub fn remaining(&self) -> Duration {
        let elapsed = self.last_reset.lock().unwrap().elapsed();
        self.duration.saturating_sub(elapsed)
    }

    /// `remaining()` truncated to whole seconds. Kept as a thin
    /// convenience for call sites that just want the integer.
    pub fn rem_sec(&self) -> u64 {
        self.remaining().as_secs()
    }

    /// Get the timer's full duration in seconds (the value it was set to)
    pub fn duration_sec(&self) -> u64 {
        self.duration.as_secs()
    }
}
