use std::future::Future;
use std::time::Duration;

#[derive(Debug)]
pub struct Timer {
    pub created_at: tokio::time::Instant,
    pub duration: Duration,
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
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(duration);
            _ = interval.tick().await;
            loop {
                interval.tick().await;
                (cb)().await;
                if typ == TimerType::Once {
                    break;
                }
            }
        });
        Timer {
            created_at: tokio::time::Instant::now(),
            duration,
        }
    }

    pub fn second(sec: u64) -> Duration {
        Duration::new(sec, 0)
    }

    pub fn remaining(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        let nanos = self.duration.as_nanos();
        if nanos == 0 {
            return Duration::ZERO;
        }
        let elapsed_nanos = elapsed.as_nanos();
        let next_fire = ((elapsed_nanos / nanos) + 1) * nanos;
        Duration::from_nanos((next_fire - elapsed_nanos) as u64)
    }
}
