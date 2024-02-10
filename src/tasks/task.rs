use std::future::Future;
use tokio::task;

#[derive(Debug)]
pub struct Task<T> {
    join_handle: task::JoinHandle<T>,
    detached: bool,
}

impl<T> Task<T> {
    pub fn spawn<Fut: Future<Output = T>>(future: Fut) -> Task<T>
    where
        Fut: Future + Send + 'static,
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
