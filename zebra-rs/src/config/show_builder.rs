use std::collections::HashMap;

/// Chained registration of show-command paths to render callbacks.
/// Generic over the per-daemon callback type (each daemon's
/// `ShowCallback` takes its own state struct), so every module
/// builds its dispatch map through the same builder:
///
/// ```ignore
/// self.show_cb = Builder::<ShowCallback>::default()
///     .path("/show/foo")
///     .set(show_foo)
///     .map();
/// ```
pub struct Builder<T> {
    path: String,
    map: HashMap<String, T>,
}

// Derived `Default` would require `T: Default`, which fn pointers
// don't implement.
impl<T> Default for Builder<T> {
    fn default() -> Self {
        Self {
            path: String::new(),
            map: HashMap::new(),
        }
    }
}

impl<T> Builder<T> {
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.into();
        self
    }

    pub fn set(mut self, cb: T) -> Self {
        self.map.insert(self.path.clone(), cb);
        self
    }

    pub fn map(self) -> HashMap<String, T> {
        self.map
    }
}
