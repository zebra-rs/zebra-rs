//! Registering an owned descriptor with the tokio reactor.
//!
//! tokio 1.53.3 deprecated `AsyncFd::new` / `AsyncFd::with_interest` in
//! favor of the `unsafe` `AsyncFd::register` / `register_with_interest`
//! (tokio-rs/tokio#8587): a descriptor the reactor watches must stay open,
//! and stay the same descriptor, for as long as the `AsyncFd` lives, which
//! a bare `AsRawFd` (a plain `RawFd`, say) cannot promise. Every `AsyncFd`
//! here wraps a type that owns its descriptor, so the promise holds by
//! construction; these two functions are the one place it is argued.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// A type that owns the file descriptor it reports: the descriptor stays
/// open until the value is dropped, and `as_raw_fd` always returns it.
pub trait OwnsFd: AsRawFd {}

impl OwnsFd for socket2::Socket {}
impl OwnsFd for OwnedFd {}

/// Register `inner` for readable and writable readiness (what
/// `AsyncFd::new` did).
pub fn register<T: OwnsFd>(inner: T) -> io::Result<AsyncFd<T>> {
    // SAFETY: `inner` owns its descriptor (`OwnsFd`) and the `AsyncFd` owns
    // `inner`, so the descriptor stays open, and the same, until the
    // `AsyncFd` drops `inner` or hands it back; nothing here swaps `inner`
    // out through `AsyncFd::get_mut`.
    unsafe { AsyncFd::register(inner) }.map_err(io::Error::from)
}

/// Register `inner` for `interest` only (what `AsyncFd::with_interest`
/// did).
pub fn register_with_interest<T: OwnsFd>(inner: T, interest: Interest) -> io::Result<AsyncFd<T>> {
    // SAFETY: as in [`register`].
    unsafe { AsyncFd::register_with_interest(inner, interest) }.map_err(io::Error::from)
}
