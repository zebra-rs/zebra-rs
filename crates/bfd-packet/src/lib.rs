//! BFD control packet codec (RFC 5880).
//!
//! Provides [`ControlPacket`] with `parse(&[u8])` and `emit(&mut BytesMut)`.
//! Structural validation per RFC 5880 §6.8.6 is performed at parse time;
//! stateful checks (discriminator demux, session role, state transitions)
//! remain the caller's responsibility.

mod auth;
mod flags;
mod packet;
mod typ;

pub use auth::AuthSection;
pub use flags::{StateFlags, VersDiag};
pub use packet::{ControlPacket, MIN_LEN, ParseError};
pub use typ::{AuthType, Diag, State};
