use std::fmt::Display;

use bytes::{BufMut, BytesMut};

use crate::auth::AuthSection;
use crate::flags::{StateFlags, VersDiag};
use crate::typ::{Diag, State};

/// Minimum size of a BFD control packet (the mandatory header, with no
/// Authentication Section). RFC 5880 §4.1.
pub const MIN_LEN: usize = 24;

/// BFD protocol version (RFC 5880).
pub const VERSION: u8 = 1;

/// A parsed BFD control packet (RFC 5880 §4.1).
///
/// All intervals are in microseconds, matching the wire encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    pub version: u8,
    pub diag: Diag,
    pub state: State,
    /// Poll bit — set by the sender of a poll sequence (RFC 5880 §6.5).
    pub poll: bool,
    /// Final bit — reply to a poll.
    pub final_bit: bool,
    /// Control Plane Independent (C).
    pub cpi: bool,
    /// Authentication Present (A). Mirrors `auth.is_some()` on emit.
    pub auth_present: bool,
    /// Demand mode (D) — only meaningful once the session is Up.
    pub demand: bool,
    /// Multipoint (M) — RFC 5880 reserves this bit; it must always be 0.
    pub multipoint: bool,
    pub detect_mult: u8,
    pub my_disc: u32,
    pub your_disc: u32,
    pub desired_min_tx_interval: u32,
    pub required_min_rx_interval: u32,
    pub required_min_echo_rx_interval: u32,
    pub auth: Option<AuthSection>,
}

/// Errors surfaced by [`ControlPacket::parse`]. All map to "silently
/// discard" actions in RFC 5880 §6.8.6 (the parser does not log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input slice is shorter than the 24-byte mandatory header.
    TooShort,
    /// Version field is not 1.
    BadVersion(u8),
    /// Length field is < 24 or otherwise structurally invalid.
    BadLength(u8),
    /// Length field exceeds the available input.
    Truncated { declared: u8, actual: usize },
    /// Detect Mult is zero (RFC 5880 §6.8.6).
    ZeroDetectMult,
    /// My Discriminator is zero (RFC 5880 §6.8.6).
    ZeroMyDisc,
    /// Multipoint bit is set (RFC 5880 reserves M; receivers MUST discard).
    MultipointSet,
    /// Auth bit clear but Length > 24 (extra bytes with no auth section).
    ExtraDataNoAuth,
    /// Auth bit set but no auth section bytes follow.
    AuthTruncated,
    /// Auth Len field is inconsistent with the surrounding packet length.
    AuthBadLength { declared: u8, actual: usize },
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "packet shorter than 24-byte BFD header"),
            ParseError::BadVersion(v) => write!(f, "unsupported BFD version {v}"),
            ParseError::BadLength(l) => write!(f, "invalid Length field {l}"),
            ParseError::Truncated { declared, actual } => {
                write!(f, "Length {declared} exceeds buffer of {actual} bytes")
            }
            ParseError::ZeroDetectMult => write!(f, "Detect Mult is zero"),
            ParseError::ZeroMyDisc => write!(f, "My Discriminator is zero"),
            ParseError::MultipointSet => write!(f, "Multipoint (M) bit is set"),
            ParseError::ExtraDataNoAuth => write!(f, "Length > 24 but A bit clear"),
            ParseError::AuthTruncated => write!(f, "A bit set but auth section missing"),
            ParseError::AuthBadLength { declared, actual } => {
                write!(
                    f,
                    "Auth Len {declared} inconsistent with {actual} bytes remaining"
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl ControlPacket {
    /// Parse a BFD control packet from a UDP payload. Performs the
    /// structural checks listed in RFC 5880 §6.8.6 that do not require
    /// session context; session-level validation (discriminator demux,
    /// state checks) is left to the caller.
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < MIN_LEN {
            return Err(ParseError::TooShort);
        }
        let vd = VersDiag::from(input[0]);
        if vd.version() != VERSION {
            return Err(ParseError::BadVersion(vd.version()));
        }
        let sf = StateFlags::from(input[1]);
        let detect_mult = input[2];
        if detect_mult == 0 {
            return Err(ParseError::ZeroDetectMult);
        }
        let length = input[3];
        if (length as usize) < MIN_LEN {
            return Err(ParseError::BadLength(length));
        }
        if (length as usize) > input.len() {
            return Err(ParseError::Truncated {
                declared: length,
                actual: input.len(),
            });
        }
        if sf.multipoint() {
            return Err(ParseError::MultipointSet);
        }
        let my_disc = u32::from_be_bytes(input[4..8].try_into().unwrap());
        if my_disc == 0 {
            return Err(ParseError::ZeroMyDisc);
        }
        let your_disc = u32::from_be_bytes(input[8..12].try_into().unwrap());
        let desired_min_tx = u32::from_be_bytes(input[12..16].try_into().unwrap());
        let required_min_rx = u32::from_be_bytes(input[16..20].try_into().unwrap());
        let required_min_echo_rx = u32::from_be_bytes(input[20..24].try_into().unwrap());

        let auth = if sf.authentication() {
            Some(AuthSection::parse(&input[MIN_LEN..length as usize])?)
        } else {
            if (length as usize) > MIN_LEN {
                return Err(ParseError::ExtraDataNoAuth);
            }
            None
        };

        Ok(Self {
            version: VERSION,
            diag: Diag::from(vd.diag()),
            state: State::from_bits(sf.state()),
            poll: sf.poll(),
            final_bit: sf.final_bit(),
            cpi: sf.cpi(),
            auth_present: sf.authentication(),
            demand: sf.demand(),
            multipoint: false,
            detect_mult,
            my_disc,
            your_disc,
            desired_min_tx_interval: desired_min_tx,
            required_min_rx_interval: required_min_rx,
            required_min_echo_rx_interval: required_min_echo_rx,
            auth,
        })
    }

    /// Encode this packet into `buf`. The Length field is filled in
    /// automatically from the produced byte count; `auth_present` is
    /// derived from `auth.is_some()` to keep the two consistent on the
    /// wire.
    pub fn emit(&self, buf: &mut BytesMut) {
        let auth_on_wire = self.auth.is_some();
        let vd = VersDiag::new()
            .with_version(self.version)
            .with_diag(u8::from(self.diag) & 0b0001_1111);
        let sf = StateFlags::new()
            .with_state(u8::from(self.state))
            .with_poll(self.poll)
            .with_final_bit(self.final_bit)
            .with_cpi(self.cpi)
            .with_authentication(auth_on_wire)
            .with_demand(self.demand)
            .with_multipoint(self.multipoint);

        let start = buf.len();
        buf.put_u8(vd.into());
        buf.put_u8(sf.into());
        buf.put_u8(self.detect_mult);
        buf.put_u8(0); // Length placeholder, fixed up below.
        buf.put_u32(self.my_disc);
        buf.put_u32(self.your_disc);
        buf.put_u32(self.desired_min_tx_interval);
        buf.put_u32(self.required_min_rx_interval);
        buf.put_u32(self.required_min_echo_rx_interval);
        if let Some(auth) = &self.auth {
            auth.emit(buf);
        }
        let total = (buf.len() - start) as u8;
        buf[start + 3] = total;
    }
}

impl Default for ControlPacket {
    fn default() -> Self {
        Self {
            version: VERSION,
            diag: Diag::None,
            state: State::Down,
            poll: false,
            final_bit: false,
            cpi: false,
            auth_present: false,
            demand: false,
            multipoint: false,
            detect_mult: 3,
            my_disc: 0,
            your_disc: 0,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_rx_interval: 0,
            auth: None,
        }
    }
}

impl Display for ControlPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BFD v{} state={} diag={} mult={} my={:#010x} your={:#010x} \
             desired-tx={}us req-rx={}us req-echo-rx={}us \
             [P={} F={} C={} A={} D={} M={}]",
            self.version,
            self.state,
            self.diag,
            self.detect_mult,
            self.my_disc,
            self.your_disc,
            self.desired_min_tx_interval,
            self.required_min_rx_interval,
            self.required_min_echo_rx_interval,
            self.poll as u8,
            self.final_bit as u8,
            self.cpi as u8,
            self.auth_present as u8,
            self.demand as u8,
            self.multipoint as u8,
        )
    }
}
