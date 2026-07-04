use bytes::{BufMut, BytesMut};

use crate::packet::ParseError;
use crate::typ::AuthType;

/// Authentication Section (RFC 5880 §4.2 – §4.4).
///
/// This parses the section but does not validate digests, sequence
/// numbers, or password contents — the session layer decides whether to
/// honour or drop authenticated packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSection {
    /// Simple Password (RFC 5880 §4.2). Password length 1–16 bytes.
    SimplePassword { key_id: u8, password: Vec<u8> },
    /// Keyed MD5 (RFC 5880 §4.3); `meticulous` selects type 3 over type 2.
    KeyedMd5 {
        meticulous: bool,
        key_id: u8,
        seq_num: u32,
        digest: [u8; 16],
    },
    /// Keyed SHA-1 (RFC 5880 §4.4); `meticulous` selects type 5 over type 4.
    KeyedSha1 {
        meticulous: bool,
        key_id: u8,
        seq_num: u32,
        digest: [u8; 20],
    },
    /// Auth Type values reserved or unknown to this implementation.
    Unknown { auth_type: u8, data: Vec<u8> },
}

const HDR: usize = 2; // Auth Type + Auth Len
const MD5_LEN: usize = 24;
const SHA1_LEN: usize = 28;
const MIN_SIMPLE: usize = 4; // type+len+key_id+1-byte password

impl AuthSection {
    /// Parse an authentication section. `input` is the slice of the packet
    /// starting at the Auth Type byte (offset 24 in the full control packet)
    /// and ending at the byte indicated by the control packet's `Length`
    /// field.
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < HDR {
            return Err(ParseError::AuthTruncated);
        }
        let auth_type = input[0];
        let auth_len = input[1] as usize;
        if auth_len < HDR || auth_len > input.len() {
            return Err(ParseError::AuthBadLength {
                declared: input[1],
                actual: input.len(),
            });
        }
        let body = &input[HDR..auth_len];
        match AuthType::from(auth_type) {
            AuthType::SimplePassword => {
                if auth_len < MIN_SIMPLE {
                    return Err(ParseError::AuthBadLength {
                        declared: input[1],
                        actual: input.len(),
                    });
                }
                Ok(AuthSection::SimplePassword {
                    key_id: body[0],
                    password: body[1..].to_vec(),
                })
            }
            t @ (AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5) => {
                if auth_len != MD5_LEN {
                    return Err(ParseError::AuthBadLength {
                        declared: input[1],
                        actual: input.len(),
                    });
                }
                // body = [key_id, reserved, seq(4), digest(16)]
                let key_id = body[0];
                let seq_num = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
                let mut digest = [0u8; 16];
                digest.copy_from_slice(&body[6..22]);
                Ok(AuthSection::KeyedMd5 {
                    meticulous: matches!(t, AuthType::MeticulousKeyedMd5),
                    key_id,
                    seq_num,
                    digest,
                })
            }
            t @ (AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1) => {
                if auth_len != SHA1_LEN {
                    return Err(ParseError::AuthBadLength {
                        declared: input[1],
                        actual: input.len(),
                    });
                }
                let key_id = body[0];
                let seq_num = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
                let mut digest = [0u8; 20];
                digest.copy_from_slice(&body[6..26]);
                Ok(AuthSection::KeyedSha1 {
                    meticulous: matches!(t, AuthType::MeticulousKeyedSha1),
                    key_id,
                    seq_num,
                    digest,
                })
            }
            AuthType::Reserved(t) => Ok(AuthSection::Unknown {
                auth_type: t,
                data: body.to_vec(),
            }),
        }
    }

    /// Length on the wire (the value placed in the Auth Len field).
    pub fn wire_len(&self) -> u8 {
        match self {
            AuthSection::SimplePassword { password, .. } => (3 + password.len()) as u8,
            AuthSection::KeyedMd5 { .. } => MD5_LEN as u8,
            AuthSection::KeyedSha1 { .. } => SHA1_LEN as u8,
            AuthSection::Unknown { data, .. } => (HDR + data.len()) as u8,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        let len = self.wire_len();
        match self {
            AuthSection::SimplePassword { key_id, password } => {
                buf.put_u8(AuthType::SimplePassword.into());
                buf.put_u8(len);
                buf.put_u8(*key_id);
                buf.put_slice(password);
            }
            AuthSection::KeyedMd5 {
                meticulous,
                key_id,
                seq_num,
                digest,
            } => {
                let t = if *meticulous {
                    AuthType::MeticulousKeyedMd5
                } else {
                    AuthType::KeyedMd5
                };
                buf.put_u8(t.into());
                buf.put_u8(len);
                buf.put_u8(*key_id);
                buf.put_u8(0); // Reserved
                buf.put_u32(*seq_num);
                buf.put_slice(digest);
            }
            AuthSection::KeyedSha1 {
                meticulous,
                key_id,
                seq_num,
                digest,
            } => {
                let t = if *meticulous {
                    AuthType::MeticulousKeyedSha1
                } else {
                    AuthType::KeyedSha1
                };
                buf.put_u8(t.into());
                buf.put_u8(len);
                buf.put_u8(*key_id);
                buf.put_u8(0);
                buf.put_u32(*seq_num);
                buf.put_slice(digest);
            }
            AuthSection::Unknown { auth_type, data } => {
                buf.put_u8(*auth_type);
                buf.put_u8(len);
                buf.put_slice(data);
            }
        }
    }
}
