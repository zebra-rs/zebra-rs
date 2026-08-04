//! Minimal client for charon's VICI control interface, used by
//! `show vpn ipsec` — the same channel VyOS's op-mode scripts use
//! (python-vici), rather than scraping `swanctl` text output.
//!
//! Implements exactly the subset the show commands need: the
//! command-event streaming pattern (`list-sas` streams one `list-sa`
//! EVENT per IKE_SA, then an empty CMD_RESPONSE; same for
//! `list-conns`/`list-conn`). Wire protocol per the strongSwan vici
//! README: 32-bit network-order length framing, 8-bit packet types,
//! 8-bit name lengths, message elements as a flat byte stream of
//! typed sections / key-values / lists.

use std::path::Path;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// Packet types.
const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
const EVENT_REGISTER: u8 = 3;
const EVENT_UNREGISTER: u8 = 4;
const EVENT_CONFIRM: u8 = 5;
const EVENT_UNKNOWN: u8 = 6;
const EVENT: u8 = 7;

// Message element types.
const SECTION_START: u8 = 1;
const SECTION_END: u8 = 2;
const KEY_VALUE: u8 = 3;
const LIST_START: u8 = 4;
const LIST_ITEM: u8 = 5;
const LIST_END: u8 = 6;

/// A decoded vici message tree. Sections keep their key order — the
/// show views iterate them in charon's order, like the VyOS scripts
/// iterate python-vici's OrderedDicts.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Nested section: ordered (name, value) pairs.
    Section(Vec<(String, Value)>),
    /// List of scalar items (vici lists cannot nest).
    List(Vec<String>),
    /// Scalar value. Charon emits ASCII here for everything the show
    /// views read.
    Scalar(String),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Section(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Scalar value of a child key, if present.
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Value::Scalar(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Value::List(items)) => items.clone(),
            _ => Vec::new(),
        }
    }

    pub fn entries(&self) -> &[(String, Value)] {
        match self {
            Value::Section(items) => items,
            _ => &[],
        }
    }

    /// Convert to serde_json for the machine-readable show views.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Scalar(s) => serde_json::Value::String(s.clone()),
            Value::List(items) => items
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
            Value::Section(items) => {
                let mut map = serde_json::Map::new();
                for (k, v) in items {
                    map.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(map)
            }
        }
    }
}

// ---------------------------------------------------------------
// Message codec
// ---------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> anyhow::Result<u8> {
        let Some(&b) = self.buf.get(self.pos) else {
            bail!("vici: truncated message");
        };
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
        let Some(chunk) = self.buf.get(self.pos..self.pos + len) else {
            bail!("vici: truncated message");
        };
        self.pos += len;
        Ok(chunk)
    }

    fn name(&mut self) -> anyhow::Result<String> {
        let len = self.u8()? as usize;
        Ok(String::from_utf8_lossy(self.bytes(len)?).into_owned())
    }

    fn value(&mut self) -> anyhow::Result<String> {
        let len = u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()) as usize;
        Ok(String::from_utf8_lossy(self.bytes(len)?).into_owned())
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

/// Decode a message byte stream into a root section.
pub fn parse_message(buf: &[u8]) -> anyhow::Result<Value> {
    let mut r = Reader { buf, pos: 0 };
    let root = parse_section(&mut r, true)?;
    Ok(root)
}

fn parse_section(r: &mut Reader, root: bool) -> anyhow::Result<Value> {
    let mut items: Vec<(String, Value)> = Vec::new();
    loop {
        if r.done() {
            if root {
                return Ok(Value::Section(items));
            }
            bail!("vici: unterminated section");
        }
        match r.u8()? {
            SECTION_START => {
                let name = r.name()?;
                items.push((name, parse_section(r, false)?));
            }
            SECTION_END if !root => return Ok(Value::Section(items)),
            KEY_VALUE => {
                let name = r.name()?;
                items.push((name, Value::Scalar(r.value()?)));
            }
            LIST_START => {
                let name = r.name()?;
                let mut list = Vec::new();
                loop {
                    match r.u8()? {
                        LIST_ITEM => list.push(r.value()?),
                        LIST_END => break,
                        t => bail!("vici: unexpected element {t} in list"),
                    }
                }
                items.push((name, Value::List(list)));
            }
            t => bail!("vici: unexpected element type {t}"),
        }
    }
}

// ---------------------------------------------------------------
// Transport
// ---------------------------------------------------------------

fn named_packet(ptype: u8, name: &str) -> Vec<u8> {
    let mut pkt = vec![ptype, name.len() as u8];
    pkt.extend_from_slice(name.as_bytes());
    pkt
}

async fn send(stream: &mut UnixStream, pkt: &[u8]) -> anyhow::Result<()> {
    stream.write_all(&(pkt.len() as u32).to_be_bytes()).await?;
    stream.write_all(pkt).await?;
    Ok(())
}

async fn recv(stream: &mut UnixStream) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    // The protocol caps segments at 512 KiB; anything larger means a
    // framing bug, so refuse rather than allocate unboundedly.
    if len == 0 || len > 512 * 1024 {
        bail!("vici: bad segment length {len}");
    }
    let mut pkt = vec![0u8; len];
    stream.read_exact(&mut pkt).await?;
    Ok((pkt[0], pkt[1..].to_vec()))
}

/// Run one streamed command: register `event`, issue `command`,
/// collect one decoded message per event, stop at the response.
/// Errors if charon is unreachable or rejects the command/event.
pub async fn streamed_request(
    socket: &Path,
    command: &str,
    event: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect {}", socket.display()))?;

    send(&mut stream, &named_packet(EVENT_REGISTER, event)).await?;
    match recv(&mut stream).await? {
        (EVENT_CONFIRM, _) => {}
        (EVENT_UNKNOWN, _) => bail!("vici: event {event} unknown to charon"),
        (t, _) => bail!("vici: unexpected packet {t} to event registration"),
    }

    send(&mut stream, &named_packet(CMD_REQUEST, command)).await?;
    let mut out = Vec::new();
    loop {
        match recv(&mut stream).await? {
            (EVENT, body) => {
                // 8-bit name length + name, then the message.
                let Some(&name_len) = body.first() else {
                    bail!("vici: empty event packet");
                };
                let msg_at = 1 + name_len as usize;
                if body.len() < msg_at {
                    bail!("vici: truncated event packet");
                }
                out.push(parse_message(&body[msg_at..])?);
            }
            (CMD_RESPONSE, _) => break,
            (CMD_UNKNOWN, _) => bail!("vici: command {command} unknown to charon"),
            (t, _) => bail!("vici: unexpected packet {t} to {command}"),
        }
    }

    // Best effort: the socket is dropped right after either way.
    let _ = send(&mut stream, &named_packet(EVENT_UNREGISTER, event)).await;
    Ok(out)
}

#[cfg(test)]
pub mod test_encode {
    //! Encoding helpers for tests (the client itself only ever sends
    //! empty request messages, so production code needs no encoder).

    use super::*;

    pub fn section(out: &mut Vec<u8>, name: &str, body: impl FnOnce(&mut Vec<u8>)) {
        out.push(SECTION_START);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        body(out);
        out.push(SECTION_END);
    }

    pub fn key_value(out: &mut Vec<u8>, name: &str, value: &str) {
        out.push(KEY_VALUE);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    pub fn list(out: &mut Vec<u8>, name: &str, items: &[&str]) {
        out.push(LIST_START);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        for item in items {
            out.push(LIST_ITEM);
            out.extend_from_slice(&(item.len() as u16).to_be_bytes());
            out.extend_from_slice(item.as_bytes());
        }
        out.push(LIST_END);
    }
}

#[cfg(test)]
mod tests {
    use super::test_encode::*;
    use super::*;

    #[test]
    fn parse_round_trip() {
        let mut buf = Vec::new();
        section(&mut buf, "peer-1", |out| {
            key_value(out, "state", "ESTABLISHED");
            key_value(out, "remote-host", "203.0.113.9");
            list(out, "remote-ts", &["10.0.2.0/24", "10.0.3.0/24"]);
            section(out, "child-sas", |out| {
                section(out, "peer-1-tunnel-1-7", |out| {
                    key_value(out, "name", "peer-1-tunnel-1");
                    key_value(out, "state", "INSTALLED");
                });
            });
        });

        let msg = parse_message(&buf).expect("parses");
        let (name, sa) = &msg.entries()[0];
        assert_eq!(name, "peer-1");
        assert_eq!(sa.str("state"), Some("ESTABLISHED"));
        assert_eq!(sa.list("remote-ts"), vec!["10.0.2.0/24", "10.0.3.0/24"]);
        let child = sa.get("child-sas").unwrap().entries();
        assert_eq!(child[0].0, "peer-1-tunnel-1-7");
        assert_eq!(child[0].1.str("state"), Some("INSTALLED"));

        let json = msg.to_json();
        assert_eq!(json["peer-1"]["state"], "ESTABLISHED");
        assert_eq!(json["peer-1"]["remote-ts"][1], "10.0.3.0/24");
    }

    #[test]
    fn truncated_and_malformed_fail_cleanly() {
        let mut buf = Vec::new();
        key_value(&mut buf, "state", "ESTABLISHED");
        buf.truncate(buf.len() - 3);
        assert!(parse_message(&buf).is_err());

        // section never closed
        let buf = vec![SECTION_START, 1, b'x', KEY_VALUE, 1, b'k', 0, 1, b'v'];
        assert!(parse_message(&buf).is_err());

        // unknown element type
        assert!(parse_message(&[9]).is_err());
    }
}
