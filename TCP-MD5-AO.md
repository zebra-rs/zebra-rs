# BGP TCP MD5 authentication and Authentication Option

Design and development plan for adding TCP MD5 (RFC 2385) and TCP
Authentication Option / TCP-AO (RFC 5925, RFC 5926) support to the
BGP implementation in zebra-rs.

Working branch: `feature/bgp-tcp-md5-and-ao-auth`.

## Development plan (phased)

| Phase | Deliverable | Lands as |
|-------|-------------|----------|
| 1 | RFC specification summary (this document) | doc-only commit |
| 2 | Standalone TCP MD5 and TCP-AO example binaries | `zebra-rs/examples/` |
| 3 | YANG model extensions for MD5 password and AO key chain | `zebra-rs/yang/` |
| 4 | BGP integration: `PeerTransportConfig`, socket hooks, config callbacks | `zebra-rs/src/bgp/` |
| 5 | Architecture doc, CLI tests, interop notes | `cli/tests/`, this doc |

Phases 1 and 2 are intended to land first as a reviewable reference.
Phases 3–5 depend on phase 2 and can land together or split.

# Specification

## RFC 2385 — TCP MD5 Signature Option

- Adds a TCP option (kind 19, length 18) carrying a 16-byte MD5 digest
  computed over: the TCP pseudo-header, the TCP header (with checksum
  and digest-option zeroed), the TCP segment data, and a shared secret.
- One key per peer. No in-band key rotation — rekey requires tearing
  the session down.
- Obsoleted as "historic" by RFC 5925 but still the most widely
  deployed BGP session authentication mechanism in practice.
- Linux kernel API: `setsockopt(TCP_MD5SIG_EXT)` with a
  `struct tcp_md5sig` that carries peer address, optional prefix
  length (for listening sockets serving multiple peers), key length,
  and up to 80 bytes of key material.
- Placement is asymmetric between the two sides of a session:
  - Active side: on the `TcpSocket` after creation, before `connect()`.
  - Passive side: on the **listening** socket, keyed by peer address
    or prefix, installed **before the peer's SYN arrives**. The MD5
    check runs during the three-way handshake, so by the time
    `accept()` returns the handshake is already over — a post-`accept()`
    setsockopt has no effect on authentication of that session.

## RFC 5925 — TCP Authentication Option (TCP-AO) and RFC 5926 — Cryptographic Algorithms

- Replaces MD5. Uses TCP option kind 29 carrying a KeyID, RNextKeyID,
  and a truncated MAC (96 bits by default).
- Master Key Tuples (MKTs) bind SendID/RecvID, traffic keys, and a MAC
  algorithm to a connection. Multiple MKTs per connection allow
  in-band, seamless key rollover via the RNextKeyID field.
- RFC 5926 mandates HMAC-SHA-1-96 and AES-128-CMAC-96; traffic keys
  are derived via a KDF from the master key and connection identifiers
  (ISN pair), so MACs are not vulnerable to the same replay and
  cross-connection attacks as MD5.
- Linux kernel API (≥ 6.7): `setsockopt(TCP_AO_ADD_KEY)`,
  `TCP_AO_DEL_KEY`, `TCP_AO_INFO`, `TCP_AO_REPAIR`, and
  `TCP_AO_GET_KEYS`. Each key carries algorithm name, SendID, RecvID,
  address/prefix, and key material.

## Option coverage flag: `TCP_AO_KEYF_EXCLUDE_OPT`

`TCP_AO_KEYF_EXCLUDE_OPT` (bit 1 of `tcp_ao_add.keyflags` in
`<linux/tcp.h>`) controls whether TCP options other than TCP-AO itself
are covered by the MAC computation. Per-key, per-direction setting —
both endpoints must agree, and a mismatch produces silent segment
drops.

### What the MAC covers in each mode

TCP-AO MAC input (RFC 5925 §3.1) always contains:

1. Pseudo-header (src IP, dst IP, proto, length).
2. TCP header with the checksum zeroed.
3. TCP segment data.

The TCP-AO option itself is always zeroed in the MAC input (you cannot
MAC over a field you are about to write). The difference is how the
**other** TCP options are treated:

| Flag | Other TCP options in MAC | Header range covered |
|------|--------------------------|----------------------|
| Unset (default) | **Included** | Full TCP header — MSS, timestamps, SACK, WScale, etc. |
| Set (`TCP_AO_KEYF_EXCLUDE_OPT`) | **Excluded** (zeroed in MAC input) | Fixed 20-byte TCP header only |

### Why exclude exists — middleboxes

TCP middleboxes sometimes rewrite options in flight: NAT, MSS clamping
(common at PPPoE / IPsec edges), option-stripping firewalls, timestamp
rewriters. When the MAC covers those options, any in-flight
modification breaks the MAC and kills the session. Excluding options
allows the session to survive, at the cost of MAC coverage over the
option fields. The fixed header and payload remain covered, so replay
protection and spoofing resistance are preserved.

RFC 5925 §5.1 warns that excluding options weakens the authentication
binding and should only be used when operationally necessary.

### Polarity — name inversion across layers

| Layer | Name | True means |
|-------|------|------------|
| Linux kernel | `TCP_AO_KEYF_EXCLUDE_OPT` | exclude options |
| Cisco CLI | `include-tcp-options disable` | exclude options |
| Cisco CLI | `include-tcp-options enable` | include options (default) |
| zebra-bgp-ao YANG | `include-tcp-options: true` | include options (default) |

Translation in the BGP integration code:

```rust
let mut keyflags: u8 = 0;
if !include_tcp_options {
    keyflags |= TCP_AO_KEYF_EXCLUDE_OPT;
}
```

### Operational guidance

- **Default (include)** for iBGP and direct-link eBGP — highest
  security.
- **Exclude** for eBGP across middleboxes that touch TCP options,
  only when include-mode fails to establish and exclude-mode works.
- Both sides of a session must be configured identically per MKT.

## Kernel availability

- `TCP_MD5SIG` / `TCP_MD5SIG_EXT`: available for many years, stable.
- `TCP_AO_*`: Linux 6.7+. Absence is detected at runtime — fall back
  to logging a configuration error if AO is configured on a kernel
  that does not support it.
- macOS / BSD: not supported in this phase. Configuring MD5 or AO on
  non-Linux targets should log a warning and leave the socket
  un-authenticated, rather than fail hard.

# Example code

Small standalone binaries under `zebra-rs/examples/` that exercise the
setsockopt plumbing end-to-end, independent of BGP. These are the
reference for phase 4 and a regression harness for kernel-API changes.

Linux-only; guarded with `#[cfg(target_os = "linux")]`.

## TCP MD5 server & client

- `examples/tcp_md5_server.rs` — binds a `TcpListener` on a chosen
  port, sets `TCP_MD5SIG_EXT` for an expected peer address and shared
  key, accepts one connection, echoes bytes.
- `examples/tcp_md5_client.rs` — creates a `TcpSocket`, sets
  `TCP_MD5SIG_EXT` for the server address and the same key, connects,
  sends a line.
- Uses `libc` / `nix` crate for setsockopt; no dependency on tokio to
  keep the example minimal.

## TCP AO server & client

- `examples/tcp_ao_server.rs` and `examples/tcp_ao_client.rs` —
  equivalent structure, using `TCP_AO_ADD_KEY` to install one MKT per
  direction with SendID/RecvID and HMAC-SHA-1-96.
- Demonstrates key-rollover by calling `TCP_AO_ADD_KEY` a second time
  mid-session and switching via RNextKeyID.

# BGP integration

## Configuration sample for TCP MD5 (YAML)

```yaml
routing:
  bgp:
    global:
      as: 65001
      identifier: 192.168.0.1
    neighbor:
    - remote-address: 192.168.0.2
      peer-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4-unicast
        enabled: true
      tcp-md5:
        encoding: clear
        password: "shared-md5-secret"
```

`encoding` is `clear` (cleartext) or `encrypted` (zebra-rs
obfuscated form). Maximum password length: 80 bytes, matching
Linux's `TCP_MD5SIG_MAXKEYLEN`.

## Configuration sample for TCP-AO (YAML)

```yaml
key-chains:
  key-chain:
  - name: BGP-AO
    key:
    - key-id: 100
      crypto-algorithm: hmac-sha-1
      send-id: 100
      recv-id: 100
      key-string:
        keystring: "shared-ao-secret"

routing:
  bgp:
    global:
      as: 65001
      identifier: 192.168.0.1
    neighbor:
    - remote-address: 192.168.0.2
      peer-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4-unicast
        enabled: true
      tcp-ao:
        key-chain: BGP-AO
        include-tcp-options: true
```

The key-chain reuses RFC 8177 (`ietf-key-chain@2017-06-15`)
vendored in `zebra-rs/yang/`, augmented by `zebra-bgp-auth.yang`
with per-key `send-id` / `recv-id` (RFC 5925 SendID / RecvID,
uint8). Keys can alternatively be specified in hex via
`hexadecimal-string`.

## Manual verification

BDD scaffolding under `bdd/tests/`:
- `features/bgp_tcp_md5_auth.feature` + `data/bgp_tcp_md5_auth/`
  — matching-password establish + mismatch drop + restore.
- `features/bgp_tcp_ao_auth.feature` + `data/bgp_tcp_ao_auth/`
  — matching-MKT establish (requires kernel ≥ 6.7).

The BDD harness needs root (netns creation) and the zebra-rs
binary with `cap_net_bind_service,cap_net_admin` granted — see
`Makefile`'s `run` target.

Lightweight manual trace when a full BDD run is not available:

```
# Build + capabilities
make cap

# Run in one terminal with strace
sudo strace -e trace=setsockopt -f -p $(pgrep zebra-rs)

# Apply tcp-md5 config in another terminal (vtysh or API). You
# should see setsockopt(..., IPPROTO_TCP, TCP_MD5SIG (14), ...)
# calls on both the listening fd and the active TcpSocket.
```

A mismatched password on one side matches RFC 2385 behavior: the
kernel silently drops the offending peer's SYN, so the session
stays in `Active` / `Idle` flap with no log on the receiving side.
zebra-rs's connect-side logs the TCP timeout when the SYN-ACK
never arrives.

# Architecture design in zebra-rs's BGP

## Touchpoints

Current state (verified on `feature/bgp-tcp-md5-and-ao-auth`):

- `zebra-rs/src/bgp/peer.rs:118` — `PeerTransportConfig`
  (`passive`, `update_source`). Extend with
  `md5_password: Option<String>` and `ao_keychain: Option<AoKeychain>`.
- `zebra-rs/src/bgp/peer.rs:771` — `peer_connect()` creates the
  active `TcpSocket` and calls `connect()`. Insert setsockopt calls
  between socket creation and connect.
- `zebra-rs/src/bgp/inst.rs:245` — IPv4 `TcpListener::bind` on
  `0.0.0.0:179`.
- `zebra-rs/src/bgp/inst.rs:27–42` — `create_ipv6_listener()` using
  `socket2::Socket`. Apply MD5/AO keys per peer on the listening
  socket via `TCP_MD5SIG_EXT` / `TCP_AO_ADD_KEY` with peer prefix, so
  a single listener can serve many peers with distinct keys.
- `zebra-rs/src/bgp/config.rs:38–68` — add
  `config_peer_password()` and `config_peer_keychain()` callbacks
  mirroring the existing `config_peer_as()` pattern.

## Passive vs active side placement

Where the MD5 / AO key goes is not symmetric, and getting this wrong
on the passive side silently drops the peer's SYN with no log at the
BGP layer.

- **Active side** (`peer_connect()` in `peer.rs`): after the
  `TcpSocket` is created and before `connect()`, install
  `TCP_MD5SIG_EXT` / `TCP_AO_ADD_KEY` bound to the remote peer's
  address. The key is used when sending the SYN.
- **Passive side** (listener in `inst.rs`): install the key on the
  `TcpListener` socket itself, keyed by the peer's address or prefix
  via the `tcpm_prefixlen` field. This must happen **before the
  peer's SYN arrives**.

The reason the passive side cannot recover after `accept()`:

1. The peer's SYN carries a TCP MD5 option.
2. The kernel looks up the matching key on the **listening** socket.
3. If no key matches, or the digest does not validate, the kernel
   silently drops the SYN. No SYN-ACK is sent, no child socket is
   created, `accept()` never fires.
4. Only if the digest validates does the handshake complete and
   `accept()` return a new fd. By that point the handshake is
   already over — a subsequent setsockopt on the child socket only
   affects segments going forward, and a mismatched key immediately
   kills the session.

Operational implications:

- **Config ordering**: each peer's key is installed on the listener
  at peer-creation time, not lazily on first connection. A SYN that
  arrives before the key is installed is dropped with no BGP-layer
  signal.
- **Listen-range / dynamic peers**: cannot use MD5 without
  per-prefix keys installed in advance. Not a regression today
  (zebra-rs does not support listen-range), but a constraint to
  remember if that feature is added later.
- **Key removal**: de-configuring a password must also issue
  `TCP_MD5SIG_EXT` with an empty key on the listener for that peer,
  in addition to tearing down any active session.

## Data flow

```
YANG config change
   -> libyang validation
   -> bgp::config callback (password / keychain)
   -> Peer.config.transport update
   -> setsockopt on the shared listener for this peer's address
      (passive path: must happen before the peer's next SYN)
   -> if peer is up: FSM back to Idle, re-establish
   -> peer_connect() creates a fresh TcpSocket, applies setsockopt,
      then connects (active path)
```

## Key lifecycle

- Initial configuration: applied at peer creation, before first
  connect / before listener starts accepting that peer's prefix.
- Key change on a running session:
  - MD5: tear the FSM down to Idle and reconnect (kernel does not
    support in-place rekey for TCP_MD5SIG).
  - AO: supports in-band rollover via RNextKeyID; for the initial
    implementation we use the same tear-down path for simplicity and
    defer seamless rollover to a follow-up.
- Key removal: explicit `TCP_MD5SIG_EXT` / `TCP_AO_DEL_KEY` on the
  listener socket for that peer, plus tear-down of the active session
  if any.

## Platform guards

All setsockopt plumbing sits behind `#[cfg(target_os = "linux")]`.
Non-Linux builds compile a stub that logs a warning and returns `Ok`
so that configuration with MD5/AO still parses but does not enforce
authentication. This matches zebra-rs's existing Linux-primary
posture.

# Open questions

1. **PR granularity** — land phases 1 + 2 first as a reference, then
   3–5 together? Recommended: yes.
2. **TCP-AO kernel floor** — require Linux ≥ 6.7 unconditionally, or
   add a feature flag to compile-out AO? Recommended: runtime detect,
   no feature flag.
3. **Key chain model** — reuse `ietf-key-chain@2017-06-15` if
   vendored, otherwise inline minimal grouping. To be resolved in
   phase 3.
4. **macOS / BSD** — stub with warning log, or compile error?
   Recommended: stub + warning, matching zebra-rs's current
   platform posture.
