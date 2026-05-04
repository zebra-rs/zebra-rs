# BGP Session Authentication

BGP sessions ride directly on TCP, so authenticating a session means
authenticating each TCP segment. Two mechanisms are in widespread
operational use: **TCP MD5 Signature** (RFC 2385) and **TCP
Authentication Option / TCP-AO** (RFC 5925, RFC 5926). zebra-rs
supports both on Linux.

## RFC 2385 — TCP MD5 Signature Option

A TCP option (kind 19, length 18) carries a 16-byte MD5 digest
computed over the TCP pseudo-header, the TCP header (with checksum
and digest-option zeroed), the segment data, and a shared secret.

- One key per peer.
- No in-band key rotation — changing the key requires tearing the
  session down.
- Obsoleted as "historic" by RFC 5925, but still the most widely
  deployed BGP authentication mechanism in practice.

The kernel verifies the digest during the three-way handshake. A
mismatched password causes the SYN to be **silently dropped** by the
receiver — the receive side logs nothing at the BGP layer, and the
connect side eventually reports a TCP timeout. This is the canonical
"BGP stays in Active/Idle with no reason given" symptom of an
asymmetric password configuration.

## RFC 5925 / RFC 5926 — TCP Authentication Option (TCP-AO)

Replacement for MD5. Uses TCP option kind 29 carrying a KeyID,
RNextKeyID, and a truncated MAC (96 bits by default).

- **Master Key Tuples (MKTs)** bind a SendID, RecvID, traffic keys,
  and a MAC algorithm to a connection. Multiple MKTs per connection
  enable seamless in-band key rollover via the RNextKeyID field.
- RFC 5926 mandates **HMAC-SHA-1-96** and **AES-128-CMAC-96**.
- Traffic keys are derived via a KDF from the master key and
  connection identifiers (the ISN pair), so MACs are not vulnerable
  to the same replay and cross-connection attacks as MD5.

## Option coverage — including or excluding TCP options in the MAC

TCP-AO offers a per-key flag controlling whether TCP options other
than TCP-AO itself are covered by the MAC computation. The pseudo-
header, fixed TCP header (with checksum zeroed), and segment data
are always covered.

| Mode | Other TCP options in MAC | Header range covered |
|------|--------------------------|----------------------|
| **Include** (default) | Included | Full TCP header — MSS, timestamps, SACK, WScale, etc. |
| **Exclude** | Excluded (zeroed in MAC input) | Fixed 20-byte TCP header only |

### Why exclude exists — middleboxes

Some middleboxes rewrite TCP options in flight: NAT, MSS clamping
(common at PPPoE / IPsec edges), option-stripping firewalls,
timestamp rewriters. With the MAC covering those options, any
in-flight modification breaks the MAC and kills the session.
Excluding options lets the session survive, at the cost of MAC
coverage over the option fields. The fixed header and payload remain
covered, so replay protection and spoofing resistance are preserved.

RFC 5925 §5.1 warns that excluding options weakens the
authentication binding and should only be used when operationally
necessary.

### Polarity — name inversion across vendors

Different layers use opposite polarities for the same flag:

| Layer | Setting | True / enabled means |
|-------|---------|----------------------|
| Linux kernel | `TCP_AO_KEYF_EXCLUDE_OPT` | exclude options |
| Cisco CLI | `include-tcp-options disable` | exclude options |
| Cisco CLI | `include-tcp-options enable` | include options (default) |
| zebra-rs | `include-tcp-options: true` | include options (default) |

zebra-rs follows the Cisco convention: a positive `include-tcp-options`
leaf, default `true`. Both endpoints of a session must agree per MKT;
a mismatch produces silent segment drops.

### Operational guidance

- **Default (include)** for iBGP and direct-link eBGP — highest
  security.
- **Exclude** for eBGP across middleboxes that touch TCP options,
  only when include-mode fails to establish and exclude-mode works.

## Kernel availability

| Mechanism | Linux kernel | Notes |
|-----------|--------------|-------|
| TCP MD5 (`TCP_MD5SIG`, `TCP_MD5SIG_EXT`) | Available for many years; stable | Maximum key length 80 bytes (`TCP_MD5SIG_MAXKEYLEN`) |
| TCP-AO (`TCP_AO_ADD_KEY`, `TCP_AO_DEL_KEY`, …) | **Linux 6.7+** | Absence is detected at runtime; configuring AO on an older kernel logs a configuration error |
| macOS / BSD / Windows | Not supported | Configuring MD5 or AO logs a warning and leaves the socket un-authenticated; zebra-rs is Linux-primary |

## Configuration

### TCP MD5

One shared password per peer, applied to both the active connect
socket and the listener.

```yaml
router:
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
obfuscated form). Maximum password length is 80 bytes, matching the
kernel's `TCP_MD5SIG_MAXKEYLEN`.

### TCP-AO

A key chain (RFC 8177) carries one or more keys; the BGP neighbor
references the chain by name and decides whether TCP options are
covered.

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

router:
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

The key chain reuses RFC 8177 (`ietf-key-chain`), augmented with
per-key `send-id` / `recv-id` (RFC 5925 SendID / RecvID, uint8).
Keys may alternatively be specified in hex via a `hexadecimal-string`
leaf instead of `keystring`.

## Troubleshooting

A mismatched MD5 password matches RFC 2385 behavior: the kernel
silently drops the offending peer's SYN. The receive side logs
nothing at the BGP layer; the connect side eventually reports a TCP
timeout. If a session refuses to come up and both ends look configured
correctly, double-check the password, then trace the kernel calls:

```
sudo strace -e trace=setsockopt -f -p $(pgrep zebra-rs)
```

You should see `setsockopt(..., IPPROTO_TCP, TCP_MD5SIG, ...)`
calls on both the listening fd and the active connect socket as
the configuration is applied. If only one side shows the call, the
key was not installed where the failing peer's SYN is being checked.

For TCP-AO on a kernel older than 6.7, the configuration is rejected
at commit time with a clear error message rather than silently
producing an authentication failure at runtime.
