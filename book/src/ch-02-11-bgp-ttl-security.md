# BGP TTL Security (GTSM)

The **Generalized TTL Security Mechanism** (GTSM, RFC 5082 — originally
RFC 3682) protects a directly-connected BGP session from off-path
spoofing by exploiting a property an attacker more than one hop away
cannot forge: the **received IP TTL** (IPv6 Hop Limit).

A router decrements TTL on every forwarding hop. A directly-connected
peer's packets therefore arrive with the TTL they were sent with; a
packet that has crossed even one router arrives at least one lower. If
both ends agree to send at TTL 255 and to accept only packets that
arrive at TTL 255, then any packet originated more than one hop away —
necessarily TTL < 255 — is dropped by the kernel before BGP ever sees
it. The attacker would have to be on the directly-attached link.

## What zebra-rs implements

zebra-rs supports only the **directly-connected** case, which is the
case GTSM was designed for and the one operators almost always want:

- Egress: every BGP segment leaves with IP TTL / IPv6 Hop Limit
  **255**.
- Ingress: the kernel is told to drop any segment that arrives below
  **255** (`IP_MINTTL` for IPv4, `IPV6_MINHOPCOUNT` for IPv6).

There is **no configurable hop count**. The YANG leaf is `type empty`
— a flag that is either present or absent — rather than a number of
hops. This matches RFC 5082's directly-connected profile (expected hop
count 0 ⇒ TTL 255) and deliberately omits the multi-hop variant
(`neighbor X ttl-security hops <N>` on other platforms).

## Where the TTL policy is applied

The socket options are installed on the **established TCP connection**,
right after the three-way handshake completes and before the BGP OPEN
is sent. The same code path is used whether zebra-rs initiated the
connection (active) or accepted it (passive), so both roles are covered
from one place.

This means the TCP handshake itself (SYN / SYN-ACK / ACK) is **not**
TTL-filtered — only the established session that carries OPEN and every
subsequent BGP message is. This is the standard GTSM trade-off and is
intentional:

- TCP's own sequence-number randomization protects the handshake from
  off-path injection.
- GTSM protects the established session, which is where BGP data
  actually flows. An off-path attacker cannot complete the handshake
  *and* deliver data segments at TTL 255, so the session cannot be
  hijacked or reset by a spoofed packet.

A consequence worth internalizing: because each end refuses packets
below TTL 255 once established, **GTSM must be symmetric**. If only one
end enables it, that end discards the other's default-TTL (64) packets
and the session never reaches Established.

## Relationship to ebgp-multihop

`ttl-security` and `ebgp-multihop` are mutually exclusive. GTSM asserts
the peer is exactly one hop away (TTL pinned to 255); `ebgp-multihop`
explicitly permits the TTL to be decremented across intermediate
routers. Enabling both on the same neighbor is a contradiction and is
not supported.

## Platform availability

| Mechanism | Linux | Notes |
|-----------|-------|-------|
| Egress TTL 255 | `IP_TTL` / `IPV6_UNICAST_HOPS` | Always available |
| Ingress floor 255 | `IP_MINTTL` / `IPV6_MINHOPCOUNT` | Long-stable in Linux; both v4 and v6 |

zebra-rs is Linux-primary; the GTSM socket options use the Linux
constants above.

## Configuration

`ttl-security` is a per-neighbor flag. Enable it on **both** ends of a
directly-connected eBGP session.

```yaml
router:
  bgp:
    global:
      as: 65001
      identifier: 192.168.0.1
    neighbor:
    - remote-address: 192.168.0.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      ttl-security: null
```

`ttl-security: null` is the YAML spelling of a `type empty` leaf — the
key is present with no value, which the loader turns into
`set router bgp neighbor 192.168.0.2 ttl-security`. The FRR / IOS-style
CLI form is the same path:

```
set router bgp neighbor 192.168.0.2 ttl-security
```

Toggling the flag on a session that is already up bounces it (the same
teardown `clear bgp <peer>` performs), so the new TTL policy takes
effect on the reconnect rather than waiting for the next unrelated
flap.

## Verification

`show ip bgp neighbor <addr>` reports the policy when it is active:

```
  TTL security (GTSM) enabled, minimum received TTL 255
```

To confirm the kernel actually received the options, trace the
`setsockopt` calls as the session establishes:

```
sudo strace -e trace=setsockopt -f -p $(pgrep zebra-rs)
```

For an IPv4 peer you should see, on the connection's socket,
`setsockopt(..., IPPROTO_IP, IP_TTL, [255], 4)` and
`setsockopt(..., IPPROTO_IP, IP_MINTTL, [255], 4)`; for IPv6, the
`IPV6_UNICAST_HOPS` / `IPV6_MINHOPCOUNT` pair.

## Troubleshooting

The classic failure is **asymmetric configuration**. If a session
refuses to reach Established and one end has `ttl-security` while the
other does not, the GTSM end is silently dropping the bare-TTL packets
from the non-GTSM end. The symptom looks like a one-way black hole:
each side may report sending OPEN, but the GTSM side never sees the
peer's reply. Enable `ttl-security` on both ends, or remove it from
both.

Because the drop happens in the kernel's IP layer, there is no BGP-
level log of the discarded packets — the same diagnostic posture as a
mismatched TCP-MD5 password (see
[Session Authentication](ch-02-02-tcp-authentication.md)).
