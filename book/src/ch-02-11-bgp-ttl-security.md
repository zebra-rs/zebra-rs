# BGP TTL: eBGP Multihop and Security (GTSM)

BGP rides on TCP, which rides on IP, so every BGP segment carries an IP
**TTL** (IPv6 **Hop Limit**). A router decrements it on each forwarding
hop and drops the packet when it reaches zero. zebra-rs uses the TTL in
two ways: to bound how far a session is allowed to reach
(`ebgp-multihop`), and to harden a directly-connected session against
spoofing (`ttl-security` / GTSM).

## The BGP TTL model

The egress TTL zebra-rs sets on a session depends on its type, matching
the long-standing FRR / Cisco convention:

| Session | Egress TTL | Ingress check | Rationale |
|---------|-----------|---------------|-----------|
| eBGP, directly connected (default) | **1** | none | The peer must be one hop away; a router in the path drops the packet. |
| eBGP with `ebgp-multihop N` | **N** | none | The peer may be up to N hops away. |
| iBGP | **255** | none | iBGP peers are typically several IGP hops away. |
| `ttl-security` (GTSM) | **255** | **received TTL must be 255** | Directly connected; reject anything that crossed a router. |

The key default is **eBGP = TTL 1**. Because a TTL-1 packet cannot
survive a single router hop, a directly-connected eBGP session works but
a session to a peer *behind* a router does not — unless the operator
explicitly opts into `ebgp-multihop`. This is the standard safety
behavior; without it, an eBGP peer could silently be many hops away.

The egress TTL is set on the socket **before connect** on the active
side (so the SYN already carries it), then re-applied after the handshake
in `fsm_connected` — the path both roles share, which is what covers a
passively-accepted session (it has no pre-connect step). `ttl-security`
precedes `ebgp-multihop`, which is ignored on an iBGP session (already
255).

## eBGP multihop

When the eBGP peer is not directly connected — most commonly when
peering on loopback addresses that are reachable only across one or more
routers — raise the egress TTL with `ebgp-multihop`:

```yaml
router:
  bgp:
    global:
      as: 65001
      identifier: 10.0.0.1
    neighbor:
    - remote-address: 10.0.0.2
      remote-as: 65002
      enabled: true
      afi-safi:
      - name: ipv4
        enabled: true
      ebgp-multihop: 5
```

The value (1–255) is the egress TTL, i.e. the maximum number of hops to
the peer. The FRR / IOS CLI form is the same path:

```
set router bgp neighbor 10.0.0.2 ebgp-multihop 5
```

`ebgp-multihop` only raises the egress TTL; it does **not** add an
ingress check. It is mutually exclusive with `ttl-security` (which pins
the TTL to 255 and *does* filter the received TTL): configuring both on
one neighbor is **rejected** — the daemon refuses the second with a
warning, and the first-configured one wins, so remove one before adding
the other. `ebgp-multihop` has no effect on an iBGP session.

## TTL Security (GTSM)

The **Generalized TTL Security Mechanism** (GTSM, RFC 5082 — originally
RFC 3682) protects a directly-connected session from off-path spoofing
by exploiting a property an attacker more than one hop away cannot
forge: the **received TTL**. If both ends send at TTL 255 and accept
only packets that arrive at 255, any packet originated more than one hop
away — necessarily TTL < 255 — is dropped by the kernel before BGP ever
sees it. The attacker would have to be on the directly-attached link.

### What zebra-rs implements

zebra-rs supports only the **directly-connected** case, which is the one
GTSM was designed for and the one operators almost always want:

- Egress: every BGP segment leaves with IP TTL / IPv6 Hop Limit
  **255**.
- Ingress: the kernel drops any segment that arrives below **255**
  (`IP_MINTTL` for IPv4, `IPV6_MINHOPCOUNT` for IPv6).

There is **no configurable hop count**. The YANG leaf is `type empty` —
a flag that is either present or absent — rather than a number of hops.
This matches RFC 5082's directly-connected profile (expected hop count 0
⇒ TTL 255) and deliberately omits the multi-hop variant
(`neighbor X ttl-security hops <N>` on other platforms).

### Where the TTL policy is applied

The ingress floor (`IP_MINTTL` / `IPV6_MINHOPCOUNT`) is installed on the
**established TCP connection**, after the three-way handshake completes
and before the BGP OPEN is sent. The same code path covers both the
active and the passive role.

The TCP handshake itself (SYN / SYN-ACK / ACK) is therefore **not**
TTL-filtered — only the established session that carries OPEN onward is.
This is the standard GTSM trade-off and is intentional:

- TCP's own sequence-number randomization protects the handshake from
  off-path injection.
- GTSM protects the established session, which is where BGP data flows.
  An off-path attacker cannot complete the handshake *and* deliver data
  segments at TTL 255, so the session cannot be hijacked or reset by a
  spoofed packet.

Because each end refuses packets below TTL 255 once established, **GTSM
must be symmetric**. If only one end enables it, that end discards the
other's default-TTL packets and the session never reaches Established.

### Configuration

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

Toggling either `ttl-security` or `ebgp-multihop` on a session that is
already up bounces it (the same teardown `clear bgp <peer>` performs),
so the new TTL policy takes effect on the reconnect rather than waiting
for the next unrelated flap.

### Verification

`show ip bgp neighbor <addr>` reports the active policy:

```
  TTL security (GTSM) enabled, minimum received TTL 255
  External BGP neighbor may be up to 5 hops away (ebgp-multihop)
```

To confirm the kernel received the options, trace the `setsockopt` calls
as the session establishes:

```
sudo strace -e trace=setsockopt -f -p $(pgrep zebra-rs)
```

For an IPv4 peer you should see, on the connection's socket, an
`IP_TTL` set to the session TTL (1 for a plain directly-connected eBGP
peer, N for `ebgp-multihop`, 255 for iBGP / `ttl-security`), and for
`ttl-security` an additional `IP_MINTTL` of 255; for IPv6 the
`IPV6_UNICAST_HOPS` / `IPV6_MINHOPCOUNT` equivalents.

### Troubleshooting

The classic GTSM failure is **asymmetric configuration**: one end has
`ttl-security` and the other does not, so the GTSM end silently drops
the bare-TTL packets from the non-GTSM end. The symptom looks like a
one-way black hole — each side may report sending OPEN, but the GTSM
side never sees the peer's reply. Enable `ttl-security` on both ends, or
remove it from both.

The classic `ebgp-multihop` failure is forgetting it: a session to a
peer reachable only across a router stays down because the default eBGP
TTL of 1 cannot survive the hop. Configure `ebgp-multihop` with a hop
count at least as large as the distance to the peer.

Because both drops happen in the kernel's IP layer, there is no BGP-
level log of the discarded packets — the same diagnostic posture as a
mismatched TCP-MD5 password (see
[Session Authentication](ch-02-02-tcp-authentication.md)).
