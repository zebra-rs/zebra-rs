# Authentication

OSPFv3 removed the per-packet authentication field that OSPFv2
carries in its header — the original design delegated security to
IPsec (RFC 4552). zebra-rs implements the modern alternative: the
**Authentication Trailer** of RFC 7166, which appends an HMAC-SHA
digest to each packet without IPsec infrastructure.

How it works on the wire:

- The **AT-bit** is set in the options field of Hellos and Database
  Description packets (RFC 7166 §2.2), announcing that packets carry
  the trailer.
- Each packet ends with a trailer holding a 16-bit **Security
  Association ID** (the key-id), a **64-bit sequence number** for
  replay protection, and the digest.
- The digest is `HMAC-SHA-x(key, source-address ‖ packet ‖ trailer)`
  with the Apad construction of RFC 7166 §3.5 — including the IPv6
  source address defeats packet-replay from a different link.
- The trailer rides *outside* the OSPF length field and checksum, as
  a pure tail (RFC 7166 §4.1).

The algorithm set matches OSPFv2's cryptographic authentication:
HMAC-SHA-1, -256, -384, and -512.

## Configuration

The authentication state (mode, keys, key-chain reference) is
per-interface and **shared between the v2 and v3 instances of a
link** — the same leaves documented in the OSPFv2 chapter's
[Authentication page](ch-08-16-ospf-authentication.md) drive both
versions. Configure `authentication message-digest` plus a
`crypto-key` (or `key-chain`) on the interface entry, and the v3
side emits and requires the RFC 7166 trailer:

```
router ospf {
  area 0 {
    interface enp0s6 {
      enable true;
      authentication message-digest;
      crypto-key 1 {
        hmac-sha-256 SECRET;
      }
    }
  }
}
router ospfv3 {
  area 0 {
    interface enp0s6 {
      enable true;
    }
  }
}
```

Note the caveat: there is currently no separate
`router ospfv3 … authentication` configuration path — the leaves
attach to the `router ospf` interface tree only, which is awkward
for an IPv6-only deployment (a `router ospf` block must exist to
carry the keys). Key rollover semantics, silent-drop behavior on
verification failure, and RFC 8177 key-chain handling are identical
to v2.
