# Authentication

OSPFv3 removed the per-packet authentication field that OSPFv2
carries in its header — the original design delegated security to
IPsec (RFC 4552). zebra-rs implements the modern alternative: the
**Authentication Trailer** of RFC 7166, configured natively on the
`router ospfv3` interface tree.

How it works on the wire:

- The **AT-bit** is set in the options field of Hellos and Database
  Description packets (RFC 7166 §2.2), announcing that packets carry
  the trailer.
- Each packet ends with a trailer holding a 16-bit **Security
  Association ID** (the configured key-id), a **64-bit sequence
  number** for replay protection, and the digest.
- The digest is `HMAC-SHA-x(key, source-address ‖ packet ‖ trailer)`
  with the Apad construction of RFC 7166 §3.5 — including the IPv6
  source address defeats packet replay from a different link.
- The trailer rides *outside* the OSPF length field and checksum, as
  a pure tail (RFC 7166 §4.1).

## Configuration

```
router ospfv3 {
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
```

| YANG leaf (`/router/ospfv3/area/<id>/interface/<n>/…`) | Type | Notes |
|---|---|---|
| `authentication` | `null` \| `message-digest` | Trailer on/off. RFC 7166 defines only HMAC-SHA algorithms, so unlike OSPFv2 there is no `simple` mode and no keyed-MD5 list. |
| `crypto-key/<key-id>/hmac-sha-1` … `hmac-sha-512` | key-id 1..255 | The key-id is carried as the trailer's Security Association ID; the secret is capped at the digest length (20/32/48/64). |
| `key-chain` | string | An RFC 8177 `/key-chains/key-chain` reference — supersedes inline `crypto-key` entries, with send/accept-lifetime driven rollover. |

Key rollover, chain semantics, silent-drop behavior on verification
failure, and the send-lowest / accept-any key-id model are identical
to [the OSPFv2 page](ch-08-16-ospf-authentication.md); the same
`/key-chains` tree serves IS-IS, BGP, and both OSPF versions.

All three modes — inline HMAC-SHA-256, key-chain, and the
mismatched-secret negative — are BDD-validated end to end over the
native config path (`ospfv3_auth.feature`), with no `router ospf`
block required in an IPv6-only deployment.

For OSPFv2's authentication surface (simple password, keyed-MD5,
RFC 5709 HMAC-SHA), see
[the v2 Authentication page](ch-08-16-ospf-authentication.md).
