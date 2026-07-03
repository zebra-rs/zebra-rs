# Authentication

OSPFv2 packet authentication is configured per interface, under the
area/interface entry. All three RFC 2328 Appendix D authentication
types are supported, plus the HMAC-SHA cryptographic authentication
of RFC 5709 and RFC 8177 key-chains:

- **Null** (AuType 0, RFC 2328 §D.2) — the default when no
  `authentication` leaf is configured.
- **Simple password** (AuType 1, RFC 2328 §D.3) — an 8-octet
  cleartext password carried in every packet header.
- **Cryptographic** (AuType 2, RFC 2328 §D.4 / RFC 5709) — a keyed
  digest appended after the packet. `authentication
  message-digest` selects this mode for both legacy keyed-MD5 and
  HMAC-SHA keys; the algorithm is a property of each key, not of
  the mode.

| YANG leaf (`/router/ospf/area/<id>/interface/<n>/…`) | Type | Notes |
|---|---|---|
| `authentication` | `null` \| `simple` \| `message-digest` | AuType selector; absent = null |
| `authentication-key` | string, 1..8 chars | Simple-password secret. Longer keys are rejected at commit, not truncated. |
| `message-digest-key/<key-id>/md5` | key-id 1..255, secret 1..16 chars | Keyed-MD5 (`MD5(packet ‖ key)`, RFC 2328 §D.4.3) |
| `crypto-key/<key-id>/hmac-sha-1` … `hmac-sha-512` | key-id 1..255 | HMAC-SHA per RFC 5709 §3.3 (`HMAC(key, packet)`); secret capped at the digest length (20/32/48/64) |
| `key-chain` | string | Name of a global `/key-chains/key-chain` entry (RFC 8177) |

## Simple password

Both ends must carry the same password:

```
router ospf {
  area 0 {
    interface enp0s6 {
      enable true;
      authentication simple;
      authentication-key MYPASS;
    }
  }
}
```

## Keyed-MD5

```
router ospf {
  area 0 {
    interface enp0s6 {
      enable true;
      authentication message-digest;
      message-digest-key 1 {
        md5 SECRET;
      }
    }
  }
}
```

## HMAC-SHA (RFC 5709)

Same mode, stronger algorithm — pick the algorithm by leaf name
inside a `crypto-key` entry:

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
```

`message-digest-key` and `crypto-key` entries merge into a single
per-interface keyring keyed by key-id — reusing the same key-id in
both lists is a configuration error.

## Key rollover and multiple keys

Several keys may coexist on one interface. The **send** side always
uses the lowest configured key-id; the **receive** side accepts any
packet whose key-id is known (and, for chains, within its
accept-lifetime), regardless of which key we currently send with.
Rolling a key over is therefore hitless: add the new key on all
routers first (it is accepted immediately), then remove the old one
(sending switches to the survivor).

For time-driven rollover, reference an RFC 8177 key-chain instead
of inline keys:

```
key-chains {
  key-chain OSPF-KC {
    key 1 {
      crypto-algorithm hmac-sha-256;
      key-string {
        keystring SECRET;
      }
      lifetime {
        send-accept-lifetime {
          always;
        }
      }
    }
  }
}
router ospf {
  area 0 {
    interface enp0s6 {
      enable true;
      authentication message-digest;
      key-chain OSPF-KC;
    }
  }
}
```

When `key-chain` is set (with `authentication message-digest`), the
chain supersedes any per-interface `message-digest-key` /
`crypto-key` entries: sending uses the chain's currently active key
(lowest key-id whose send-lifetime contains now) and receiving
validates the sender's key-id against its accept-lifetime window.
Key chains are shared infrastructure — the same `/key-chains` tree
also serves IS-IS and BGP.

## Wire format and verification behavior

- The OSPF packet checksum follows RFC 2328 Appendix D exactly:
  for Null and Simple authentication it is computed over the packet
  *excluding* the 64-bit authentication field, and for
  cryptographic authentication (AuType 2) it is **not computed at
  all** — the field stays zero and the digest trailer carries the
  integrity check (§D.4.3). Ingress likewise skips checksum
  validation on AuType-2 packets, so FRR's checksum-zero
  cryptographic packets interoperate in both directions.
- Cryptographic packets carry a per-link 32-bit sequence number;
  a received sequence lower than the neighbor's last-seen value is
  dropped as a replay (equal is accepted, matching FRR, so
  retransmitted packets survive; RFC 2328 §D.5 / RFC 7474).
- Digests are compared in constant time.
- Authentication failures (type mismatch, unknown key-id, bad
  digest, expired chain key) drop the packet **silently** — the
  adjacency simply never forms or times out. The drops are visible
  only at `debug` log level (`OSPFv2 auth drop …`); there is no
  drop counter in `show` output yet, so a dead adjacency after an
  auth change is the main symptom to check for.
- In `message-digest` mode with no usable key (empty keyring,
  missing or fully expired chain), zebra-rs deliberately sends a
  zero-length trailer with key-id 0 so the peer visibly rejects
  the packet rather than silently authenticating with an empty
  key.

## OSPFv3 — Authentication Trailer (RFC 7166)

OSPFv3 has no authentication field of its own in the packet header;
zebra-rs implements the RFC 7166 Authentication Trailer instead:
the AT-bit is set in the options of Hellos and DBDs, and an
HMAC-SHA trailer — with a 16-bit Security Association ID, a 64-bit
sequence number, and the Apad construction of RFC 7166 §3.5
covering the IPv6 source address — is appended outside the OSPF
length and checksum. The same HMAC-SHA algorithm set as v2 applies,
and the per-interface authentication state (mode, keys, key-chain)
is shared between the v2 and v3 instances of a link.

Note the configuration caveat: the authentication leaves shown
above attach to the `router ospf` (v2) interface tree only — there
is currently no separate `router ospfv3 … authentication` path.

All four OSPFv2 modes — simple password, keyed-MD5, HMAC-SHA-256,
and key-chain — are BDD-validated end to end
(`ospfv2_auth.feature`), including the negative case: mismatched
secrets never create a neighbor.
