# OSPF Authentication — Plan & Completion Summary

Scoping doc for OSPF authentication on zebra-rs. The locked plan
spanned six phases (Phase 0 through Phase 5); all landed on `main`
between PRs #857 and #886 as of 2026-05-26.

References:

- RFC 2328 §D — OSPFv2 authentication (Null / Simple / Cryptographic-MD5).
- RFC 5709 — HMAC-SHA Authentication Trailer for OSPFv2.
- RFC 7474 — Security Extension for OSPFv2 with Manual Key Management.
- RFC 7166 — Authentication Trailer for OSPFv3.
- RFC 8177 — YANG Data Model for Key Chains.
- RFC 4552 — Authentication / Confidentiality for OSPFv3 (IPsec). **Deferred.**

## Phase map

| Phase | PR | Scope |
| --- | --- | --- |
| 0 | #857 | Wire scaffolding: `Ospfv2Auth` enum, `Ospfv2Packet::auth_trailer`, RFC text drops, parser slicing. |
| 1 | #860 | Null (AuType 0) + Simple password (AuType 1), RFC 2328 §D.2 / §D.3. New vendor YANG `zebra-ospf-auth-simple`. |
| 2 | #870 | Keyed-MD5 (AuType 2 / RFC 2328 §D.4) + per-neighbor §D.5 replay window. Added `md-5 = "0.10"`. |
| 3 | #876 | HMAC-SHA-1 / 256 / 384 / 512 trailer (RFC 5709 + 7474). Added `hmac` + `sha1` + `sha2`. |
| 4 | #882 | RFC 8177 key chains with lifetime-aware send/recv selection. Reused the IETF `/key-chains` model. |
| 5 | #886 | OSPFv3 Authentication Trailer (RFC 7166). v3 reuses v2's per-link auth config; no new YANG. |

## Final config shape

The whole tree, with both per-interface explicit keys and the
key-chain reference path:

```
key-chains {
  key-chain core {
    key 1 {
      crypto-algorithm hmac-sha-256;
      key-string { keystring SECRET; }
      lifetime {
        send-accept-lifetime {
          start-date-time 2026-01-01T00:00:00Z;
          end-date-time   2026-02-01T00:00:00Z;
        }
      }
    }
  }
}

router ospf {
  area 0 {
    interface eth0 {
      # FRR-flat path (Phase 1-3):
      authentication message-digest;
      message-digest-key 1 { md5 LEGACY; }
      crypto-key 2 { hmac-sha-256 NEW; }
      # OR the key-chain path (Phase 4); supersedes the flat keys above:
      key-chain core;
    }
  }
}

router ospfv3 {
  area 0 {
    interface eth0 {
      # Same per-link knobs (auth_mode / crypto_keys / key_chain)
      # drive both v2 and v3. Phase 5 didn't add v3-specific YANG.
      authentication message-digest;
      key-chain core;
    }
  }
}
```

## Out of scope (deferred)

Each item below was explicitly flagged in the relevant phase's PR;
none of them are required for the locked plan to be "complete."

- **AT-bit negotiation (v3).** Today both v3 peers must be
  symmetrically configured; the AT-bit is set on outbound Hello/DBD
  but not used for capability negotiation. RFC 7166 §3 says peers
  MAY negotiate — we don't.
- **64-bit `auth_md5_last_seq`.** v3 has a 64-bit seq on the wire;
  `Neighbor::auth_md5_last_seq` is `u32`. Acceptable until the
  counter exceeds 2^32 (decades at realistic packet rates).
- **`independent-send-accept-lifetime`.** Phase 4 wired only
  `send-accept-lifetime` (one window shared by both directions).
  YANG dispatch rejects the independent paths since no callback is
  registered.
- **`accept-tolerance`.** RFC 8177 §4.4 clock-skew window not yet
  honored.
- **`hexadecimal-string` key form.** Only `keystring` (plain text)
  is wired through; BGP already supports both.
- **IETF send-id / recv-id.** OSPFv2 carries a single 8-bit key-id
  per RFC 2328 §D.3; the IETF model's per-direction id distinction
  doesn't apply on the wire. BGP's TCP-AO path uses them.
- **Cross-protocol key-chain registry.** Done as of PR #928 / #930.
  The canonical `/key-chains/...` data model lives in
  `policy::keychain`; the policy actor parses each commit once and
  pushes per-name snapshots to OSPF / BGP / IS-IS via
  `PolicyRx::KeyChain`. Each protocol still owns its selection
  helpers (lowest active by lifetime, key-id-matched receive, …)
  and projects the shared `CryptoAlgorithm` enum onto its own
  supported subset.
- **OSPFv3 IPsec (RFC 4552).** Out-of-process key management,
  large surface; skip until a customer asks.
- **Live interop testing against FRR.** Every PR's test plan
  flagged this as deferred; it's the natural gate before declaring
  customer-ready.
- **Virtual / sham link auth.** Both features don't exist in
  zebra-rs yet; auth support follows.

## Architecture decisions worth remembering

### Per-link runtime state lives on `LinkConfig` (shared v2/v3)

`OspfLink<V>` is generic over OSPF version, but its `config:
LinkConfig` is not generic. `auth_mode` / `auth_key` / `crypto_keys`
/ `key_chain` all sit on `LinkConfig` directly. This is why Phase 5
needed no new YANG: the same per-interface leaves that Phase 1-4
added drive v3 too.

### `AtomicU32` for `md5_seq`, not `Cell<u32>`

Phase 2's first implementation used `Cell<u32>` for the outbound
cryptographic-auth sequence number on `OspfLink`. That broke
compilation: `Cell` is `!Sync`, and `Ospf<V>` is held across
`.await` boundaries in the `process_show_msg(&self, ...)` task
spawn, which requires `Sync`. `AtomicU32` is `Sync`, supports
lock-free `fetch_add`, and fits the single-threaded event-loop
performance profile fine.

### `KeySource` enum decouples verify from storage

Phase 4 introduced `KeySource { PerIface(&map) | Chain { chain, now } }`
as the receive-side key-lookup abstraction. v3 reuses it verbatim
in Phase 5. This keeps `verify_link_auth` ignorant of whether the
caller is using the FRR-flat key list or an RFC 8177 chain — both
shapes funnel through `KeySource::lookup(key_id)`.

### Send-side `AuthSendCtx` bundle

`apply_link_auth(packet, &AuthSendCtx)` takes one struct carrying
`(mode, simple_key, crypto_key, md5_seq)` rather than four args.
The cost of bundling shows up in flood loops where calling
`link.auth_send_ctx()` per iteration would conflict with the
`nbrs.iter_mut()` borrow held over the loop body — solved by
`build_auth_ctx(mode, simple_key, crypto_key, &seq)` which takes a
snapshot from outside the loop plus the `&AtomicU32` for per-packet
seq bumps.

### v3 hashes over `IPv6src || packet || trailer`, not just `packet || key`

RFC 7166 §4.5 binds the trailer to the IPv6 source so a relay can't
forward. This is a real shape difference from v2: `compute_v3_trailer_digest`
prepends the 16-byte IPv6 address; v2's `compute_crypto_trailer`
doesn't. The two functions live next to each other in
`ospf/packet.rs` and `ospf/packet_v3.rs` so the divergence is
visible.

### Apad — used only during hash computation

RFC 7166 §3.5 / §4.5: the trailer's "Authentication Data" field is
filled with `Apad` (0x878FE1F3 repeated) **during** the HMAC
computation; after the hash settles, the digest replaces `Apad`
in-place for the on-wire form. `apply_v3_auth_trailer` does this
swap: emits the trailer-with-Apad to feed the HMAC, then emits a
fresh trailer with the real digest to stash in
`packet.auth_trailer`.

### Wire-format `raw_body` cache

Both v2 (`Ospfv2Packet::raw_body`) and v3 (`Ospfv3Packet::raw_body`)
cache the bytes covered by the cryptographic digest at parse time.
The alternative — re-emitting at verify time — would round-trip
fine for correct packets but introduces subtle mismatch risk
(LSA byte ordering, header field stamping order) on the verify
path. Caching is what FRR/Cisco do.

### `network.rs` slices to header `len` before checksum

Phase 0 follow-up (c) lived in Phase 2: the inbound IP-payload
slice must be bounded by the OSPF header `len` before passing it
to `validate_checksum`. Trailer bytes are not covered by the
1's-complement checksum; without slicing, every Type 2 ingress
fails verification. Same fix shape will apply to v3 if anyone ever
wires `ospfv3_verify_checksum` to include trailer-aware slicing
(today it gets the OSPF body slice via the kernel and doesn't see
trailer bytes mixed in, because IPv6 raw sockets deliver only the
OSPF payload).

## Files that matter

```
crates/ospf-packet/
  src/parser.rs                 Ospfv2Auth, Ospfv2AuthCrypto, auth_trailer, raw_body
  src/v3.rs                     Ospfv3Options::at, Ospfv3AuthTrailer, raw_body
zebra-rs/src/policy/keychain/
  set.rs                        Lifetime / LifetimeEnd / Key / KeyChain / CryptoAlgorithm
  config.rs                     KeyChainSetConfig (/key-chains/... commit)
  mod.rs                        KeyChainScope (OspfInterface / BgpNeighbor / IsisIih / …)
zebra-rs/src/ospf/
  link.rs                       OspfAuthMode, AuthKey, OspfCryptoAlgo, LinkConfig auth fields,
                                chain_key_is_send_active, policy_algo_to_ospf,
                                resolve_active_send_key (consumes policy::KeyChain snapshot)
  packet.rs                     AuthSendCtx, apply_link_auth, verify_link_auth, KeySource,
                                compute_crypto_trailer, constant_time_eq
  packet_v3.rs                  apply_v3_auth_trailer, verify_v3_auth_trailer,
                                compute_v3_trailer_digest, set_at_bit, apad_bytes
  network.rs                    inbound checksum slicing (Phase 0c)
  network_v6.rs                 outbound trailer append (Phase 5)
  inst.rs                       Ospf::key_chains snapshot, process_policy_msg (PolicyRx::KeyChain),
                                v2 + v3 process_recv auth verify
  config.rs                     /area/interface/* callbacks; per-interface key-chain
                                Register/Unregister against policy actor
zebra-rs/yang/
  zebra-ospf-auth-simple.yang   authentication / authentication-key / key-chain
  zebra-ospf-auth-md5.yang      message-digest-key/<id>/md5
  zebra-ospf-auth-trailer.yang  crypto-key/<id>/hmac-sha-{1,256,384,512}
rfc/ospf/
  rfc4552.txt rfc5709.txt rfc7166.txt rfc7474.txt rfc8177.txt
```

## What "complete" means here

The locked plan goal was end-to-end on-the-wire support across both
versions, configurable via FRR-flat and IETF key-chain paths, with
replay protection. All of that landed. The features in the
"out of scope" list above are real follow-ups but were explicitly
out of scope from the start — they're not gaps in the locked plan,
they're its boundaries.
