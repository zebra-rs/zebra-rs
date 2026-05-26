# IS-IS Authentication — Plan & Completion Summary

Scoping doc for IS-IS authentication on zebra-rs. The locked plan
spanned six phases (Phase 1 through Phase 5, with a 4b follow-on
for the SHA family); all landed on `main` between PRs #916 and
#924 on 2026-05-26.

References:

- ISO 10589 §9.5 — Authentication Information TLV (type 10) and
  cleartext password (auth-type 1).
- RFC 5304 — IS-IS Cryptographic Authentication (HMAC-MD5,
  auth-type 54).
- RFC 5310 — IS-IS Generic Cryptographic Authentication
  (auth-type 3 with 2-byte Key ID prefix; HMAC-SHA-1/256/384/512).
- RFC 6232 — Purge Originator Identification TLV — purges must
  also be authenticated against the area / domain key.

Both RFCs 5304 and 5310 are checked into `rfc/isis/`.

## Phase map

| Phase | PR | Scope |
| --- | --- | --- |
| 1 | #916 | Wire layer: `IsisTlvType::Auth = 10` and `IsisTlvAuth { auth_type, value }` in `crates/isis-packet`. Pulled RFCs 5304 + 5310 into `rfc/isis/`. |
| 2 | #918 | YANG schema + Rust storage: three presence containers (`area-password`, `domain-password`, `hello-authentication`) with `password` (mandatory), `auth-type` enum, `send-only` bool. Storage-only. |
| 3a | #919 | Hello (LAN + P2P) sign + verify. New `zebra-rs/src/isis/auth.rs` with `hmac_md5` / `digest_eq` / `locate_auth_tlv`. `network.rs` starts preserving raw bytes for all PDU types so the verify path can recompute HMAC against the exact peer-signed buffer. Four per-link counters added. |
| 3b | #921 | CSNP + PSNP sign + verify reusing the 3a helpers. SNPs use the per-level area/domain key per RFC 5304 §3 (not the per-link hello-auth key). `lsp_emit`-side `append_auth_tlv` / `sign_md5_inplace` moved into `auth.rs` so all PDU types route through the same code. |
| 4 | #922 | LSP sign + verify + RFC 6232 purge auth. `sign_lsp_md5_inplace` adds the LSP-specific zeroing of Remaining Lifetime + Checksum during HMAC (RFC 5304 §3) and re-stamps Fletcher after patching the digest. Re-flooding works without a code change since Fletcher excludes bytes 10..12 and HMAC zeros lifetime. |
| 4b | #923 | RFC 5310 generic crypto: HMAC-SHA-1/256/384/512 plus 2-byte Key ID. `hmac_for_algo`, `apad(len)`, `sign_inplace(algo)` / `sign_lsp_inplace(algo)` replace the md5-only helpers. Wire shape gains the Apad-filled placeholder. |
| 5 | #924 | Operational visibility: `show isis interface detail` per-interface auth block (mode, key-id, send-only, four counters) and `show isis summary` instance-scope lines for area-password / domain-password. JSON gains an `authentication` object on `InterfaceDetailJson`. |

## Final config shape

```
router isis {
  net 49.0001.1921.6800.0001.00;

  # Instance-scope. L1 LSPs + L1 SNPs use area-password;
  # L2 LSPs + L2 SNPs use domain-password (RFC 5304 §3).
  area-password {
    password   AREA-KEY;
    auth-type  hmac-sha-256;
    key-id     42;
    # send-only true;   # rollover hatch (RFC 5304 §1)
  }
  domain-password {
    password   DOMAIN-KEY;
    auth-type  hmac-sha-512;
    key-id     43;
  }

  # Per-link. Drives IIH authentication only.
  interface eth0 {
    hello-authentication {
      password   LINK-KEY;
      auth-type  md5;
    }
  }
}
```

`auth-type` admits `text | md5 | hmac-sha-1 | hmac-sha-256 |
hmac-sha-384 | hmac-sha-512`. Default `text`. `key-id` defaults
to 1 and is only meaningful for the `hmac-sha-*` variants
(emitted as the 2-byte prefix on TLV-10 value).

## What gets signed by what

| PDU | Auth scope | Key source |
| --- | --- | --- |
| L1/L2/P2P Hello | per-link | `interface */hello-authentication` |
| L1 CSNP / L1 PSNP | per-level | `router isis/area-password` |
| L2 CSNP / L2 PSNP | per-level | `router isis/domain-password` |
| L1 LSP (incl. purge) | per-level | `router isis/area-password` |
| L2 LSP (incl. purge) | per-level | `router isis/domain-password` |

The selector lives in `packet::auth_scope_for(IsisType)`; the
key lookup in `lsp::level_auth_cfg(&IsisConfig, Level)`.

## Two-pass HMAC details

The wire layout puts the Auth TLV at the *end* of the real TLVs
but *before* padding (Hello case) so the padding helper sees its
size and the PDU lands exactly at MTU.

### Hello / SNP (`sign_inplace`)

1. Emit the PDU with a placeholder Auth TLV: digest area
   zero-filled for md5, Apad-filled (RFC 5310 §3.3) for
   generic-crypto.
2. Compute HMAC over the whole emitted buffer.
3. Patch the digest into the placeholder.

### LSP (`sign_lsp_inplace`)

Two extra fields get zeroed during the HMAC so the digest
survives the lifetime-aging that re-floods inflict:

1. Emit the LSP with a placeholder Auth TLV.
2. In a scratch copy, zero Remaining Lifetime (bytes 10..12) +
   Checksum (24..26) + the digest area (auth-value or apad).
3. Compute HMAC over the scratch.
4. Patch the digest into the *live* buffer at the auth-value
   range.
5. **Re-stamp Fletcher checksum** at 24..26 — `checksum_calc`
   assumes the field reads as zero before recompute, so the
   helper explicitly zeros buf[24..26] before calling. The
   existing `IsisPacket::emit` path satisfies this implicitly
   via `IsisLsp.checksum = 0`; the post-emit sign path has to
   redo it after patching the digest.

### Re-flooding correctness (no code change needed)

`flood.rs` updates `Remaining Lifetime` in cached LSP bytes via
`isis_packet::write_hold_time` and sends as `Packet::Bytes`.

- Fletcher only covers bytes 12+, so the lifetime change at
  10..12 doesn't break it.
- HMAC zeros lifetime in the verify scratch, so the digest
  stays valid as the LSP ages.

## Verify decision matrix

In `packet::verify_pdu_auth`:

| Configured | Inbound | Action |
| --- | --- | --- |
| No auth | any | accept |
| Auth + `send-only` | any | accept (RFC 5304 §1 rollover hatch) |
| Auth, no Auth TLV | — | drop, bump `auth_rx_no_auth` |
| Auth, type / digest mismatch | — | drop, bump `auth_rx_bad` |
| Auth, match | — | accept, bump `auth_rx_good` |

Outbound signing bumps `auth_tx_signed` regardless of mode.
Digest compare is constant-time (`auth::digest_eq`) so a
partial-match digest doesn't leak timing.

## Operational visibility

```
$ show isis summary
LSP MTU: 1492 bytes
Area-password (L1): mode hmac-sha-256, key-id 42
Domain-password (L2): mode hmac-sha-512, key-id 43

$ show isis interface detail
Interface: eth0, State: Up, Active, Circuit Id: 0x02
  Type: lan, Level: level-1-2, SNPA: ...
  Level-1 Information:
    ...
  Hello Authentication:
    Mode: md5, Key ID: 1, Send-only: false
    Counters: tx-signed 1234, rx-good 1230, rx-bad 0, rx-no-auth 4
```

Lines / blocks suppress entirely when the relevant scope isn't
configured so un-authed nodes stay clean.

## Key design decisions

- **One `IsisTlvAuth` struct for all three on-wire shapes.** The
  Phase 1 wire layer models cleartext, HMAC-MD5, and RFC 5310
  generic crypto via a single `auth_type` byte + opaque `value`
  Vec. Callers reinterpret per auth-type. Lets Phase 4b add SHA
  without touching the parser.
- **Placeholder approach over emit-twice.** Sign at byte level
  after `IsisPacket::emit`, not via a second serialization
  round. Cheaper and avoids any chance of producing different
  bytes between sign and re-emit.
- **Snapshot config fields by value in verify.** `verify_pdu_auth`
  clones the password+mode+send-only into locals before mutating
  `link.state.auth_rx_*` counters; otherwise the immutable
  borrow of `link.config` / `link.up_config` would fight the
  `&mut link.state` borrow.
- **No re-origination triggers on auth-config change.** Phase 4
  didn't wire LSP re-origination when the operator commits a
  new area/domain key. Operators are expected to either bounce
  the adjacency or accept that the new key is used on the next
  natural refresh.

## Known deferred / out-of-scope

- **Key-chain rotation** (multiple Key IDs per scope, rolled
  over the wire with start/end lifetimes) — original plan
  marked this Phase 6. The single-key path landed here is
  enough for interop with FRR / Cisco in single-key mode. The
  RFC 8177 model that OSPF Phase 4 adopted is the natural shape
  if/when this is picked up.
- **BDD coverage.** Unit-level tests only; no end-to-end /
  multi-router scenarios exercise sign+verify across the wire.
- **FRR interop validation.** Wire formats track the RFCs and
  Phase 1's RFC-2202 HMAC-MD5 test vector matches, but no
  two-router test against FRR has been run yet.
- **`/key-chains` integration.** OSPF Phase 4 wired the IETF
  key-chains YANG model. IS-IS auth uses its own scope-local
  `password` / `auth-type` / `key-id` leaves and doesn't share
  storage with OSPF.

## Where the code lives

- `crates/isis-packet/src/parser.rs` — `IsisTlvAuth`, auth-type
  constants, digest-length constants.
- `zebra-rs/src/isis/auth.rs` — HMAC dispatch, Apad, append /
  sign / locate / digest_eq helpers.
- `zebra-rs/src/isis/config.rs` — `IsisAuthType`,
  `IsisAuthConfig`, `auth_reset` / `auth_set_*` helpers, leaf
  callbacks.
- `zebra-rs/src/isis/packet.rs` — `verify_pdu_auth`,
  `verify_hmac`, `auth_scope_for`, `pdu_auth_tlv`,
  `sign_snp_outgoing`.
- `zebra-rs/src/isis/ifsm.rs` — Hello send path with
  `sign_inplace`.
- `zebra-rs/src/isis/lsp.rs` — `lsp_emit` (LSP sign hook),
  `level_auth_cfg`, `csnp_generate` (auth TLV in fragmentation
  budget).
- `zebra-rs/src/isis/flood.rs` — PSNP packer (auth TLV in
  fragmentation budget).
- `zebra-rs/src/isis/link.rs` — per-link counters, `AuthInfo`,
  show renderer.
- `zebra-rs/src/isis/show.rs` — `show isis summary` instance
  scope lines.
- `zebra-rs/yang/config.yang` — schema.
- `rfc/isis/rfc5304.txt`, `rfc/isis/rfc5310.txt` — references.
