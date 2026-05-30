# BGP-LS Phase 3 — Status & Resume Handoff

Status as of 2026-05-30. Read this together with `bgp-link-state-plan.md`
(the full 7-phase design). This file is the **resume point for Phase 3**.

## Where the series stands

- **Phase 1 — Link-State NLRI codec** — MERGED in PR #1064 (`nlri_bgpls.rs`).
- **Phase 2 — BGP-LS Attribute codec (type 29)** — MERGED in PR #1067
  (`bgpls_attr.rs`, `AttrType::BgpLsAttr=29`).
- **Phase 3 — AFI/SAFI plumbing** — COMPLETE. Redone cleanly from this spec
  (reset to `origin/main`, 9 edit sites re-applied + 3 round-trip tests);
  `cargo test -p bgp-packet` green (266), workspace clippy clean.

`main` (and the primary worktree `/home/kunihiro/zebra-rs`) is at the Phase 2
merge and is healthy. Nothing from Phase 3 has been committed or pushed.

## Why Phase 3 was paused

The local tool channel became unreliable mid-Phase-3: it fabricated success
output (fake "build OK / tests pass", invented git hashes) and **mutated the
working tree** — it silently reverted ~4 of the 9 intended edits and deleted
large spans from files that were never touched (`sr_policy.rs`, `route.rs`,
`inst.rs`, `nht.rs`). Those 4 files were restored from `origin/main`; no commit
was made. The recommendation is to **start a fresh session, hard-reset the
branch to `origin/main`, and redo Phase 3 cleanly** from the spec below.

```bash
# In a fresh, healthy session, from /home/kunihiro/zebra-rs.bgp-link-state:
git fetch origin
git checkout bgp-ls-afi-safi 2>/dev/null || git checkout -b bgp-ls-afi-safi origin/main
git reset --hard origin/main        # discard the corrupted partial edits
```

## Scope of Phase 3 (exact, additive)

Add the `LinkState` AFI/SAFI enum variants and wire them everywhere an
AFI/SAFI must be matched, so a BGP-LS session can be negotiated and BGP-LS
NLRIs parsed/serialized through MP_REACH/MP_UNREACH and the BGP-LS Attribute
(type 29). **No RIB storage and no origination yet** — those are Phases 4–7.

Wire values (RFC 9552): **AFI 16388, SAFI 71** (non-VPN). SAFI 72 (VPN)
deferred. Config schema name: **`afi-safi link-state`** (locked with Kunihiro).

A clean `cargo build -p bgp-packet` and `cargo build -p zebra-rs` succeeded
locally with all edits applied (before the channel corrupted things), so the
edit set below is known-complete. The one compiler-forced site that is easy to
miss is the **`MpUnreachAttr` `Display` match** (it is exhaustive — no
wildcard — so the new variant MUST get an arm; the `MpReachAttr` `Display` is
likewise exhaustive).

## The 9 edit sites (exact code)

### 1. `crates/bgp-packet/src/afi.rs` — enum variants + conversions

Add to `enum Afi` (after `L2vpn = 25`):
```rust
    /// BGP Link-State (RFC 9552). Used with SAFI 71 (non-VPN).
    #[strum(serialize = "Link-State")]
    LinkState = 16388,
```
Add to `enum Safi` (after `SrTePolicy = 73`):
```rust
    /// BGP Link-State (RFC 9552), non-VPN. Used with AFI 16388.
    #[strum(serialize = "Link-State")]
    LinkState = 71,
```
`From<Afi> for u16`: add `LinkState => 16388,`
`From<u16> for Afi`: add `16388 => LinkState,`
`From<Safi> for u8`: add `LinkState => 71,`
`From<u8> for Safi`: add `71 => LinkState,`
In the `safi_round_trip_known_values` test array: add `Safi::LinkState,`

### 2. `crates/bgp-packet/src/attrs/bgpls_attr.rs` — ParseBe impl

Import: `use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};`
Add before `impl AttrEmitter for BgpLsAttr {`:
```rust
impl ParseBe<BgpLsAttr> for BgpLsAttr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        Self::parse(input)
    }
}
```

### 3. `crates/bgp-packet/src/attrs/attr.rs` — Attr enum wiring (type 29)

`enum Attr` (after the `TunnelEncap(TunnelEncap)` variant):
```rust
    #[nom(Selector = "AttrSelector(AttrType::BgpLsAttr, None)")]
    BgpLs(BgpLsAttr),
```
`Attr::emit` match: add `Attr::BgpLs(v) => v.attr_emit(buf),`
`impl Display for Attr`: add `Attr::BgpLs(v) => write!(f, "{}", v),`
`impl Debug for Attr`: add `Attr::BgpLs(v) => write!(f, "{:?}", v),`
`parse_bgp_update_attribute` match: add
```rust
            Attr::BgpLs(v) => {
                bgp_attr.bgp_ls = Some(v);
            }
```
(`AttrType::BgpLsAttr = 29` already exists from Phase 2.)

### 4. `crates/bgp-packet/src/bgp_attr.rs` — BgpAttr field

Import list: add `BgpLsAttr` (e.g. `AttrEmitter, BgpLsAttr, BgpNexthop, ...`).
Add field after `pub tunnel_encap: Option<TunnelEncap>,`:
```rust
    /// BGP-LS Attribute (path attribute type 29, RFC 9552).
    pub bgp_ls: Option<BgpLsAttr>,
```

### 5. `crates/bgp-packet/src/attrs/mp_reach.rs` — MP_REACH LinkState

Import: add `BgpLsNlri` to the `use crate::{...}` list.
`enum MpReachAttr` (after the `SrPolicy { ... }` variant):
```rust
    /// BGP Link-State (RFC 9552), AFI 16388 / SAFI 71. Carries Node/Link/
    /// Prefix NLRIs; the companion attributes ride in the BGP-LS Attribute
    /// (path attribute type 29), not here.
    LinkState {
        nhop: IpAddr,
        updates: Vec<BgpLsNlri>,
    },
```
`attr_emit` match (before the `_ => {}` arm):
```rust
            MpReachAttr::LinkState { nhop, updates } => {
                linkstate_attr_emit(nhop, updates, buf);
            }
```
In `parse_nlri_opt`, add a branch (next to the EVPN/MUP branches):
```rust
        if header.afi == Afi::LinkState && header.safi == Safi::LinkState {
            // Next-hop is a 4-octet (IPv4) or 16-octet (IPv6) address.
            if header.nhop_len != 4 && header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = if header.nhop_len == 4 {
                let (input, addr) = be_u32(input)?;
                (input, IpAddr::V4(Ipv4Addr::from(addr)))
            } else {
                let (input, addr) = be_u128(input)?;
                (input, IpAddr::V6(Ipv6Addr::from(addr)))
            };
            let (input, _snpa) = be_u8(input)?;
            let (input, updates) =
                many0_complete(|i| BgpLsNlri::parse(i, add_path)).parse(input)?;
            return Ok((input, MpReachAttr::LinkState { nhop, updates }));
        }
```
`impl Display for MpReachAttr` (exhaustive — add an arm, e.g. after `Evpn`):
```rust
            LinkState { nhop, updates } => {
                for nlri in updates.iter() {
                    writeln!(
                        f,
                        " LS type={} proto={:?} => {nhop}",
                        nlri.nlri_type(),
                        nlri.protocol_id()
                    )?;
                }
            }
```
Add the emitter function (place above `impl fmt::Display for MpReachAttr`):
```rust
/// Serialize an `MpReachAttr::LinkState { nhop, updates }` as a complete
/// `MP_REACH_NLRI` path attribute (RFC 9552 §3.4): AFI 16388, SAFI 71, the
/// next-hop (4 or 16 octets), a zero SNPA count, then the Link-State NLRIs.
fn linkstate_attr_emit(nhop: &IpAddr, updates: &[BgpLsNlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::LinkState));
    value.put_u8(u8::from(Safi::LinkState));
    match nhop {
        IpAddr::V4(a) => {
            value.put_u8(4);
            value.put_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            value.put_u8(16);
            value.put_slice(&a.octets());
        }
    }
    value.put_u8(0); // Reserved (SNPA count).
    for nlri in updates {
        crate::bgpls_nlri_emit(&mut value, nlri);
    }

    let len = value.len();
    let extended = len > 255;
    let flags = if extended {
        AttrFlags::new().with_optional(true).with_extended(true)
    } else {
        AttrFlags::new().with_optional(true)
    };
    buf.put_u8(flags.into());
    buf.put_u8(AttrType::MpReachNlri.into());
    if extended {
        buf.put_u16(len as u16);
    } else {
        buf.put_u8(len as u8);
    }
    buf.put(&value[..]);
}
```

### 6. `crates/bgp-packet/src/attrs/mp_unreach.rs` — MP_UNREACH LinkState

Import: add `BgpLsNlri` to the `use crate::{...}` list.
`enum MpUnreachAttr` (after the `SrPolicy { ... }` variant):
```rust
    /// BGP Link-State withdrawals (RFC 9552), AFI 16388 / SAFI 71. An empty
    /// `withdraws` list represents end-of-RIB.
    LinkState {
        withdraws: Vec<BgpLsNlri>,
    },
```
`attr_emit` match (before the `_ => {}` arm):
```rust
            MpUnreachAttr::LinkState { withdraws } => {
                linkstate_unreach_attr_emit(withdraws, buf);
            }
```
In `parse_nlri_opt`, before the final `Err(... NoneOf)`:
```rust
        if header.afi == Afi::LinkState && header.safi == Safi::LinkState {
            if input.is_empty() {
                return Ok((input, MpUnreachAttr::LinkState { withdraws: vec![] }));
            }
            let (input, withdraws) =
                many0_complete(|i| BgpLsNlri::parse(i, add_path)).parse(input)?;
            return Ok((input, MpUnreachAttr::LinkState { withdraws }));
        }
```
`impl Display for MpUnreachAttr` (exhaustive — add an arm after `SrPolicy`):
```rust
            LinkState { withdraws } => {
                if withdraws.is_empty() {
                    return writeln!(f, " EoR: {}/{}", Afi::LinkState, Safi::LinkState);
                }
                for nlri in withdraws {
                    writeln!(
                        f,
                        " LS type={} proto={:?}",
                        nlri.nlri_type(),
                        nlri.protocol_id()
                    )?;
                }
                Ok(())
            }
```
Add the emitter function (place above `impl MpUnreachAttr {` that holds
`parse_nlri_opt`):
```rust
/// Serialize an `MpUnreachAttr::LinkState { withdraws }` (empty `withdraws`
/// encodes an end-of-RIB marker) as a complete `MP_UNREACH_NLRI` path
/// attribute: AFI 16388, SAFI 71, then the Link-State NLRI list (RFC 9552).
fn linkstate_unreach_attr_emit(withdraws: &[BgpLsNlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::LinkState));
    value.put_u8(u8::from(Safi::LinkState));
    for w in withdraws {
        crate::bgpls_nlri_emit(&mut value, w);
    }

    let len = value.len();
    let extended = len > 255;
    let flags = if extended {
        AttrFlags::new().with_optional(true).with_extended(true)
    } else {
        AttrFlags::new().with_optional(true)
    };
    buf.put_u8(flags.into());
    buf.put_u8(AttrType::MpUnreachNlri.into());
    if extended {
        buf.put_u16(len as u16);
    } else {
        buf.put_u8(len as u8);
    }
    buf.put(&value[..]);
}
```

### 7. `zebra-rs/src/bgp/cap.rs` — MP capability negotiation

In `CapAfiMap::new`, after `let mp6srp = ...SrTePolicy);`:
```rust
        let mpls = CapMultiProtocol::new(&Afi::LinkState, &Safi::LinkState);
```
After `cmap.entries.insert(mp6srp, SendRecv::default());`:
```rust
        cmap.entries.insert(mpls, SendRecv::default());
```
(`mpls` here = "MP link-state"; rename if it reads ambiguously next to MPLS.)

### 8. `zebra-rs/src/config/configs.rs` — `Args::afi_safi`

After the `"sr-policy-v6" => ...` arm:
```rust
            "link-state" => Some(AfiSafi::new(Afi::LinkState, Safi::LinkState)),
```

### 9. `zebra-rs/yang/zebra-afi-safi.yang` — config enum

After the `enum sr-policy-v6 { ... }` entry in the **main** `afi-safi`
grouping's `leaf name` enumeration:
```yang
        enum link-state {
          description "BGP Link-State (AFI 16388, SAFI 71, RFC 9552).";
        }
```
NOTE: only add it to the full `afi-safi` grouping, NOT to
`afi-safi-unicast` (that one is IS-IS / per-VRF unicast-only). There is a
`yang_load_tests` CI guard, so the YANG must stay loadable.

## Verification (use exit codes — the channel display lied last time)

```bash
git diff --stat origin/main      # MUST be exactly these 5 files + this doc:
#   afi.rs, bgpls_attr.rs, mp_reach.rs, mp_unreach.rs (bgp-packet),
#   zebra-rs/src/bgp/cap.rs, zebra-rs/src/config/configs.rs,
#   zebra-rs/yang/zebra-afi-safi.yang
#   If ANY other file shows deletions, the env corrupted it — restore from
#   origin/main before continuing.
cargo test -p bgp-packet                 # expect ~263 passed (was 248 pre-P3)
cargo build -p zebra-rs                   # expect exit 0
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # expect exit 0
```

Consider adding one round-trip test in `mp_reach.rs`/`mp_unreach.rs` tests
(emit a `LinkState` MP_REACH with a Node NLRI, strip the attr header, parse
back, assert equal) — mirrors the existing srpolicy/flowspec unreach tests.

## After Phase 3 merges

Phase 4 = receive-side RIB: `LocalRib.bgpls` exact-match table (keyed by
`BgpLsNlri`, like flowspec/EVPN), `route_bgpls_update`/`route_bgpls_withdraw`,
dispatch the new `MpReachAttr::LinkState` / `MpUnreachAttr::LinkState` in
`route_from_peer` (`zebra-rs/src/bgp/route.rs`), iBGP/RR propagation. The
BGP-LS Attribute (type 29) is already captured into `BgpAttr.bgp_ls` by edit #3.

## Gotchas carried from earlier phases

- Two flag types in `crates/bgp-packet/src/attrs/flags.rs`: `AttributeFlags`
  (bitflags: `OPTIONAL`, `from_bits_truncate`) vs `AttrFlags` (bitfield_struct:
  `AttrFlags::new().with_optional(true)`). `AttrEmitter::attr_flags` returns
  `AttrFlags`.
- `crates/bgp-packet/src/attrs/mod.rs` must keep `pub mod srpolicy;` /
  `pub use srpolicy::*;` (a corrupted rebuild dropped it once → CI red in #1067;
  fixed by amend). Don't hand-rewrite mod.rs; edit it surgically.
- CI is the source of truth. `cargo fmt` before every commit; clippy is
  `--workspace --all-targets -- -D warnings`. `main` is branch-protected
  (`enforce_admins`), so PRs need green CI to merge.
- This is a linked worktree; `main` lives in the primary worktree
  `/home/kunihiro/zebra-rs`. `/merge-pr` cleanup must not `git checkout main`
  here — switch to `bgp-link-state` and verify with
  `git merge-base --is-ancestor <branch> origin/main` before deleting.
```
