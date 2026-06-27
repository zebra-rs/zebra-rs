# BGP Unrecognized Path Attribute Handling (RFC 4271 §9 / §6.3)

How zebra-rs handles BGP path attributes whose **Type Code it does not
recognize**. This memo captures **what existed before** (essentially
nothing — it was a correctness gap), **what the
`bgp-unknown-attr-transitive` branch added** (PR #1667), and **why the
key design decisions were made** — in particular why the classification
lives in the attribute loop rather than the `nom-derive` selector, and
why the per-neighbor debug knob has to shard the update-group.

Read this first if you're touching the attribute parser
(`crates/bgp-packet/src/attrs/attr.rs`), the `BgpAttr` container
(`crates/bgp-packet/src/bgp_attr.rs`), the UPDATE receive path / FSM
(`zebra-rs/src/bgp/peer.rs`), or the IPv4 egress builder
(`zebra-rs/src/bgp/route.rs::route_update_ipv4`).

Related: [`bgp-prefix-sid-rfc9252.md`](bgp-prefix-sid-rfc9252.md) (the
RFC 7606 *treat-as-withdraw* path that shares the attribute loop) and the
project memory note `zebra-rs-bgp-unknown-attr-transitive`.

## The RFC, in one table

The receiver's action is decided entirely by the **Attribute Flags**
octet (Optional 0x80, Transitive 0x40, Partial 0x20, Extended 0x10):

| Received attribute (Type Code unknown) | Required action | Reference |
|---|---|---|
| Optional **transitive** | accept the route, **set the Partial bit**, **retain** the attribute, and re-advertise it to other peers | RFC 4271 §9, §5 |
| Optional **non-transitive** | **quietly ignore** — do not store, do not propagate | RFC 4271 §9 |
| **Well-known** (Optional bit clear) | error: reset the session with a **NOTIFICATION** (Update Message Error, subcode 2 — *Unrecognized Well-known Attribute*); Data field carries the offending attribute | RFC 4271 §6.3 |

## What existed before (the gap)

`AttrType::Unknown(u8)` existed in `attr.rs`, but:

- the `Attr` enum had **no variant** to carry an unknown attribute, so the
  `nom-derive` selector dispatch had nothing to match;
- `BgpAttr` carried a literal `// TODO: Unknown Attributes` — nowhere to
  store one;
- `Attr::emit` had a silent `_ => {}` arm that dropped unknowns.

Net effect: **any** unrecognized attribute made `parse_bgp_update_attribute`
return an error, and the reader (`peer_read`) turned every parse error into
a bare `ConnFail` — the connection was dropped **without** a NOTIFICATION.
That violated all three rows of the table above (no propagation, no
Partial, no proper NOTIFICATION; even an optional non-transitive attribute
killed the session).

## Codec design (`crates/bgp-packet`)

### `UnknownAttr` — `attrs/unknown.rs`

```rust
pub struct UnknownAttr {
    pub flags: u8,      // Attribute Flags octet (Optional/Transitive/Partial/Extended)
    pub type_code: u8,  // Attribute Type Code
    pub value: Vec<u8>, // raw Value bytes (Length octet(s) excluded)
}
```

- Stored on the route via a new `BgpAttr.unknown: Vec<UnknownAttr>`.
- Derives `Clone, PartialEq, Eq, PartialOrd, Ord, Hash` — `Ord`/`Hash` are
  required because the attach knob (below) puts it inside `UpdateGroupSig`,
  which is a `BTreeMap` key.
- `attr_emit` writes the attribute verbatim — flags, type, length, value —
  but **re-derives the Extended-Length bit from `value.len()`** so the
  on-wire length-field width always matches, regardless of what the
  stored flags say.

The attrs submodule is `mod unknown` (**not** `pub mod`): the crate root
globs `attrs::*`, and a public `unknown` module name would collide with
the existing `caps::unknown` module under that glob.

### Why classification lives in `parse_bgp_update_attribute`, not the selector

The known attributes are parsed by a `nom-derive` `Selector` dispatch on
`AttrType`. That dispatch is handed only the *type*, not the *flags* — but
the RFC's three-way decision is **flag-driven**. So rather than bolt an
`Attr::Unknown` variant onto the selector (which would still lack the
flags, and would force a synthetic `Parse` impl), the unknown case is
intercepted in the attribute loop itself, where `parse_attr_header` has
already decoded `flags`:

```text
for each attribute:
    (rest, type, flags, payload) = parse_attr_header(...)
    if type is Unknown(code):
        if !flags.OPTIONAL:        -> Err(UnrecognizedWellknownAttribute{code, full-TLV-bytes})
        else if flags.TRANSITIVE:  -> push UnknownAttr (with Partial set) onto bgp_attr.unknown
        else:                      -> drop (optional non-transitive)
        continue
    ... existing known-attribute path ...
```

`set_partial()` is applied **at receive time**, matching the RFC wording:
*"the Partial bit ... is set to 1, and the attribute is retained for
propagation."* So a stored unknown transitive attribute always carries
Partial = 1, and `BgpAttr::attr_emit` re-emits it that way with no extra
logic at egress.

### The new error variant

`BgpParseError::UnrecognizedWellknownAttribute { type_code, attr }` — the
`attr` field is the **full attribute TLV** (flags, type, length, value),
sliced out of the input as `remaining[..consumed]`, for the NOTIFICATION
Data field.

## NOTIFICATION path (`zebra-rs/src/bgp/peer.rs`)

The reader task (`peer_read` → `peer_packet_parse`) runs without a
`&mut Peer`, and NOTIFICATIONs are sent from the FSM. So the well-known
case is plumbed through an event:

1. `peer_packet_parse` matches `BgpParseError::UnrecognizedWellknownAttribute`
   and sends a new **`Event::UpdateError(NotifyCode, sub_code, data)`**
   (code = `UpdateMsgError`, sub_code = 2, data = the offending TLV).
2. The FSM arm calls **`fsm_update_error`**, which mirrors
   `fsm_holdtimer_expires`: `peer_send_notification(...)` then return
   `State::Idle`. The Established→Idle teardown drains the queued
   NOTIFICATION (the writer is detached, not aborted) and cleans the
   Adj-RIBs.
3. `peer_packet_parse` still returns `Err`, so the reader's subsequent
   `ConnFail` is a no-op once the FSM has already gone Idle.

A small codec addition was needed: `impl From<UpdateError> for u8` (only
`From<u8>` existed, and the enum's `Unknown(u8)` variant makes a plain
`as u8` cast illegal).

## Propagation & the debug originate knob

### Propagation is automatic

Every IPv4-unicast advertisement runs through
`route_update_ipv4` → `BgpAttr::attr_emit`. Because the received unknown
transitive attribute is stored on the route's `BgpAttr` (with Partial
already set), re-advertisement is bit-faithful with **no egress-specific
code** — a transit speaker forwards what it could not understand, exactly
as §9 requires.

### Per-neighbor `attach-unknown-attribute` (debug/test)

To drive the **receiver-side** behaviour from configuration (instead of
hand-crafting packets), a per-neighbor knob originates a synthetic unknown
attribute toward one neighbor:

- **YANG** `zebra-rs/yang/zebra-bgp-unknown-attr.yang` — a string leaf
  `attach-unknown-attribute` whose value is the compact spec
  `"<type>:<flags>:<value-hex>"`, e.g. `250:192:deadbeef` (type 250,
  flags 0xC0 = Optional|Transitive, value `DE AD BE EF`). Augmented into
  the neighbor's `set` and `delete` subtrees, imported from `config.yang`.
- **config** `config_attach_unknown_attribute` (registered via
  `callback_peer`) parses the spec into `PeerConfig.attach_unknown_attr`.
- **plumbing** `PeerConfig` → `SyncCtx` (via `Peer::sync_ctx`) →
  appended to `attrs.unknown` in `route_update_ipv4` (skipping if the
  route already carries an unknown attribute of the same Type Code, so a
  received-and-re-advertised attribute is never duplicated).

Because `route_update_ipv4` is the single egress builder shared by the
N=1, sharded (N>1), and update-group paths, one injection point covers
them all.

### Why it must shard the update-group

`route_update_ipv4`'s output is replicated to every peer in an
update-group from one canonical encoding. The attach knob changes those
encoded bytes per neighbor, so it **must** be part of `UpdateGroupSig`
(`zebra-rs/src/bgp/update_group.rs`) — otherwise one peer's attached
attribute would leak to every other peer in the group. The field was
added to the signature and `SIGNATURE_VERSION` bumped 4 → 5. (Same class
of trap as `as-override` / `remove-private-as` / `local-as`, which are in
the signature for the same reason.)

## Observability

`show bgp -j` route rows now carry an `unknown_attributes` array (omitted
when empty), each entry decoding the flags for operators and tests:

```json
"unknown_attributes": [
  { "type_code": 250, "flags": 192, "optional": true,
    "transitive": true, "partial": true, "value": "deadbeef" }
]
```

Built by `show_unknown_attrs` in `zebra-rs/src/bgp/show.rs`.

## Test coverage

- **Codec unit tests** (`attrs/attr.rs`): transitive-retain + Partial set
  + bit-faithful re-emit; non-transitive drop; well-known →
  `UnrecognizedWellknownAttribute`; whole-`BgpAttr` round-trip.
- **Config tests** (`bgp/config.rs`): spec set/delete onto the peer, and
  `parse_attach_unknown_attr` edge cases (empty value, odd-length hex,
  out-of-range fields).
- **Schema guard** (`config/manager.rs`):
  `bgp_neighbor_attach_unknown_attribute_paths_parse` pins the YANG path.
- **Signature guard** (`update_group.rs`): the attach field distinguishes
  signatures.
- **BDD** `@bgp_unknown_attr_transitive` — a z1→z2→z3 eBGP line where z1
  originates `10.0.0.1/32` and attaches the attribute toward z2:
  baseline (no unknown attrs), transitive (z2 **and** z3 retain type 250
  with Partial set), non-transitive (dropped at z2, absent at z3).

## File map

| Piece | Where |
|---|---|
| `UnknownAttr` type + emit | `crates/bgp-packet/src/attrs/unknown.rs` |
| Classification on receive | `crates/bgp-packet/src/attrs/attr.rs::parse_bgp_update_attribute` |
| Storage + emit on the route | `crates/bgp-packet/src/bgp_attr.rs` (`BgpAttr.unknown`, `attr_emit`) |
| Error variant | `crates/bgp-packet/src/error.rs` |
| NOTIFICATION subcode conversion | `crates/bgp-packet/src/notification.rs` (`From<UpdateError> for u8`) |
| `Event::UpdateError` + `fsm_update_error` + reader wiring | `zebra-rs/src/bgp/peer.rs` |
| Egress re-emit + attach knob | `zebra-rs/src/bgp/route.rs::route_update_ipv4`, `SyncCtx` |
| Update-group signature | `zebra-rs/src/bgp/update_group.rs` |
| `show bgp -j` rendering | `zebra-rs/src/bgp/show.rs::show_unknown_attrs` |
| Config callback + spec parser | `zebra-rs/src/bgp/config.rs` |
| YANG leaf | `zebra-rs/yang/zebra-bgp-unknown-attr.yang` (imported by `config.yang`) |
| BDD | `bdd/tests/features/bgp_unknown_attr_transitive.feature` + `bdd/tests/configs/bgp_unknown_attr_transitive/` |

## Known limitations / follow-ups

- **The attach knob takes effect on the next (re)advertisement.** The
  config callback only writes `PeerConfig.attach_unknown_attr`; it does
  not itself trigger a soft-out or regroup. The BDD forces re-send with a
  `clear`. A follow-up could make the callback drive a soft-out + regroup
  so a live config change is observable without an operator clear.
- **Well-known is the only fatal UPDATE error routed through
  `Event::UpdateError` today.** The plumbing is generic
  (`NotifyCode`, sub_code, data), so other RFC 7606 / RFC 4271 §6.3
  errors that warrant a NOTIFICATION can reuse it rather than the bare
  `ConnFail` drop the reader still uses for generic parse failures.
- **No outbound *filtering* of unknown attributes.** Every retained
  unknown transitive attribute is propagated to all eligible peers; there
  is no per-neighbor/per-policy "strip unknown attribute N" knob. Not
  required by the RFC, but a plausible operator request.
