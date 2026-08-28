# RFC 9234 — BGP Roles and the Only-to-Customer (OTC) attribute

Plan for route-leak prevention/detection in zebra-rs BGP: the Role
capability (OPEN, code 9), the Role Mismatch NOTIFICATION (OPEN error
subcode 11), the OTC path attribute (type 35), and the five ingress/egress
procedures. Reference implementations consulted: RFC 9234 itself, the
Cisco IOS XR 26.4.1 implementation (xrdocs "RFC 9234 BGP Only-to-Customer
(OTC) on IOS XR", 2026-08-13), FRR `local-role`, VyOS/TNSR `local-role`.

## 0. What is already in the tree

| Piece | Status |
|---|---|
| `CapabilityType::Role = 9` (`crates/bgp-packet/src/caps/typ.rs`) | code named, no typed capability — falls through to `CapUnknown` (a unit test in `caps/packet.rs` *asserts* this fallthrough; it must be re-pointed at another code) |
| `OpenError::RoleMismatch = 11` (`notification.rs`) | present incl. Display string |
| `iana-bgp-notification@2023-07-05.yang` `open-role-mismatch` | present |
| OTC attribute (type 35) | not named in `AttrType` → parses as `Unknown(35)`, retained with the Partial bit and re-emitted verbatim (RFC 4271 §9). zebra-rs already *preserves* OTC transparently — good — but does not read or set it |
| Per-neighbor knob template | `enforce-first-as` (YANG grouping + `config.rs` callback + `neighbor_group.rs` inheritance + `vrf_config.rs` + `show.rs`) — the shape to copy |
| No `role`/`local-role` leaf in vendored `ietf-bgp-common` | verified by grep — no augment-name collision (see memory `zebra-rs-bgp-neighbor-yang-ietf-collision`) |

## 1. Semantics to implement (normative summary)

Roles: `provider(0) rs(1) rs-client(2) customer(3) peer(4)`; valid pairs
provider↔customer, rs↔rs-client, peer↔peer.

Session (RFC 9234 §4):
* If a local role is configured on an eBGP session, advertise the Role
  capability (code 9, length 1).
* Both sides send: pair must be valid, else NOTIFICATION Open Message Error
  / Role Mismatch (2/11) and the session does not come up.
* Only we send (**loose**, the default): SHOULD proceed; treat the remote
  role as *inferred* from ours (Cisco displays "(inferred)").
* **strict**: no Role capability received → Role Mismatch.
* Multiple Role caps with different values → Role Mismatch. Same value →
  one.
* Roles are only defined for eBGP. iBGP: knob is a no-op (same convention as
  `enforce-first-as` / `as-override`); OTC still rides through iBGP and
  route reflection unchanged because it is transitive.
* A role change is exchanged only in OPEN → **bounce the session** on change
  (Cisco: CEASE "configuration change"; zebra-rs: `PeerDownReason::ConfigChange`,
  Cease subcode 6).

Routes (RFC 9234 §5, §6) — **IPv4 unicast and IPv6 unicast only** (AFI 1/2,
SAFI 1); MUST NOT be applied to other families by default; "the operator
MUST NOT have the ability to modify the procedures":

| Rule | Direction | Condition | Action |
|---|---|---|---|
| IR1 | in | OTC present, from customer or rs-client | leak → ineligible (not selected, not re-advertised) |
| IR2 | in | OTC present, from peer, value ≠ remote AS | leak → ineligible |
| IR3 | in | OTC absent, from provider / peer / rs | add OTC = **remote AS** |
| ER1 | out | OTC absent, to customer / peer / rs-client | add OTC = **local AS** |
| ER2 | out | OTC present, to provider / peer / rs | do not advertise |

OTC malformed (length ≠ 4) → RFC 7606 treat-as-withdraw (the
`UpdatePacket.treat_as_withdraw` path already exists). Once set, OTC is
preserved unchanged (no policy `set otc`; Cloudflare found Tier-1s stripping
it — we must not).

Loose-mode detail worth copying from Cisco: only the *configured* side
applies OTC processing; an inferred role never drives the unconfigured
side (it has no role). So "z1 provider (configured) → z2 no role" still
yields OTC=AS(z1) on z2 via ER1 on z1, and "z1 no role → z2 customer
(configured)" yields OTC=AS(z1) via IR3 on z2.

## 2. Decisions

1. **CLI spelling — Cisco IOS XR compatible (decided 2026-08-28):**
   `neighbor <X> otc-local-role {customer|provider|peer|route-server-client} [strict]`,
   the exact 26.4.1 syntax. One superset value, `route-server` (RFC role 1),
   is added so zebra-rs can take the RS side of an RS↔RS-Client pair; XR
   omits it only because XR has no route-server function. Every user-visible
   string follows Cisco too (see PR 2 / PR 3): `OTC Local Mode: Loose|Strict`,
   `OTC Local Role : Provider`, `OTC Remote Role: Customer (received|inferred)`,
   capability row `OTC Role: Yes/No`, `By OTC ingress rule 1: n, By OTC
   ingress rule 2: n`, `OTC-AS: <asn>` on a path, and the last-reset reason
   `OTC role mismatch`. FRR/VyOS `local-role` is **not** offered as an alias.
2. **YANG shape** — `list otc-local-role { key role; max-elements 1; leaf role { enumeration customer|provider|peer|route-server-client|route-server }; leaf strict { type empty } }`
   gives exactly the `otc-local-role customer [strict]` CLI. **Proven in
   PR 2** by `config/manager.rs::bgp_neighbor_otc_local_role_paths_parse`
   (enum list-key + empty leaf parse on the neighbor, neighbor-group and
   VRF neighbor). `max-elements` is not engine-enforced (same as
   `local-as`): the staging helpers on `InheritableKnobs` refuse a second
   role with a warning — delete the current role before setting another.
   Module `zebra-bgp-otc.yang`, prefix `zbotc`, grouping
   `bgp-neighbor-otc-local-role-extension`; the VRF copy is inline in
   `zebra-bgp-vrf.yang`.
3. **Local AS for ER1** = `peer.open_local_as()` (the substitute when
   `local-as` is active — the AS the neighbor sees us as, and what its own
   IR3 would stamp). **Remote AS for IR2/IR3** = `peer.remote_as`.
4. **"Ineligible"** = drop at the per-UPDATE inbound gate (same fate as an
   `enforce-first-as` violation: no Loc-RIB entry, no advertise). Count it
   per peer (`otc_denied_ir1`, `otc_denied_ir2`) and trace it. Cisco keeps a
   received-only copy under soft-reconfiguration; zebra-rs replays the
   stored UPDATEs through the same gate, so no special case.
5. **Unknown role value (5–255) received** → treat as Role Mismatch (it can
   form no valid pair). **Role cap with length ≠ 1** → parse as opaque
   `Unknown` (ignored) so a malformed cap does not kill the whole OPEN; in
   strict mode that then reads as "no role received" → mismatch.
6. **Update-group signature** — ER1/ER2 depend on the local role (and on
   local AS, already a sig field), so `local_role: Option<LocalRole>` joins
   `UpdateGroupSig` and `SIGNATURE_VERSION` 6→7 (memory
   `zebra-rs-bgp-update-group-signature-trap`). Not doing this is a silent
   wrong-bytes bug the BDD cannot catch.
7. Per-prefix role override via route-map (Cisco RPL `set otc-local-role`)
   is **deferred** (§6 of the RFC discourages it; keep the first cut
   session-scoped).

## 3. Phases (one PR each, smallest first)

### PR 1 — codec (`crates/bgp-packet`)
* `caps/role.rs`: `CapRole { role: u8 }` + `BgpRole` enum (`Provider=0, Rs=1, RsClient=2, Customer=3, Peer=4`) with `counterpart()` and `pairs_with()`; `CapEmit` (`len()=1`); Display "Role: customer".
* `CapabilityPacket::Role` arm (`Selector = "CapCode::Role"`), `encode` arm.
* `BgpCap.role: Option<CapRole>` + `role_conflict: bool` (set when a second Role cap carries a different value); emit + Display.
* Fix `caps/packet.rs::unknown_short_capability_parses_and_round_trips` (uses code 9 as the "unknown" example) → use an unassigned code; update the `CapUnknown` doc comment that cites RFC 9234.
* `attrs/otc.rs`: `Otc { asn: u32 }`, flags Optional|Transitive, fixed len 4; `AttrType::Otc = 35` (+ both `From` impls), `Attr::Otc`, `BgpAttr.otc: Option<Otc>`, `attr_emit` arm, Display; length ≠ 4 → treat-as-withdraw (follow the existing RFC 7606 pattern in `update.rs`/`parser.rs`).
* Follow `SECURITY_AUDIT.md` "Invariants to preserve" (bounded slice, reject remainder, fixed length).
* Tests: cap round-trip, duplicate-cap collapse/conflict, OTC round-trip, OTC bad length → treat-as-withdraw, `Unknown(35)` no longer produced.

### PR 2 — session: knob, OPEN exchange, mismatch
* YANG `zebra-bgp-otc.yang` (prefix `zbotc`), grouping `bgp-neighbor-otc-local-role-extension`, augments for set/delete; import in `config.yang`; `uses` in `zebra-bgp-neighbor-group.yang`; inline list in `zebra-bgp-vrf.yang` next to `enforce-first-as`. `yang_load_tests` grammar pin + parse test.
* `PeerConfig.otc_local_role: Option<OtcLocalRole { role: BgpRole, strict: bool }>`; `InheritableKnobs.otc_local_role` (compiler forces `apply_inherited`); `config_otc_local_role` (record→resolve→`apply_otc_local_role`), `config_neighbor_group_otc_local_role` **with `sweep_members_inherit`** (memory: forgetting the sweep is a silent bug), `config_vrf_neighbor_otc_local_role`; registrations under `/otc-local-role`. `apply_otc_local_role` bounces an Established/Open* session on change (`ConfigChange`; log line mirrors XR: "neighbor X Down - OTC local role changed").
* `build_open_packet`: `if is_ebgp() && let Some(r) = config.otc_local_role { bgp_cap.role = Some(CapRole::new(r.role)) }`.
* `fsm_bgp_open`: right after the `BadPeerAS`/AS4-consistency block (so it covers both `ConnTag::Primary` and `ConnTag::Collision` via the same `close_collision` / `peer_send_notification` split): `otc_role_check(local, is_ebgp, &packet.bgp_cap) -> Result<(), OtcRoleMismatch>` → NOTIFICATION 2/11 + `State::Idle` on `Err`. **As built:** no `PeerDownReason` variant — `last_reset` is only written when an *Established* session ends, and a role mismatch happens in OpenSent, so the reason lives in `Peer::otc_role_mismatch` (cleared by the next passing OPEN) and is rendered as `OTC Role Mismatch: …`. The remote role is not stored; `Peer::otc_remote_role()` derives it from `cap_recv` (received, while OpenConfirm/Established) or the local role's counterpart (inferred).
* `show bgp neighbor` (text + JSON), Cisco strings verbatim:
  ```
   OTC Local Mode: Loose
   OTC Local Role : Provider
   OTC Remote Role: Customer (received)
  Neighbor capabilities:            Adv         Rcvd
    OTC Role:                       Yes         Yes
  ```
  rendered in the `as4`/`fqdn` style (`show.rs` ~3731/4012); `Last reset ... OTC role mismatch`. JSON: `otc_local_mode`, `otc_local_role`, `otc_remote_role`, `otc_remote_role_source`.
* Unit tests (`peer.rs` FSM tests already have an `open_packet(...)` helper): valid pair, invalid pair → 2/11, loose absent → OpenConfirm with inferred, strict absent → 2/11, conflicting duplicates → 2/11, unknown value → 2/11, iBGP → no cap sent; config tests mirroring `enforce_first_as_*` and `group_enforce_first_as_propagates_no_bounce` (this one *does* bounce).

### PR 3 — OTC procedures + BDD
* Ingress (v4 unicast: `inbound_attr_checks` + the single-prefix `route_ipv4_update` path; v6 unicast: `route_ipv6_update` ~6896). Only these two families — **not** the other six `enforce-first-as` sites. IR1/IR2 → return `None` + counter + `bgp_packet_trace!`-style trace "DENIED by OTC ingress rule N". IR3 mutates the attr: clone the UPDATE's attr once *before* the batch/shard split (N>1 runs policy in the shard, so the stamp must be main-side and shared by all prefixes).
* Egress: `SyncCtx.otc_local_role` (from `Peer::sync_ctx`) and `EgressAs`-adjacent helper `otc_egress(role, local_as, &mut attrs) -> bool /*suppress*/` called in `route_update_ipv4` right after `ebgp_egress_aspath` (ER2 → `return None`, which already flows into `AdvertiseOutcome::Withdraw`); same in `route_update_ipv6` (takes `&mut Peer`, read `peer.config` directly).
* `UpdateGroupSig.otc_local_role`, `SIGNATURE_VERSION = 7`, extend `signature_fields_each_distinguish`.
* `show bgp <prefix>` / detail: `OTC-AS: 65540` line beside AIGP (`show.rs` ~1912 and ~4409) + JSON `otc_as`.
* `show bgp neighbor`: `By OTC ingress rule 1: n, By OTC ingress rule 2: n` (Cisco wording, under the prefix-denied counters); trace line `Prefix P received from X DENIED due to OTC ingress rule 1: route leak from Customer/RS-Client` / `... rule 2: OTC AS mismatch from Peer`.
* BDD `bgp_otc_local_role.feature` (line z1 AS65001 — z2 AS65002 — z3 AS65003, z1 originates 10.0.0.1/32), scenarios:
  1. z1 provider / z2 customer: Established, both show `OTC Remote Role: ... (received)` and `OTC Role: Yes Yes`; z2 has the route with `OTC-AS: 65001`.
  2. ER2: z2 customer toward z3 (z3 provider) → z3 does **not** get 10.0.0.1/32.
  3. IR3 + loose: z1 role removed, z2 customer → z2 still stamps OTC 65001, remote shown "(inferred)".
  4. IR1: z2 role toward z3 removed (z2 forwards the OTC route), z3 provider → z3 drops, counter IR1 = 1.
  5. IR2: z2/z3 peer/peer with an OTC ≠ 65002 arriving at z3 (route already OTC-marked by z1 = 65001) → dropped, counter IR2.
  6. Mismatch: z1 provider + z2 provider → not Established, last reset contains `OTC role mismatch`.
  7. Strict: z1 `otc-local-role customer strict`, z2 no role → not Established, `OTC Local Mode: Strict`; add z2 role → Established.
  New cucumber steps: `BGP route in "z" has "p" with OTC-AS <asn>` / `without OTC`; `show command ... should contain` covers the rest (memory: literal `show`, literal `clear`). Session bounce via `clear bgp ipv4 neighbor` where needed.
* Config-file (YAML) spelling that the BDD uses, for the record:
  ```yaml
  router:
    bgp:
      neighbor:
        - address: 192.168.0.2
          remote-as: 65002
          otc-local-role:
            - role: provider
              strict: null      # omit for loose (see memory zebra-rs-bdd-empty-leaf-yaml)
  ```

### PR 4 — docs (can fold into PR 3)
* `book/src/ch-02-42-bgp-otc-local-role.md` ("Route Leak Prevention: OTC Local Role (RFC 9234)") + `SUMMARY.md` (after Enforce First AS), `appendix-b-supported-rfcs.md` row for RFC 9234, `docs/design/bgp-update-groups.md` §3.1 (otc-local-role now a sig field), `CHANGELOG.yaml` note at release cut. The chapter should state the XR-compatible syntax and the one superset value (`route-server`).

### PR 5 — optional follow-ups
* Route-map `set otc-local-role <role>` (in/out) per-prefix override, Cisco RPL parity — only if asked.
* Dynamic-neighbor (listen-range) members inherit via the group path already; verify with a scenario.
* Interop run against FRR/BIRD (`local role`, `require roles`) and — when a lab is available — IOS XR 26.4.1.

### Separate task — route-server mode (RFC 7947)
zebra-rs has no RS mode today (always prepends; no `route-server-client`
knob; the book's RFC 7947 appendix row is unbacked). That work is tracked
in its own design, **`bgp-route-server-plan.md`**, and is not part of this
arc. The `otc-local-role` enum still accepts `route-server` and
`route-server-client` so the wire/OPEN side is complete; the RS role is
simply not *useful* until that plan lands.

## 4. Gotchas to carry into implementation
* `route_update_ipv4` output must depend only on `UpdateGroupSig` fields — hence decision 6.
* `remote_as` for `remote-as external` / interface peers is learned from OPEN; the OTC gates run post-Established so it is always known there.
* iBGP transit: a leak that enters via iBGP is caught only at the *other* border's ER2 — OTC must survive `strip_ibgp_only_attrs` (it is not iBGP-only; do not add it there).
* `soft-reconfiguration inbound` replay re-runs IR1–IR3; counters will double on replay — count per replay is acceptable, document it.
* Group knob without a sweep = config-order-dependent bug (memory `zebra-rs-bgp-neighbor-group-inheritance`).
* `cargo fmt` before every commit; full suite = `cargo test --workspace --exclude bdd`; BDD needs `make -C bdd stage` and YANG copied to `/usr/share/zebra-rs/yang/`.
