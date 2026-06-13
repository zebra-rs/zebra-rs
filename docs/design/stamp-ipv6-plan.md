# STAMP IPv6 sessions — implementation plan

> **Status:** plan, awaiting review (2026-06-13)
> **Parent docs:** [stamp-phase1-implementation-plan.md](./stamp-phase1-implementation-plan.md)
> (the shipped IPv4 measurement plane — this extends it to IPv6),
> [stamp-sr-mpls-te-plan.md](./stamp-sr-mpls-te-plan.md) §6 (IPv6 sessions = a Phase-1
> deferred item).
> **Branch:** `stamp-ipv6`

---

## 1. Why / scope

STAMP today is IPv4-only (Phase 1 decision D13). Every other routing feature here is
dual-stack — IS-IS v6, OSPFv3, BGP v6 — so IPv4-only delay measurement is the conspicuous
gap, and delay-TE on IPv6 fabrics is a real use case (OSPFv3 / IS-IS v6 Flex-Algo
metric-type-1).

This slice measures a link whose **IS-IS** adjacency is **IPv6 link-local**, mirroring BFD's
single-hop v6 model exactly:

- **One session per link**, address pair chosen by the existing BFD rule
  (`isis::packet::bfd_session_addrs`): **prefer the IPv4 pair; fall back to the IPv6
  link-local pair** when no shared v4 exists. So a dual-stack link keeps its v4 session
  unchanged; a **v6-only IS-IS adjacency** newly gets a v6 session. No link runs two
  sessions — link delay is AF-independent.
- Link-local addressing throughout (like BFD v6 single-hop), so sockets are **scoped by
  ifindex** (the scope is already in `SessionKey.ifindex`).
- Rung-1 kernel RX `SO_TIMESTAMPING` carries over unchanged — it's an `SOL_SOCKET` option and
  the `ScmTimestampsns` cmsg is address-family-agnostic, and software RX stamps work on v6
  veth just as on v4.
- Origination is AF-agnostic on IS-IS: the measured delay flows into the same TLV 22 / 222
  sub-TLVs (RFC 8570) via `te_metric_effective()`, no new emit path.

**OSPF is out of scope, and not for lack of effort — it has nowhere to publish a v6 delay:**
OSPFv2 is IPv4-only on the wire; **OSPFv3 has no TE-metric origination at all** (no
`te-metric` in `config_v3.rs`; `asla_sub_subs()`/`te_metric_effective()` feed only
`ext_link_lsa_originate`, the OSPFv2 Extended-Link *Opaque* LSA — `ospf/link.rs` notes the
measured field is "only ever populated on v2"). A v6 STAMP session on an OSPFv3 link would
measure correctly but have no LSA to carry the result. OSPFv3 delay-TE (an RFC 8362 OSPFv3
Extended-LSA + a v3 `te-metric` model + Flex-Algo v3 metric-type-1 consumption) is a
**separate, larger prerequisite** — deferred until that exists. So this slice touches **no
OSPF code**.

**Also out of scope:** global-scope IPv6 addressing (link-local only, as BFD); multi-AF dual
sessions per link; VRF (still default-VRF, separate deferred item); RFC 9503 / SR-MPLS.

## 2. The one hard part: link-local scope

Unlike v4, v6 link-local addressing needs the **scope id (ifindex)** on every bind/connect,
and `fe80::…` can collide across interfaces. Two consequences:

1. **Sender socket** binds `(local_ll, scope=ifindex)` and connects `(peer_ll, scope=ifindex)`;
   the kernel's 4-tuple demux then includes scope, so replies land on the right session.
2. **Reflector allow-list** must disambiguate by `(src, ifindex)`, not address alone — two
   links can both present `fe80::1`. `SessionTable::reflect_allowed` grows an `ifindex`
   argument (match it whenever the candidate session's key ifindex is non-zero).
3. **Reflector reply** must stamp the probed link-local as source **and** pin egress to the
   ingress ifindex (`IPV6_PKTINFO.ipi6_addr` + `ipi6_ifindex`) — exactly what BFD's
   `write_packet_v6` does.

## 3. Design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| V1 | One session/link, BFD-style v4-preferred / v6-LL-fallback selection (reuse `bfd_session_addrs` for IS-IS) | Minimal IGP-side change; consistent with BFD; delay is AF-independent so a second session adds nothing |
| V2 | Second reflector socket `[::]:862` (`IPV6_V6ONLY`), its own read task + `reflect_tx_v6` → `reflector_write_v6` | Mirrors BFD's dual v4/v6 listeners; `on_probe_recv` routes the reply to the channel matching the probe's family |
| V3 | Per-session sender socket is v4 or v6 by the key's family; `add_session` picks `stamp_sender_socket{,_v6}` | The connected-socket demux model is identical; only `Domain` + scope differ |
| V4 | `reflect_allowed(src, ifindex)` — match ifindex when the session key's ifindex is non-zero | Link-local address collisions across interfaces; v4 sessions (ifindex may be 0) keep address-only match |
| V5 | Reuse rung-1 `set_so_timestamping` on the v6 sockets; `kernel_rx_stamp` unchanged | `SO_TIMESTAMPING` / `ScmTimestampsns` are AF-agnostic |
| V6 | Bind failure on `[::]:862` is non-fatal (warn, v6 sessions just don't form), like the v4 port and like BFD's v6 listener | Don't break v4 measurement if v6 is unavailable in the namespace/kernel |
| V7 | Probe TTL→Hop-Limit 255 on egress; received Hop-Limit surfaced like the v4 TTL | Symmetry with v4 / BFD GTSM-style hygiene (no floor *enforced*, per Phase 1) |

## 4. Step-by-step

### Step 0 — branch (done: `stamp-ipv6`)

### Step 1 — sockets (`stamp/socket.rs`)
- `stamp_reflector_socket_v6(ctx, bind: SocketAddrV6)` — `Domain::IPV6`, nonblocking, reuse,
  `IPV6_V6ONLY`, hop-limit 255, `IPV6_RECVHOPLIMIT`, `IPV6_RECVPKTINFO`, `set_so_timestamping`
  (RX flags), bind. Copy of `bfd_socket_ipv6` + the rung-1 timestamping line.
- `stamp_sender_socket_v6(ctx, local: SocketAddrV6, remote: SocketAddrV6)` — `Domain::IPV6`,
  nonblocking, hop-limit 255, `set_so_timestamping(RX)`, bind `local` (carries the scope),
  `connect(remote)`.

### Step 2 — network (`stamp/network.rs`)
- `reflector_read_v6(sock, tx)` — `recvmsg::<SockaddrIn6>` with `in6_pktinfo` +
  `Ipv6HopLimit` + `Timestamps` cmsgs (copy of `bfd::network::read_packet_v6` + the rung-1
  `kernel_rx_stamp` branch); emit `Message::ProbeRecv` with the v6 `src`/`dst`/`ifindex`.
- `reflector_write_v6(sock, rx)` — `sendmsg` with `in6_pktinfo { ipi6_addr = probed LL,
  ipi6_ifindex }` (copy of `bfd::network::write_packet_v6`); drains a `ReflectRequest`.
- `sender_read` — make AF-agnostic: the connected socket ignores `msg.address`, so switch the
  recvmsg address type to one that works for both (or add a `sender_read_v6` sibling if the
  type param forces it). The cmsg/`kernel_rx_stamp`/parse logic is identical.

### Step 3 — instance (`stamp/inst.rs`)
- Second reflector socket in `new_with`: bind `[::]:862` (non-fatal), spawn `reflector_read_v6`
  + `reflector_write_v6`, hold a `reflect_tx_v6`. (Test ctor: optional, like the v4 ephemeral
  bind.)
- `on_probe_recv` routes the `ReflectRequest` to `reflect_tx` or `reflect_tx_v6` by the reply
  `dst` family.
- `add_session`: build a v4 or v6 sender socket by `key`'s family (`SocketAddrV6` carries the
  scope from `key.ifindex`); spawn the same `sender_read` task.
- `reflect_allowed` call passes the ingress `ifindex`.

### Step 4 — session table (`stamp/session.rs`)
- `reflect_allowed(&self, src: IpAddr, ifindex: u32) -> Option<SessionKey>` — match
  `remote == src` and (`key.ifindex == 0 || key.ifindex == ifindex`). Unit-test the
  link-local-collision disambiguation (two sessions, same `fe80::` remote, different ifindex).

### Step 5 — IS-IS reconcile (only IGP change)
- `isis/inst.rs::stamp_reconcile_link`: replace the v4-only pair selection with
  `super::packet::bfd_session_addrs(local_v4, remote_v4, local_v6ll, remote_v6ll)` — the same
  helper BFD uses — so a v6-only adjacency yields a v6 `SessionKey`. Address snapshots:
  `link.state.v4addr` / `v6laddr` × the Up neighbor's `addr4` / `addr6l` (exactly what
  `bfd_reconcile_all` already gathers). No OSPF change (see §1).

### Step 6 — tests
- Unit: `reflect_allowed` ifindex disambiguation; v6 socket builds; a `::1` loopback
  network-test that the v6 reflector socket delivers a software RX stamp (rung-1 parity).
- Integration: a v6 sibling of the loopback integration test (`Stamp::new_with` v6 bind, a
  `::1` session) asserting a populated `MetricUpdate`.
- BDD: a new `@stamp_te_metric_v6` feature — two namespaces, a **v6-only** IS-IS P2P link
  (link-locals only, no v4 on the measured interface, so the session must form over `fe80::`),
  `te-metric measurement` on both ends. Assert `show isis database detail` carries
  "Min/Max Unidirectional Link Delay", `show stamp` shows the `fe80::` remote, and the rung-1
  `T4 kernel timestamps` leaves zero on the v6 path. Explicit teardown.

### Step 7 — verify & deliver
- `cargo test --workspace --exclude bdd`, `cargo fmt`, `cargo clippy --workspace
  --all-targets -- -D warnings`.
- Release build, md5-guarded install, `make stamp_te_metric_v6` + the existing
  `stamp_te_metric` (v4 regression) + one IS-IS v6 feature (e.g. `isis_ipv6`). PR.

## 5. Risks

| Risk | Mitigation |
|------|------------|
| Link-local scope handling on bind/connect (the v6 footgun) | `SocketAddrV6` carries `scope_id`; set it from `key.ifindex`. Lean on BFD's working v6 path as the template; an integration test over a real v6 veth LL pair in the BDD proves it. |
| `fe80::` collision across interfaces in the reflector allow-list | V4: `reflect_allowed` matches `(src, ifindex)` (decision V4) with a dedicated unit test. |
| `sender_read` recvmsg address-type for a v6 connected socket | The address is ignored on the connected socket; use an AF-agnostic recvmsg or a `_v6` sibling — decided at implementation, both are trivial. |
| Doubling reflector sockets/tasks | Mirrors BFD exactly; negligible. |

## 6. Resolved: OSPFv3 is out (verified)

The "is OSPFv3 in scope" question is settled by inspection: OSPFv3 has **no TE-metric
origination** (no `te-metric` registration in `config_v3.rs`; the measured field is "only ever
populated on v2"; emission goes solely through the v2-only `ext_link_lsa_originate` Opaque
LSA). A v6 session there would measure but not publish, so OSPFv3 is deferred behind a separate
"OSPFv3 delay-TE origination" effort. **This slice is IS-IS v6 only and touches no OSPF code** —
which also keeps it small and fully testable on a v6 veth.
