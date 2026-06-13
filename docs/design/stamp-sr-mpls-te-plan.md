# STAMP / TWAMP-Light Measurement Plan for SR-MPLS TE

> **Status:** recommended implementation plan (as of 2026-06-12)  
> **Scope:** zebra-rs link delay measurement → IGP advertisement → Flex-Algorithm SPF  
> **Audience:** implementers integrating active performance measurement with IS-IS and OSPFv2 SR-MPLS TE  
> **Related docs:** [book ch-09 TWAMP/STAMP](../../book/src/ch-09-00-twamp-stamp.md), [flex-algo roadmap](./flex-algo-roadmap.md), [BFD/STAMP XDP notes](./bfd-sbfd-stamp-xdp-offload-notes.md)

---

## 1. Executive summary

zebra-rs already implements the **distribution and consumption** planes for delay-based SR-MPLS TE: RFC 8570/7471 link attributes, Flex-Algorithm ASLA (RFC 9479/9492), and Flex-Algorithm SPF metric-type 1 (RFC 9350). Static per-interface `te-metric` configuration exercises the full path end to end.

The **measurement plane** is the remaining work: an active prober that populates those same `te-metric` fields dynamically.

**Recommended protocol stack:**

| Tier | Specs | Purpose |
|------|-------|---------|
| **Core** | RFC 8762 (STAMP), RFC 4656, RFC 6038, RFC 8545 | Normative controlless measurement; Cisco/Juniper TWAMP-Light interop (unauthenticated) |
| **SR-MPLS TE** | RFC 8972 + RFC 9503 | TLV framework and SR-MPLS return-path measurement |
| **Procedures (later)** | draft-ietf-spring-stamp-srpm | Operational modes for SR Policy / loopback PM |
| **Defer** | RFC 5357 TWAMP-Control (TCP) | Only if managed Cisco TWAMP server interop is required |

**Primary zebra-rs role:** Session-Sender (probe IGP neighbors on Full adjacencies).  
**Secondary role:** Session-Reflector (stateless first) for external controllers probing zebra-rs.

**Do not** design against RFC 5357 Appendix I (TWAMP Light) alone — it is informative. RFC 8762 supersedes it normatively and was written to fix TWAMP-Light interoperability gaps.

---

## 2. Problem statement

Modern traffic engineering steers on **latency**, not only hop count. zebra-rs treats per-link delay, jitter, and loss as first-class link attributes:

1. **Measurement** — actively probe a link and derive metrics.
2. **Distribution** — advertise metrics in the IGP (IS-IS RFC 8570, OSPFv2 RFC 7471).
3. **Consumption** — Flex-Algorithm SPF with `metric-type min-unidir-link-delay` (RFC 9350 §5.1).

The two planes meet at one seam: per-interface **`te-metric`**. The measurement task writes it; the IGP reads it. That separation mirrors Cisco IOS-XR SR Performance Measurement and Nokia SR-OS OAM-PM / Link Measurement.

---

## 3. Current zebra-rs status

### 3.1 Implemented — distribution & consumption

| Component | IS-IS | OSPFv2 |
|-----------|-------|--------|
| Static `te-metric` config | `router isis / interface / te-metric` | `router ospf / area / interface / te-metric` |
| Wire encoding | RFC 8570 sub-TLVs inline + in ASLA (RFC 9479) | RFC 7471 sub-sub-TLVs in Extended-Link ASLA (RFC 9492) |
| Origination gate | reach entry build | **SR-MPLS only** (`segment-routing / mpls`) |
| Flex-Algo metric-type 1 SPF | `isis/graph.rs` | `ospf/inst.rs` `graph_flex_algo` |
| Show | `show isis database`, `show isis flex-algo` | `show ospf database detail`, `show ospf flex-algo` |

### 3.2 Implemented — wire codec

- **`crates/stamp-packet`** — RFC 8762 base packets, RFC 8972 TLV framework, RFC 9503 return-path sub-TLVs.
- Linked into `zebra-rs` since Phase 1 (see §3.3).

### 3.3 Implemented — measurement runtime (Phase 1, 2026-06)

Built per [stamp-phase1-implementation-plan.md](./stamp-phase1-implementation-plan.md)
(decisions D1–D16, implicit-reflector deviation §2):

- `zebra-rs/src/stamp/` — RFC 8762 unauthenticated Session-Sender (one
  connected socket + prober per session), implicit stateless
  Session-Reflector on `0.0.0.0:862` (allow-list = registered sessions'
  remotes), per-period stats window, export damping
  (`max(old/10, 50 µs)` per field; empty period ⇒ clear), BFD-style
  Subscribe/Unsubscribe client API shared across protocols.
- `spawn_stamp` / `despawn_stamp` in `config/stamp.rs`, eager-spawned by
  the `router isis` / `router ospf` commit arms; `stamp_client_tx` on
  `ConfigManager`.
- `te-metric measurement { enable; interval; damping-period }` on IS-IS
  and OSPFv2 interfaces; runtime `measured_te_metric` on the link with
  static-wins-per-field merge (`te_metric_effective()`) consumed by
  LSP/Extended-Link-LSA origination and flex-algo metric-type-1 SPF.
- `show stamp` / `show stamp session` / `show stamp statistics`; BDD
  `@stamp_te_metric`.
- Phase-1 scope limits: IPv4 P2P links, default VRF, no loss export, no
  configured external reflector (Phase 2+, §6 of the phase-1 plan).

### 3.4 Patterns to follow when implementing

| Existing module | Pattern |
|-----------------|---------|
| **BFD** (`bfd/inst.rs`, `config/bfd.rs`) | Central task; `client_req_tx` on `ConfigManager`; OSPF/IS-IS subscribe on adjacency lifecycle |
| **ND** (`nd/inst.rs`, `config/nd.rs`) | Eager/idempotent spawn; `nd_client_tx`; standalone task not inside IGP |
| **Static te-metric** (`ospf/config.rs`, `isis/link.rs`) | Config change → `ext_link_lsa_originate` / `LspOriginate` |

---

## 4. Spec recommendation (detailed)

### 4.1 Tier 1 — ship first (link TE metrics → Flex-Algo)

Implement **STAMP (RFC 8762)** in **unauthenticated** mode.

| RFC | Role |
|-----|------|
| [RFC 8762](https://www.rfc-editor.org/rfc/rfc8762) | STAMP base: Session-Sender / Session-Reflector, stateless reflector, UDP port 862 |
| [RFC 4656](https://www.rfc-editor.org/rfc/rfc4656) | OWAMP timestamp and Error Estimate semantics |
| [RFC 6038](https://www.rfc-editor.org/rfc/rfc6038) | Symmetric test packet sizes (Juniper STAMP reflectors) |
| [RFC 8545](https://www.rfc-editor.org/rfc/rfc8545) | Well-known port 862 |

**Interoperability:** unauthenticated STAMP interworks with TWAMP-Light reflectors per RFC 8762 §4.6. This covers Cisco IOS XE TWAMP-Light and Juniper TWAMP-Light reflectors.

**Authenticated modes:** defer. TWAMP (HMAC-SHA-1) and STAMP (HMAC-SHA-256) do not interwork.

### 4.2 Tier 2 — SR-MPLS TE correctness

Add after Tier 1 sender works for basic on-link probing:

| RFC | Role |
|-----|------|
| [RFC 8972](https://www.rfc-editor.org/rfc/rfc8972) | STAMP optional TLV framework (codec exists in `stamp-packet`) |
| [RFC 9503](https://www.rfc-editor.org/rfc/rfc9503) | Destination Node Address TLV; Return Path TLV for SR-MPLS bidirectional same-path measurement |

Use when:

- Test packets are **SR-MPLS-encapsulated**, or
- The reflector must reply on a defined **SR label stack** (IOS-XR SR-PM / Nokia SR-OS model).

### 4.3 Tier 3 — defer

| Item | When |
|------|------|
| [RFC 5357](https://www.rfc-editor.org/rfc/rfc5357) TWAMP-Control (TCP 862) | Driving Cisco `ip sla server twamp` without preconfigured 4-tuples |
| RFC 5357 Appendix I alone | Not a design target; treat as TWAMP-Light wire-compat alias for unauth STAMP |
| [draft-ietf-spring-stamp-srpm](https://datatracker.ietf.org/doc/draft-ietf-spring-stamp-srpm/) | End-to-end SR Policy PM, loopback modes, after link TE is stable |
| XDP/eBPF offload | See [bfd-sbfd-stamp-xdp-offload-notes.md](./bfd-sbfd-stamp-xdp-offload-notes.md); reflector-side offload is a later optimization |

### 4.4 Distribution specs (already implemented — no new work)

| RFC | IS-IS | OSPFv2 |
|-----|-------|--------|
| RFC 8570 / RFC 7471 | Link delay, min/max, variation, loss sub-TLVs | Same semantics in ASLA sub-sub-TLVs |
| RFC 9479 / RFC 9492 | ASLA with SABM X-bit | Extended-Link Opaque ASLA |
| RFC 9350 | Flex-Algo metric-type 1, link pruning without delay | Same |

---

## 5. zebra-rs roles

| Role | Priority | Description |
|------|----------|-------------|
| **Session-Sender** | P0 | Probe each Full IGP neighbor on the direct link; derive delay/jitter/loss; feed damped metrics to IGP |
| **Session-Reflector (stateless)** | P1 | Match configured 4-tuple; copy sequence number; symmetric size (RFC 6038); for external Cisco/Juniper controllers |
| **Session-Reflector (stateful)** | P2 | Independent reflector sequence; directional loss (Juniper STAMP) |
| **TWAMP-Control server/client** | P3 | Managed TWAMP only if explicitly required |

**Production default:** Sender on every measured adjacency + optional reflector for interoperability testing and controller-driven probes.

---

## 6. Critical Flex-Algo detail — what to measure and advertise

Flex-Algorithm **metric-type 1** (`min-unidir-link-delay`) uses the **Min** field of the **Min/Max Unidirectional Link Delay** attribute, not `unidirectional-delay`.

| Field | Used by Flex-Algo SPF? | Wire requirement |
|-------|------------------------|------------------|
| `min-delay` | **Yes** — edge cost for metric-type 1 | Required |
| `max-delay` | Origination only (Min/Max pair) | **Both min and max must be set** to emit sub-TLV 28/34 |
| `unidirectional-delay` | No (visibility / other consumers) | Optional |
| `delay-variation` | No | Optional |
| `loss` | No (today) | Optional; needs stateful seq tracking for accuracy |

**Measurement task must populate `min-delay` and `max-delay`** from a rolling window (e.g. window min and window max). Average delay can populate `unidirectional-delay` for operators and `show` output.

Links without min/max delay advertised are **pruned** from metric-type 1 topology (RFC 9350 §15).

---

## 7. Architecture

### 7.1 Two-plane model

```
┌─────────────────────────────────────────────────────────────┐
│  Configuration / orchestration (YANG, future controller)    │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         │         stamp/ task (new)          │
         │  sender · reflector · stats · damp │
         └─────────────────┬─────────────────┘
                           │ StampEvent::MetricUpdate
         ┌─────────────────┴─────────────────┐
         │   OSPF / IS-IS (existing)        │
         │   merge measured + static te-metric│
         │   originate LSP/LSA → Flex-Algo SPF│
         └───────────────────────────────────┘
```

Measurement is a **separate tokio task** (like BFD and ND), not code inside IGP event loops.

### 7.2 Proposed module layout

```
zebra-rs/src/stamp/
  mod.rs
  inst.rs          # Stamp instance, event loop, serve() — mirror bfd/inst.rs
  config.rs        # YANG callbacks
  client.rs        # ClientReq / StampEvent API for IGP modules
  session.rs       # 4-tuple key, sequence state, reflector mode
  sender.rs        # probe scheduler per session
  reflector.rs     # 4-tuple allow-list, stateless then stateful
  network.rs       # async UDP read/write
  socket.rs        # bind UDP 862 + per-session ports
  timestamp.rs     # NTP wire format (default for TWAMP-Light interop)
  stats.rs         # rolling min/max/mean/jitter, loss from seq gaps
  damping.rs       # threshold + periodic export to IGP
  show.rs          # show stamp session / statistics

zebra-rs/src/config/stamp.rs   # spawn_stamp / despawn_stamp
crates/stamp-packet/           # wire codec (exists)
```

Add `mod stamp;` to `main.rs`. Publish `stamp_client_tx` (or registration channel) from `ConfigManager`, mirroring `bfd_client_tx` and `nd_client_tx`.

### 7.3 IGP client API

```rust
// Conceptual — stamp/client.rs

pub enum ClientReq {
    RegisterSession {
        client: ClientId,           // "ospf" | "isis"
        key: SessionKey,            // ifindex + local/remote addrs + ports
        params: SessionParams,
        notifier: UnboundedSender<StampEvent>,
    },
    UnregisterSession { client: ClientId, key: SessionKey },
}

pub enum StampEvent {
    MetricUpdate {
        key: SessionKey,
        snapshot: LinkTeMetric,
        anomalous: TeMetricFlags,
    },
    SessionDown { key: SessionKey },
}
```

**OSPF:** parallel `bfd_reconcile_nbr` — on neighbor Full → `RegisterSession`; on damped update → `ext_link_lsa_originate(ifindex)`.

**IS-IS:** on adjacency Up → `RegisterSession`; on damped update → `Message::LspOriginate`.

Reuse neighbor address resolution patterns from BFD (`Ospfv2::bfd_addrs`, `Ospfv3::bfd_addrs`, IS-IS adjacency addresses).

### 7.4 Runtime vs config `te-metric`

| Storage | Writer | Purpose |
|---------|--------|---------|
| `LinkConfig.te_metric` | YANG / operator | Static override or seed values |
| `Link.measured_te_metric` (new) | `stamp/` task | Live probe results |

At origination, **merge** with documented precedence (recommended: static leaf overrides measured when set; otherwise measured). Extend `LinkTeMetric::asla_sub_subs()` / `sub_tlvs()` to accept per-field **anomalous** flags (comments in `ospf/link.rs` already anticipate this).

---

## 8. Phased delivery

### Phase 1 — Link TE metrics (Tier 1 specs) — **DONE** (2026-06)

**Goal:** Close the loop from probe → Flex-Algo SPF on a lab topology.

> Shipped per [stamp-phase1-implementation-plan.md](./stamp-phase1-implementation-plan.md),
> including a minimal **implicit** stateless reflector (registered-peer
> allow-list) pulled forward from Phase 2 so two zebra-rs routers can
> measure each other; the *configured* external-reflector block stays
> in Phase 2.

| Work item | Detail |
|-----------|--------|
| `stamp/` skeleton | `inst`, `network`, `socket`, `sender`, `stats`, `damping`, `client` |
| Wire | Add `stamp-packet` to `zebra-rs/Cargo.toml`; RFC 8762 unauth sender |
| IGP hooks | `measured_te_metric` on `Link`; OSPF P2P + IS-IS P2P on Full adjacency |
| Metrics exported | **`min-delay` + `max-delay`** (rolling window); optional `unidirectional-delay`, `delay-variation` |
| Damping | Rolling average + threshold/periodic suppression before LSP/LSA re-origination |
| Config | `measurement { enable; interval; damping-period; }` under interface or `services monitoring stamp` |
| Show | `show stamp session`, `show stamp statistics` |
| Tests | Unit tests for stats/damping; integration test with loopback reflector |

**Interop target:** Juniper/Cisco TWAMP-Light reflectors (unauth, port 862 or configured).

### Phase 2 — Reflector + LAN adjacencies

| Work item | Detail |
|-----------|--------|
| Stateless reflector | 4-tuple allow-list; RFC 6038 symmetric size |
| OSPF broadcast / IS-IS LAN | Probe toward correct neighbor address on shared media |
| `show` parity | Per-session loss/delay in show commands |

### Phase 3 — SR-MPLS encapsulation (Tier 2 specs)

| Work item | Detail |
|-----------|--------|
| RFC 9503 Return Path TLV | Sender requests SR-MPLS return path on reflector reply |
| RFC 9503 Destination Node Address | Node identification in SR terms |
| SR-MPLS encapsulation | UDP/STAMP inside SR-MPLS label stack where data plane requires it |
| Interop | IOS-XR SR-PM style peers |

### Phase 4 — Advanced

| Work item | Detail |
|-----------|--------|
| Stateful reflector | Directional loss |
| RFC 8972 extensions beyond padding | As needed for controller interop |
| draft-ietf-spring-stamp-srpm procedures | SR Policy / loopback PM |
| RFC 5357 TWAMP-Control | Managed Cisco TWAMP server |
| XDP reflector offload | Optional; see design notes doc |

---

## 9. Interoperability matrix

| Peer | Tier 1 (RFC 8762 unauth) | Tier 2 (RFC 9503 SR-MPLS) |
|------|--------------------------|---------------------------|
| Juniper STAMP reflector | Yes — RFC 8762 + RFC 6038 symmetric size | Yes — full STAMP + stateful options |
| Juniper TWAMP-Light reflector | Yes — STAMP unauth sender | Unlikely on basic light config |
| Cisco TWAMP-Light reflector | Yes — RFC 8762 §4.6 interop | Depends on platform / SR-PM config |
| Cisco managed TWAMP server | No — needs RFC 5357 Control (Phase 4) | SR-PM via STAMP, not Control |
| zebra-rs reflector (Phase 2) | Yes — stateless, 4-tuple matched | Phase 3 if Return Path implemented |

**Defaults for interop:**

- UDP port **862** (allow configured alternates).
- Timestamps: **NTP format**, Z=0 (RFC 8762 §4.6 for TWAMP-Light peers).
- **Unauthenticated** mode only until explicit auth interop is required.

---

## 10. Configuration sketch (illustrative)

### IGP-driven measurement (recommended)

```
router isis {
  interface eth1 {
    te-metric {
      measurement {
        enable true;
        interval 100;        # ms between probes
        damping-period 30;   # s minimum between IGP exports
      }
    }
  }
}

router ospf {
  segment-routing {
    mpls;
  }
  area 0 {
    interface eth1 {
      te-metric {
        measurement {
          enable true;
          interval 100;
          damping-period 30;
        }
      }
    }
  }
}
```

### Reflector for external probes (Phase 2)

```
services monitoring stamp {
  reflector {
    session peer1 {
      local-address 10.0.0.1;
      local-port 862;
      remote-address 10.0.0.2;
      remote-port 54321;
      mode stateless;
    }
  }
}
```

### Flex-Algorithm consumption (already supported)

```
router isis {
  flex-algo 128 {
    metric-type min-unidir-link-delay;
    advertise-definition true;
  }
}
```

---

## 11. Verification checklist

| Check | Command / expectation |
|-------|----------------------|
| Metrics on wire (IS-IS) | `show isis database` — sub-TLVs 33–36 inline and in ASLA |
| Metrics on wire (OSPF) | `show ospf database detail` — ASLA sub-sub-TLVs 27–30 on Extended-Link Opaque |
| Flex-Algo paths | `show isis flex-algo` / `show ospf flex-algo` — metric-type 1, delay-weighted paths |
| Measurement running | `show stamp session` — active sessions, last export |
| Damping | LSP/LSA seq not changing on every probe packet |
| Metric-type 1 pruning | Link without min/max delay absent from algo 128 topology |

---

## 12. References

### Measurement (implement)

- RFC 8762 — Simple Two-Way Active Measurement Protocol (STAMP)
- RFC 8972 — STAMP Optional Extensions
- RFC 9503 — STAMP Extensions for Segment Routing Networks
- RFC 4656 — OWAMP (timestamp semantics)
- RFC 6038 — Symmetrical Size for TWAMP-Test
- RFC 8545 — Well-known ports for TWAMP
- RFC 5357 — TWAMP (Appendix I = TWAMP Light; §4.2 Session-Reflector; Control = Phase 4 only)

### Distribution & consumption (implemented)

- RFC 8570 — IS-IS TE metrics
- RFC 7471 — OSPF TE metrics
- RFC 9479 — IS-IS ASLA
- RFC 9492 — OSPF ASLA
- RFC 9350 — Flex-Algorithm

### zebra-rs internal

- `book/src/ch-09-00-twamp-stamp.md` — architecture overview
- `crates/stamp-packet/` — packet codec
- `zebra-rs/src/ospf/link.rs` — `LinkTeMetric`
- `zebra-rs/src/isis/link.rs` — `LinkTeMetric`
- `zebra-rs/src/isis/graph.rs` — metric-type 1 edge cost from `min_delay`
- `zebra-rs/src/ospf/inst.rs` — `graph_flex_algo`, `flex_algo_link_delay`
- `docs/design/bfd-sbfd-stamp-xdp-offload-notes.md` — offload feasibility

---

## 13. Decision log

| Decision | Rationale |
|----------|-----------|
| RFC 8762 over TWAMP Light Appendix I | Standards Track; fixes interop gaps; TWAMP Light is wire-compat subset |
| STAMP sender as primary role | Matches SR-PM link measurement model; feeds existing `te-metric` seam |
| Separate `stamp/` task | Same separation as BFD/ND; avoids IGP event-loop coupling |
| Populate min-delay + max-delay | Flex-Algo metric-type 1 and Min/Max sub-TLV origination require both |
| Unauthenticated first | Auth does not interwork between TWAMP and STAMP |
| RFC 9503 in Phase 3 | Tier 1 sufficient for on-link IP probes; 9503 needed for SR-MPLS same-path PM |
| OSPF gated on SR-MPLS | Extended-Link Opaque / ASLA only originated with `segment-routing / mpls` today |

---

*Document path for download:* `docs/design/stamp-sr-mpls-te-plan.md`
