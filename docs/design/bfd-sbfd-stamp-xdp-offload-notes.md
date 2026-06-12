# BFD / S-BFD / STAMP XDP/eBPF Offload — Design Notes

> Technical reference for zebra-rs / zebra-agent
> Scope: feasibility of data-plane offload for BFD/Echo/S-BFD/STAMP on Linux, commercial-router support status, discriminator management, implementation strategy
> Note: vendor support and defaults are release/platform dependent. Re-check current documentation before implementing.

---

## 0. Executive summary (conclusions first)

- **No mature project implements BFD/Echo/S-BFD/STAMP "wholesale" in pure XDP.** The biggest obstacle is the **TX timer** (XDP is RX-triggered only and cannot originate periodic transmission on its own).
- **Splitting by role clarifies the picture**:
  - **Reflector (loop-back side) = stateless → an ideal XDP use case** (`XDP_TX`).
  - **Originator/Sender (transmit + detect side) = needs TX timers and timeout detection → requires `bpf_timer` (5.15+) or userspace.** RX validation is where XDP shines.
- **S-BFD is, in practice, a path-continuity check for SR-TE / SR Policy.** The Initiator is active; the Reflector is stateless.
- **For SRv6 the vendors diverge**:
  - **Cisco**: S-BFD is SR-MPLS/IPv4 only. SRv6 liveness uses **STAMP-based Performance Measurement (PM/IPM)**.
  - **Juniper**: **S-BFD supported** on SRv6 TE paths (IPv6 discriminators).
  - **Nokia**: **S-BFD supported** on SRv6 Policy.
- **zebra-rs implementation strategy**: separate the control plane (Rust / aya userspace) from the data plane (aya-ebpf / XDP). Put the Reflector in XDP; on the Originator/Sender side keep the timer half in userspace or `bpf_timer`. Where full features are needed (high-precision timestamps, authentication, SRv6 encap), lean on **AF_XDP**.

---

## 1. State of BFD eBPF/XDP implementations on Linux

- There is no mature BFD implementation that lives entirely in pure XDP/eBPF. The root problem is that eBPF cannot originate periodic TX (millisecond-interval self-clocked transmission).
- Every existing Linux BFD is userspace or a kernel module:
  - **FRRouting `bfdd`**: the de-facto standard. Integrates with BGP/OSPF/IS-IS.
  - **OpenBFDD / FreeBFD / aiobfd (Python)**: standalone userspace daemons.
  - **kbfd**: a kernel module from the old Quagga/zebra era (unmaintained).
- The Cilium discussion about adding BFD to its BGP Control Plane states the same: "the biggest obstacle to a pure eBPF implementation is timer-driven transmission."
- **Where XDP realistically helps**: keep session state and TX timers in userspace (or `bpf_timer`), and use XDP to **accelerate the RX side** — parsing BFD control packets, matching discriminators against a map, resetting the detect timer, and fast detection of liveness loss.

---

## 2. BFD Echo and XDP (separating reflector / originator)

BFD Echo is essentially "local sends → the remote's forwarding plane loops it back → local watches the returns and judges."

### Reflector side = fully implementable in pure XDP (the best case)
- On receiving a packet to UDP 3785, just swap the source/destination MAC and send it back out the receiving interface with `XDP_TX`.
- With a pure L2 loop (MAC swap only), in theory neither an IP/UDP checksum recomputation nor a TTL decrement is needed.
  **[2026-06-01 correction]** That theory does not survive real interop. The BFD Echo loop is performed by the remote's
  **forwarding plane** — i.e. one hop — and FRR's forwarding-plane Echo receiver
  (`bfd_recv_ipv4_fp`) **requires TTL=254 (255 minus one decrement)** on the looped frame and
  discards anything else. The reflector therefore **must decrement the TTL and recompute the IPv4
  header checksum (RFC 1141: checksum += 0x0100 with end-around carry)** — the UDP checksum is
  unaffected since TTL is not part of its pseudo-header. The zebra-rs XDP reflector implements
  this and is interop-validated against FRR `echo-mode`.

  **[2026-06-07 update — FRR Echo addressing is asymmetric across IPv4/IPv6; the
  reflector must treat each differently. Found via a real-world IPv6 loop against
  FRR.]** Reading the FRR source, the Echo transmit dispatch
  (`ptm_bfd_echo_xmt_TO`, `bfdd/bfd.c:583-590`) hardcodes an `if IPv6 … else`
  split:
  - **IPv4 Echo** (`ptm_bfd_echo_fp_snd`) is **self-addressed**
    (`src == dst == local`, TTL 255) and looped by the peer's **forwarding
    plane** — the RFC 5881 model. The reflector never touches the dst (already
    the originator), so a **MAC swap + TTL decrement** suffices. This is the path
    already lab-validated against FRR `echo-mode` (see the 2026-06-01 note).
  - **IPv6 Echo** (`ptm_bfd_echo_snd`, `bfd_packet.c:326`) is **peer-addressed**
    (`src = local, dst = bfd->key.peer`, hlim 255) and looped by the peer's
    **bfdd in software** (`bp_bfd_echo_in`): an IPv6 link-local Echo cannot be
    forwarding-plane looped. FRR's reflect sends the frame back to the source at
    `hlim - 1` (= 254); the originator IDs its own return by `hlim != 255`
    (255 → re-reflect, otherwise → match by `my_discr`). That hlim distinction is
    what stops a mutual-reflection loop.
  - **Bug + fix:** the XDP reflector's IPv6 path must therefore swap the IPv6
    src/dst too, not just the MACs. Without it the reflected frame keeps
    `dst = us`, FRR's forwarding plane bounces it back, and it ping-pongs until
    hlim 0 (observed 2026-06-07 on IS-IS IPv6 BFD vs FRR: tcpdump shows src/dst
    unchanged, hlim decrementing, MAC flipping between the two boxes). Fix:
    `swap_ip6` in `try_reflect_v6` (16-byte ×2 volatile byte-swap, same shape as
    `swap_macs` to dodge the verifier's memcpy rejection). **No checksum fix-up**
    (the UDP pseudo-header sum `src + dst` is invariant under the swap). The hlim
    255→254 decrement stays mandatory (FRR reflects only hlim 255). A
    self-addressed Echo (e.g. our own originator) has `src == dst`, so the swap is
    a no-op and its return is still caught by the `OUR_LOCAL_IPS_V6` branch.
  - **IPv4 path left unchanged (minimal):** FRR IPv4 Echo is self-addressed, so
    `try_reflect_v4` (MAC swap + TTL decrement, no IP swap) is correct. The only
    way IPv4 Echo is peer-addressed is the non-Linux FRR branch
    (`#else → ptm_bfd_echo_snd`, dst = peer) or another implementation; the same
    swap would fix that harmlessly (the swap is commutative, so neither the IPv4
    header checksum nor the UDP pseudo-header checksum changes) but is unnecessary
    for Linux / RFC-compliant peers.

  **Cross-vendor / RFC check — is FRR's IPv6 model an industry convention? No,
  it's FRR-specific (and contrary to RFC 5881):**
  - **RFC 5881 §5**: Echo is **self-addressed** — the destination MUST be chosen
    so the remote *forwards* it back ("a system implementing the Echo function
    MUST be capable of sending packets to its own address … bypassing the normal
    forwarding lookup"), and the source SHOULD NOT be an IPv6 link-local address.
    FRR's IPv6 Echo violates all three (dst = peer, link-local src, software
    reflection).
  - **Cisco (IOS-XR)**: no IPv6 Echo at all — Echo is IPv4-only ("echo packets
    transmitted over UDP/IPv4, port 3785"); IPv6 liveness uses async BFD. Nothing
    to be consistent with.
  - **Juniper (Junos 22.4R1+)**: `echo` / `echo-lite`; `echo-lite` works "without
    requiring BFD configuration on the neighbor" = forwarding-plane (RFC
    self-addressed), the **opposite** of FRR's "peer must run a reflector".
  - **FRR's own docs**: "echo mode works only when the peer is also FRR" unless
    distributed BFD — confirming the IPv6 model is a both-ends-FRR feature.
  - **Implication**: the reflector's v4/v6 asymmetry intentionally mirrors FRR's.
    `swap_ip6` is robust to **both** addressing models — a no-op for
    self-addressed (RFC / Juniper echo-lite / our own originator) and a retarget
    for peer-addressed (FRR) — so making zebra-rs an FRR-compatible IPv6 reflector
    does not break standards-compliant peers. The old code/README premise "IPv6
    Echo is self-addressed, so no swap needed" held only for our own originator;
    FRR originators are peer-addressed.
- This matches the "unaffiliated BFD echo" reflector concept (a small XDP reflector can be placed in front of a device that has no BFD stack at all).

### Originator side = not possible in XDP alone
- Periodic Echo transmission (TX) → `bpf_timer` or userspace.
- Receiving and validating the looped-back Echo (RX) → XDP's strength (keep last-seen / seq in a map and match).
- Detect timeout (returns stop → Down) → needs a timer to fire, so XDP alone cannot do it.

> **As-built**: both reflector and originator are implemented; the helper is
> consolidated as **`xdp-bfd-echo`** (formerly `bfd-echo-reflector`). As predicted
> here, TX lives in userspace over `AF_PACKET`, and detection is XDP arming a
> per-session `bpf_timer` on every returned Echo (returns stop → `Down` +
> `EchoFunctionFailed`). The `bpf_timer`-from-XDP kernel recipe has since been
> lab-confirmed.

### Implementation notes
- The Echo payload is **"a local matter"** per RFC 5880 §6.4 (sender's discretion). Packing our discriminator + seq + transmit timestamp makes the RX-side XDP map match cheap.
- Loop-back jitter bounds how aggressively the detection timer can be set → the reflector should run in native XDP mode where possible (i40e/ice/ixgbe/mlx5 etc.).

---

## 2b. Expiration-watchdog offload for standard BFD control packets (implemented 2026-06-12)

This implements exactly the "realistic XDP use" from the end of §1 — RX-side
detect-timer reset and fast liveness-loss detection. It applies the same
mechanism as the Echo originator's `bpf_timer` detection (§2) to **standard
BFD control packets on UDP/3784**.

- **The XDP side is a pure observer**: a control packet is checked only for
  TTL/Hop-Limit == 255 (GTSM, RFC 5881 §5) and version == 1, its Your
  Discriminator is looked up in `CONTROL_TIMERS` (a BTF map whose value is the
  `DetectState` shared with Echo), the `bpf_timer` is re-armed, and the frame
  is **always `XDP_PASS`ed**. The FSM, Poll/Final handling, and parameter
  renegotiation all stay in the daemon as before (only the liveness timing
  moves into the kernel). Unlike the Echo reflector there is no packet
  rewriting, so no verifier workarounds were needed either.
- **Armed only after establishment**: before establishment the remote may send
  `Your Discriminator = 0`, which cannot key the map. zebra-rs sends
  `detect-add <discr> <detect-us>` to the helper's stdin on the Up transition
  and `detect-del` on leaving Up (`Bfd::detect_offload_reconcile`, same shape
  as the Echo reconcile). When renegotiation changes the detection time,
  `detect-add` is re-sent (a map-element replace — the kernel cancels the old
  timer).
- **The userspace timer is demoted to a backstop**: while the watchdog is
  armed it is kept stretched ×4 (`DETECT_BACKSTOP_FACTOR`); on helper death
  (`Message::HelperGone`) it is immediately restored to 1×. This eliminates
  both false Downs (the daemon scheduled out with packets piling up in the
  socket queue while the userspace timer fires anyway) and late detection —
  which is what makes aggressively short detection times (sub-10 ms class)
  honest.
- **The transmit side is not offloaded**: our own control-packet transmission
  stays in the daemon. If the daemon halts entirely, the peer's detection
  takes the session down (only our RX detection is kernel-resident).
- **Scope**: single-hop only (the helper attaches per ifindex; multihop has no
  fixed ingress interface and its GTSM floor is below 255). If BFD
  **authentication** ever lands, authenticated sessions must NOT be offloaded
  (XDP cannot verify MD5/SHA1).
- **Configuration**: `bfd { detect-offload true; }` on OSPF / IS-IS / BGP
  (per-interface or per-neighbor, plus instance level, with the same
  inheritance as echo-mode). BGP is single-hop only (inert on multihop).
- **BGP ifindex resolution (added in a follow-up PR)**: BGP BFD SessionKeys
  used to be hardcoded `ifindex: 0` — the per-ifindex helper could **never
  start**, so BGP echo was effectively inert. `ConnectedSubnets` now keeps the
  recording ifindex (`ifindex_for`, v6 link-locals excluded), and single-hop
  sessions are keyed by the connected interface. If the address is learned
  after `bfd enable`, the `RibRx::AddrAdd` hook's `bfd_reconcile_all` re-keys
  the session (unsubscribe → subscribe). With this, both BGP echo and BGP
  detect-offload actually work.
- **Validation**: `scripts/veth-detect-test.sh` — with a 600 ms detection
  time, stream control packets at 150 ms intervals for 1.2 s (a premature fire
  = the bootstrap fallback tripping = FAIL, which is what proves the XDP
  re-arm works), then stop and expect `detect-down` ~600 ms later.
  Lab PASS 2026-06-12.

---

## 3. S-BFD (Seamless BFD) overview

- **RFC 7880 (2016).** A derivative that eliminates classic BFD's handshake (the three-way Down→Init→Up).
- Uses **pre-distributed 32-bit discriminators**. The Initiator already knows the peer's reflector discriminator, so it transmits immediately without negotiation → immediate reflection confirms reachability (completes in one round trip).
- **Two asymmetric roles**:
  - **Initiator**: active. Owns the state machine, transmits and judges.
  - **Reflector**: stateless. On receiving a packet addressed to its discriminator, it just swaps my/your discriminators and returns it.
- **Ports**: UDP 7784 (S-BFD control) / 7785 (S-BFD Echo). (Classic BFD is 3784/3785.)
- **Uses**: on-demand reachability checks, **SR-TE / SR Policy path validation** (send along a specific segment list and watch the reflection).
- **Why it suits XDP**: the reflector is stateless (match UDP 7784 → look up your-discriminator in a map → swap my/your + set state → swap MAC/IP → incrementally update the UDP checksum → `XDP_TX`). The discriminator rewrite and checksum fix make it one step heavier than classic Echo's MAC swap.
- **Related RFCs**: 7880 (core) / 7881 (IPv4/IPv6/MPLS encapsulation) / 7882 (use cases) / 7883 (discriminator advertisement in IS-IS) / 7884 (OSPF extension).

---

## 4. Commercial-router S-BFD support (in the SR-TE / SR Policy context)

> All four vendors support it. In practice "the SR-TE/SR Policy headend is the initiator, the tail is a stateless reflector." Generic link BFD (OSPF/IS-IS/BGP neighbor monitoring) stays classic BFD everywhere — the division of labor is common across vendors.

| Vendor | Support | Main constraints / notes |
|---|---|---|
| **Cisco IOS-XE (ASR1000)** | Yes | S-BFD with SR-TE. **IPv4 only / single-hop only**. Tail is the reflector |
| **Cisco IOS-XR (NCS5500)** | No | Explicitly documented as **no Seamless BFD support**. Large per-platform differences (verify individually) |
| **Cisco IOS-XR (ASR9000 etc.)** | Yes | sBFD reflector/initiator configuration exists for SR-TE |
| **Juniper (Junos / Evolved)** | Yes (broad) | Colored/non-colored SR LSPs, SR policy. S-BFD FRR from 23.2R1 (MX). Evolved 22.4R1+ auto-derives the remote discriminator on PTX |
| **Nokia (SR-OS)** | Yes (broad) | SR-TE LSPs since 19.10.R1. **Requires CPM-NP, 10 ms minimum**. static/BGP SR policy supported |
| **Arista (EOS)** | Yes | EOS 4.24.1F+ (SR-TE/SR Policy). Recent releases add an **S-BFD Hold-down Timer** (4.34/4.35/4.36F) |

---

## 5. SRv6-specific support (Cisco / Juniper / Nokia) and End.X monitoring

### Cisco (IOS-XR): no S-BFD on SRv6
- S-BFD is **SR-MPLS / IPv4 only** (control packets are label-switched in both directions).
- SRv6 liveness uses **Performance Measurement (PM) liveness detection = STAMP (RFC 8762/8972) based**.
  - Applies uniformly to non-MPLS IPv4/IPv6/SRv6. **Loopback measurement-mode** (the headend sets the destination to its own loopback and injects with the same encapsulation as the SR policy).
  - On SRv6, the **flow label (20 bits) inside the SRH** monitors liveness per ECMP path.
  - Commercial name: **Integrated Performance Measurement (IPM)**. STAMP-conformant, integrated with uSID policies.
- Background: running S-BFD (connectivity) and STAMP (performance) side by side is complex/costly → consolidation proposal `draft-gandhi-spring-sr-enhanced-plm`.

### Juniper (Junos / Evolved): S-BFD works on SRv6 too
- S-BFD on SRv6 TE paths:
  - Ingress: `[edit protocols bfd] sbfd local-discriminator`; on the SRv6 TE path, `sbfd remote-discriminator` under `bfd-liveness-detection`.
  - Egress (responder): `sbfd local-discriminator <n> local-ipv6-address <addr>`. The responder's local must equal the ingress's remote.
  - `bfd-liveness-detection sbfd destination-ipv6-local-host` for responders limited to the IPv6 local-host address.
- STAMP/TWAMP/RPM exist separately (performance measurement).

### Nokia (SR-OS): S-BFD on SRv6 Policy
- Seamless BFD on SRv6 Policies for fast detection of "silent" data-path failures.
- S-BFD down on the active policy's segment list → failover. All S-BFD down → fall back to the SRv6 shortest path.

### Reference: Huawei / H3C
- S-BFD on SRv6 TE policy (static sessions only; remote discriminator must be manual).

### About End.X (adjacency SID) monitoring (important)
- All the S-BFD/PM above monitor **end-to-end segment lists (SR policies)**. There is no "dedicated session for one particular End.X SID" feature.
- The liveness of an individual End.X (uA SID in uSID notation) **follows the IGP (IS-IS) adjacency state**:
  - Link/adjacency down → the IGP withdraws the End.X SID → with protection, traffic shifts to the TI-LFA backup.
- So the two-layer structure is: **per-End.X fast detection = classic link BFD + IGP withdraw + TI-LFA**, and reachability of a specific path containing that End.X = S-BFD/PM end to end.
- To make the BFD/S-BFD **return path deterministic** on SRv6, one can put both the forward and reverse SID lists in the SRH to pin the return path (useful for pinpoint monitoring of a path through a specific End.X).

---

## 6. How discriminators are obtained (per vendor)

> Three broad families: manual configuration / derived from an IP address / automatic distribution via IGP advertisement.

### Standards (the basis for automatic distribution)
- 32-bit value, unique within the administrative domain (RFC 7880).
- **RFC 7883**: advertised in the IS-IS Router CAPABILITY TLV.
- **RFC 7884**: advertised in the OSPF Router Information (RI) TLV (**Type 11**) (OSPFv2/v3). Information changes do not trigger SPF.
- Both can be exported to a controller via **BGP-LS**.

### Per vendor
| Vendor | Manual | IP-derived | IGP advert (7883/7884) | Notes |
|---|---|---|---|---|
| **Cisco IOS-XR** | Yes | Yes | (not explicitly confirmed) | reflector: `local-discriminator {ipv4-address \| 32bit \| dynamic \| interface}`. initiator: **RTI table** maps destination → remote discriminator (`remote-target ipv4 <addr>`). For IPv4 targets the destination address itself can be the remote discriminator. XRv9k does not support S-BFD |
| **Juniper** | Yes | Yes | - | Evolved 22.4R1+ `set protocols bfd sbfd local-discriminator-ip` auto-derives the remote from the tunnel endpoint; common sBFD template |
| **Nokia SR-OS** | Yes | - | **Yes (most automated)** | Encoded as opaque info in the IGP link state per 7883/7884 → exported via BGP-LS |
| **Huawei/H3C** | Yes (required) | Yes (integer conversion) | - | Even on SRv6, static only; manual remote discriminator required |

---

## 7. Running classic BFD Echo one-way

- **Possible. Echo is inherently an asymmetric, per-system-independent function.** One side (A) running Echo while the other (B) only loops it back is a natural deployment.
- A's Echo round-trips A→B→A, so it exercises both physical directions, but **only A learns liveness**. If B wants it too, B independently runs B→A→B (= two independent one-way Echos).
- **Negotiation caveat — `Required Min Echo RX Interval`**:
  - The value tells the peer "the minimum interval at which I can support receiving (looping) Echo."
  - **0 = no Echo receive support** → the peer must not send Echo.
  - One-way Echo requires: A enables Echo; B doesn't need its own Echo but **must advertise non-zero Echo receive support**.
- **Precondition**: classic Echo is not a standalone session — it is an auxiliary function that assumes **an async control session is already Up**. While Echo is active, the control-packet rate may be lowered.
- **Single-hop only** (RFC 5881). Multihop BFD (RFC 5883) has no Echo.
- → This asymmetry *is* the originator/reflector split. B (the loop side) is the side that rides the XDP_TX reflect.

---

## 8. FRR's BFD Echo defaults and "distributed BFD"

### FRR's Echo defaults
- **`echo-mode` (Echo transmission) = off by default.**
- `echo receive-interval` (ability to loop the peer's Echo) = **50 ms by default (non-zero)**.
  - → Out of the box, FRR is in a reflector-ish state: "I won't originate Echo, but I'll loop yours back."
- `show bfd peers` shows `Echo transmission interval: disabled` by default.
- **FRR-specific caveat**: unless distributed BFD is used, **Echo only works when the peer is also FRR** (an implementation artifact — FRR loops the return in software). Don't count on FRR Echo against commercial routers.
- Contrast: old classic Cisco IOS had **Echo on by default**. Defaults differ per vendor, so check both ends when interoperating.

### What "distributed BFD" means
Two senses:
1. **The general sense**: offload the periodic TX/RX and detection timers of BFD sessions **to line cards / the data plane (ASIC/NPU)**. The RP only creates/deletes sessions and receives state notifications. → Scale, sub-10 ms timers, BFD survives RP switchover/GR.
2. **The FRR sense**: separate the control plane (`bfdd`) from the data plane. Exchange session config and state with an external data plane (HW/SmartNIC/another software forwarder/ASIC) over FRR's own **BFD Data Plane Protocol (`bfddp`)** (`bfdd/bfddp_packet.h`). FRR does control; the muscle is external.
- → Directly relevant to the zebra-rs design: Rust control logic + XDP/eBPF data plane = exactly the bfddp split, implemented with XDP. The Echo/S-BFD reflector XDP offload is the "data-plane side" of that split.

---

## 9. Feasibility of TWAMP Light / STAMP offload in XDP

> STAMP = Simple Two-way Active Measurement Protocol (RFC 8762/8972). Together with TWAMP Light: control channel omitted, two roles (Sender/Reflector).

### Conclusion
- If **liveness is the only goal**, the Reflector is perfectly feasible in pure XDP (close to the BFD echo reflector).
- Aiming for **accurate delay/loss measurement** hits a timestamp-precision ceiling in XDP alone → integrate HW timestamps or move to AF_XDP.

### Reflector side (one notch heavier than BFD echo)
- Work: capture RX time T2; copy the Sender's Seq/Timestamp/Error Estimate into the "Sender…" fields; fill in the Reflector Seq (stateless = Sender seq / stateful = from a map) and TX time T3; swap src/dst IP, port, MAC; incrementally fix the IP/UDP checksums; `XDP_TX`.
- **XDP-friendly aspects**: the Sender packet carries padding (MBZ) sized so the Reflector's added fields fit inside it → **in-place overwrite without changing packet length** (no `bpf_xdp_adjust_tail` needed). Fixed layout keeps bounds checks straightforward.
- **Hard parts**:
  - **Timestamp precision**: RX is good (XDP sits right after the driver; with a capable driver, `bpf_xdp_metadata_rx_timestamp` gives HW RX time). TX writes T3 before the actual `XDP_TX` transmission, an inherent error. Reflecting HW TX timestamps is practically infeasible.
  - **Clock domain**: STAMP uses NTP/PTP formats. `bpf_ktime_get_ns` is a monotonic clock. In PHC-synced environments the HW timestamps are the accurate ones. Pure XDP is SW-clock based → declare larger uncertainty in the Error Estimate.
  - **Authentication (HMAC-SHA256)**: unrealistic in the XDP datapath → **authenticated mode is not XDP-able; unauth only**.
  - **TLVs (RFC 8972)**: variable-length TLV loops fight the verifier. Direct Measurement (statistics readout) etc. are awkward in XDP. The base (no TLVs) is trivial.
  - **SRv6 encap**: parsing IPv6+SRH+UDP+STAMP; if the return needs a reverse SR Policy pushed, `bpf_xdp_adjust_head` for the SRH push (heavy). In loopback mode the normal SRv6 forwarding handles it — light.

### Sender side (same as the BFD originator)
- Periodic transmission → `bpf_timer` / userspace. RX validation and detect-timer reset are XDP-able. If delay/loss computation is needed, punt to userspace.

### Feasibility by use case
| Use case | Pure XDP | Notes |
|---|---|---|
| Liveness only (unauth, no TLVs, IPv4 / single-hop IPv6) | Excellent | On par with the BFD echo reflector. SW clock suffices |
| Coarse delay/loss measurement | Good | HW RX timestamp recommended; accept TX imprecision |
| High-precision delay (PTP class) | Marginal | HW timestamps required; inherent TX-side error |
| Authenticated / TLV-rich / reverse SRH encap | No | Go AF_XDP / hybrid |

### The pragmatic answer: AF_XDP hybrid
- Use XDP to redirect only the target UDP (STAMP default UDP 862) to AF_XDP (XSK) → a userspace fast path does the rewriting, timestamps (PHC), HMAC/TLVs, reverse SRH encap. Balances performance and features.

### Environment note
- The virtual NICs under Parallels on Apple Silicon offer neither HW timestamps nor native XDP metadata → the lab tops out at SW clock + generic/native XDP. Precision evaluation needs real NICs (mlx5 etc.).

---

## 10. aya (Rust eBPF library)

- A library/framework for writing eBPF in Rust. **No libbpf/bcc dependency, pure Rust; syscalls only via the libc crate.**
- **Two-crate structure**: userspace `aya` (loading / map management / attach / event receipt) + kernel-space `aya-ebpf` (formerly aya-bpf; the eBPF program itself). Data structures can be shared between the two.
- **Advantages**: no C toolchain / kernel headers / kernel build needed; fast builds. **BTF → CO-RE** (runs on different kernels without recompilation). musl linking gives a single self-contained binary. Userspace is async-ready with tokio/async-std.
- Supports: XDP / TC / kprobe / tracepoint / cgroup_skb; hash maps / arrays / ring buffers, etc.
- Documentation: aya-rs.dev (the Aya Book).
- → "Userspace (aya) = control plane, kernel (aya-ebpf) = data plane" maps directly onto distributed BFD's control/data split. The reflector datapath extends naturally from zebra-agent (nftables→eBPF).

---

## 11. Summary and next actions for zebra-rs

### Architecture direction
- **Control plane**: zebra-rs / Rust (session management, IGP/BGP client notifications, discriminator mapping tables).
- **Data plane**: aya-ebpf / XDP (reflector loops, RX validation, detect-timer reset).
- **TX timers / timeout detection**: `bpf_timer` (5.15+) or userspace.
- **Full features (high-precision measurement, authentication, SRv6 reverse encap)**: redirect to AF_XDP.

### Interop alignment points (discriminators)
- Hold the reflector's local discriminator **derived from an IPv6 loopback** → meshes with Cisco/Juniper/Huawei.
- On the initiator side, an **endpoint-IP → remote-discriminator mapping table** (Cisco's RTI equivalent).
- To match Nokia-style fully automatic operation, add **RFC 7883 S-BFD Discriminator sub-TLV** send/receive to the IS-IS implementation → carry it into BGP-LS (zebra-rs already has IS-IS and BGP-LS, so this is a natural extension).

### Required work per SRv6 peer
- **Against Nokia / Juniper**: **S-BFD over SRv6** (reflector/initiator, IPv6 discriminators).
- **Against Cisco (IOS-XR) SRv6**: they don't speak S-BFD — they use **STAMP-based PM liveness** → zebra-rs also needs a **STAMP (RFC 8762/8972, TWAMP-light) responder/sender**.
  - → For Nokia/Juniper: XDP offload of an S-BFD reflector. For Cisco SRv6: consider a STAMP reflector.

### Staged implementation plan (XDP/aya)
1. **Stage 1**: an unauth STAMP (or S-BFD) liveness reflector in pure XDP (in-place rewrite + `XDP_TX`). Targets Cisco SRv6 loopback liveness / Nokia/Juniper S-BFD.
2. **Stage 2**: redirect to AF_XDP only where precision/features demand it.
3. In parallel: the originator/sender TX timers (`bpf_timer` or userspace) and detect timeouts.

### Not yet started / deep-dive candidates
- Encoding details of the S-BFD Discriminator sub-TLV inside the IS-IS Router CAPABILITY TLV (RFC 7883).
- The XDP packet-rewrite skeleton for an unauth STAMP reflector (field offsets, incremental checksums, aya/Rust loader).
- Return-path design for SRv6 loopback mode.
- The FRR `bfddp` message spec (stay compatible, or define our own data-plane protocol?).

---

## References (primary sources first)

### RFC / IETF
- RFC 5880 BFD / RFC 5881 BFD for IPv4/IPv6 single-hop / RFC 5883 Multihop BFD
- RFC 7880 Seamless BFD: https://datatracker.ietf.org/doc/html/rfc7880
- RFC 7881 S-BFD for IPv4/IPv6/MPLS
- RFC 7883 S-BFD Discriminators in IS-IS: https://www.rfc-editor.org/rfc/rfc7883.html
- RFC 7884 S-BFD Discriminators in OSPF: https://www.rfc-editor.org/rfc/rfc7884.html
- RFC 8762 STAMP / RFC 8972 STAMP Optional Extensions / RFC 8986 SRv6 Network Programming
- draft-gandhi-spring-sr-enhanced-plm: https://datatracker.ietf.org/doc/html/draft-gandhi-spring-sr-enhanced-plm

### Vendor documentation
- Cisco IOS-XE S-BFD with SR: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/seg_routing/configuration/xe-17/segrt-xe-17-book/m_sr-smlsbfd-sspf.html
- Cisco SRv6 Performance Measurement: https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/srv6/b-srv6-configuration-guide/m-performance-measurement.html
- Cisco IOS-XR BFD Commands (discriminator): https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/routing/b-ncs5500-routing-cli-reference/b-ncs5500-routing-cli-reference_chapter_0111.html
- Juniper Segment Routing LSP (S-BFD over SRv6 TE): https://www.juniper.net/documentation/us/en/software/junos/mpls/topics/topic-map/segment-routing-lsp-configuration.html
- Juniper BFD overview: https://www.juniper.net/documentation/us/en/software/junos/high-availability/topics/topic-map/bfd.html
- Nokia Seamless BFD for SR-TE LSPs: https://documentation.nokia.com/acg/23-7-2/books/classic-cli-part-i/c212-s-bfd.html
- Nokia Automated S-BFD discriminator distribution: https://infocenter.nokia.com/public/7750SR225R1A/topic/com.nokia.OAM_Guide/automated_s-bfd-ai9exgsvaa.html
- Arista EOS BFD/S-BFD: https://www.arista.com/en/um-eos/eos-bidirectional-forwarding-detection

### FRR / eBPF / aya
- FRR BFD (echo-mode defaults, distributed BFD): https://docs.frrouting.org/en/latest/bfd.html
- FRR bfd.rst (bfddp): https://github.com/FRRouting/frr/blob/master/doc/user/bfd.rst
- aya: https://github.com/aya-rs/aya / https://aya-rs.dev/ / https://docs.rs/aya
- Cilium BFD discussion: https://github.com/cilium/cilium/issues/22394
