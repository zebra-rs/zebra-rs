# OSPF: applicability of RFC 4222 (packet priority and congestion avoidance)

Status: **Assessment, 2026-11-18, with two findings reproduced on
2026-11-19. One thing is implemented since: the 64 KB receive buffer
(§4.2). Nothing else is.**
zebra-rs OSPF was read at `main` `f59b36fe` against RFC 4222 (BCP 112,
"Prioritized Treatment of Specific OSPF Version 2 Packets and Congestion
Avoidance"). FRR, holo and BIRD were read in source. Commercial behaviour
comes from vendor documentation.

What is and is not verified:

- **zebra-rs, reproduced:** the packet-size limit (§4.2) and the
  re-origination of every redistributed LSA (§4.5), both for OSPFv2, in
  a two-router lab on a release build of `main` `bd2cebd0`. The
  packet-size limit was later reproduced for OSPFv3 too, with the
  26.11.4 package.
- **zebra-rs, read only:** everything else, including the rest of
  OSPFv3. No backlog depth was measured.
- **FRR:** read directly at `9b9c7c4138` (2026-11-18, `frr-10.8.0-dev`).
- **holo, BIRD:** read by a research agent (holo `af71aedb`, BIRD master
  `94568d7`, version 2.20.0). The dead-timer and retransmission points
  were spot-checked in the source; the rest was not.
- **Commercial:** vendor documents gathered by a research agent on
  2026-11-18 and not re-read. NX-OS could not be read at all, and the
  Huawei entries come from search-engine snippets of Huawei pages.

---

## 0. Summary

RFC 4222 makes five recommendations for OSPF under a storm of LSAs. For
zebra-rs:

| # | Recommendation | Applies to zebra-rs? |
|---|---|---|
| 1 | Process Hello and LS Ack ahead of other packets | In part. OSPFv2 already avoids the harm on receive through its single event queue; OSPFv3 does not. Neither protects the sending of our own Hello. |
| 2 | Restart the dead timer on any packet | No. It is the fallback for a router without 1, and fixing OSPFv3's queueing removes the need. |
| 3 | Exponential backoff of LSA retransmission | No. No implementation surveyed does it. Our retransmission needs other repairs first (§3.4). |
| 4 | Slow flooding to a neighbor with many unacknowledged LSAs | Yes, later. Fixed pacing is what most stacks ship; the adaptive form is optional. |
| 5 | Limit adjacencies brought up at once | Yes. It is the most widely adopted of the five. |

Three gaps outside the RFC matter more than any of the five for the
large networks the RFC is about (§4):

- **No OSPF packet is sized to the MTU, and the receive buffer is
  16 KB.** Reproduced: two zebra-rs routers synchronize 453 Type-5 LSAs
  and fail, silently and for good, from 454. (The buffer is 64 KB since;
  the limit is now 1,819 and it is logged. See §4.2.)
- **Every redistributed route re-originates every Type-5 LSA.**
  Reproduced: adding 199 routes sent 20,102 LS Updates to one neighbor.
  This is a storm of the router's own making, the case the RFC's
  Appendix A lists as "injecting a large number of external routes".
- **OSPFv3 can take a live neighbor down** when its dead-timer event
  overtakes queued Hellos (§3.1). Read, not reproduced.

The proposed order of work is in §6.

---

## 1. What RFC 4222 recommends

The problem is a positive feedback loop. A burst of LSAs loads the
router; acknowledgments delayed beyond `RxmtInterval` cause
retransmissions; Hellos delayed beyond `RouterDeadInterval` take
adjacencies down, which originates more LSAs.

1. **Two packet classes.** High priority is Hello and Link State
   Acknowledgment; low priority is everything else. High-priority packets
   are processed first, when receiving and when transmitting. With
   cryptographic authentication the transmitter does not reorder, because
   the receiver requires a non-decreasing sequence number; the receiver
   classifies after the security checks.
2. **Only where 1 is not implemented:** restart the inactivity timer on
   any unicast OSPF packet, or any packet sent to AllSPFRouters on a
   point-to-point link, not on Hello alone.
3. **Exponential backoff of the LSA retransmission interval:**
   `R(1) = Rmin`, `R(i+1) = min(K·R(i), Rmax)`, with examples `K = 2`,
   `Rmin = 5 s`, `Rmax = 40 s`.
4. **Implicit congestion detection, per neighbor.** When the number of
   unacknowledged LSAs exceeds a high-water mark `H`, multiply the gap
   between LSAs sent to that neighbor by `F`, up to `Gmax`; below a
   low-water mark `L`, divide it, down to `Gmin`. Examples: `H = 20`,
   `L = 10`, `F = 2`, re-evaluated every `T = 1 s`, `Gmin = 20 ms`,
   `Gmax = 1 s`. It covers unicast LSAs and LSAs sent to AllSPFRouters on
   a point-to-point link.
5. **Throttle adjacencies brought up at once:** at most a configurable
   `n` in database synchronization, first come first served, not
   preempted once started.

Appendix C adds optional ideas: a different IP precedence for the high
class, a "medium" class (the slave's Database Description; LSAs carrying
intra-area topology changes), and a note that LSA purges should not be
processed out of order.

The RFC is written for OSPFv2 and says the techniques "may also apply to
OSPFv3".

---

## 2. How zebra-rs handles OSPF packets today

Each OSPF instance is one task with helpers around it
(`zebra-rs/src/ospf/`):

| Piece | OSPFv2 | OSPFv3 |
|---|---|---|
| Reader task | `network::read_packet`: `recvmsg`, checksum, parse, post `Message::Recv` to the instance channel `tx` | `network_v6::read_packet_v6`: same, but posts to its own channel `v3_recv_rx` |
| Timers | Each is a task that posts a message to `tx`: `HelloTimer`, `Nfsm(.., InactivityTimer)`, `Retransmit`, `DelayedAck`, … | Same |
| Main task | `Ospf::event_loop`: unbiased `tokio::select!` over `rx`, the RIB, config, show and other channels | Same, plus the `v3_recv_rx` branch |
| Writer task | `network::write_packet`: FIFO from the channel `ptx`, one `sendmsg` per packet | `network_v6::write_packet_v6`, likewise |
| SPF | `spawn_blocking`, result returned as `Message::SpfDone` | Same |

All channels are unbounded. The reader keeps draining the socket whatever
the main task is doing, so a backlog builds in process memory, not in the
kernel socket buffer, and nothing pushes back on the sender.

The difference between the versions decides most of §3:

- **OSPFv2 has one queue for packets and timers.** A timer event is
  queued behind every packet that arrived before the timer fired.
- **OSPFv3 has two.** `select!` picks among ready branches at random, so
  the timer queue and the packet queue are served alternately, and a
  timer event overtakes packets that arrived long before it.

---

## 3. Assessment by recommendation

### 3.1 Recommendation 1, receive side

The recommendation exists to prevent two things: an adjacency declared
down because its Hello waited too long, and LSAs retransmitted because
their acknowledgment waited too long.

**OSPFv2 avoids both without classifying anything.** A Hello that arrived
before the dead timer fired is ahead of the `InactivityTimer` message in
the queue. Processing it restarts the timer and stamps `heard_at`
(`nfsm::ospf_nfsm_hello_received`); `Ospf::inactivity_stale` then discards
the timer event. The same ordering puts a queued LS Ack ahead of the
`Retransmit` message, so `process_retransmit` sees the list already
pruned. A neighbor is taken down only when no Hello reached the reader
for a dead interval.

**OSPFv3 is exposed to both.** The `InactivityTimer` message travels on
`rx` while the Hellos wait in `v3_recv_rx`. With a packet backlog deeper
than `RouterDeadInterval − HelloInterval`, the timer event is handled
first, `heard_at` is still old, and a live neighbor is removed. That is
30 s of backlog with the default timers and 3 s with `hello-interval 1`,
`dead-interval 4`. `Retransmit` overtakes queued acknowledgments the same
way.

How deep the backlog gets under load has not been measured.

### 3.2 Recommendation 1, transmit side

Our own Hello is not sent by the timer. The timer posts
`Message::HelloTimer`, and the main task builds and queues the packet
when it reaches that message.

- **OSPFv2:** the message waits behind the whole receive backlog. Our
  Hello leaves late by the depth of the backlog, and the neighbor's dead
  timer runs out when that exceeds `RouterDeadInterval − HelloInterval`.
- **OSPFv3:** the message does not wait behind packets, for the reason
  that makes §3.1 worse.

The writer queue itself is FIFO with no priority, but it is short: the
writer does nothing except `sendmsg`. Authentication sequence numbers are
assigned when a packet is built, so the FIFO must be kept under
cryptographic authentication, as the RFC says.

### 3.3 Recommendation 2

Not implemented: only a Hello restarts the timer
(`nfsm::ospf_nfsm_hello_received`). The RFC asks for it only where 1 is
absent, and warns that stale low-priority packets can then keep a dead
adjacency alive. OSPFv2 does not need it. For OSPFv3 it would hide the
problem of §3.1 in the common case; putting the packets in the main queue
removes the problem instead (§6, step 3).

### 3.4 Recommendation 3

Not implemented, and retransmission has larger problems than the missing
backoff (`flood::ospf_ls_retransmit_add`, `Ospf::process_retransmit`,
both versions):

- **One timer per neighbor**, armed when the first LSA goes on the list,
  at the fixed `retransmit-interval` (default 5 s).
- **Each expiry resends the whole list**, including an LSA added a moment
  earlier, which is then retransmitted long before `RxmtInterval`.
- **The whole list goes in one LS Update**, whatever its size (§4.1).
  Past 64 KB the packet cannot be sent at all, the error from `sendmsg`
  is ignored, and nothing is retransmitted until acknowledgments shrink
  the list.

With `N` LSAs unacknowledged, all `N` are resent every interval. This is
the retransmission pattern the RFC identifies as what sustains congestion.

### 3.5 Recommendation 4

Not implemented. Flooding (`Ospf::flood_lsa_through_link`, both versions)
sends one LS Update per LSA per neighbor, unicast, as soon as the LSA is
handled. There is no gap, no batching and no reaction to the length of
the retransmission list.

Because every flooded LSA is a unicast to one neighbor, recommendation 4
as written would cover all of our flooding.

### 3.6 Recommendation 5

Not implemented. A neighbor that qualifies moves from 2-Way to ExStart at
once (`nfsm::ospf_nfsm_twoway_received`), with no count of exchanges in
progress. After a restart on a router with many neighbors, every
adjacency synchronizes at the same time, and each Database Description
carries the whole database summary (§4.1).

### 3.7 Appendix C

- **Marking:** OSPFv2 sends every packet with precedence Internetwork
  Control (`socket::ospf_socket_ipv4`). OSPFv3 sets no traffic class
  (§4.4). Neither marks Hellos differently.
- **Purges:** MaxAge LSAs are not reordered.

### 3.8 Protections that exist

`min-ls-interval` (5 s) and `min-ls-arrival` (1 s) are implemented and
configurable, the SPF throttle defaults to 50 / 200 / 5000 ms, and SPF
runs off the main task in both versions.

`min-ls-interval` does not cover redistributed Type-5 LSAs (§4.5).

---

## 4. Gaps the RFC takes for granted

### 4.1 No packet is sized to the MTU

RFC 2328 §A.1 allows OSPF packets up to 65,535 bytes but says of the
large packet types that splitting them "is recommended; IP fragmentation
should be avoided whenever possible". zebra-rs reads the interface MTU
only for the Database Description `Interface MTU` field and its mismatch
check.

| Packet | What one packet carries | Where |
|---|---|---|
| Database Description | The whole database summary | `packet::ospf_packet_db_desc_set`, and its twin in `packet_v3.rs` |
| LS Request | The whole request list | `packet::ospf_packet_ls_req_set` |
| LS Update answering a request | Every LSA requested | `packet::ospf_ls_req_recv` |
| LS Update, retransmission | The whole retransmission list | `Ospf::process_retransmit` |
| LS Ack, delayed | Every header queued | `Ospf::process_delayed_ack` |
| LS Update, flooding | One LSA | `Ospf::flood_lsa_through_link` |

Up to 64 KB these packets rely on IP fragmentation, where losing one
fragment loses the packet. Beyond 64 KB they cannot be sent: the encoders
clamp the 16-bit length field (`Ospfv2Packet::emit`, and the same in
`v3.rs`, each with a `debug_assert!`), and an IP datagram cannot be that
large.

### 4.2 The receive buffer is 16 KB (reproduced)

Both readers receive into `[0u8; 1024 * 16]`. A larger datagram is
truncated, fails the length check and is dropped without a log line.
Together with §4.1 this caps what two zebra-rs routers can synchronize.

**Lab (2026-11-19, OSPFv2, release build of `main` `bd2cebd0`).** Two
routers on a point-to-point link. `b` holds `N` static `/32` routes and
`redistribute static`, so it originates `N` Type-5 LSAs; it is started
first and holds all of them before `a` starts. Namespaces and daemons
are fresh for every run.

| `N` | `a` sees `b` | `b` sees `a` | Type-5 LSAs on `a` |
|---|---|---|---|
| 100, 400, 452, 453 | Full | Full | all `N` |
| 454, 500, 815 | Loading | Full | 0 |
| 816, 1000 | Exchange | Exchange | 0 |

Both boundaries are where one packet passes 16,384 bytes, IP header
included:

- **LS Update answering the request, from `N = 454`.** `a` requests all
  `N` LSAs in one LS Request and `b` answers with all of them in one LS
  Update: `20 + 24 + 4 + 36·N` bytes, which is 16,356 at 453 and 16,392
  at 454.
- **Database Description, from `N = 816`.** `b`'s summary lists its
  Router-LSA and the `N` Type-5 LSAs: `20 + 24 + 8 + 20·(N + 1)` bytes,
  which is 16,372 at 815 and 16,392 at 816.

What was observed at `N = 454`:

- **On the wire:** every 5 s `a` sends `LS-Request [len 5472]` and `b`
  answers `LS-Update [len 16372]`, in IP fragments.
- **In the receiver:** each answer is read as `recvmsg(...) = 16384`
  with `MSG_TRUNC`.
- **In the show output:** `a` stays in Loading with 454 requests
  outstanding and none of the LSAs; `b` shows the neighbor as Full.
- **In the logs:** nothing, on either router.

The state does not clear by itself. `a` repeats the same request every
`RxmtInterval` and `b` gives the same answer.

So the limit is a size, not a count: an adjacency cannot form when the
LSAs one router lacks total more than about 16.3 KB. That is 453 Type-5
LSAs at 36 bytes each, and fewer of anything larger. A Router-LSA with
many links, or an Opaque LSA, counts for more.

**OSPFv3 (2026-11-19, the 26.11.4 package).** The same lab with `N`
static `/64` routes, whose AS-External-LSAs are also 36 bytes: 440 reach
Full, and at 500 `a` stays in Loading with none of them.

Not reproduced, from reading:

- **Toward FRR**, which accepts packets up to 65,535 bytes and sends
  MTU-sized ones, the limit should be the 64 KB of §4.1: about 3,270
  LSAs in the Database Description zebra-rs sends.

**Since fixed in part (2026-11-19).** Both readers now receive into
65,536 bytes, which holds any IPv4 datagram and any OSPFv3 packet short
of a jumbogram, and they log a packet that is truncated all the same.
Both writers log a send that fails. The same lab afterwards, as `a`
sees `b`:

| `N` | OSPFv2 | OSPFv3 |
|---|---|---|
| 454 | Full | not run |
| 500 | not run | Full |
| 816 | Full | not run |
| 1,819 | Full | Full |
| 1,820 | Loading, no LSAs | Loading, no LSAs |

The limit is now the 64 KB of §4.1. At 1,820 the LS Update answering the
request is 65,568 bytes with its IP header, `sendmsg` refuses it, and
`b` logs `failed to send a packet ... packet=LS Update bytes=65548
error=Message too long`. Packets above the MTU still travel as IP
fragments. Sizing them is
[`ospf-packet-sizing-plan.md`](ospf-packet-sizing-plan.md).

### 4.3 Flooding is unicast on broadcast networks

RFC 2328 §13.3 has LS Updates multicast on a broadcast network, to
AllSPFRouters from the DR and Backup and to AllDRouters from the others.
zebra-rs sends a separate unicast to each neighbor. It interoperates, but
a LAN with `N` neighbors costs `N` packets per LSA instead of one.

### 4.4 OSPFv3 packets are not marked

RFC 5340 §A.1: "OSPF protocol packets are sent with IP precedence set to
Internetwork Control". `socket::ospf_socket_ipv6` sets no traffic class;
`socket::ospf_socket_ipv4` sets `IPTOS_PREC_INTERNETCONTROL`.

### 4.5 Every redistributed route re-originates every Type-5 LSA (reproduced)

Found in the lab of §4.2: with 1,000 static routes on `b`, the Type-5
LSA of the first route had sequence number `0x800003e8` (1,000) and that
of the last `0x80000001`.

`Ospf::route_redist_add` runs for each batch of routes the RIB delivers
and calls `as_external_redist_resync_all`. `as_external_redist_resync`
then calls `as_external_lsa_originate_for_prefix` for every redistributed
prefix. That function does not compare with the instance already in the
database: it takes the next sequence number and floods. Nothing on this
path applies `min-ls-interval`, although RFC 2328 §12.4 forbids a new
instance of an LSA within `MinLSInterval`.

In the lab each static route arrived as its own batch, so `N` routes
cost `N·(N+1)/2` originations.

**Measured with a neighbor.** With the adjacency Full and one route
redistributed, 199 more routes were applied in one commit. `b` sent
20,102 LS Update packets, one LSA each, where 199 would have done
(`2 + 3 + … + 200 = 20,099`). The same step with 1,000 routes would send
about 500,000 to every neighbor.

`as_external_redist_resync_v3` has the same loop, and OSPFv3 shows the
same pattern: with five static routes the AS-External-LSAs carry
sequence numbers `0x80000005` down to `0x80000001`. The LS Updates were
not counted for OSPFv3.

This is an LSA storm of the router's own making, and it is the case the
RFC's Appendix A names as "(g) injecting a large number of external
routes to OSPF".

**Since fixed (2026-11-19).** The four originators (Type-5 and Type-7,
in both versions) leave an LSA alone when the database already holds it
as this router's own with the same contents (`Ospf::keeps_own`). The
step measured above, 199 routes added to a Full adjacency, now sends 201
LS Update packets in OSPFv2 and in OSPFv3, and every LSA stays at its
first sequence number. OSPFv3 was measured before the fix too, with the
26.11.4 package: 20,102 packets, as OSPFv2.

An unchanged LSA is still originated in three cases:

- **A copy learned back from a neighbor** (RFC 2328 §13.4) is not this
  router's own. That LSA alone is originated anew, where all of them
  were.
- **An LSA at MaxAge.**
- **The exit from a graceful restart** originates all of them, as it
  did.

FRR draws the same lines (read at `9b9c7c4138`): `ospf6d` in
`ospf6_lsa_originate`, `ospfd` by comparing the route it is given with
the one it holds (`ospf_external_info_add`). Neither applies
`min-ls-interval` to a single external LSA, and neither does this fix.

**A route is handled by itself (2026-11-19).** After the fix above each
route still ran a pass over every redistributed prefix, which only
compared, and originated a Router-LSA, MinLSInterval apart. The route
handlers now look at the prefixes of the batch alone
(`route_redist_changed`), as FRR does in `ospf_zebra_read_route`:

- **Type-5 LSAs** of `redistribute <source>` and `redistribute table`:
  the batch's prefixes only. So is the LSA a neighbor sends back.
- **The default route** of `default-information originate`: only when
  the batch has a default route.
- **The Router-LSA:** not for a route. Its E-bit follows the
  configuration.
- **Type-7 LSAs of an NSSA:** all of them, as before. They are few
  (connected routes), and carry the area's forwarding address and this
  router's ABR status besides the route.

The pass over every prefix remains for a change of configuration or
policy, a Router ID change and the exit from a graceful restart.

Measured: the 199 routes now cost 199 LS Update packets in both
versions, and an OSPFv3 router originates 5,000 static routes in 2 s
where the 26.11.4 package took 24 s.

---

## 5. Other implementations

### 5.1 FRR `ospfd`

Read at `9b9c7c4138`. Explicit RFC 4222 support arrived in 2026, all of
it per interface and off by default.

| # | What FRR does | Knob | Default | Release |
|---|---|---|---|---|
| 1, receive | Nothing: one socket, FIFO, up to `write-multiplier` (20) packets per read event, dispatched inline by type (`ospf_read`) | — | — | — |
| 1, transmit | Hello goes to the head of the interface output queue (`ospf_packet_add_top`); acknowledgments go to the tail | — | always | since 2010 (`aa276fd783`) |
| 1, marking | DSCP by packet type: Hello and LS Ack use one value, the others may use a lower one (`ospf_tos_for_type`) | `ip ospf dscp <all\|low-control> (0-63)` | both CS6 | 10.7.0 (`7bd6d5564b`) |
| 2 | Any unicast packet, or any packet to AllSPFRouters on a point-to-point link, restarts the dead timer once the neighbor is at 2-Way or beyond (`ospf_maybe_restart_inactivity`) | `ip ospf dead-timer-reset any-control` | off | 10.7.0 (`8f62a22af5`) |
| 3 | Not implemented. Each LSA has its own due time and is rescheduled at the same fixed interval (`ospf_ls_rxmt_timer`) | `ip ospf retransmit-interval`, `ip ospf retransmit-window` (ms, batching only) | 5 s, 50 ms | — |
| 4 | Per-neighbor queue and gap, adjusted by the unacknowledged count (`pace_maybe_adjust_gap`) | `ip ospf lsa-pacing` and sub-commands | off; gap 20 ms to 1 s, factor 2, every 1 s, high 100, low 2, 1 LSA per update | master only (`127c6c4dd1`) |
| 5 | Per-interface limit on adjacencies in progress, with a queue of waiting neighbors (`ospf_adj_pacing_allow`) | `ip ospf adjacency-pacing static (1-65535)` or `dynamic` | off | master only (`2acd8f1184`) |

Notes:

- **The "rec 1" commit adds only the DSCP.** Nothing is reordered on
  receive.
- **The authentication sequence number is stamped when a packet is
  written**, not when it is built, which is what lets a Hello jump the
  queue under cryptographic authentication.
- **Recommendation 4 deviates from the RFC in two places:** the gap also
  drops straight to the minimum when nothing is unacknowledged, and the
  default marks are 100 and 2, not 20 and 10.
- **The dynamic adjacency limit** starts at 1, halves when the
  interface's unacknowledged total passes the high mark and grows by one
  below the low mark, up to 50.

### 5.2 FRR `ospf6d`

None of the 2026 work. Hello goes to the head of the output queue
(`ospf6_packet_add_top`), only a Hello restarts the dead timer, and each
retransmission resends the whole list at a fixed interval. A search for
pacing, water marks, unacknowledged counts, backoff and "4222" finds
nothing.

### 5.3 holo

One generic implementation for both versions.

- **1:** no classification on receive. The Hello is sent by its own
  interval task straight to the interface's transmit queue, so it does
  not wait for the instance loop.
- **2, 3, 5:** not implemented. Retransmission is a fixed interval, one
  MTU-sized packet per tick.
- **4:** LS Updates are batched for 100 ms and packed to the MTU; nothing
  reacts to unacknowledged LSAs.

### 5.4 BIRD

- **1:** no classification and no output queue; a send that would block
  is dropped.
- **2:** always on, and wider than the RFC: every packet type restarts
  the timer, with no unicast or point-to-point condition. The source
  marks the calls "Not in RFC" and "Questionable".
- **3:** fixed interval, with the burst capped at twice the flood queue.
- **4, 5:** batching only; no adjacency limit.

### 5.5 Commercial

| Vendor / OS | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Cisco IOS / IOS XE | Received Hellos have their own process and queue | Not documented | No; `limit retransmissions`, 24 | Fixed: `timers pacing flood` 33 ms, `timers pacing retransmission` 66 ms | `adjacency stagger`, default 300 (IOS XE) |
| Cisco IOS XR | Three receive classes: Hello, LS Ack, the rest (`queue limit high/medium/low`), plus a Hello thread | Not documented | No | Pacing timers documented for OSPFv3 only | `adjacency stagger`, on by default, 2 then 64 |
| Cisco NX-OS | Unknown | Unknown | Unknown | Unknown | Unknown |
| Juniper Junos | Unknown | Unknown | No | Unknown | Unknown |
| Arista EOS | Unknown | Unknown | No | A `timers pacing` command exists, undocumented | `adjacency exchange-start threshold`, default 10 |
| Nokia SR OS | Lists RFC 4222 as supported; no mechanism documented | — | — | — | — |
| Huawei VRP | Unknown | Unknown | No; optional `retransmission-limit` | Fixed-rate `flooding-control` | Unknown |
| IP Infusion OcNOS | — | — | — | — | `max-concurrent-dd`, default 64 |

- **Cisco IOS** describes the Hello queue as sitting "between the packet
  switching code (process IP Input) and the OSPF hello process for all
  received OSPF packets", and the Router queue as carrying "all received
  OSPF packets except OSPF hellos". LS Acks are therefore in the low
  queue.
- **Cisco IOS XR** defines the classes as "high-priority events
  (state-changing Hellos)", "medium-priority events (LSA ACK)" and
  "low-priority events (DBD/LSUpd/LSReq)", with limits 9500, 9000 and
  8000.
- **IOS XR's adjacency stagger** applies to "reload, process restart,
  and process clear", and is mutually exclusive with nonstop forwarding.
- **Junos** does not list RFC 4222 among its supported standards. Its
  periodic packet management daemon is in the OSPF liveness path
  according to a CVE description, but no document says it sends OSPF
  Hellos.
- **Nokia** is the only vendor found that lists RFC 4222. Its command
  reference describes a fixed 5 s retransmission interval, so what the
  listing covers is unknown.
- **Arista's** manual gives the default 10 but shows 20 in its own
  sample output.

### 5.6 What the survey shows

- **Nobody implements recommendation 3.** No source tree and no vendor
  document shows exponential backoff.
- **Recommendation 5 is the most widely adopted:** IOS XE, IOS XR,
  Arista, OcNOS, and FRR master.
- **Flood pacing is common, but as a fixed gap.** Only FRR master ties it
  to unacknowledged LSAs.
- **Recommendation 1 is implemented as a separate path for Hellos**, not
  as two classes: on receive in IOS and IOS XR, on transmit in FRR and
  holo. Only IOS XR gives LS Acks a class of their own.
- **Recommendation 2 is rare:** BIRD always, FRR as an option.

---

## 6. Proposed order of work

Each step is the same change in OSPFv2 and OSPFv3.

1. **Size packets to the MTU and enlarge the receive buffer** (§4.1,
   §4.2). Split Database Description, LS Request, LS Update and LS Ack at
   the interface MTU; receive up to 65,535 bytes. This comes first: it
   is reproduced, it stops adjacencies from forming at a few hundred
   LSAs, and pacing and retransmission limits mean little while one
   packet carries a whole list.
2. **Originate only what changed when redistributing** (§4.5): skip a
   prefix whose LSA would be identical, and put the path under
   `min-ls-interval`. It is independent of the other steps and small, so
   it can also go first. *Done, without the `min-ls-interval` part
   (§4.5).*
3. **Send OSPFv3 packets through the main queue**, as `Message::Recv`,
   which is already generic over the version. This gives OSPFv3 the
   ordering of §3.1 and makes recommendation 2 unnecessary.
4. **Take Hello sending out of the backlog** (§3.2). The smallest change
   is a second channel that carries only `HelloTimer`, polled first with
   a `biased` select: the Hello is still built by the main task, so
   sequence numbers stay in sending order, and `InactivityTimer` and
   `Retransmit` stay in the main queue, which keeps §3.1 intact.
   Classifying received packets into two queues, as the RFC describes,
   would break that ordering unless Hellos, LS Acks and their timers all
   moved together, and would require the authentication sequence check
   to run before the split.
5. **Limit adjacencies in progress** (recommendation 5): a configurable
   count of neighbors in ExStart, Exchange and Loading, with the others
   waiting in 2-Way in arrival order. Defaults elsewhere range from 10
   (Arista) to 300 (IOS XE).
6. **Repair retransmission and pace flooding** (§3.4, §3.5). Give each
   LSA its own due time, send at most an MTU-sized packet per expiry, and
   batch flooded LSAs per neighbor with a fixed gap. The adaptive gap of
   recommendation 4 can follow, with FRR master as the reference.
7. **Small items:** mark OSPFv3 packets Internetwork Control (§4.4);
   multicast LS Updates on broadcast networks (§4.3).

Not proposed: recommendation 3 (nobody implements it, and step 6 removes
most of what it is meant to cure) and recommendation 2 (step 3 covers
it).

---

## 7. Open points

- **Keep the reproductions as tests.** The lab of §4.2 and §4.5 was a
  throwaway. Two BDD features would hold the fixes: one that
  synchronizes 1,000 redistributed routes, one that counts the LS
  Updates sent when routes are added.
- **Run the same lab for OSPFv3**, where both findings are read, not
  reproduced.
- **Measure the backlog.** §3.1 and §3.2 state the condition for a false
  neighbor-down, not how easily it is met. A storm test of 10,000 to
  100,000 LSAs with short Hello timers would show it.
- **Unbounded channels.** Nothing limits the memory a backlog takes. A
  bound would move the queueing into the socket buffer, where
  recommendation 1 would then have to be implemented for real.
- **Scope of the adjacency limit:** per instance (Cisco, Arista) or per
  interface (FRR).
- **The commercial rows** should be checked against a device or a
  current manual before they are relied on.

---

## References

- RFC 4222, RFC 2328 (§10.5, §13.3, §A.1), RFC 5340 (§A.1).
- FRR: `ospfd/ospf_packet.c`, `ospfd/ospf_flood.c`, `ospfd/ospf_nsm.c`,
  `ospfd/ospf_interface.h`, `doc/user/ospfd.rst`; commits `aa276fd783`,
  `7bd6d5564b`, `8f62a22af5`, `2acd8f1184`, `127c6c4dd1`.
- holo: `holo-ospf/src/tasks.rs`, `neighbor.rs`, `output.rs`,
  `network.rs`.
- BIRD: `proto/ospf/neighbor.c`, `lsupd.c`, `packet.c`.
- Cisco IOS:
  [OSPF Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book.pdf),
  [limiting adjacency formation (IOS XE)](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/configuration/xe-16-10/iro-xe-16-10-book/iro-limit-adj-form.pdf),
  [Selective Packet Discard](https://sec.cloudapps.cisco.com/security/center/resources/selective_packet_discard.html).
- Cisco IOS XR:
  [NCS 5500 Routing Command Reference](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/routing/b-ncs5500-routing-cli-reference.pdf).
- Juniper:
  [OSPF User Guide](https://www.juniper.net/documentation/us/en/software/junos/ospf/ospf.pdf).
- Arista:
  [EOS OSPFv2 chapter](https://www.arista.com/en/um-eos/eos-open-shortest-path-first-version-2).
- Nokia:
  [SR OS standards and protocol support](https://documentation.nokia.com/sr/25-7/7750-sr/books/common/dita_standards-13.html).
- Huawei:
  [restricting the flooding of update LSAs](https://support.huawei.com/enterprise/en/doc/EDOC1100198820/38bcf8d6/optional-restricting-the-flooding-of-update-lsas),
  [retransmission limit](https://support.huawei.com/enterprise/en/doc/EDOC1100116613/4e79a277/setting-an-ospf-packet-retransmission-limit).
- IP Infusion:
  [OcNOS OSPF command reference](https://docs.ipinfusion.com/sp-6.3.3-configuration-guide/OcNOS-SP/OSPF-CR/OSPFcmds.101.081.html).
