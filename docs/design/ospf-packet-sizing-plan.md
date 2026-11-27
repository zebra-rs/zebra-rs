# OSPF: sizing packets to the MTU

Status: **Plan, 2026-11-19. Pull request 1 of §7, the receive buffer, is
implemented; pull requests 2 to 4 are not.** This is step 1 of the
order of work in
[`ospf-rfc4222-applicability.md`](ospf-rfc4222-applicability.md) (§6),
and it removes the limit reproduced in that memo's §4.2: two zebra-rs
routers synchronize 453 Type-5 LSAs and fail, silently and for good, from
454.

The code was read at `main` `6097c998`. Function names below are in
`zebra-rs/src/ospf/` unless a crate is named.

---

## 0. Summary

zebra-rs builds four of the five OSPF packet types without looking at
the interface MTU, and reads every packet into a 16 KB buffer. The fix
has two halves:

- **Receive whatever a peer may send:** a 64 KB buffer, and a log line
  when a packet is dropped.
- **Send nothing larger than the interface MTU:** one budget function,
  and each packet type split to fit it.

Splitting is mechanical for LS Update and LS Ack. Database Description
and LS Request are exchanges, and splitting them exposes two things the
single-packet shortcut has hidden until now:

- **The slave decides ExchangeDone too early** in the test, so with more
  than one packet to send it never leaves Exchange (§4.4).
- **Nothing sends the next LS Request** when the previous one is
  answered; only the 5 s retransmission timer would (§4.5).

Delivery is four pull requests (§7). The first, the receive buffer
alone, already moves the limit from 453 to about 1,800 Type-5 LSAs.

The acceptance test is a BDD feature that drops every IP fragment on the
link and still synchronizes a few thousand LSAs (§6).

---

## 1. The limit today

| Packet | What one packet carries | Built in |
|---|---|---|
| Hello | The neighbor list | not in scope (§2) |
| Database Description | The whole database summary | `packet::ospf_packet_db_desc_set`; `packet_v3.rs` likewise |
| LS Request | The whole request list | `packet::ospf_packet_ls_req_set` |
| LS Update answering a request | Every LSA requested | `packet::ospf_ls_req_recv` |
| LS Update, retransmission | The whole retransmission list | `Ospf::process_retransmit` |
| LS Ack, delayed | Every header queued on the interface | `Ospf::process_delayed_ack` |
| LS Update, flooding | One LSA | `Ospf::flood_lsa_through_link` |

Both readers (`network::read_packet`, `network_v6::read_packet_v6`)
receive into `[0u8; 1024 * 16]`. A longer datagram is truncated, fails
the length check and is dropped with no log line.

The effects, in the order they appear as a database grows:

1. **Past the MTU**, packets leave as IP fragments. Losing one fragment
   loses the packet.
2. **Past 16 KB**, another zebra-rs cannot read the packet. This is the
   reproduced limit: the LS Update answering a request first (454 Type-5
   LSAs), the Database Description next (816 LSAs).
3. **Past 64 KB**, the packet cannot be sent to anyone. The encoders
   clamp the 16-bit length field, and the error from `sendmsg` is
   dropped (`let _ =` in both writers).

---

## 2. Goals and non-goals

Goals:

- No OSPF packet zebra-rs builds is larger than the interface MTU. The
  one exception is a single LSA that is itself larger than the MTU,
  which travels alone.
- zebra-rs reads any OSPF packet a peer may send, up to 65,535 bytes.
- OSPFv2 and OSPFv3 change together.
- No new configuration.
- A router that has the change and one that does not still form an
  adjacency, at least as well as two old routers do (§5).

Non-goals, each a later step of the applicability memo:

- Pacing or batching of flooded LS Updates. Flooding keeps one LSA per
  packet.
- Per-LSA retransmission timing. A retransmission still resends the
  whole list every interval, now in MTU-sized packets.
- A limit on adjacencies in progress.
- The re-origination of every redistributed LSA (that memo's §4.5). It
  is independent of this plan and has its own fix.

Also out of scope: a Hello whose neighbor list exceeds the MTU (about
360 neighbors on one segment), and Path MTU discovery on virtual links.

---

## 3. The packet budget

One function gives the number of bytes available after the OSPF header,
and every builder asks it. It is computed when a packet is built, so an
MTU change needs no extra handling.

| | OSPFv2 | OSPFv3 |
|---|---|---|
| Interface MTU | `OspfLink::mtu` | `OspfLink::mtu` |
| IP header | 20 | 40 |
| OSPF header | 24 | 16 |
| Authentication | Digest length under cryptographic authentication (16 to 64, `AuthAlgo::digest_len`); nothing for null or simple | `Ospfv3AuthTrailer::PREFIX_LEN` (16) plus the digest length when a trailer is sent |
| Floor for the MTU | 576 | 1280 |

`budget = max(mtu, floor) − IP header − OSPF header − authentication`

The floor covers an interface whose MTU is unknown or implausibly small.
The authentication term is the trailer that follows the packet: it is
not counted in the OSPF length field but it is in the IP datagram.

What fits at an MTU of 1500 with no authentication:

| Packet | Fixed part | Per item | OSPFv2 | OSPFv3 |
|---|---|---|---|---|
| Database Description | 8 (v2), 12 (v3) | 20 per header | 72 headers | 71 headers |
| LS Request | 0 | 12 per entry | 121 entries | 120 entries |
| LS Update | 4 | the LSA's length | 1,452 bytes of LSAs (40 Type-5) | 1,440 bytes |
| LS Ack | 0 | 20 per header | 72 headers | 72 headers |

An LSA's size is the `length` field of its header, in both versions.

**Virtual links.** A virtual link has no interface; `OspfLink` gives it
an MTU of 1500 today. RFC 2328 §A.1 says packets sent over virtual links
should be limited to 576 bytes unless Path MTU discovery is performed,
and RFC 5340 §A.1 says 1280 for OSPFv3. FRR uses 1500 (`OSPF_VL_MTU`).
This plan proposes the RFC values; see §8.

---

## 4. Changes by packet type

### 4.1 Receiving

- **Buffer:** 65,536 bytes, allocated once per reader task on the heap,
  in `read_packet` and `read_packet_v6`.
- **Truncation:** check `MSG_TRUNC` on the result of `recvmsg` and log
  it, rate-limited, with the interface and the source. With the larger
  buffer it should never fire; it is there so that this class of failure
  is never silent again.
- **Sending:** log a `sendmsg` error in `write_packet` and
  `write_packet_v6`, rate-limited, where it is discarded today.

Nothing else in the receive path depends on the size.

### 4.2 LS Update

One helper splits a list of LSAs into groups that each fit the budget
less the 4-byte LSA count. An LSA larger than that goes in a group of
its own and leaves as IP fragments; there is no other way to send it.

It is used wherever several LSAs go to one neighbor:

- **Answering an LS Request** (`ospf_ls_req_recv`, `ospfv3_ls_req_recv`):
  one LS Update per group instead of one for everything. `BadLSReq`
  handling does not change: a request for an LSA not in the database
  still answers nothing.
- **Retransmission** (`Ospf::process_retransmit`, both versions): one LS
  Update per group. `ospf_ls_retransmit_resent` keeps recording what was
  sent; the timer and the interval do not change.

Flooding is not touched.

### 4.3 LS Ack

`Ospf::process_delayed_ack` and the direct acknowledgment
(`ospf_ls_ack_send`, `ospfv3_ls_ack_send`) send the headers in groups of
`budget / 20`.

### 4.4 Database Description

**Sending.** `ospf_packet_db_desc_set` moves at most
`(budget − fixed part) / 20` headers from `nbr.db_sum` into the packet
instead of all of them. `ospf_db_desc_send` already derives the More bit
from what is left in `db_sum` after that, and already keeps the packet
in `nbr.dd.sent` for the master's retransmission and the slave's answer
to a duplicate. Neither changes.

**Master.** `ospf_db_desc_proc` already continues correctly: on the
slave's answer it advances the sequence number and either sends the next
packet or, when the slave's More bit and its own last More bit are both
clear, raises ExchangeDone.

**Slave: a fix is required.** Today the slave tests for ExchangeDone
*before* it builds its answer:

```rust
if !dd.flags.more() && ospf_db_summary_isempty(nbr) {
    nbr.dd.flags.set_more(false);
    nbr_sched_event(nbr, NfsmEvent::ExchangeDone);
}
ospf_db_desc_send(oi, nbr, oi.ident);
```

RFC 2328 §10.6 puts the test on the packet being sent: ExchangeDone when
the received packet has the More bit clear "and the packet to be sent by
the slave will also have the M-bit set to 0". The two are the same only
while the slave's first answer empties its summary, which is always the
case today. With a summary of two or more packets:

1. The master, with nothing left, sends a packet with More clear.
2. The slave still holds its last group, so the test fails. It sends
   that group, now with More clear.
3. The master sees both More bits clear, raises ExchangeDone and sends
   no further packet.
4. The slave is never asked again and stays in Exchange.

The fix is to send first and then test the More bit of the packet just
sent: `!dd.flags.more() && !nbr.dd.flags.more()`. `ospfv3_db_desc_proc`
has the same code and takes the same fix.

The exchange then takes one round trip per packet: 14 for 1,000 LSAs,
139 for 10,000. It is stop-and-wait by design, so no burst is created.

### 4.5 LS Request

**Sending.** `ospf_packet_ls_req_set` takes the first `budget / 12`
entries of `nbr.ls_req` instead of all of them.

**Asking for the rest.** RFC 2328 §10.9: when the neighbor answers, "the
Link state request list is truncated and a new Link State Request packet
is sent", until the list is empty. Today a request leaves only at
ExchangeDone (`nfsm::ospf_nfsm_exchange_done`) and on the retransmission
timer, so a split request would advance one packet every 5 s: 10,000
LSAs would take seven minutes.

The mechanism is already half there, ported from FRR and left unused:

- `Neighbor::ls_req_last` exists and is only ever cleared.
- `nfsm::ospf_nfsm_check_nbr_loading` ends with a commented-out
  `ospf_ls_req_event(nbr)`.

FRR records the last LSA of each request in `nbr->ls_req_last`, clears
it when that LSA leaves the request list, and in `ospf_check_nbr_loading`
sends the next request as soon as it is clear and the list is not empty.
This plan completes the same three pieces:

1. When a request is built, remember the identity of its last entry.
2. Wherever an entry leaves `nbr.ls_req` (the LSA arrived, or a flooded
   instance made it unnecessary), clear the mark if it was that entry.
3. In `ospf_nfsm_check_nbr_loading`, with the mark clear and the list
   not empty, send the next request at once.

The retransmission timer stays as the fallback: it resends whatever is
at the front of the list.

An LS Update that arrives out of order can clear the mark while earlier
entries are still outstanding. Those entries are then at the front of
the list and are asked for again; the duplicate answers are harmless.

Requests of about 120 entries also bound the answer to three or four
packets, which is the flow control RFC 2328 intends for loading.

---

## 5. Interoperation and upgrade

"New" has this plan; "old" is zebra-rs before it.

| Sender | Receiver | Result |
|---|---|---|
| new | new | No size limit. |
| new | old | Works: every packet fits the old 16 KB buffer. |
| old | new | Works up to 64 KB per packet, where it failed at 16 KB. |
| new | FRR and others | MTU-sized packets, as they send themselves. |
| old | old | Unchanged: the limits of §1. |

So routers can be upgraded in any order, and each upgraded router
improves both directions of its adjacencies.

The exchange changes are what every other implementation already does,
and zebra-rs already receives multi-packet exchanges from FRR. What is
new is zebra-rs *sending* them, which is why both roles need tests
(§6).

---

## 6. Tests

**Unit**, each for OSPFv2 and OSPFv3:

- The budget for each authentication mode, the MTU floor and a virtual
  link.
- The LSA grouping helper: exact fit, one byte over, and an LSA larger
  than the budget.
- A Database Description exchange between two in-process neighbors with
  summaries of several packets, as master and as slave, including the
  case of §4.4 where the master runs out first. The second fails
  without the slave fix.
- LS Request: a split request, the next one sent when the last entry
  arrives, and nothing sent while it has not.
- An LS Request answered in several LS Updates; a retransmission and a
  delayed acknowledgment split the same way.
- The reader accepts a 60 KB packet.

**BDD.** One feature per version, `ospfv2_large_database` and
`ospfv3_large_database`:

- Two routers on a point-to-point link; one redistributes 1,000 static
  routes before the other starts.
- A packet filter on the link drops every IP fragment. Any packet over
  the MTU is then lost, so the feature passes only when every packet
  fits.
- Both reach Full and the second router holds all 1,000 LSAs.
- Run once with the redistributing router as master and once as slave
  (the higher Router ID is master).

With the filter the route count does not have to reach a 64 KB limit;
it has to make each exchange several packets long. 1,000 Type-5 LSAs
give 14 Database Descriptions, 9 LS Requests and 25 LS Updates. A larger
count would mostly measure the re-origination cost of the applicability
memo's §4.5, which this plan does not fix.

**Manual.** Re-run the lab of the applicability memo's §4.2 at 454, 816
and 5,000 routes, and once against FRR in each role.

**Regression.** `cargo test --workspace --exclude bdd` and the full BDD
suite on every pull request, since the exchange code is shared by every
OSPF feature.

---

## 7. Delivery

Four pull requests, each useful alone and each carrying its own tests.

| # | Content | Limit afterwards, two zebra-rs routers |
|---|---|---|
| 1 | Receive buffer of 64 KB; truncation and send errors logged (§4.1) | About 1,800 Type-5 LSAs (the LS Update answering a request reaches 64 KB), still as IP fragments |
| 2 | The budget, the grouping helper, LS Update answers, retransmission and LS Ack split (§3, §4.2, §4.3) | About 3,270 LSAs (the Database Description reaches 64 KB) |
| 3 | Database Description split, with the slave fix (§4.4) | About 5,400 LSAs (the LS Request reaches 64 KB) |
| 4 | LS Request split and the next-request trigger (§4.5); the BDD features of §6 | None |

The BDD features land with the fourth because the fragment filter fails
until every packet type fits. Pull requests 1 to 3 are covered by their
unit tests and by re-running the lab at the sizes they unlock.

Pull request 1 is a few lines and could ship at once.

**Pull request 1, as built.** `network::RECV_BUF_LEN` is 65,536 for both
readers. A truncated packet and a failed send are each logged at most
once per 10 s per task, with the count of those not logged. Re-running
the lab, in OSPFv2 and in OSPFv3:

| Routes | Before | After |
|---|---|---|
| 454 (OSPFv2), 500 (OSPFv3) | Loading for good | Full |
| 816 (OSPFv2) | Exchange for good | Full |
| 1,819 (both) | not run | Full |
| 1,820 (both) | not run | Loading for good, and logged |

At 1,820 the LS Update answering the request is 65,548 bytes of OSPFv2
(65,568 with its IP header) and 65,540 of OSPFv3, and the sender logs:

```
WARN ospf: failed to send a packet dest=10.0.12.1 interface=etha packet=LS Update bytes=65548 error=Message too long (os error 90) suppressed=1
```

---

## 8. Open questions

- **Virtual-link packet size:** 576 and 1280 as the RFCs say, or 1500
  as FRR does. The RFC values are safe on any transit path; 1500 needs
  fewer packets and matches the nearest reference implementation.
- **Retransmission bursts.** A long retransmission list now leaves as
  many MTU-sized packets at once, every interval. That is no worse than
  one oversized packet, but it is the first thing pacing should take on
  (the applicability memo's step 6).
- **A drop counter.** Whether truncated and unsendable packets should
  also be counted in `show ospf interface`, beside the log line.
- **The Database Description `Interface MTU` on a virtual link.** RFC
  2328 §10.8 says it should be 0 there. What zebra-rs sends was not
  checked for this plan.

---

## References

- [`ospf-rfc4222-applicability.md`](ospf-rfc4222-applicability.md), §4.1
  and §4.2: the limit and its reproduction.
- RFC 2328 §10.6 and §10.8 (Database Description exchange), §10.9 (LS
  Requests), §A.1 (packet size and fragmentation); RFC 5340 §A.1.
- FRR `ospfd/ospf_packet.c`: `ospf_packet_max`, and the builders that
  test against it; `ospfd/ospf_flood.c` and `ospfd/ospf_nsm.c` for
  `ls_req_last` and `ospf_check_nbr_loading`.
