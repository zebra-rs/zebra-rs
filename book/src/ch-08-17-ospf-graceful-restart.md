# Graceful Restart

OSPFv2 implements RFC 3623 Graceful Restart in both roles: as a
**helper**, keeping an adjacency alive while a neighbor restarts,
and as a **restarter**, restarting the daemon itself without
disturbing forwarding. Helper mode is on by default and needs no
configuration; a graceful restart of the local daemon is an
operator-driven `clear` sequence backed by an on-disk checkpoint.

## Helper configuration

```
router ospf {
  graceful-restart {
    helper-enabled true;
    max-grace-period 1800;
    helper-strict-lsa-checking true;
    drain-time-ms 200;
  }
}
```

| YANG leaf (`/router/ospf/graceful-restart/…`) | Default | Range | Units |
|---|---|---|---|
| `helper-enabled` | `true` | — | boolean |
| `max-grace-period` | 1800 | uint32 | seconds |
| `helper-strict-lsa-checking` | `true` | — | boolean |
| `drain-time-ms` | 200 | 50..2000 | milliseconds |

Defaults match the IETF OSPF YANG model and FRR's helper defaults.

## Helper mode

A restarting neighbor announces itself by flooding a **Grace-LSA**
(link-local opaque LSA, type 9) carrying its grace period and
restart reason. zebra-rs enters helper mode for that neighbor when
the adjacency is Full, `helper-enabled` is true, and the requested
grace period is within `max-grace-period` (RFC 3623 §3.1 leaves the
bound to the helper's policy). While helping:

- The neighbor's dead-interval expiry is suppressed — the adjacency
  stays Full even though Hellos stop.
- The helper snapshots the sequence number and checksum of every
  LSA the restarter had originated. If the restarter comes back and
  re-floods them byte-identical, the restart is quiescent and
  helping continues.

Helping ends — and the neighbor is torn down through the normal
dead-timer path — when the grace period expires, when the restarter
floods an LSA that *differs* from its snapshot (it forgot its
pre-restart state, so the topology must reconverge), or, with
`helper-strict-lsa-checking true`, when any topology-affecting LSA
from a third router floods through the area (RFC 3623 §3.2). Set
`helper-strict-lsa-checking false` to let unrelated topology churn
elsewhere ride out a restart.

Disabling `helper-enabled` stops *new* helper sessions; sessions
already in progress run to their normal exit.

## Restarting the local daemon

A graceful restart is staged, then committed:

```
clear ospf graceful-restart begin
clear ospf graceful-restart commit
```

`begin` floods a Grace-LSA out every enabled interface (grace
period 120 s, reason software-restart) and stages the restart; if
no `commit` follows within the grace period, an auto-abort timer
cancels it. `clear ospf graceful-restart abort` cancels explicitly,
flushing the Grace-LSAs.

`commit` writes a checkpoint of the instance —
router-id, every area's full LSDB at exact sequence/checksum,
neighbor state, and allocated SR labels — to
`/var/lib/zebra-rs/checkpoint/ospf.cbor` (CBOR, written
atomically), waits `drain-time-ms` so the Grace-LSAs reach the
wire, and exits the process. Kernel routes are deliberately left
installed, so forwarding continues while the daemon is down. A
process supervisor (e.g. systemd) must restart zebra-rs; graceful
restart does not survive without one.

On start-up, a checkpoint younger than 1.5× its grace period is
replayed: the LSDB is restored byte-identical — so helpers'
snapshots keep matching — and the checkpoint file is deleted (a
stale or unreadable checkpoint falls back to a cold start). The
restart completes when all pre-restart adjacencies are Full again:
the Grace-LSAs are flushed and the router re-originates its own
LSAs at the next sequence number.

For debugging, `clear ospf checkpoint write` dumps a checkpoint
without restarting and `clear ospf checkpoint clear` deletes the
on-disk file.

## Observing graceful restart

`show ospf graceful-restart` displays the helper configuration, a
`Restart staged:` line while a local restart is pending, and a
table of active helper sessions (neighbor, interface, restart
reason, grace period, time remaining). `show ospf checkpoint`
summarizes the on-disk checkpoint, and `show ospf database` marks
neighbors advertising the Router Information "Graceful Restart
helper" capability.

The full cycle is BDD-validated (`ospfv2_graceful_restart.feature`):
a staged restart drives helper entry on the peer and abort recovers,
and a committed restart holds the adjacency and route on the helper
well past the 40 s dead interval while the daemon is down, then
resumes from the checkpoint — the adjacency re-exchanges
(Full → ExStart → Full) inside the grace window without ever taking
a dead-timer kill.

## OSPFv3

OSPFv3 implements both roles with the same configuration block,
staging commands, and checkpoint flow (on `ospfv3.cbor`), using the
RFC 5187 v3 Grace-LSA — see
[the OSPFv3 chapter's Graceful Restart page](ch-15-12-ospfv3-graceful-restart.md).
