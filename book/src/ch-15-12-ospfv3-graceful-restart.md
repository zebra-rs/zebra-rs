# Graceful Restart

OSPFv3 implements RFC 5187 graceful restart in both roles, mirroring
[the OSPFv2 implementation](ch-08-17-ospf-graceful-restart.md): as a
**helper**, keeping a restarting neighbor's adjacency alive past the
dead interval, and as a **restarter**, restarting the daemon without
disturbing forwarding. The v3 Grace-LSA is LS type `0x000B`
(link-local scope, LS-ID = the interface ID) carrying the same
grace-period and reason TLVs as v2; the v2 IP-Interface-Address TLV
is unused, since the v3 LSA header already identifies the interface.

## Helper configuration

```
router ospfv3 {
  graceful-restart {
    helper-enabled true;
    max-grace-period 1800;
    helper-strict-lsa-checking true;
    drain-time-ms 200;
  }
}
```

| YANG leaf (`/router/ospfv3/graceful-restart/…`) | Default | Range | Units |
|---|---|---|---|
| `helper-enabled` | `true` | — | boolean |
| `max-grace-period` | 1800 | uint32 | seconds |
| `helper-strict-lsa-checking` | `true` | — | boolean |
| `drain-time-ms` | 200 | 50..2000 | milliseconds |

The helper semantics — entry on a Grace-LSA from a Full neighbor,
dead-interval suppression, the LSA snapshot, and the three exit
conditions — are identical to
[the v2 page's description](ch-08-17-ospf-graceful-restart.md).

## Restarting the local daemon

```
clear ospfv3 graceful-restart begin
clear ospfv3 graceful-restart commit
```

`begin` floods a v3 Grace-LSA out every enabled interface (grace
period 120 s, reason software-restart) and stages the restart with
an auto-abort timer; `abort` cancels and flushes. `commit` writes
the checkpoint — router-id and every area's full LSDB at exact
sequence/checksum — to `/var/lib/zebra-rs/checkpoint/ospfv3.cbor`,
waits `drain-time-ms`, and exits the process, leaving kernel routes
installed. A process supervisor must relaunch zebra-rs.

On start-up, a checkpoint younger than 1.5× its grace period is
replayed byte-identical (so helpers' snapshots keep matching) and
deleted; the restart concludes when all pre-restart adjacencies are
Full again, flushing the Grace-LSAs and re-originating the Router,
Link, Network, and Intra-Area-Prefix LSAs at the next sequence
number. During the window, all topology-affecting self-origination
is gated so the restored LSDB stands unchanged. SRv6 End.X SIDs are
not checkpointed — they re-reconcile per adjacency as neighbors
return.

For debugging, `clear ospfv3 checkpoint write` dumps a checkpoint
without restarting and `clear ospfv3 checkpoint clear` deletes the
file.

## Observing

`show ospfv3 graceful-restart` displays the helper configuration, a
`Restart staged:` line while a local restart is pending, and the
active helper sessions; `show ospfv3 checkpoint` summarizes the
on-disk file. The full cycle — helper entry, abort recovery, and the
commit/exit/replay round trip holding the adjacency past the dead
interval — is BDD-validated by `ospfv3_graceful_restart.feature`,
the v6 mirror of the v2 topology.

One residual v2/v3 difference: the v2 restarter also advertises a
`gr_capable` bit in its SR-MPLS Router Information LSA; v3 relies on
the Grace-LSA alone as the entry trigger, which is also what FRR
accepts.
