# Clearing OSPFv3 State

OSPFv3 exposes operational `clear` commands that act on the running
instance without touching the configuration. They live under
`clear ospfv3 …` and take effect immediately — there is no `commit`.

## Resetting adjacencies — `clear ospfv3 neighbor`

```
clear ospfv3 neighbor [<router-id>]
```

Tear an OSPFv3 adjacency down so it re-forms from scratch — the
operator-driven equivalent of a dead-timer expiry. Bare, it resets
every OSPFv3 adjacency; with an argument it resets only the neighbor
whose OSPF Router-ID (the `Router-ID` column of
`show ospfv3 neighbor`) matches. Because a live peer keeps sending
Hellos, the adjacency is re-learned on the next Hello and walks the
full state machine back up through a fresh Database-Description
exchange.

OSPFv3 keys its neighbors by Router-ID (RFC 5340 §10) — unlike
OSPFv2 on broadcast networks, where the key is the interface
address — so the `<router-id>` argument is also the internal
neighbor-table key. Tab completion offers the live neighbor set.

## Forcing an SPF run — `clear ospfv3 spf`

```
clear ospfv3 spf
```

Force-recalculates the OSPFv3 SPF for every attached area from the
current LSDB, without touching adjacencies. Useful to rule the SPF
scheduler in or out when a route looks stale.

## Graceful-restart staging — `clear ospfv3 graceful-restart`

```
clear ospfv3 graceful-restart begin
clear ospfv3 graceful-restart commit
clear ospfv3 graceful-restart abort
```

Stage, commit, or cancel a graceful restart of the local daemon —
see [Graceful Restart](ch-15-12-ospfv3-graceful-restart.md) for the
full flow. `clear ospfv3 checkpoint write | clear` are the matching
checkpoint debug commands.
