# Clearing OSPF State

OSPF exposes a small set of operational `clear` commands that act on
the running instance without touching the configuration. They live
under the `clear` tree (`clear ospf …` for OSPFv2, `clear ospfv3 …`
for OSPFv3) and take effect immediately — there is no `commit`.

## Resetting adjacencies — `clear ospf neighbor`

```
clear ospf   neighbor [<router-id>]
clear ospfv3 neighbor [<router-id>]
```

Tear an OSPF adjacency down so it re-forms from scratch. This is the
operator-driven equivalent of a dead-timer expiry: the neighbor
instance is **destroyed**, not merely nudged. Because a live peer keeps
sending Hellos, the adjacency is re-learned on the next Hello and walks
the full state machine back up — `Down → Init → ExStart → Exchange →
Loading → Full` — performing a fresh Database-Description exchange.
Use it to force a clean re-synchronisation after a suspected
database or SPF anomaly without restarting the daemon.

The argument is the neighbor's **Router-ID** — the value shown in the
`Neighbor ID` column of `show ospf neighbor` — *not* the neighbor's
interface address:

```
zebra# show ospf neighbor
Neighbor ID     Pri State      Up Time   Dead Time Address       Interface ...
10.0.0.2         64 Full/  -   2m13s     38s       10.0.12.2     eth1 ...

zebra# clear ospf neighbor 10.0.0.2
```

With **no Router-ID**, the bare form clears *every* adjacency on the
instance:

```
clear ospf neighbor          # reset all OSPFv2 adjacencies
```

The OSPFv3 commands behave identically; for OSPFv3 the Router-ID is the
neighbor identity shown by `show ipv6 ospf neighbor` (RFC 5340 §10
keys neighbors by Router-ID rather than by interface address).

What a clear triggers, as a side effect of the adjacency dropping and
re-forming:

- the local Router-LSA (and, on a DR, the Network-LSA) is re-originated
  without then with the adjacency,
- SPF re-runs, so routes learned through the neighbor are withdrawn and
  re-installed as it bounces,
- the DR/BDR election re-runs on multi-access links,
- any BFD session bound to the neighbor is released and re-subscribed.

Tab-completion offers the live neighbor Router-IDs:

```
zebra# clear ospf neighbor <TAB>
10.0.0.2
```

> **Note** — clearing a neighbor is briefly traffic-affecting: routes
> reachable only through that adjacency are withdrawn until it returns
> to `Full`. The neighbor's up-time resets, which is the simplest way
> to confirm the reset actually happened.

## Forcing an SPF run — `clear ospf spf`

```
clear ospf   spf
clear ospfv3 spf
```

Force an immediate shortest-path-first recomputation for every attached
area instead of waiting for the next LSDB event or the SPF coalescing
timer. This recomputes routes from the **current** database; it does
not re-exchange anything with neighbours. It is useful when manual
diagnosis suspects a stale route after an LSDB-side change.

## Graceful restart — `clear ospf graceful-restart`

```
clear ospf graceful-restart begin
clear ospf graceful-restart commit
clear ospf graceful-restart abort
```

Stage, commit, or unstage a planned RFC 3623 graceful restart of the
local router. `begin` floods Grace-LSAs and marks the instance
restart-capable; `commit` writes the restart checkpoint, drains, and
exits the process for a supervisor to restart it (kernel routes
survive); `abort` walks the staging back without exiting. These are
covered in the graceful-restart material; they are listed here only
because they share the `clear ospf` tree.
