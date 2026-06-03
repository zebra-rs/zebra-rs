# Clearing IS-IS State

IS-IS exposes a small set of operational `clear` commands that act on
the running instance without touching the configuration. They live
under the `clear isis …` tree and take effect immediately — there is
no `commit`.

## Resetting adjacencies — `clear isis neighbor`

```
clear isis neighbor [<system-id>]
```

Tear an IS-IS adjacency down so it re-forms from scratch. This is the
operator-driven equivalent of a hold-timer expiry: the neighbor
instance is **destroyed**, not merely nudged. Because a live peer keeps
sending Hellos, the adjacency is re-learned on the next IIH and walks
the state machine back up — `Down → Init → Up` — re-running the
three-way handshake on point-to-point links (and DIS election on a
LAN).

The argument is the neighbor's **System ID** — the value shown in the
`System Id` column of `show isis neighbor`, formatted `xxxx.xxxx.xxxx`:

```
zebra# show isis neighbor
System Id           Interface   L  State         Holdtime SNPA
0000.0000.0002      eth1        2  Up            27       2020.2020.2020

zebra# clear isis neighbor 0000.0000.0002
```

With **no System ID**, the bare form clears *every* adjacency on the
instance, across both levels:

```
clear isis neighbor          # reset all IS-IS adjacencies
```

A given System ID is matched on every interface and at both Level-1 and
Level-2, so a neighbor reachable over parallel links or at both levels
is reset everywhere it appears.

What a clear triggers, as a side effect of the adjacency dropping and
re-forming:

- the local LSP is re-originated without then with the adjacency, and
  the neighbour's TLV is withdrawn from the LSDB,
- SPF re-runs, so routes learned through the neighbor are withdrawn and
  re-installed as it bounces,
- the DIS election re-runs on broadcast (LAN) circuits,
- any Adjacency-SID / SRv6 End.X SID allocated for the neighbor is
  released, and
- any BFD session bound to the neighbor is released and re-subscribed.

Tab-completion offers the live neighbor System IDs:

```
zebra# clear isis neighbor <TAB>
0000.0000.0002
```

> **Note** — clearing a neighbor is briefly traffic-affecting: routes
> reachable only through that adjacency are withdrawn until it returns
> to `Up`. The neighbor's hold-time/up-time resets, which is the
> simplest way to confirm the reset actually happened.

## Forcing an SPF run — `clear isis spf`

```
clear isis spf [level-1 | level-2]
```

Force an immediate shortest-path-first recomputation instead of waiting
for the next LSDB update or the SPF debounce timer. This recomputes
routes from the **current** database; it does not re-exchange anything
with neighbours. It is useful when manual diagnosis suspects a stale
route after an LSDB-side change.

IS-IS keeps a separate SPF tree per level — Level-1 for intra-area
paths and Level-2 for the inter-area backbone — so the command can
target one level or both:

```
clear isis spf            # recompute both Level-1 and Level-2
clear isis spf level-1    # recompute only the Level-1 SPF
clear isis spf level-2    # recompute only the Level-2 SPF
```

The bare form (no level) recomputes both levels. On an L1-only or
L2-only router the level it does not run is simply a no-op, so the bare
form is always safe. Tab-completion offers the two levels alongside the
bare `<cr>`:

```
zebra# clear isis spf <TAB>
level-1  level-2
```

## Graceful restart — `clear isis graceful-restart`

```
clear isis graceful-restart begin
clear isis graceful-restart commit
clear isis graceful-restart abort
```

Stage, commit, or unstage a planned RFC 5306 graceful restart of the
local router. `begin` floods IIHs with the Restart TLV (RR set) and
freezes self-LSP refresh; `commit` writes the restart checkpoint,
drains, and exits the process for a supervisor to restart it (kernel
routes tagged with the IS-IS RIB type survive); `abort` walks the
staging back without exiting. These are covered in the graceful-restart
material; they are listed here only because they share the `clear isis`
tree.
