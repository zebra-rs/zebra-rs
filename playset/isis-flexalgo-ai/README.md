# IS-IS FlexAlgo — AI & Ontology demo

This playset is the *starting point* of a demonstration in which an AI
assistant designs and deploys an IS-IS Flexible Algorithm (RFC 9350) on a
running network, using nothing but the network's own management plane (MCP
over gRPC) and the semantic description of the network in `ontology.json`.

It is the same eleven-node global backbone as
[`playset/isis-flexalgo`](../isis-flexalgo/README.md) — same namespaces,
links, addresses and algorithm-0 Prefix-SIDs — but with **every trace of
Flex-Algorithm configuration removed**. Plain IS-IS with SR-MPLS comes up;
what the constrained topology should look like exists only as intent. The
hand-written playset next door is the answer key.

## The demo in two stages

1. **Configuration without FlexAlgo.** `./up.sh` brings up the baseline
   below. There is no affinity map, no link coloring, no Flex-Algorithm
   Definition and no per-algorithm SIDs anywhere in the domain.

2. **AI-generated FlexAlgo.** From Claude Desktop, connected to the lab
   through MCP, a goal-level prompt — *"traffic in a constrained class must
   never cross a trans-Pacific link"* — is all the operator supplies. The
   assistant extracts the running configuration, reads the ontology to learn
   which router sits in which region, identifies the trans-Pacific links
   from the IS-IS topology, then generates, applies and commits the full
   Flex-Algorithm configuration on every router — and verifies its own work
   through the same MCP tools.

The point of the exercise: the operator states *intent*, the ontology
supplies *meaning* (regions), the IGP supplies *topology*, and the AI turns
the three into committed device configuration.

## Topology and ontology

Eleven nodes in three regions. The region of each node comes from
`ontology.json` — this file is the only place the demo says anything about
geography, and it is the input the AI derives the design from:

```
        AP                      US                        EU
  ┌──────────────┐      ┌──────────────────┐      ┌─────────────────┐
  │ tk  Tokyo    │      │ se  Seattle      │      │ ln  London      │
  │ sy  Sydney   │      │ sj  San Jose     │      │ fr  Frankfurt   │
  │ sg  Singapore│      │ ch  Chicago      │      └─────────────────┘
  └──────────────┘      │ da  Dallas       │
                        │ va  Virginia     │
                        │ at  Atlanta      │
                        └──────────────────┘
```

Six links cross a region boundary; three of them cross the Pacific:

```
  sj ── tk    US <-> AP    trans-Pacific
  se ── sg    US <-> AP    trans-Pacific
  sj ── sy    US <-> AP    trans-Pacific
  ch ── ln    US <-> EU
  va ── fr    US <-> EU
  fr ── sg    EU <-> AP
```

Nothing in the router configuration marks these links. Deciding that the
constraint "no trans-Pacific" maps to exactly those three links — because
their endpoints are in `US` and `AP` respectively — is the AI's job.

Every link has metric 10, and the loopback / addressing plan is identical
to the appendices of the
[isis-flexalgo README](../isis-flexalgo/README.md#appendix-loopbacks-and-prefix-sids).

## What is configured — and what is not

Each `<node>.yaml` carries only the algorithm-0 baseline:

* interfaces and addresses, `system hostname`
* `router isis`: NET, level-2-only, `segment-routing mpls`, `te-router-id`
* per-interface IS-IS: point-to-point, metric 10
* one algorithm-0 `prefix-sid` per loopback (indexes 100..1100, SRGB 16000)

Compared with `playset/isis-flexalgo`, the following are **absent** — this
is precisely the set the AI has to author:

* the global `affinity-map` (name-to-bit table, RFC 7308)
* the per-interface `affinity` coloring on the trans-Pacific links
* the `flex-algo` definition (FAD) with `exclude-any`, including
  `advertise-definition` on at least one router
* the per-loopback `flex-algo-prefix-sid` (a second, non-overlapping SID
  index block — the hand-written playset uses algo-0 index + 2000)

## Stage 1: bring up the baseline

``` shell
$ ./up.sh
```

This creates one network namespace per node and starts zebra-rs in each on
its own `<node>.yaml`. Runtime state lives in
`/tmp/zebra-rs-playset/isis-flexalgo-ai/`.

> The namespaces share their names (`se` … `tk`) with `playset/isis-flexalgo`,
> so only one of the two playsets can be up at a time.

Verify that routing works and that no Flex-Algorithm exists anywhere:

``` shell
$ sudo ip netns exec tk vty
tk>show ip route
L2 *> 10.0.0.1/32 [115/30] via 192.168.6.1, tk-sj, label 16100, weight 1, ...
                           via 192.168.15.1, tk-sg, label 16100, weight 1, ...
L2 *> 10.0.0.2/32 [115/20] via 192.168.6.1, tk-sj, label (16200), ...
...
```

Ordinary SR-MPLS, and Tokyo reaches the US straight across the Pacific
(San Jose is one hop on `tk-sj`). The Flex-Algorithm view is empty:

``` shell
tk>show isis flex-algo
Area 49.0000:

Local Flex-Algorithms: (none configured)

Level-2:
  Peer SR-Algorithm Participation:
    se (0000.0000.0001): [0]
    sj (0000.0000.0002): [0]
    ...
    sy (0000.0000.0010): [0]
```

and the wire agrees — all eleven routers advertise participation in
algorithm 0 only:

``` shell
tk>show isis database detail | grep "Segment Routing Algorithm"
   Segment Routing Algorithm: SPF(0)
   ...
```

The [3D topology viewer](../../ai/topology/README.md) makes the same point
visually: started against this playset, its Algorithm selector offers only
`0 — SPF`.

## Stage 2: let the AI build the FlexAlgo

The assistant works through the zebra-rs MCP server. `./mcp.sh` starts it
in **fleet mode** (`vtyctl mcp --fleet ontology.json`): one stdio server
fronting all eleven routers, where every tool takes a `router` argument
and the call is forwarded into that router's network namespace. The
assistant can read the ontology (`get-ontology`), extract any router's
running configuration (`get-config`, whose default `formal` format is the
same `set`-line syntax configuration is applied with), inspect the IS-IS
graph and SPF (`get-isis-graph`, `get-isis-spf`), and apply and commit
configuration (`apply-config` — atomic per router: on any error nothing
is applied and the offending line is returned).

Connect Claude Desktop by adding to `claude_desktop_config.json`:

``` json
{
  "mcpServers": {
    "zebra-fleet": {
      "command": "/path/to/zebra-rs/playset/isis-flexalgo-ai/mcp.sh"
    }
  }
}
```

(or `"command": "ssh", "args": ["-T", "user@lab-host", ".../mcp.sh"]`
when Claude Desktop runs on another machine). The server needs root to
enter the namespaces and to commit configuration, so grant passwordless
sudo for the vtyctl binary — the header of `mcp.sh` has the exact
sudoers line.

The end state to expect is the hand-written playset next door. When the AI
has done its job:

``` shell
tk>show isis flex-algo
Local Flex-Algorithms:
  Algo  Metric                 Priority Adv FRR       Constraints
  128   igp                    -        no  off       exclude-any=trans-pacific
...

tk>show isis flex-algo 128 route
```

must show **every** US destination leaving Tokyo via `tk-sg` (Singapore)
— the long way round through Asia and Europe — while `show ip route`
keeps using the direct Pacific crossing. The
[isis-flexalgo README](../isis-flexalgo/README.md) walks through all of
the verification detail, down to pushing the algorithm-128 label and
proving the path with TTLs.

``` shell
$ ./down.sh
```

tears the lab back down.
