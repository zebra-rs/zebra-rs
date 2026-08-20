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

### The wiring

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

When Claude Desktop runs **on the lab host itself**, connect it by
adding to `claude_desktop_config.json`:

``` json
{
  "mcpServers": {
    "zebra-fleet": {
      "command": "/path/to/zebra-rs/playset/isis-flexalgo-ai/mcp.sh"
    }
  }
}
```

When it runs **on another machine** — the typical case: Claude Desktop
on a Mac, the lab in a Linux VM or server — bridge the connector over
ssh, which carries the MCP stdio stream unchanged:

``` json
{
  "mcpServers": {
    "zebra-fleet": {
      "command": "ssh",
      "args": [
        "-T",
        "-o", "BatchMode=yes",
        "user@lab-host",
        "/path/to/zebra-rs/playset/isis-flexalgo-ai/mcp.sh"
      ]
    }
  }
}
```

On macOS the config file is
`~/Library/Application Support/Claude/claude_desktop_config.json`;
restart Claude Desktop after editing it, and the `zebra-fleet` server
with its tools appears under the connectors. `-T` keeps the channel a
plain pipe rather than a terminal, and `BatchMode=yes` makes ssh fail
fast instead of hanging on a password prompt — so authentication must
be by key (the usual `ssh-copy-id` setup).

Two requirements on the lab host either way: the server needs root to
enter the namespaces and to commit configuration, so grant passwordless
sudo for the vtyctl binary (the header of `mcp.sh` has the exact
sudoers line), and for the ssh variant its sshd must be reachable from
the Desktop machine. The connector starts even while the lab is down —
tool calls simply return errors until `./up.sh` has run.

### The prompt

The point of the demo is that the operator supplies *intent*, not
configuration — but a live demo also wants a predictable arc, so the
recommended prompt states the goal, names the mechanism, and leaves every
interesting decision (which links, which interfaces, which SID indexes,
what to put on each of the eleven routers) to the assistant:

> You are operating a network lab through the zebra-fleet MCP server: an
> eleven-router IS-IS + SR-MPLS backbone. `get-ontology` tells you each
> router's name, full name and region.
>
> New compliance requirement: a class of constrained traffic must never
> cross a trans-Pacific link — between the US and AP regions this
> traffic has to travel the other way around, via Europe.
>
> Implement this with an IS-IS Flexible Algorithm (algorithm 128, IGP
> metric, SR-MPLS data plane). The zebra-rs Flex-Algorithm configuration
> manual is at <https://zebra.rs/docs.html#ch-07-11-isis-flexalgo> —
> follow its syntax and consistency rules:
>
> 1. Work out from the ontology and the live IS-IS topology which links
>    cross the Pacific. Do not ask me — derive it.
> 2. Extract the running configuration of the routers and generate the
>    changes: a shared affinity-map, coloring on both ends of each
>    trans-Pacific link, the algorithm definition with its constraint
>    (advertised by at least two routers), and a second loopback
>    prefix-SID per router for algorithm 128 that does not collide with
>    the existing SID indexes.
> 3. Apply and commit the changes on every router with `apply-config`.
> 4. Verify your own work: all eleven routers must participate in
>    algorithm 128, and Tokyo must reach Seattle without touching a
>    trans-Pacific link. Show me Tokyo's algorithm-128 paths before you
>    declare success.

For a braver run, compress it to pure intent and watch the assistant
work out the rest itself:

> Constrained traffic may not cross trans-Pacific links. Design and
> deploy an IS-IS Flex-Algorithm on every router of this lab that
> enforces it, then prove it worked.

### What to watch

The tool-call stream in Claude Desktop *is* the demo. The expected arc:

1. `get-ontology` — the assistant learns `se..at` are US, `ln`/`fr` are
   EU, `sg`/`sy`/`tk` are AP.
2. `get-isis-graph` on some router — seventeen links; exactly three
   connect a US name to an AP name: `se–sg`, `sj–tk`, `sj–sy`.
3. `get-config` per router — current interface names and the algorithm-0
   SID indexes 100..1100 (so a disjoint block, e.g. +2000, is needed).
4. `apply-config` — eleven calls, one atomic commit per router:
   affinity-map, `affinity trans-pacific` on both ends of the three
   links, the `flex-algo 128` definition with `exclude-any`, and a
   `flex-algo-prefix-sid` per loopback. A wrong line costs nothing:
   the whole batch is discarded and the error names the offending
   line, so the assistant corrects itself and retries.
5. `get-isis-flex-algo` / `get-isis-spf algorithm=128` — self-check:
   participation `[0, 128]` on all eleven, and Tokyo's constrained
   paths run through Singapore and Frankfurt.

IS-IS floods and converges within a few seconds of the last commit.

### Check the result yourself

The end state to expect is the hand-written playset next door:

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
[3D topology viewer](../../ai/topology/README.md) shows the same moment
visually: refresh it and the Algorithm selector now offers
`128 — exclude-any: trans-pacific`; select it and the Tokyo-to-Seattle
path swings the long way around the globe. For the deepest proof — real
packets steered by the algorithm-128 label, verified hop by hop with
TTLs — follow the
[isis-flexalgo README](../isis-flexalgo/README.md), whose walkthrough
applies verbatim once the AI has built the same configuration.

### Encore, and resetting

Two follow-ups that make good encores, both pure prompt work:

* *"Now remove everything you added and prove the network is back to
  algorithm 0 only."* — configuration delete through the same
  `apply-config`, and the cleanest way to reset between runs.
* *"Add algorithm 129 that must **stay on** trans-Pacific links
  (include-any) with its own SID block."* — a second constraint class
  over the same links.

For a guaranteed clean slate, `./down.sh && ./up.sh` rebuilds the
baseline from the yaml files in a few seconds — nothing the assistant
commits survives a restart, because the daemons load their startup
configuration from `<node>.yaml`.

``` shell
$ ./down.sh
```

tears the lab back down.
