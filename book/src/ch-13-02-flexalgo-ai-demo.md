# AI-Designed Flex-Algorithm

Everything in the two previous sections comes together in one
demonstration: an AI assistant designs, deploys, and verifies an IS-IS
Flexible Algorithm (RFC 9350) on a running eleven-router network — from a
single sentence of operator intent.

The division of labor is the interesting part:

* the **operator** states intent: *"constrained traffic must never cross
  a trans-Pacific link"*;
* the **ontology** supplies meaning: which router is in which region —
  knowledge the routing protocols do not carry;
* the **IGP** supplies topology: the live link-state graph;
* the **assistant** turns the three into committed device configuration,
  through the same MCP tools an operator's scripts would use.

No part of the answer is scripted. The assistant has to derive which
links cross the Pacific by joining the ontology's regions against the
IS-IS graph, read each router's running configuration to find interface
names and an unused SID index block, author the four configuration parts
(affinity-map, link coloring, the algorithm definition, per-loopback
algorithm SIDs), commit them router by router, and prove the result.

## The lab

[`playset/isis-flexalgo-ai`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo-ai)
is an eleven-node global backbone (US, EU, and AP regions) running plain
IS-IS with SR-MPLS — deliberately stripped of every trace of
Flex-Algorithm configuration. Its sibling
[`playset/isis-flexalgo`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo)
is the same network with the Flex-Algorithm hand-written: the answer key
the AI's work can be compared against.

`ontology.json` describes each router — short name, full name, region —
and doubles as the fleet roster:

``` json
{ "name": "tk", "full-name": "Tokyo", "region": "AP" }
```

## The wiring

One connector entry gives the assistant the whole lab. The playset's
`mcp.sh` starts `vtyctl mcp --fleet ontology.json` (self-elevating via
`sudo -n`), and Claude Desktop points at it:

``` json
{
  "mcpServers": {
    "zebra-fleet": {
      "command": "/path/to/zebra-rs/playset/isis-flexalgo-ai/mcp.sh"
    }
  }
}
```

Every tool takes a `router` argument; `apply-config` commits each
router's changes as one atomic transaction, and a rejected line costs
nothing — the daemon reports it, and the assistant corrects itself.

## The arc

With the lab up (`./up.sh`) and the connector configured, the operator
pastes a goal-level prompt — the full recommended text lives in the
[playset README](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo-ai#the-prompt)
— and watches the tool-call stream:

1. `get-ontology` → three regions.
2. `get-isis-graph` → seventeen links, of which exactly three join a US
   router to an AP router: `se–sg`, `sj–tk`, `sj–sy`.
3. `get-config` per router → interface names, and algorithm-0 SID
   indexes 100..1100, so the new per-algorithm SIDs need a disjoint
   block.
4. `apply-config` × 11 → affinity-map, both ends of the three links
   colored `trans-pacific`, `flex-algo 128` with
   `exclude-any: trans-pacific` (advertised by at least two routers),
   and a second loopback prefix-SID per router.
5. `get-isis-flex-algo`, `get-isis-spf algorithm=128` → all eleven
   routers participate, and Tokyo reaches Seattle via Singapore,
   Frankfurt, and Chicago — never touching the Pacific.

The network converges within seconds of the last commit. On the
[3D topology viewer](ch-13-01-topology-viewer.md), the Algorithm
selector — which offered only `0 — SPF` against the baseline — now
lists `128 — exclude-any: trans-pacific`, and selecting it swings the
Tokyo-to-Seattle path the long way around the globe.

## Why this works

Three properties of the MCP surface carry the demo:

* **Round-trip syntax.** `get-config` format `formal` returns the
  configuration as `set ...` lines — exactly what `apply-config`
  consumes. The assistant learns the configuration grammar from the
  device itself and writes changes in the same dialect.
* **Atomic, self-describing failure.** The Apply transaction either
  commits everything or nothing, and the error names the offending
  line. Trial and error is safe, so the assistant can be wrong once
  and right the second time without ever leaving the network in a
  half-configured state.
* **Semantics live beside the network.** The ontology is data the IGP
  cannot know. Serving it through the same MCP server the routers live
  behind is what lets a single prompt say "trans-Pacific" and mean
  three specific links.

The encore writes itself: ask the assistant to remove everything it
added — configuration delete through the same tools — or to add a
second algorithm with the opposite constraint. And `./down.sh && ./up.sh`
always rebuilds the pristine baseline, because the committed changes
live only in the running daemons, not in the yaml files they boot from.
