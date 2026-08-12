# Native MCP Server

Model Context Protocol is built in. Ask Claude or any MCP-aware agent to inspect
routes, diagnose adjacencies, or draft policy.

zebra-rs is the first routing daemon to ship with a native [Model Context
Protocol](https://modelcontextprotocol.io/) (MCP) server. MCP is the open
standard that lets AI assistants work directly with the systems they operate —
reading live state and taking action through well-defined tools. With zebra-rs,
that capability is part of the daemon itself, not a plugin or an external bridge
you have to assemble.

## Operate your network in plain language

Point Claude — or any MCP-aware agent — at zebra-rs and describe what you want:

- **Inspect routes.** "Why isn't 10.0.0.0/8 in the table?" The agent walks the
  RIB and BGP paths and explains what it finds.
- **Diagnose adjacencies.** "Which IS-IS neighbors are down, and since when?"
  The agent reads the topology and adjacency state and pinpoints the break.
- **Draft policy.** "Write a route-map that prefers the SRv6 path and tags it
  with community 65000:100." The agent drafts the configuration for you to
  review and apply.

The agent sees exactly what an operator sees at the CLI — one source of truth,
no diverging copy of the network.

## Built in, ready to connect

Because the server is part of zebra-rs, there is nothing extra to deploy. Add it
to any MCP client and your assistant can reach the router straight away:

```json
{
  "mcpServers": {
    "zebra-rs": {
      "command": "vtyctl",
      "args": ["mcp"]
    }
  }
}
```

## The tools

The server is read-only by contract: every tool answers from the daemon's
live state, and none of them mutate it. Two tools cover the whole `show`
surface, and a small typed family serves the data that topology-aware
agents ask for most:

| tool | arguments | returns |
|:-----|:----------|:--------|
| `list-show-commands` | — | every runnable `show` command with one-line help, generated live from the daemon's command grammar. Call it first to discover what `show` can do. |
| `show` | `command`, `json` | the output of any operational `show` command — value arguments included (`show isis flex-algo 128 spf`, `show bgp summary`). `json: true` returns structured output where the command supports it. |
| `get-isis-graph` | `level`, `algorithm` | the IS-IS topology graph: nodes with hostnames and system-ids, links with costs. With `algorithm` (128–255) it is that Flex-Algorithm's constraint-pruned graph. |
| `get-isis-spf` | `algorithm` | the IS-IS SPF result: per-destination cost, nexthops, and the full hop-by-hop paths from this router — plain SPF, or a Flex-Algorithm's constrained SPF. |
| `get-isis-flex-algo` | — | Flexible Algorithm (RFC 9350) state: local FADs with their constraints, peer FAD advertisements, and per-level algorithm participation. |
| `get-ospf-graph` | `version` | the OSPF area graph with router names and link costs. `version` selects OSPFv2 (2, the default) or OSPFv3 (3). |
| `get-ospf-spf` | `version` | the OSPF SPF tree: per-vertex cost and first hops. OSPF's SPF does not retain hop-by-hop vertex chains, so join vertex ids against `get-ospf-graph` for names and links. |
| `get-ospf-flex-algo` | `version` | OSPF Flexible Algorithm state: each configured algorithm's definition and constraints, its per-algorithm SPF status, and per-algorithm routes. |

The typed `get-*` tools return validated JSON, so an agent — or an ordinary
program using MCP as its API — can consume them without scraping CLI text.
The [3D Traffic Path Visualizer](ch-13-01-topology-viewer.md) is exactly
that: a web application whose only data plane is these tools.

## Current protocol, older clients welcome

The server speaks the stateless [MCP 2026-07-28
revision](https://modelcontextprotocol.io/specification/2026-07-28) and stays
compatible with earlier handshake-based clients, following the spec's dual-era
rules:

- **Modern clients** declare their protocol version on every request (and may
  probe with `server/discover` first); requests are served statelessly, and
  `tools/list` results carry cache hints so the client need not refetch them.
- **Legacy clients** negotiate `2025-06-18` or `2024-11-05` through the classic
  `initialize` handshake, unchanged.

Either way the transport is stdio: the server runs as a local subprocess of
your MCP client, so the daemon sees your own OS identity — no tokens, no
network listener.

This is what *AI native* means for a routing stack: the network is no longer a
black box your tools poke at from the outside — it is a first-class participant
in the conversation.
