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

This is what *AI native* means for a routing stack: the network is no longer a
black box your tools poke at from the outside — it is a first-class participant
in the conversation.
