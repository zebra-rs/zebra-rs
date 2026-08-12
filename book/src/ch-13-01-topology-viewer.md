# 3D Traffic Path Visualizer

The routers' own view of the network, on a globe. `zebra-topology` renders
live connectivity and per-algorithm SPF paths from a running zebra-rs lab —
and every byte of routing state it draws arrives through the
[MCP server](ch-13-00-mcp-server.md), not through CLI scraping. The same
tools an AI assistant calls in conversation turn out to be a perfectly good
API for an ordinary web application: MCP is the router's API surface, and
this viewer is the proof.

The viewer ships in the repository under `ai/topology` and is built for the
`playset/isis-flexalgo` lab: eleven routers named after cities across the
US, Europe and Asia-Pacific, running plain IS-IS (algorithm 0) and a
Flexible Algorithm 128 defined as `exclude-any: trans-pacific` over the
same links. Pick Tokyo as the source and flip the algorithm selector:
algorithm 0 crosses the Pacific in one hop, algorithm 128 sends the same
traffic the long way round — Singapore, Frankfurt, and onward — exactly as
RFC 9350 promises. There is no TE telemetry in the lab, so the globe shows
what the routers actually know: connectivity, IGP metrics, and paths.

## How it is put together

```
browser ── HTTP ── zebra-topology ── stdio/JSON-RPC ── ip netns exec <rtr> vtyctl mcp ── gRPC ── zebra-rs
```

- The backend is a single Rust binary serving an embedded
  [globe.gl](https://globe.gl) frontend and three JSON APIs
  (`/api/routers`, `/api/algorithms`, `/api/topology`).
- Every router query is a stateless MCP 2026-07-28 `tools/call` against
  `vtyctl mcp`, spawned inside that router's network namespace. The
  daemon's VTY endpoint (`unix:zebra-rs/vty`) is a Linux *abstract* Unix
  socket, and abstract sockets are network-namespaced — which is why each
  of the eleven daemons can bind the same name, and why the MCP server
  must run inside the namespace to reach one.
- Three tools carry everything: `get-isis-flex-algo` fills the Algorithm
  dropdown, `get-isis-graph` draws the connectivity arcs, and
  `get-isis-spf` draws the paths.
- Router geography comes from the playset's `ontology.json` (name, city,
  region per router) joined with a small built-in city gazetteer for
  coordinates.

## Run it

```shell
# 1. Bring up the eleven-node lab (root required)
cd playset/isis-flexalgo && ./up.sh && cd -

# 2. Build the daemon tooling and the viewer
cargo build -p zebra-rs -p vtyctl -p zebra-topology

# 3. Run the viewer from the repository root (root required for
#    `ip netns exec`; a non-root run falls back to `sudo -n`)
sudo ./target/debug/zebra-topology

# 4. Browse
open http://localhost:8080
```

The globe itself needs internet access in the browser — three.js, globe.gl
and the earth textures load from unpkg.com, integrity-pinned.

## Reading the globe

- **Points** are routers, colored by region (US, EU, AP) and grey when a
  router is absent from the IS-IS topology.
- **Grey arcs** are the connectivity mesh of the *selected algorithm's own
  graph*. Switch to algorithm 128 and the three trans-Pacific links do not
  dim — they vanish, because the FAD pruned them before SPF ran.
- **Colored, animated arcs** are the SPF paths from the selected source —
  one color per path, ECMP included, with a legend chip per path to toggle
  it. Selecting a single destination narrows the view; "All destinations"
  shows the source's entire SPF fan-out.
- **Click a path arc** (or its legend chip) for the hop-by-hop table: each
  hop's router, region, link metric, and the cumulative cost, plus the
  egress interface.

## Things to try

- Source `tk`, destination `se`, algorithm 0 → 128: cost 20 across the
  Pacific becomes cost 50 through `sg → fr → {ln,va} → ch`, and the edge
  count visibly drops as the pruned links disappear.
- Partition an algorithm without touching the other:
  `sudo ip netns exec fr ip link set fr-sg down`, then Refresh. Algorithm
  128 loses everything outside Asia-Pacific — Tokyo can still reach only
  Singapore and Sydney — while algorithm 0 keeps spanning the world.
  `... set fr-sg up` and Refresh heals it.
- Change the source router: SPF is computed from the source's LSDB, so
  Seattle's algorithm-128 view heads *east* through Chicago, the mirror
  image of Tokyo's.

`ai/topology/README.md` documents the command-line flags and the HTTP API;
the [playset README](https://github.com/zebra-rs/zebra-rs/tree/main/playset/isis-flexalgo)
tells the full Flex-Algorithm story the viewer animates.
