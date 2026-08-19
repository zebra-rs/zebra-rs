# zebra-topology — 3D Traffic Path Visualizer

A 3D globe visualizer for the [`playset/isis-flexalgo`](../../playset/isis-flexalgo)
lab: eleven zebra-rs routers across the US, Europe and Asia-Pacific running
IS-IS Flexible Algorithm (RFC 9350). Pick a source router, a destination and
an algorithm, and watch the SPF paths arc across the globe — algorithm 0
crosses the Pacific directly, algorithm 128 (`exclude-any: trans-pacific`)
sends the same traffic the long way round through Asia and Europe.

There is no TE telemetry (latency/jitter/loss) in this lab; the viewer shows
what the routers actually know: connectivity, IGP metrics, and per-algorithm
SPF paths.

## How it gets its data — MCP only

The backend never scrapes `vty`/`vtyctl` CLI output. Every query is a
[Model Context Protocol](https://modelcontextprotocol.io) `tools/call`
(2026-07-28 stateless revision) against `vtyctl mcp`, spawned inside the
router's network namespace — the daemon's VTY endpoint is a Linux abstract
Unix socket (`@zebra-rs/vty`), which is network-namespaced, so the MCP
server must run inside the namespace to reach it:

```
browser ── HTTP ── zebra-topology ── stdio/JSON-RPC ── ip netns exec <rtr> vtyctl mcp ── gRPC ── zebra-rs
```

Tools used (any MCP client, an AI assistant included, can call the same
ones):

| tool                 | arguments            | backs                       |
|----------------------|----------------------|-----------------------------|
| `get-isis-flex-algo` | —                    | the Algorithm dropdown      |
| `get-isis-graph`     | `level`, `algorithm` | connectivity arcs           |
| `get-isis-spf`       | `algorithm`          | the colored path arcs       |

Router locations come from the playset's
[`ontology.json`](../../playset/isis-flexalgo/ontology.json) (name, city,
region), joined with a built-in city → latitude/longitude gazetteer.

## Usage

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

The globe needs internet access in the browser (three.js, globe.gl and the
earth textures load from unpkg.com, integrity-pinned).

### Things to try

* Source `tk`, destination `se`: flip Algorithm between `0` and `128` and
  watch the two ECMP paths jump from the direct Pacific crossing to
  `tk → sg → fr → {ln,va} → ch → se`. The grey connectivity mesh changes
  too — algorithm 128's graph genuinely does not contain the three
  trans-Pacific links.
* `sudo ip netns exec fr ip link set fr-sg down`, then Refresh: algorithm
  128 partitions (Tokyo can only reach AP), while algorithm 0 still spans
  the world. `... set fr-sg up` and Refresh to heal it.
* Click a path arc (or its legend chip) for the hop-by-hop table with link
  and cumulative metrics.

### Globe designs

The Globe dropdown switches the earth's look between four designs:

| design          | texture             | character                                |
|-----------------|---------------------|------------------------------------------|
| **Day**         | `earth-day`         | flat relief daylight map (default)       |
| **Blue Marble** | `earth-blue-marble` | photographic satellite earth             |
| **Night lights**| `earth-night`       | city lights on a dark earth              |
| **Dark**        | `earth-dark`        | muted grey earth — the arcs pop the most |

All textures come from the same three-globe example set on unpkg.com the
default already loads from. The choice is mirrored into the `globe` URL
parameter (like source, destination and algorithm), so it survives a
reload and travels with a shared link.

### Flags

| flag         | default                                | meaning                        |
|--------------|----------------------------------------|--------------------------------|
| `--port`     | `8080`                                 | HTTP listen port               |
| `--ontology` | `playset/isis-flexalgo/ontology.json`  | router ontology                |
| `--vtyctl`   | auto (sibling → `target/debug` → PATH) | vtyctl binary for `vtyctl mcp` |
| `--mcp-host` | `unix:zebra-rs/vty`                    | daemon endpoint inside each ns |
| `--timeout`  | `15`                                   | per-MCP-call timeout (seconds) |

## HTTP API

* `GET /api/routers` — the ontology with coordinates.
* `GET /api/algorithms?source=<rtr>` — algorithm 0 plus every
  Flex-Algorithm the source runs, labeled with its constraints.
* `GET /api/topology?source=<rtr>&algorithm=<0|128-255>&destination=<rtr|__all__>`
  — nodes (with `active` = present in the IS-IS graph), undirected
  connectivity edges of *that algorithm's* graph, and the SPF paths as
  complete hop lists with cost and egress interface.

## Provenance

Ported from the Graphiant `graphiant-topology` viewer (Go + globe.gl,
driven by the Graphiant NaaS assurance API). This version swaps the data
plane for MCP against local zebra-rs routers and drops the TE-specific UI
(time slider, latency/jitter/loss columns) that has no data source here.
