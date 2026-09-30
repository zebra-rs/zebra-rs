# zebra-topology — 3D Traffic Path Visualizer

A 3D globe visualizer for the [`playset/isis-flexalgo`](../../playset/isis-flexalgo)
lab: eleven zebra-rs routers across the US, Europe and Asia-Pacific running
IS-IS Flexible Algorithm (RFC 9350). Pick a source router, a destination and
an algorithm, and watch the SPF paths arc across the globe — algorithm 0
crosses the Pacific directly, algorithm 128 (`exclude-any: trans-pacific`)
sends the same traffic the long way round through Asia and Europe.

The viewer shows what the routers actually know: connectivity, IGP metrics,
and per-algorithm SPF paths — and, where the links advertise them, their
TE performance metrics. Point it at
[`playset/isis-te-metric`](../../playset/isis-te-metric) — the same eleven
routers, with STAMP measuring each link's delay and loss and algorithm 128
routing on the lowest latency — and the path detail table gains per-hop
delay, jitter and loss columns and a cumulative path delay. In a lab without
TE metrics, such as `isis-flexalgo`, those columns simply do not appear.

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
| `get-isis-graph`     | `level`, `algorithm` | connectivity arcs; each directed link's cost and TE metrics |
| `get-isis-spf`       | `algorithm`          | the colored path arcs       |

`get-isis-graph` attaches to every link the TE metrics its *advertising*
router floods (RFC 8570): `te.delay`, `min_delay`, `max_delay` and
`delay_variation` in microseconds, `loss` in units of 0.000003 %, and
`delay_anomalous` / `loss_anomalous` for the Anomalous bit. They are
directional — a hop's values are what the router at its near end measured —
so the backend joins each SPF path with the graph's directed links rather
than its undirected connectivity edges.

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

For the TE view, bring up `playset/isis-te-metric` in step 1 instead. It
uses the same router names and cities, so the default `--ontology` works
for both labs (they share namespace names too, so run one at a time).

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

With `playset/isis-te-metric` up instead:

* Source `at`, destination `sg`, and click the path. Algorithm 0 goes
  `at → va → fr → sg` — three hops, **path delay 134.08 ms**. Switch to
  algorithm 128 (`metric: min delay`) and it goes
  `at → da → sj → tk → sg` — four hops, but 121.22 ms. The table shows
  each hop's measured Min and average delay, jitter and loss, and the
  delay accumulating along the path:

  ```
  Hop  Node             Link metric  Cumulative  Min delay  Avg delay  Jitter   Loss     Cum. delay
  0    at — Atlanta     —            0           —          —          —        —        0.00 ms
  1    da — Dallas      11025        11025       11.03 ms   11.47 ms   0.49 ms  0.000 %  11.03 ms
  2    sj — San Jose    20056        31081       20.06 ms   20.35 ms   0.29 ms  0.000 %  31.08 ms
  3    tk — Tokyo       55052        86133       55.05 ms   55.49 ms   0.43 ms  0.000 %  86.13 ms
  4    sg — Singapore   35092        121225      35.09 ms   35.69 ms   0.70 ms  0.000 %  121.22 ms
  ```

  In algorithm 128 the link metric *is* the Min delay in microseconds —
  that is what the algorithm sums.
* Slow a link down —
  `sudo ip netns exec sj tc qdisc change dev sj-tk root netem delay 120ms`
  and the same on `tk-sj` — wait a few seconds for the measurement to
  flood, and Refresh: algorithm 128 re-routes around it while algorithm 0
  does not move.
* Set an anomaly threshold on a link
  (`set router isis interface sj-tk te-metric measurement anomaly-threshold 1000`
  on `sj`) and Refresh: the hop's delays turn red with a ⚠ — the link
  raised the RFC 8570 Anomalous bit.

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
| `--port`     | `8080`                                 | HTTP listen port (serve mode)  |
| `--ontology` | `playset/isis-flexalgo/ontology.json`  | router ontology                |
| `--vtyctl`   | auto (sibling → `target/debug` → PATH) | vtyctl binary for `vtyctl mcp` |
| `--mcp-host` | `unix:zebra-rs/vty`                    | daemon endpoint inside each ns |
| `--timeout`  | `15`                                   | per-MCP-call timeout (seconds) |

## Static snapshot (GitHub Pages)

The viewer also runs without any backend: `snapshot` pre-fetches every
API response from the live lab and writes a self-contained static site.

```shell
# With the lab up (root required, same as serve mode)
sudo ./target/debug/zebra-topology snapshot --out dist/topology
```

The export contains the frontend plus one JSON file per API response —
`data/routers.json`, `data/algorithms-<src>.json` per router, and one
all-destinations `data/topology-<src>-<algo>.json` per (source,
algorithm). The destination filter is applied client-side (in live mode
too), so those files cover every dropdown combination; only the Refresh
button and live experiments (like downing a link) need the real
backend. `data/manifest.js` sets `window.ZEBRA_SNAPSHOT`, which is how
the frontend knows to read `data/` files instead of `/api/…`, hide
Refresh, and show the snapshot timestamp in the status bar.

The export is convergence-guarded: it retries (up to
`--settle-timeout`, default 120 s) until every router is active in
every algorithm's graph and every source has a path to every other
router, and refuses to write a partial topology.

`--algorithms` restricts the export (comma-separated): `--algorithms 0`
exports the plain-SPF view only — the Algorithm dropdown and the data
files both omit everything else. That is how zebra.rs serves both
`topology/` (full Flex-Algo snapshot) and `topology0/` (algorithm 0
only, the pre-Flex-Algo view) from the same lab.

Deploy by copying the output directory to any static host. For
https://zebra.rs it goes into the `zebra-rs/zebra-rs.github.io` repo as
`topology/`, serving at https://zebra.rs/topology/. Everything is
relative-path, so any subdirectory works.

## HTTP API

* `GET /api/routers` — the ontology with coordinates.
* `GET /api/algorithms?source=<rtr>` — algorithm 0 plus every
  Flex-Algorithm the source runs, labeled with its metric type (when not
  the IGP metric) and its constraints.
* `GET /api/topology?source=<rtr>&algorithm=<0|128-255>&destination=<rtr|__all__>`
  — nodes (with `active` = present in the IS-IS graph), undirected
  connectivity edges of *that algorithm's* graph, and the SPF paths as
  complete hop lists with cost and egress interface. Each path also
  carries `segments`, one per hop — `from`, `to`, the directed link's
  `cost`, and its `te` metrics when the link advertises them.

## Provenance

Ported from the Graphiant `graphiant-topology` viewer (Go + globe.gl,
driven by the Graphiant NaaS assurance API). This version swaps the data
plane for MCP against local zebra-rs routers. The latency/jitter/loss
columns come back when the links advertise RFC 8570 TE metrics; the time
slider stays dropped, since the routers hold only the current measurement.
