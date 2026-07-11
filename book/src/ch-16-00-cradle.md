# cradle eBPF Data Plane

[cradle](https://github.com/cradle-rs/cradle-rs) is a separate project: an
**eBPF/XDP data plane** (L2–L7) that programs its forwarding state from a
control plane over a gRPC API. zebra-rs is that control plane. When the cradle
integration is enabled, every route zebra-rs computes — static, BGP, OSPF,
IS-IS, plus the SR-MPLS / SRv6 / EVPN / MUP forwarding state — is **teed** to a
running cradle in addition to the kernel FIB, so the eBPF datapath forwards it.

The tee is bidirectional:

- **Forward** (zebra-rs → cradle): each RIB install is mirrored to cradle over
  its gRPC control API (`SetNexthop` / route / ILM / SID / GTP-PDR / … calls).
  The kernel install still happens as usual, so the two planes stay in sync.
- **Reverse** (cradle → zebra-rs): zebra-rs subscribes to cradle's datapath
  **MAC learning** (`WatchFdb`); each learned/aged MAC is fed back into the RIB
  and re-originated as an **EVPN Type-2** route,
  exactly as a kernel-bridge learn would be. The subscriber reconnects with
  backoff for the daemon's lifetime.

Some forwarding behaviours have **no mainline-kernel equivalent** and therefore
*require* cradle — notably real GTP-U for [MUP](ch-02-35-bgp-mup.md)
(`dataplane gtp`) and [EVPN VPWS](ch-02-38-bgp-evpn-vpws.md) egress.

The integration has two halves, on independent switches:

| Knob | Owns |
|---|---|
| `system ebpf enabled` | **The engine process**: zebra-rs spawns and supervises the cradle daemon itself. |
| `system cradle enabled` | **The FIB tee**: zebra-rs programs whatever cradle answers the endpoint. |

They compose: both on is the fully-managed data plane (the typical
deployment); `system cradle` alone is the classic *external* mode (you run
cradle yourself, e.g. the cradle-rs BDD harness); `system ebpf` alone runs
the engine with ports but tees no routes — a pure eBPF L2 switch.

## Managed engine (`system ebpf`)

```
system {
  ebpf {
    enabled true;
  }
  cradle {
    enabled true;
  }
}
interface enp0s6 {
  ebpf {
    enabled true;
  }
}
```

With `system ebpf enabled true`, zebra-rs launches
`cradle serve --grpc <endpoint>` as a **managed child process** and keeps it
healthy:

- **Binary resolution**: `$ZEBRA_CRADLE_BIN`, else `~/.zebra/bin/cradle`,
  else `/usr/bin/cradle` (where the `cradle-rs` Debian package installs it —
  the zebra-rs package *recommends* it).
- **Adopt-if-running**: if a cradle already answers the endpoint it is
  adopted — monitored, never killed — so externally-started engines keep
  working; if the adopted instance dies, the supervisor spawns its own.
- **Crash recovery**: a dead engine is respawned with exponential backoff
  (1 s → 30 s, reset after a healthy minute).
- **Lifetime binding**: the child runs with `kill_on_drop` and
  `PR_SET_PDEATHSIG=SIGTERM`, so no root engine process can outlive zebra-rs
  — even a SIGKILLed daemon takes its engine down.
- **Unified logs**: the engine's stdout/stderr are piped into zebra-rs
  tracing under the `cradle` target.
- Disabling (`delete system ebpf enabled true`) SIGTERMs the child (SIGKILL
  after 5 s) and detaches everything.

### Data-plane ports (`interface <name> ebpf`)

`interface <name> ebpf enabled true` makes that interface a cradle
data-plane port (the XDP + TC programs attach to it), replacing cradle's
`-c` JSON `ports` array for zebra-driven deployments. The port set is
**reconciled**: config before the link exists attaches the moment the device
appears; a deleted-and-recreated link re-attaches under its new ifindex;
disabling detaches (`DelPort`) and flushes the MACs learned on the port.
Current scope: routed ports in the default VRF; VRF/bridge (L2) binding is
follow-on work.

### Restart behaviour: state replay

A restarted engine starts with **empty maps**. Two mechanisms rebuild it
with no operator action, on the same engine-ready edge:

- the supervisor re-applies every configured **port**;
- the FIB tee **replays** its mirrored state — routes (v4/v6), ILM, SRv6
  SIDs, EVPN FDB/replication slots, VPWS cross-connects, GTP state, mirror
  routes, neighbors — re-creating the underlying nexthops from scratch (the
  tee's nexthop-id caches are reset, so post-restart route churn also
  resolves correctly).

The replay is driven by the supervisor's engine-up signal, so it covers
managed respawns and adopted-instance takeovers. An *external* cradle
restart has no such signal: external mode keeps today's behaviour (the tee's
transport reconnects lazily; state repopulates on route churn).

### `show ebpf`

```
zebra> show ebpf
eBPF data plane (cradle engine)
  System ebpf:     enabled
  FIB tee:         enabled (system cradle)
  Endpoint:        unix:cradle/grpc
  Engine:          managed (pid 168157), up 42s
  Engine restarts: 1
  Engine v4 FIB:   mode lpm, 3 routes
  Ports:           2 configured, 2 attached
    eth0             ifindex 3      attached
    veth9            ifindex 8      attached
```

Shows the supervisor state (managed / adopted / down / off, pid, uptime,
restart count), the port reconcile status per interface, and — when the
engine answers — its IPv4 FIB summary. A trailing `json` renders the
machine-readable form. For deeper datapath inspection use cradle's own CLI
(`cradle dump`, `cradle stats`) against the same endpoint.

## The FIB tee (`system cradle`)

The tee lives under the `system cradle` container. It is off by
default; a single boolean turns it on:

```
system {
  cradle {
    enabled true;
  }
}
```

or, in command form:

```
set system cradle enabled true
```

That is all a typical deployment needs — with no endpoint set, zebra-rs dials
cradle's own default control socket, the Linux abstract socket
`unix:cradle/grpc` (namespace-scoped, no filesystem path to coordinate). To
point the tee somewhere else, add the `grpc-endpoint` override:

```
set system cradle enabled true
set system cradle grpc-endpoint unix:/run/cradle.sock
```

| YANG leaf | Type | Default | Notes |
|---|---|---|---|
| `/system/cradle/enabled` | `boolean` | `false` | **The sole switch.** `true` enables the tee; `false` (or deleting it) disables it. |
| `/system/cradle/grpc-endpoint` | `string` | `unix:cradle/grpc` | Optional endpoint override. Takes effect **only while the tee is enabled** — setting it on its own does *not* turn the tee on. |

> **`enabled` is the tee's only switch.** `grpc-endpoint` alone is inert: it
> just re-points an already-enabled tee (and doubles as the `--grpc` argument
> for a `system ebpf`-managed engine). To tee routes you must set
> `system cradle enabled true`; to also run the engine, add
> `system ebpf enabled true`.

## Endpoint forms

`grpc-endpoint` accepts:

| Form | Meaning |
|---|---|
| `unix:NAME` | **Linux abstract socket** (no leading `/`), scoped to the network namespace. The default `unix:cradle/grpc` is this form. |
| `unix:/path/to.sock` | Filesystem unix-domain socket (leading `/`). |
| `http://host:port` | TCP. |
| `host:port` | A bare address is treated as TCP (`http://host:port`). |

The abstract-socket form is the default because it needs no shared filesystem
path and is unique per network namespace, which is how per-netns cradle
deployments (and the BDD topologies) keep instances isolated. tonic cannot dial
an abstract socket natively, so zebra-rs uses a custom connector for the
`unix:NAME` case; the other forms use tonic's built-in support.

## Runtime behaviour

All of `system cradle` is a **runtime toggle** — no restart is needed:

- `set system cradle enabled true` starts the forward tee and the reverse
  `WatchFdb` subscriber immediately.
- `set system cradle grpc-endpoint …` (while enabled) re-points both channels:
  the previous subscriber is torn down and a new client dials the new endpoint.
- `delete system cradle enabled` (or `set … false`) stops the tee and the
  subscriber. Kernel installs are unaffected either way.

## Environment fallback

For quick experiments and test harnesses, the forward tee can also be
bootstrapped from the **`CRADLE_GRPC`** environment variable at startup (same
endpoint forms as above). This is a fallback only: it does not start the
reverse EVPN MAC-learning subscriber, and any `system cradle` config change
takes over from it. Prefer the config leaves for anything other than a
throwaway run.

## Related

- [Mobile User Plane (MUP)](ch-02-35-bgp-mup.md) — `dataplane gtp` programs real
  GTP-U via cradle.
- [EVPN VPWS](ch-02-38-bgp-evpn-vpws.md) — E-Line egress runs on the cradle
  datapath.
- The cradle project itself: <https://github.com/cradle-rs/cradle-rs>.
