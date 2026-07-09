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

## Configuration

The integration lives under the `system cradle` container. It is off by
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

> **`enabled` is the only switch.** `grpc-endpoint` alone is inert: it just
> re-points an already-enabled tee. To turn the integration on you must set
> `system cradle enabled true`.

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
