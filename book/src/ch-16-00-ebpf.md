# eBPF Data Plane

zebra-rs can forward traffic in an in-kernel **eBPF/XDP data plane**: an
engine that attaches XDP + TC programs to selected interfaces and forwards
from eBPF maps that zebra-rs programs directly from its routing state. Every
route zebra-rs computes — static, BGP, OSPF, IS-IS, plus the SR-MPLS / SRv6 /
EVPN / MUP forwarding state — is installed into the eBPF FIB in addition to
the kernel FIB, and the data plane's MAC learning feeds back into EVPN
Type-2 origination. The tee is **dual-stack end to end**: VXLAN services run
over native IPv6 VTEPs, an IPv6-only core resolves MPLS service labels
through the v6 FIB (static v6 label routes included), and GTP-U tunnels take
IPv4 or IPv6 outers.

Some forwarding behaviours have **no mainline-kernel equivalent** and are
only available on the eBPF data plane:

- real **GTP-U** for [MUP](ch-02-35-bgp-mup.md) (`dataplane gtp`) — the
  kernel has no GTP action; encap and decap both run here, over v4 or v6
  outers;
- **EVPN over MPLS** ([E-LAN](ch-02-40-bgp-evpn-mpls.md) and
  [E-Line](ch-02-38-bgp-evpn-vpws.md)) — the kernel has no action that pops
  an MPLS label and hands the exposed frame to a bridge or a port, so these
  services are cradle-only end to end;
- **EVPN over SRv6** ([E-LAN](ch-02-41-bgp-evpn-srv6.md) and E-Line) — the
  kernel has no `End.DT2U` / `End.DT2M` and no `End.DX2` / `End.DX2V`
  seg6local actions;
- **EVPN VPWS / E-Line** forwarding on *any* encapsulation — the attachment
  circuit's cross-connect (the VXLAN E-Line VNI path included) is programmed
  only into the engine, never via netlink.

## Configuration

Three knobs, all runtime toggles:

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

- **`system ebpf enabled true`** runs the data plane: zebra-rs launches the
  engine as a managed child process, keeps it healthy, and **implies the
  FIB tee** — a managed engine is always programmed with zebra-rs's routing
  state.
- **`system cradle enabled true`** is the **FIB tee** standalone: every
  route zebra-rs installs — plus ILMs, SRv6 SIDs and EVPN state — is
  programmed into the engine in addition to the kernel, and the data
  plane's MAC learning is fed back into EVPN Type-2 origination. Set it
  when the engine is run **externally** rather than managed by `system
  ebpf` (with `system ebpf enabled` it is already implied). `system cradle
  grpc-endpoint` only overrides the endpoint (default `unix:cradle/grpc`) —
  it enables nothing by itself.
- **`interface <name> ebpf enabled true`** makes that interface a data-plane
  port: the forwarding programs attach to it and it participates in eBPF
  forwarding. The port follows the interface's VRF binding
  (`interface <name> vrf <v>`) — its ingress lookups and derived
  local/connected routes use the VRF's table.

| YANG leaf | Type | Default | Notes |
|---|---|---|---|
| `/system/ebpf/enabled` | `boolean` | `false` | Engine lifecycle: spawn and supervise the data plane. Implies the FIB tee. |
| `/system/cradle/enabled` | `boolean` | `false` | The FIB tee standalone (for an externally-run engine): program routes / ILM / SRv6 / EVPN into the engine. |
| `/system/cradle/grpc-endpoint` | `string` | `unix:cradle/grpc` | Endpoint override, shared by the tee and the managed engine. Does not enable the tee. |
| `/interface/ebpf/enabled` | `boolean` | `false` | Per-interface port membership. |

Port membership is **reconciled**: enabling `ebpf` on an interface that does
not exist yet attaches the moment the device appears; a deleted-and-recreated
link re-attaches under its new ifindex; moving the interface between VRFs
re-binds the port in place; disabling detaches and flushes the MACs learned
on the port.

### Automatic port attach for BFD

BFD's in-kernel datapaths — [Echo](ch-10-00-bfd.md) reflect/originate and the
control-packet detection watchdog — run inside the same `cradle_xdp` program,
so they only fire on interfaces the engine is attached to. To spare operators
a redundant per-interface line, **a single-hop session that enables
`echo-mode` or `detect-offload` auto-attaches its egress interface as a
data-plane port** — no explicit `interface <name> ebpf enabled` is needed.

The desired port set is the **union** of the config leaves and BFD's requests:
a port stays attached while either side wants it, and BFD's auto-attach is
released only when its last Echo/detect-offload session on that interface goes
away *and* no `interface … ebpf enabled` leaf keeps it. Plain (control-packet)
BFD needs no eBPF and does not trigger this. The engine itself must still be
enabled with `system ebpf enabled true`. `show ebpf` labels each port's source
(`config`, `bfd`, or `config,bfd`):

```
  Ports:           2 wanted (1 config, 1 bfd), 2 attached
    enp0s6           ifindex 3      vrf 0     config      attached
    enp0s7           ifindex 4      vrf 0     bfd         attached
```

## Lifecycle

The engine runs as a supervised child of zebra-rs:

- **Crash recovery**: a dead engine is respawned with exponential backoff,
  its ports re-attach, and the entire programmed FIB state — routes, ILM,
  SRv6 SIDs, EVPN, GTP, neighbors — is **replayed** into the fresh instance
  with no operator action.
- **Lifetime binding**: the child cannot outlive zebra-rs, even if the
  daemon is killed with SIGKILL.
- **Unified logs**: the engine's output appears in zebra-rs's own log.
- Disabling `system ebpf` stops the engine cleanly and detaches everything.

The engine binary ships as the `cradle-rs` Debian package (a `recommends` of
the zebra-rs package); zebra-rs finds it at `/usr/bin/cradle` and needs no
further configuration.

## `show ebpf`

The data-plane status — switches, engine state (pid, uptime, restart count),
and the per-port reconcile table:

```
zebra> show ebpf
eBPF data plane
  System ebpf:     enabled
  FIB tee:         enabled
  Engine:          managed (pid 168157), up 42s
  Engine restarts: 1
  Engine v4 FIB:   mode lpm
  Ports:           2 configured, 2 attached
    eth0             ifindex 3      vrf 0     attached
    eth1             ifindex 5      vrf 1     attached
```

## `show ebpf <table>` — forwarding tables

The engine's forwarding tables render directly from its live maps:

| Command | Table |
|---|---|
| `show ebpf l2` | L2 FDB (MAC table): learned and EVPN-remote entries, ages |
| `show ebpf ipv4 [vrf <name>]` | IPv4 FIB (global table, or one VRF by name) |
| `show ebpf ipv6 [vrf <name>]` | IPv6 FIB |
| `show ebpf mpls` | MPLS ILM (incoming-label map) |
| `show ebpf srv6` | SRv6 local SIDs and transit encaps |
| `show ebpf nexthop` | Nexthops and ECMP groups |
| `show ebpf stats` | Datapath packet counters |

```
zebra> show ebpf ipv4
prefix                vrf   nh_id flags      nexthop
10.1.1.1/32             0       0 local
10.1.1.0/24             0 1000003 -          dev if3
10.9.9.0/24             0       2 -          via 10.1.1.2 dev if3

zebra> show ebpf nexthop
  nh_id gateway                      oif flags           backup labels
1000003 -                              3 -                    0
      2 10.1.1.2                       3 -                    0

zebra> show ebpf stats
l2_forward     0
l2_flood       0
l3v4_forward   1024
...
```

An empty table prints nothing. Per-VRF FIBs are addressed by VRF name:

```
zebra> show ebpf ipv4 vrf red
prefix                vrf   nh_id flags      nexthop
10.30.1.1/32            1       0 local
10.30.1.0/24            1 1000003 -          dev if3
```

## JSON output

Every `show ebpf` command takes a trailing `json` and renders the same data
machine-readably — typed entry objects for the tables (flag bitmasks
expanded to names, resolved nexthops nested), a counter-keyed object for
stats, and `[]` for an empty table:

```
zebra> show ebpf ipv4 json
[{"type":"fib","prefix":"10.9.9.0/24","vrf":0,"nexthopId":2,"flags":[],
  "nexthop":{"id":2,"gateway":"10.1.1.2","oif":3,"labels":[],"flags":[]}}]

zebra> show ebpf stats json
{"l2_forward":0,"l2_flood":0,"l3v4_forward":1024, ...}
```

## Related

- [Mobile User Plane (MUP)](ch-02-35-bgp-mup.md) — `dataplane gtp` programs
  real GTP-U (v4 and v6 outers) on the eBPF data plane.
- [EVPN VPWS](ch-02-38-bgp-evpn-vpws.md) — E-Line forwarding runs on the
  eBPF data plane on all three encapsulations (VXLAN, MPLS, SRv6).
- [EVPN over MPLS](ch-02-40-bgp-evpn-mpls.md) — the per-EVI service label,
  its bridge-domain decap and every remote MAC exist only here;
  `show ebpf mpls` and `show ebpf l2` are the only place to confirm the
  service is actually programmed.
- [EVPN over SRv6](ch-02-41-bgp-evpn-srv6.md) — the `End.DT2U` / `End.DT2M`
  service SIDs and their FDB state exist only here (`show ebpf srv6`,
  `show ebpf l2`).

Hands-on labs live under `playset/`: every EVPN-over-MPLS and
EVPN-over-SRv6 lab (`bgp-evpn-mpls`, `bgp-evpn-mpls6`, `bgp-evpn-srv6`, the
`bgp-evpn-vpws-*` set) runs on the engine, and the EVPN/VXLAN labs have
eBPF twins (`bgp-evpn-vxlan4-ebpf`, `bgp-evpn-vxlan6-ebpf`, and their
`-multi` variants).
