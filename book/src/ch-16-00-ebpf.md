# eBPF Data Plane

zebra-rs can forward traffic in an in-kernel **eBPF/XDP data plane**: an
engine that attaches XDP + TC programs to selected interfaces and forwards
from eBPF maps that zebra-rs programs directly from its routing state. Every
route zebra-rs computes — static, BGP, OSPF, IS-IS, plus the SR-MPLS / SRv6 /
EVPN / MUP forwarding state — is installed into the eBPF FIB in addition to
the kernel FIB, and the data plane's MAC learning feeds back into EVPN
Type-2 origination.

Some forwarding behaviours have **no mainline-kernel equivalent** and are
only available on the eBPF data plane — notably real GTP-U for
[MUP](ch-02-35-bgp-mup.md) (`dataplane gtp`) and
[EVPN VPWS](ch-02-38-bgp-evpn-vpws.md) E-Line egress.

## Configuration

Two knobs, both runtime toggles:

```
system {
  ebpf {
    enabled true;
  }
}
interface enp0s6 {
  ebpf {
    enabled true;
  }
}
```

- **`system ebpf enabled true`** turns the data plane on: zebra-rs launches
  the engine as a managed child process, keeps it healthy, and programs the
  eBPF FIB from the RIB.
- **`interface <name> ebpf enabled true`** makes that interface a data-plane
  port: the forwarding programs attach to it and it participates in eBPF
  forwarding. The port follows the interface's VRF binding
  (`interface <name> vrf <v>`) — its ingress lookups and derived
  local/connected routes use the VRF's table.

| YANG leaf | Type | Default | Notes |
|---|---|---|---|
| `/system/ebpf/enabled` | `boolean` | `false` | The data-plane switch: engine + FIB programming. |
| `/interface/ebpf/enabled` | `boolean` | `false` | Per-interface port membership. |

Port membership is **reconciled**: enabling `ebpf` on an interface that does
not exist yet attaches the moment the device appears; a deleted-and-recreated
link re-attaches under its new ifindex; moving the interface between VRFs
re-binds the port in place; disabling detaches and flushes the MACs learned
on the port.

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
  real GTP-U on the eBPF data plane.
- [EVPN VPWS](ch-02-38-bgp-evpn-vpws.md) — E-Line egress runs on the eBPF
  data plane.
