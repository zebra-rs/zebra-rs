# EVPN VPWS between IPv6 PEs: an E-Line over MPLS, no IGP, no IPv4

The [bgp-evpn-vpws-mpls](../bgp-evpn-vpws-mpls/README.md) demo re-run on
an **IPv6-only core with no IGP at all**: the same point-to-point E-Line
(EVPN VPWS, RFC 8214) under RFC 7432's original encapsulation, the same
pure-transit **P router** — but every underlay address is IPv6 and the
transport labels are static.

Three pieces replace the IPv4 lab's IS-IS SR-MPLS:

* **`vtep-source`** names the v6 loopback each Type-1 advertises as next
  hop — a VPWS service has no VXLAN device to take an address from, and
  the router-id fallback can only express IPv4;
* a **labeled static v6 route** per PE supplies the transport LSP toward
  the far loopback;
* the P's **static MPLS label bindings with v6 nexthops** pop the
  transport label toward each PE (PHP), their explicit `interface` leaf
  opting the pop onto the eBPF XDP fast path — the P holds no route for
  the exposed service label's frame, and the XDP redirect delivers only
  between XDP-attached ports.

The P carries no BGP and no VPWS state; even the PEs' own iBGP session
rides the LSP through it. The CEs stay oblivious: one subnet, ARP
straight through the wire.

```
 c1 ── pe1 ═══════ p ═══════ pe2 ── c2     c1/c2: 10.0.0.1/24, 10.0.0.2/24
   2001:db8:12::/64  2001:db8:23::/64      pe1: lo 2001:db8:255::1
     static labels 100 → / ← 101           pe2: lo 2001:db8:255::2
   vpws eline1: evi 100, pe1 svc-id 101 ⇄ pe2 svc-id 102
```

## Bring up all nodes

```shell
$ ./up.sh
...
seed config: c2
...
start zebra-rs: c2
sleep 3sec
```

## Ping through the wire, then read the service back

```shell
$ sudo ip netns exec c1 ping -c 3 10.0.0.2
...
3 packets transmitted, 3 received, 0% packet loss
```

The Type-1s carry v6 next hops, the per-service label, and no
Encapsulation EC — its absence is the MPLS signal:

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn
Route Distinguisher: 1.1.1.1:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[101]
                    2001:db8:255::1            0         32768 i
                    Extended community: RT:65000:100 l2-attr:P:mtu0
Route Distinguisher: 2.2.2.2:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[102]
                    2001:db8:255::2            0    100      0 i
                    Extended community: RT:65000:100 l2-attr:P:mtu0
```

```shell
pe1>show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: pe1-c1
  Local Label: 16
  Remote PE: 2001:db8:255::2 (label 16) (via 2001:db8:255::2)
  State: up
```

The PE counters show the imposition and the pop-to-AC disposition, and
the P's show the transit pops that carried both the service and the BGP
session itself:

```shell
pe1>show ebpf stats
...
mpls_l2_encap  4
mpls_dx2       4
```

```shell
$ sudo ip netns exec p vty
p>show ebpf stats
...
mpls_pop       35
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| c1 | CE | `c1-pe1` 10.0.0.1/24 |
| pe1 | PE, eline1 | `lo` 2001:db8:255::1/128, `pe1-p` 2001:db8:12::1/64 |
| p | transit LSR | `p-pe1` 2001:db8:12::2/64, `p-pe2` 2001:db8:23::1/64 |
| pe2 | PE, eline1 | `lo` 2001:db8:255::2/128, `pe2-p` 2001:db8:23::2/64 |
| c2 | CE | `c2-pe2` 10.0.0.2/24 |
