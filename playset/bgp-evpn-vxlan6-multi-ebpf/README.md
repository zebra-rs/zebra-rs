# BGP EVPN VXLAN multi-tenant over IPv6 underlay, eBPF data plane

The multi-tenant demo of
[bgp-evpn-vxlan4-multi-ebpf](../bgp-evpn-vxlan4-multi-ebpf/README.md)
moved onto an **IPv6-only underlay**: three VTEPs, two isolated tenants —
VNI 10 stretches h1↔h2 across vtep1/vtep2, VNI 20 stretches h3↔h4 across
vtep3/vtep1 — and **vtep1 serves both** from one engine, its single eBPF
FDB cleanly split by bridge domain. Every VXLAN frame rides an outer
Ethernet + IPv6 + UDP header between v6 loopback VTEPs. All four hosts
share `172.16.10.0/24`; the two tenants still cannot reach each other,
which is the isolation proof.

Engine shape as in the v4 twin: one fabric-wide VTEP source per address
family, so vtep1's two vxlan devices ride the same v6 loopback
(`2001:db8::1`), both BGP sessions ride it too, and static /128s toward
the peers' loopbacks resolve the encapsulation via the teed FIB6.
Per-VNI RD/RT (`10.0.0.1:10` / `10.0.0.1:20`) keeps the tenants apart in
BGP exactly as before.

```
        h1(10)   h4(20)
           \      /
 h2 ── vtep2 ── vtep1 ── vtep3 ── h3      VNI 10: h1, h2
 (10) 2001:db8:12::/64 2001:db8:13::/64   VNI 20: h3, h4
   lo ::2      lo ::1      lo ::3         all hosts: 172.16.10.0/24
```

vtep2 and vtep3 never peer with each other — each tenant is stretched
only where it exists, so neither VTEP ever learns the other's routes.

## Bring up all nodes

```shell
$ ./up.sh
...
apply config: h4
applied
```

## Both tenants forward, and never into each other

```shell
$ sudo ip netns exec h1 ping -c 2 172.16.10.2      # VNI 10, vtep1 ↔ vtep2
2 packets transmitted, 2 received, 0% packet loss
$ sudo ip netns exec h3 ping -c 2 172.16.10.4      # VNI 20, vtep3 ↔ vtep1
2 packets transmitted, 2 received, 0% packet loss
$ sudo ip netns exec h1 ping -c 2 172.16.10.4      # cross-tenant
2 packets transmitted, 0 received, 100% packet loss
```

The cross-tenant ping dies at ARP — h1 and h4 sit behind the *same*
engine on vtep1, one bridge domain apart, and the broadcast never
crosses:

```shell
$ sudo ip netns exec h1 ip neigh show 172.16.10.4
172.16.10.4 dev h1-vtep1 INCOMPLETE
```

## One engine, two tenants, native v6 VTEPs

vtep1's eBPF FDB carries both bridge domains side by side — locally
learned MACs with an age, remote ones bound to the right peer's VTEP,
carried **native** in the engine's 16-byte address slot (not v4-mapped):

```shell
$ sudo ip netns exec vtep1 vty
vtep1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
6a:2d:c6:c7:3a:5c     20        5 learned       2058
0e:bb:a9:ab:64:70     10        0 remote           0 2001:db8::2
ca:55:0d:4f:70:53     20        0 remote           0 2001:db8::3
7e:62:f3:2e:ea:5d     10        4 learned         14
```

And in BGP each tenant keeps its own RD and its own ingress-replication
tunnel, endpoints now IPv6:

```shell
vtep1>show bgp evpn
Route Distinguisher: 10.0.0.1:10
                    PMSI: ingress-replication endpoint:2001:db8::1 vni:10
Route Distinguisher: 10.0.0.1:20
                    PMSI: ingress-replication endpoint:2001:db8::1 vni:20
Route Distinguisher: 10.0.0.2:10
                    PMSI: ingress-replication endpoint:2001:db8::2 vni:10
Route Distinguisher: 10.0.0.3:20
                    PMSI: ingress-replication endpoint:2001:db8::3 vni:20
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| h1 | tenant host, VNI 10 | `h1-vtep1` 172.16.10.1/24 |
| h2 | tenant host, VNI 10 | `h2-vtep2` 172.16.10.2/24 |
| h3 | tenant host, VNI 20 | `h3-vtep3` 172.16.10.3/24 |
| h4 | tenant host, VNI 20 | `h4-vtep1` 172.16.10.4/24 |
| vtep1 | VTEP, VNIs 10+20 | `lo` 2001:db8::1/128, `vtep1-vtep2` 2001:db8:12::1/64, `vtep1-vtep3` 2001:db8:13::1/64 |
| vtep2 | VTEP, VNI 10 | `lo` 2001:db8::2/128, `vtep2-vtep1` 2001:db8:12::2/64 |
| vtep3 | VTEP, VNI 20 | `lo` 2001:db8::3/128, `vtep3-vtep1` 2001:db8:13::2/64 |
