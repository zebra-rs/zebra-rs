# BGP EVPN VXLAN multi-tenant, eBPF data plane

The multi-tenant demo of
[bgp-evpn-vxlan4-multi](../bgp-evpn-vxlan4-multi/README.md) on the eBPF
engine: three VTEPs, two isolated tenants — VNI 10 stretches h1↔h2 across
vtep1/vtep2, VNI 20 stretches h3↔h4 across vtep3/vtep1 — and **vtep1
serves both** from one engine, its single eBPF FDB cleanly split by
bridge domain. All four hosts share `172.16.10.0/24`; the two tenants
still cannot reach each other, which is the isolation proof.

One deliberate difference from the kernel twin: there, vtep1 gives each
VNI its own per-underlay VTEP address. The engine has **one fabric-wide
VTEP source**, so both of vtep1's vxlan devices ride the same loopback
(`192.0.2.1`), both BGP sessions ride it too, and static /32s toward the
peers' loopbacks resolve the encapsulation. Per-VNI RD/RT
(`192.0.2.1:10` / `192.0.2.1:20`) keeps the tenants apart in BGP exactly
as before.

```
        h1(10)   h4(20)
           \      /
 h2 ── vtep2 ── vtep1 ── vtep3 ── h3      VNI 10: h1, h2
 (10)   192.168.0.0/24  192.168.1.0/24    VNI 20: h3, h4
        lo .2.2   lo .2.1   lo .2.3       all hosts: 172.16.10.0/24
```

vtep2 and vtep3 never peer with each other — each tenant is stretched
only where it exists, so neither VTEP ever learns the other's routes.

## Bring up all nodes

```shell
$ ./up.sh
...
seed config: h4
...
start zebra-rs: h4
sleep 3sec
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
172.16.10.4 dev h1-vtep1 FAILED
```

## One engine, two tenants

vtep1's eBPF FDB carries both bridge domains side by side — locally
learned MACs with an age, remote ones bound to the right peer's VTEP
(v4-mapped in the engine's address slot):

```shell
$ sudo ip netns exec vtep1 vty
vtep1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
7e:96:2e:a8:36:80     20        0 remote           0 ::ffff:192.0.2.3
82:09:aa:f2:41:a3     20        5 learned       7922
f6:12:8c:56:c7:86     10        0 remote           0 ::ffff:192.0.2.2
3e:7a:72:53:89:fc     10        4 learned       7922
```

And in BGP each tenant keeps its own RD and its own ingress-replication
tunnel:

```shell
vtep1>show bgp evpn
Route Distinguisher: 192.0.2.1:10
                    PMSI: ingress-replication endpoint:192.0.2.1 vni:10
Route Distinguisher: 192.0.2.1:20
                    PMSI: ingress-replication endpoint:192.0.2.1 vni:20
Route Distinguisher: 192.0.2.2:10
                    PMSI: ingress-replication endpoint:192.0.2.2 vni:10
Route Distinguisher: 192.0.2.3:20
                    PMSI: ingress-replication endpoint:192.0.2.3 vni:20
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
| vtep1 | VTEP, VNIs 10+20 | `lo` 192.0.2.1/32, `vtep1-vtep2` 192.168.0.1/24, `vtep1-vtep3` 192.168.1.1/24 |
| vtep2 | VTEP, VNI 10 | `lo` 192.0.2.2/32, `vtep2-vtep1` 192.168.0.2/24 |
| vtep3 | VTEP, VNI 20 | `lo` 192.0.2.3/32, `vtep3-vtep1` 192.168.1.2/24 |
