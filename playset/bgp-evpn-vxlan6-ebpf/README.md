# BGP EVPN VXLAN over IPv6 underlay, eBPF data plane

The same demo as [bgp-evpn-vxlan6](../bgp-evpn-vxlan6/README.md) — one L2
segment stretched between two hosts across an IPv6-only core — with the
forwarding moved onto the **eBPF engine**: `system ebpf enabled` makes
zebra-rs spawn cradle, the host ports become its L2 ports, and every MAC
learn, flood copy, VXLAN encap and decap runs in XDP. The outer header is
now **Ethernet + IPv6 + UDP** toward the peer's v6 VTEP; the tenant
payload stays IPv4 (`172.16.10.0/24`), carried unchanged across the
IPv6-only underlay. The kernel VXLAN device stays configured (it is the
VNI declaration) but never sees a frame.

Same two deliberate differences from the kernel twin as
[bgp-evpn-vxlan4-ebpf](../bgp-evpn-vxlan4-ebpf/README.md):

* **The VTEP is a loopback.** The engine has one fabric-wide VTEP source
  per address family, so `2001:db8::x/128` loopbacks carry the vxlan
  `local-address`, the BGP sessions (`update-source`), and the advertised
  routes' next hops. A static /128 toward the peer's loopback resolves
  the encapsulation via the teed FIB6.
* **Kernel forwarding is off** (both families) on the VTEPs, so the ping
  proves the engine did the work.

```
 h1 ── vtep1 ══════════ vtep2 ── h2     h1/h2: 172.16.10.1/24, .2/24
        2001:db8:12::/64                vtep1: lo/VTEP 2001:db8::1
         IPv6 underlay                  vtep2: lo/VTEP 2001:db8::2
             VNI 10 / bridge domain 10 stretched across
```

## Bring up all nodes

```shell
$ ./up.sh
...
start zebra-rs: h2
sleep 3sec
```

## Ping, then look at what the engine built

Fully dynamic — h1's first ARP floods over the ingress-replication
tunnel, the engine learns both hosts' MACs in XDP and streams them to
zebra-rs, each becoming a Type-2 with the v6 VTEP as next hop:

```shell
$ sudo ip netns exec h1 ping -c 3 172.16.10.2
...
3 packets transmitted, 3 received, 0% packet loss
```

```shell
$ sudo ip netns exec vtep1 vty
vtep1>show bgp evpn
Route Distinguisher: 10.0.0.1:10
 *>  [2]:[0]:[48]:[6a:de:ad:2a:26:05]
                    2001:db8::1                0         32768 i
                    Extended community: RT:65001:10 ET:8
 *>  [3]:[0]:[128]:[2001:db8::1]
                    2001:db8::1                0         32768 i
                    Extended community: RT:65001:10 ET:8
                    PMSI: ingress-replication endpoint:2001:db8::1 vni:10
Route Distinguisher: 10.0.0.2:10
 *>  [2]:[0]:[48]:[be:ae:83:fb:98:25]
                    2001:db8::2                0    100      0 i
                    Extended community: RT:65001:10 ET:8
 *>  [3]:[0]:[128]:[2001:db8::2]
                    2001:db8::2                0    100      0 i
                    Extended community: RT:65001:10 ET:8
                    PMSI: ingress-replication endpoint:2001:db8::2 vni:10
```

The engine's FDB shows what makes this the v6 lab: the remote MAC's
16-byte address slot carries the peer's VTEP **native** — `2001:db8::2`,
not a `::ffff:…` v4-mapped value:

```shell
vtep1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
be:ae:83:fb:98:25     10        0 remote           0 2001:db8::2
6a:de:ad:2a:26:05     10        3 learned       11465
```

```shell
vtep1>show ebpf stats
...
l2_forward     7
l2_flood       14
vxlan_encap    1
vxlan_decap    15
vxlan_flood    14
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| h1 | tenant host | `h1-vtep1` 172.16.10.1/24 |
| vtep1 | VTEP | `lo` 2001:db8::1/128, `vtep1-vtep2` 2001:db8:12::1/64, VNI 10 |
| vtep2 | VTEP | `lo` 2001:db8::2/128, `vtep2-vtep1` 2001:db8:12::2/64, VNI 10 |
| h2 | tenant host | `h2-vtep2` 172.16.10.2/24 |
