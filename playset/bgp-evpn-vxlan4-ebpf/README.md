# BGP EVPN VXLAN, eBPF data plane

The same demo as [bgp-evpn-vxlan4](../bgp-evpn-vxlan4/README.md) — one L2
segment stretched between two hosts over an EVPN/VXLAN fabric — with the
forwarding moved from the kernel's single-VXLAN-device data path onto the
**eBPF engine**: `system ebpf enabled` makes zebra-rs spawn cradle, the
host ports become its L2 ports, and every MAC learn, flood copy, VXLAN
encap and decap runs in XDP. The kernel VXLAN device stays configured (it
is the VNI declaration) but never sees a frame.

Two deliberate differences from the kernel twin:

* **The VTEP is a loopback.** The engine has one fabric-wide VTEP source,
  so `192.0.2.x/32` loopbacks carry the vxlan `local-address`, the BGP
  sessions (`update-source`), and the advertised routes' next hops — the
  classic EVPN shape. A static /32 toward the peer's loopback resolves
  the encapsulation via the teed FIB.
* **Kernel forwarding is off** on both VTEPs, so the ping proves the
  engine did the work.

```
 h1 ── vtep1 ══════════ vtep2 ── h2     h1/h2: 172.16.10.1/24, .2/24
         192.168.0.0/24                 vtep1: lo/VTEP 192.0.2.1
         IPv4 underlay                  vtep2: lo/VTEP 192.0.2.2
             VNI 10 / bridge domain 10 stretched across
```

> **Why is there no `bgp-evpn-vxlan6-ebpf`?** The engine's VXLAN underlay
> is IPv4-only (VTEPs ride v4-mapped in its tables, the outer header is
> IPv4) — a v6-VTEP MAC is deliberately handed to the kernel data path
> instead. The IPv6-underlay story is the kernel labs'
> ([bgp-evpn-vxlan6](../bgp-evpn-vxlan6/README.md)).

## Bring up all nodes

```shell
$ ./up.sh
...
apply config: h2
applied
```

## Take a look at the YAML configuration

`vtep1.yaml` in full — diff it against the kernel twin's: the additions
are `system ebpf enabled`, the per-port `ebpf enabled` leaves, and the
loopback-VTEP addressing:

```yaml
system:
  hostname: vtep1
  ebpf:
    enabled: true
interface:
- if-name: lo
  ipv4:
    address: 192.0.2.1/32
- if-name: vtep1-vtep2
  ipv4:
    address: 192.168.0.1/24
  ebpf:
    enabled: true
- if-name: vtep1-h1
  bridge: br10
  ebpf:
    enabled: true
bridge:
- name: br10
vxlan:
- name: vxlan10
  vni: 10
  local-address: 192.0.2.1
  bridge: br10
router:
  static:
    ipv4:
      route:
      - prefix: 192.0.2.2/32
        nexthop:
        - address: 192.168.0.2
  bgp:
    global:
      as: 65001
      router-id: 192.0.2.1
    afi-safi:
    - name: evpn
      advertise-all-vni: true
    neighbor:
    - remote-address: 192.0.2.2
      remote-as: 65001
      update-source: 192.0.2.1
      enabled: true
      afi-safi:
      - name: evpn
        enabled: true
```

## Ping, then look at what the engine built

Fully dynamic — h1's first ARP floods over the ingress-replication
tunnel, the engine learns both hosts' MACs in XDP and streams them to
zebra-rs, each becoming a Type-2:

```shell
$ sudo ip netns exec h1 ping -c 3 172.16.10.2
...
3 packets transmitted, 3 received, 0% packet loss, time 607ms
```

```shell
$ sudo ip netns exec vtep1 vty
vtep1>show bgp evpn
Route Distinguisher: 192.0.2.1:10
 *>  [2]:[0]:[48]:[5e:e6:e4:61:da:cd]
                    192.0.2.1                  0         32768 i
                    Extended community: RT:65001:10 ET:8
 *>  [3]:[0]:[32]:[192.0.2.1]
                    192.0.2.1                  0         32768 i
                    Extended community: RT:65001:10 ET:8
                    PMSI: ingress-replication endpoint:192.0.2.1 vni:10
Route Distinguisher: 192.0.2.2:10
 *>  [2]:[0]:[48]:[06:9c:54:9f:22:52]
                    192.0.2.2                  0    100      0 i
                    Extended community: RT:65001:10 ET:8
```

The engine's FDB is where this lab differs visibly from the kernel one:
instead of `bridge fdb show`, the MACs live in the eBPF map — locally
learned ones with an age, remote ones bound to the peer's VTEP,
**v4-mapped** (`::ffff:…`) in the engine's 16-byte address slot:

```shell
vtep1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
0e:02:37:98:bd:95     10        0 remote           0 ::ffff:192.0.2.2
5e:e6:e4:61:da:cd     10        3 learned       4460
```

```shell
vtep1>show ebpf stats
...
l2_forward     5
l2_flood       10
vxlan_encap    1
vxlan_decap    11
vxlan_flood    10
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| h1 | tenant host | `h1-vtep1` 172.16.10.1/24 |
| vtep1 | VTEP | `lo` 192.0.2.1/32, `vtep1-vtep2` 192.168.0.1/24, VNI 10 |
| vtep2 | VTEP | `lo` 192.0.2.2/32, `vtep2-vtep1` 192.168.0.2/24, VNI 10 |
| h2 | tenant host | `h2-vtep2` 172.16.10.2/24 |
