# EVPN services over VXLAN: E-LINE, E-LAN and E-TREE in eBPF

This lab runs all three Ethernet services at once over one EVPN/VXLAN
fabric (RFC 8365). The services are named as MEF names them; EVPN
signals each one:

| Service | EVPN flavour | EVI / VNI | CEs | Subnet |
|:--|:--|:--|:--|:--|
| **E-LINE** — a point-to-point wire | VPWS (RFC 8214) | 300 | line1 ↔ line2 | 172.16.1.0/24 |
| **E-LAN** — a multipoint LAN | EVPN bridging (RFC 7432) | 100 | lan1, lan2, lan3 | 172.16.2.0/24 |
| **E-TREE** — a hub and its spokes | EVPN E-Tree (RFC 8317) | 200 | root1 (root), leaf2, leaf3 (leaves) | 172.16.3.0/24 |

The topology, addressing and services are the same in all three labs of
this series. Only the encapsulation changes: this one,
[bgp-evpn-services-mpls](../bgp-evpn-services-mpls/README.md) and
[bgp-evpn-services-srv6](../bgp-evpn-services-srv6/README.md).

![EVPN services topology](../images/BgpEvpnServices.svg)

```
  line1 ─┐                             ┌─ line2
  lan1  ─┼─ pe1 ═══════ p ═══════ pe2 ─┼─ lan2
  root1 ─┘              ║              └─ leaf2
                        ║
                       pe3 ─┬─ lan3
                            └─ leaf3
```

Every PE runs the cradle eBPF engine (`system ebpf enabled`), and the
engine forwards all three services in XDP. The kernel's VXLAN devices are
configured, because they tell zebra-rs which VNI a bridge carries, but they
never see a frame. E-TREE needs cradle: the Linux bridge cannot keep two
leaves apart, and zebra-rs refuses a leaf AC without cradle at commit.

P is a plain IPv4 router. IS-IS carries the PE loopbacks, which are also
the VTEPs, and P routes the VXLAN packets on their outer header. It holds
no BGP and no EVPN state.

## Bring up all nodes

```shell
$ ./up.sh
...
start zebra-rs: leaf3
sleep 3sec
```

`up.sh` also:

* gives each CE a readable MAC, `02:00:00:00:<service>:<host>`, with
  service 01 = E-LINE, 02 = E-LAN and 03 = E-TREE, and turns its IPv6
  off. An idle IPv6 host keeps sending router solicitations and MLD
  reports, and that BUM would only blur the E-TREE counters below;
* turns GRO on for P's veths. A PE's engine sends with an XDP redirect,
  and a veth delivers a redirected frame only when its peer end runs NAPI,
  which GRO gives it. A physical NIC needs nothing of the kind;
* turns kernel IPv4 forwarding off on the PEs, so a successful ping proves
  the eBPF data plane did the work.

Give BGP about 20 seconds to come up.

## Take a look at the YAML configuration

`pe2.yaml` carries all three services, an E-TREE leaf among them. Here is
its EVPN part:

```yaml
interface:
- if-name: pe2-line2          # E-LINE AC: not in any bridge
  ebpf:
    enabled: true
- if-name: pe2-lan2           # E-LAN AC
  bridge: br100
  ebpf:
    enabled: true
- if-name: pe2-leaf2          # E-TREE AC
  bridge: br200
  ebpf:
    enabled: true
bridge:
- name: br100
- name: br200
vxlan:
- name: vxlan100
  vni: 100
  local-address: 10.0.0.2
  bridge: br100
- name: vxlan200
  vni: 200
  local-address: 10.0.0.2
  bridge: br200
router:
  bgp:
    afi-safi:
    - name: evpn
      advertise-all-vni: true
      vpws:
      - name: eline1
        evi: 300
        local-service-id: 2
        remote-service-id: 1
        interface: pe2-line2
      etree:
        leaf-interface:
        - name: pe2-leaf2
```

* **E-LINE** is a `vpws` entry: an EVI, the local and remote service IDs
  (the Ethernet Tags of the two Type-1 routes) and the AC. Under VXLAN,
  the default encapsulation, the service VNI is the EVI unless a `vni`
  leaf says otherwise.
* **E-LAN** is a VXLAN device in a bridge with its AC. `advertise-all-vni`
  originates the Type-2 (MAC/IP) and Type-3 (IMET) routes for every such
  VNI.
* **E-TREE** is an E-LAN with one more statement, `etree leaf-interface`.
  Every AC not listed is a root, so pe1, the root site, has no `etree`
  configuration at all.

## Ping every service

```shell
$ sudo ip netns exec line1 ping -c 3 172.16.1.2       # E-LINE
3 packets transmitted, 3 received, 0% packet loss
$ sudo ip netns exec lan1 ping -c 3 172.16.2.3        # E-LAN, pe1 → pe3
3 packets transmitted, 3 received, 0% packet loss
$ sudo ip netns exec root1 ping -c 3 172.16.3.2       # E-TREE root → leaf
3 packets transmitted, 3 received, 0% packet loss
$ sudo ip netns exec leaf3 ping -c 3 172.16.3.1       # E-TREE leaf → root
3 packets transmitted, 3 received, 0% packet loss
$ sudo ip netns exec leaf2 ping -c 3 172.16.3.3       # E-TREE leaf → leaf
3 packets transmitted, 0 received, 100% packet loss
```

The last one is meant to fail: two leaves never reach each other.

## What BGP carries

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn
   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 10.0.0.1:100
 *>  [2]:[0]:[48]:[02:00:00:00:02:01]
                    10.0.0.1                   0         32768 i
                    Extended community: RT:65000:100 ET:8
 *>  [3]:[0]:[32]:[10.0.0.1]
                    10.0.0.1                   0         32768 i
                    Extended community: RT:65000:100 ET:8
                    PMSI: ingress-replication endpoint:10.0.0.1 vni:100
...
Route Distinguisher: 10.0.0.1:300
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[1]
                    10.0.0.1                   0         32768 i
                    Extended community: RT:65000:300 ET:8 l2-attr:P:mtu0
...
Route Distinguisher: 10.0.0.2:200
 *>  [2]:[0]:[48]:[02:00:00:00:03:02]
                    10.0.0.2                   0    100      0 i
                    Extended community: RT:65000:200 ET:8 etree:leaf
 *>  [3]:[0]:[32]:[10.0.0.2]
                    10.0.0.2                   0    100      0 i
                    Extended community: RT:65000:200 ET:8 etree:leaf
                    PMSI: ingress-replication endpoint:10.0.0.2 vni:200
...
```

Each service has its own RD (`<router-id>:<EVI>`) and RT (`65000:<EVI>`):

* **E-LINE**: one Type-1 per end, the service ID as its Ethernet Tag, with
  the L2-Attributes EC (`l2-attr:P`, primary).
* **E-LAN**: a Type-3 per PE, which builds the ingress-replication flood
  list, and a Type-2 per learned MAC. `ET:8` is the VXLAN Encapsulation
  EC.
* **E-TREE**: the same two route types, but pe2's carry the E-Tree EC
  (`etree:leaf`). The Type-2 says that MAC is behind a leaf. The Type-3
  says every AC of VNI 200 on pe2 is a leaf: pe2 is a leaf-only PE.

```shell
pe1>show bgp evpn vpws
VPWS service: eline1
  EVI: 300
  Service ID: local 1, remote 2
  Interface: pe1-line1
  Local VNI: 300
  Remote VTEP: 10.0.0.2 (VNI 300) (via 10.0.0.2)
  State: up
```

## How the E-TREE keeps leaves apart

Known unicast is dropped at the **ingress** PE. pe2 knows leaf3's MAC
from its coloured Type-2, so the engine drops a leaf's frame to it before
encapsulating. Pin leaf3's MAC on leaf2, so that leaf2 sends unicast
without having to ARP for it:

```shell
$ sudo ip netns exec leaf2 ip neigh replace 172.16.3.3 lladdr 02:00:00:00:03:03 dev leaf2-pe2
$ sudo ip netns exec leaf2 ping -c 3 172.16.3.3
3 packets transmitted, 0 received, 100% packet loss
```

```shell
pe2>show ebpf stats
...
l2_drop_etree_uc 3
```

`show l2 mac table` flags remote leaf MACs with `L`:

```shell
pe2>show l2 mac table
VNI    MAC Address         Encap Tunnel Endpoint       Flags Seq    Installed
------ ------------------- ----- --------------------- ----- ------ ---------
100    02:00:00:00:02:01   vxlan 10.0.0.1              -     0      Yes
100    02:00:00:00:02:03   vxlan 10.0.0.3              -     0      Yes
200    02:00:00:00:03:01   vxlan 10.0.0.1              -     0      Yes
200    02:00:00:00:03:03   vxlan 10.0.0.3              L     0      Yes
```

BUM is a different case. One copy to a PE serves all of that PE's ACs, so
the copy cannot be dropped by destination. VXLAN has no label to carry a
"from a leaf" mark either, and there is no standard for E-Tree BUM over
VXLAN. zebra-rs uses the IMET-colouring form of Arista's
draft-bamberger-bess-imet-filter-evpn-etree-vxlan:

* A leaf's BUM is **not sent** to a leaf-only PE.
* BUM arriving **from** a leaf-only PE's VTEP goes to roots only.

```shell
pe2>show bgp evpn etree
EVPN E-Tree (RFC 8317)
  Leaf interfaces: 1
    pe2-leaf2        ifindex 5      EVI 200        local MACs 1
  Remote leaf MACs:
    EVI 200        1
  Leaf-only EVIs:  200
  Remote leaf-only PEs:
    EVI 200        10.0.0.3
```

Watch it on P. Flush leaf2's ARP cache and ping root1. leaf2's ARP
broadcast leaves pe2 as **one** VXLAN copy, to pe1. leaf-only pe3 gets
none:

```shell
$ sudo ip netns exec p tcpdump -nn -i any udp port 4789
p-pe2 In  IP 10.0.0.2.65021 > 10.0.0.1.4789: VXLAN, flags [I] (0x08), vni 200
ARP, Request who-has 172.16.3.1 tell 172.16.3.2, length 28
p-pe1 Out IP 10.0.0.2.65021 > 10.0.0.1.4789: VXLAN, flags [I] (0x08), vni 200
ARP, Request who-has 172.16.3.1 tell 172.16.3.2, length 28
```

On the E-LAN, lan2's ARP broadcast for lan1 goes to both other PEs:

```shell
p-pe2 In  IP 10.0.0.2.65021 > 10.0.0.3.4789: VXLAN, flags [I] (0x08), vni 100
ARP, Request who-has 172.16.2.1 tell 172.16.2.2, length 28
p-pe2 In  IP 10.0.0.2.65021 > 10.0.0.1.4789: VXLAN, flags [I] (0x08), vni 100
ARP, Request who-has 172.16.2.1 tell 172.16.2.2, length 28
```

This VXLAN scheme is exact as long as no more than one PE in an EVI has
both roots and leaves. Here none does. `show bgp evpn etree` warns about
any EVI where it is not exact.

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| p | core router | `lo` 10.0.0.9/32, `p-pe1` 10.9.1.2/30, `p-pe2` 10.9.2.2/30, `p-pe3` 10.9.3.2/30 |
| pe1 | PE, E-TREE root site | `lo` 10.0.0.1/32 (VTEP), `pe1-p` 10.9.1.1/30 |
| pe2 | PE, E-TREE leaf site | `lo` 10.0.0.2/32 (VTEP), `pe2-p` 10.9.2.1/30 |
| pe3 | PE, E-TREE leaf site | `lo` 10.0.0.3/32 (VTEP), `pe3-p` 10.9.3.1/30 |
| line1, line2 | E-LINE CEs | 172.16.1.1/24, 172.16.1.2/24 |
| lan1, lan2, lan3 | E-LAN hosts | 172.16.2.1/24, .2, .3 |
| root1 | E-TREE root | 172.16.3.1/24 |
| leaf2, leaf3 | E-TREE leaves | 172.16.3.2/24, 172.16.3.3/24 |
