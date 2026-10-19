# EVPN services over SRv6: E-LINE, E-LAN and E-TREE in eBPF

This lab runs all three Ethernet services at once over **SRv6** (RFC 9252):
every service frame crosses the core as the payload of an IPv6 packet
addressed to a SID of the egress PE.

| Service | EVPN flavour | EVI / VNI | CEs | Subnet |
|:--|:--|:--|:--|:--|
| **E-LINE** — a point-to-point wire | VPWS (RFC 8214) | 300 | line1 ↔ line2 | 172.16.1.0/24 |
| **E-LAN** — a multipoint LAN | EVPN bridging (RFC 7432) | 100 | lan1, lan2, lan3 | 172.16.2.0/24 |
| **E-TREE** — a hub and its spokes | EVPN E-Tree (RFC 8317) | 200 | root1 (root), leaf2, leaf3 (leaves) | 172.16.3.0/24 |

The topology, addressing and services are the same in all three labs of
this series. Only the encapsulation changes:
[bgp-evpn-services-vxlan](../bgp-evpn-services-vxlan/README.md),
[bgp-evpn-services-mpls](../bgp-evpn-services-mpls/README.md) and this
one.

![EVPN services topology](../images/BgpEvpnServices.svg)

```
  line1 ─┐                             ┌─ line2
  lan1  ─┼─ pe1 ═══════ p ═══════ pe2 ─┼─ lan2
  root1 ─┘              ║              └─ leaf2
                        ║
                       pe3 ─┬─ lan3
                            └─ leaf3
```

The core is IPv6. IS-IS SRv6 advertises one uSID locator per node,
`LOCn = fcbb:bbbb:n::/48`, and each PE carves its service SIDs from its
own locator:

| Service | SID behavior | Advertised on |
|:--|:--|:--|
| E-LINE | End.DX2 (decapsulate onto the AC) | the Type-1 |
| E-LAN, E-TREE known unicast | End.DT2U (decapsulate, look up the MAC) | the Type-2 |
| E-LAN, E-TREE BUM | End.DT2M (decapsulate, flood) | the Type-3 |

Every PE runs the cradle eBPF engine (`system ebpf enabled`), which
encapsulates, floods and decapsulates all three services in XDP. P is a
plain IPv6 router in the kernel. It routes each packet on its destination,
a SID inside the egress PE's locator, and holds no BGP and no EVPN state.

## Bring up all nodes

```shell
$ ./up.sh
...
start zebra-rs: leaf3
sleep 3sec
```

`up.sh` also:

* gives each CE a readable MAC, `02:00:00:00:<service>:<host>` (service
  01 = E-LINE, 02 = E-LAN, 03 = E-TREE), and turns its IPv6 off, so idle
  router solicitations and MLD reports do not blur the E-TREE counters;
* turns GRO on for P's veths, so they accept the PEs' XDP-redirected
  frames (a veth quirk; a physical NIC needs nothing of the kind);
* turns kernel IPv4 forwarding off on the PEs. IPv6 forwarding stays on:
  with it off, the PEs' own bridge interfaces would solicit routers into
  the tenant segments.

Give BGP about 20 seconds to come up.

## Take a look at the YAML configuration

`pe2.yaml` carries all three services, an E-TREE leaf among them. Here is
its SRv6 and EVPN part:

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
vxlan:                        # VNI declarations only: cradle forwards
- name: vxlan100
  vni: 100
  local-address: 2001:db8::2
  bridge: br100
- name: vxlan200
  vni: 200
  local-address: 2001:db8::2
  bridge: br200
segment-routing:
  locator:
  - name: LOC2
    prefix: fcbb:bbbb:2::/48
    behavior: usid
router:
  bgp:
    segment-routing:
      srv6:
        locator: LOC2
    afi-safi:
    - name: evpn
      advertise-all-vni: true
      encapsulation: srv6
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

Against the [VXLAN lab](../bgp-evpn-services-vxlan/README.md) there are
three differences:

* a locator,
* BGP's `segment-routing srv6 locator`, and
* `encapsulation srv6`.

The VXLAN devices stay, but only to tell zebra-rs which VNI each bridge
carries. The `vpws` and `etree` statements are identical.

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
                    2001:db8::1                0         32768 i
                    Local SID: fcbb:bbbb:1:43:: (End.DT2U)
                    Extended community: RT:65000:100 ET:8
 *>  [3]:[0]:[128]:[2001:db8::1]
                    2001:db8::1                0         32768 i
                    Local SID: fcbb:bbbb:1:41:: (End.DT2M)
                    Extended community: RT:65000:100 ET:8
                    PMSI: ingress-replication endpoint:2001:db8::1 vni:100
...
Route Distinguisher: 10.0.0.2:0
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[4294967295]
                    2001:db8::2                0    100      0 i
                    Remote SID: ::1:0:0:0 (End.DT2M)
                    Extended community: RT:65000:200 etree:leaf-arg:1
...
Route Distinguisher: 10.0.0.2:200
 *>  [2]:[0]:[48]:[02:00:00:00:03:02]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:44:: (End.DT2U)
                    Extended community: RT:65000:200 ET:8 etree:leaf
 *>  [3]:[0]:[128]:[2001:db8::2]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:42:: (End.DT2M)
                    Extended community: RT:65000:200 ET:8
                    PMSI: ingress-replication endpoint:2001:db8::2 vni:200
Route Distinguisher: 10.0.0.2:300
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[2]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:40:: (End.DX2)
                    Extended community: RT:65000:300 l2-attr:P:mtu0
...
```

Every route carries an SRv6 L2 Service SID. One route does not exist in
the VXLAN lab: pe2's **leaf-label route** under RD `10.0.0.2:0`. Under
SRv6, RFC 8317's leaf label becomes a **leaf argument** (Arg.FE2 of RFC
9252, placed as RFC 9819 says):

* With a leaf AC in VNI 200, pe2 installs that VNI's End.DT2M SID
  (`fcbb:bbbb:2:42::`) to accept a 16-bit argument right after the
  function. Its IMET advertises the argument length.
* The leaf-label route carries the argument itself, 1 for every PE, in an
  End.DT2M SID whose only bits set are the argument's. That is the
  `::1:0:0:0` above: bits 64–79, after the 32-bit block, the 16-bit node
  and the 16-bit function.

```shell
pe2>show bgp evpn vpws
VPWS service: eline1
  EVI: 300
  Service ID: local 2, remote 1
  Interface: pe2-line2
  Local SID (End.DX2): fcbb:bbbb:2:40::
  Remote SID: fcbb:bbbb:1:40:: (via 2001:db8::1)
  State: up
```

## How the E-TREE keeps leaves apart

Known unicast is dropped at the **ingress** PE, as under every
encapsulation. pe2 knows from leaf3's coloured Type-2 that its MAC is
behind a leaf:

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

A leaf's BUM copy toward a PE that advertised a leaf argument is sent to
that PE's End.DT2M SID **with the argument set**. The receiving PE
delivers it to roots only:

```shell
pe2>show bgp evpn etree
EVPN E-Tree (RFC 8317)
  Leaf interfaces: 1
    pe2-leaf2        ifindex 5      EVI 200        local MACs 1
  Remote leaf MACs:
    EVI 200        1
  Leaf argument:   1
  Remote leaf arguments:
    2001:db8::3      1 (16 bits)
```

The argument is visible on P. Flush leaf2's ARP cache and ping root1.
leaf2's broadcast leaves pe2 as two copies:

* to pe3's End.DT2M with argument 1 (`fcbb:bbbb:3:41:1::`), and
* to pe1's End.DT2M with none (`fcbb:bbbb:1:42::`). pe1 has no leaf, so
  it advertised no argument, and root1 must get the broadcast.

```shell
$ sudo ip netns exec p tcpdump -nn -i any 'ip6 and not icmp6 and not tcp'
p-pe2 In  IP6 2001:db8::2 > fcbb:bbbb:3:41:1::: ARP, Request who-has 172.16.3.1 tell 172.16.3.2, length 28
p-pe2 In  IP6 2001:db8::2 > fcbb:bbbb:1:42::: ARP, Request who-has 172.16.3.1 tell 172.16.3.2, length 28
p-pe1 In  IP6 2001:db8::1 > fcbb:bbbb:2:44::: ARP, Reply 172.16.3.1 is-at 02:00:00:00:03:01, length 28
p-pe2 In  IP6 2001:db8::2 > fcbb:bbbb:1:44::: IP 172.16.3.2 > 172.16.3.1: ICMP echo request, id 31052, seq 1, length 64
```

(root1's reply and leaf2's echo request are known unicast, so they go to
the End.DT2U SIDs, `…:44::`.) On the E-LAN, lan2's broadcast goes to the
other two PEs' VNI 100 End.DT2M SIDs, with no argument:

```shell
p-pe2 In  IP6 2001:db8::2 > fcbb:bbbb:3:40::: ARP, Request who-has 172.16.2.1 tell 172.16.2.2, length 28
p-pe2 In  IP6 2001:db8::2 > fcbb:bbbb:1:41::: ARP, Request who-has 172.16.2.1 tell 172.16.2.2, length 28
```

On pe3 every copy that arrived with its leaf argument
(`srv6_l2_leaf_decap`) was kept away from leaf3 (`l2_drop_etree_bum`):

```shell
pe3>show ebpf stats
...
l2_drop_etree_bum 14
srv6_l2_leaf_decap 14
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| p | core router | `lo` 2001:db8::9/128, LOC9 fcbb:bbbb:9::/48, `p-pe1` 2001:db8:9:1::2/64, `p-pe2` 2001:db8:9:2::2/64, `p-pe3` 2001:db8:9:3::2/64 |
| pe1 | PE, E-TREE root site | `lo` 2001:db8::1/128, LOC1 fcbb:bbbb:1::/48, `pe1-p` 2001:db8:9:1::1/64, router-id 10.0.0.1 |
| pe2 | PE, E-TREE leaf site | `lo` 2001:db8::2/128, LOC2 fcbb:bbbb:2::/48, `pe2-p` 2001:db8:9:2::1/64, router-id 10.0.0.2 |
| pe3 | PE, E-TREE leaf site | `lo` 2001:db8::3/128, LOC3 fcbb:bbbb:3::/48, `pe3-p` 2001:db8:9:3::1/64, router-id 10.0.0.3 |
| line1, line2 | E-LINE CEs | 172.16.1.1/24, 172.16.1.2/24 |
| lan1, lan2, lan3 | E-LAN hosts | 172.16.2.1/24, .2, .3 |
| root1 | E-TREE root | 172.16.3.1/24 |
| leaf2, leaf3 | E-TREE leaves | 172.16.3.2/24, 172.16.3.3/24 |
