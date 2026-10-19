# EVPN services over MPLS: E-LINE, E-LAN and E-TREE in eBPF

This lab runs all three Ethernet services at once over **MPLS**, RFC 7432's
original EVPN encapsulation, with a pure-transit P router in the core:

| Service | EVPN flavour | EVI | CEs | Subnet |
|:--|:--|:--|:--|:--|
| **E-LINE** — a point-to-point wire | VPWS (RFC 8214) | 300 | line1 ↔ line2 | 172.16.1.0/24 |
| **E-LAN** — a multipoint LAN | EVPN bridging (RFC 7432) | 100 | lan1, lan2, lan3 | 172.16.2.0/24 |
| **E-TREE** — a hub and its spokes | EVPN E-Tree (RFC 8317) | 200 | root1 (root), leaf2, leaf3 (leaves) | 172.16.3.0/24 |

The topology, addressing and services are the same in all three labs of
this series. Only the encapsulation changes:
[bgp-evpn-services-vxlan](../bgp-evpn-services-vxlan/README.md), this
one and [bgp-evpn-services-srv6](../bgp-evpn-services-srv6/README.md).

![EVPN services topology](../images/BgpEvpnServices.svg)

```
  line1 ─┐                             ┌─ line2
  lan1  ─┼─ pe1 ═══════ p ═══════ pe2 ─┼─ lan2
  root1 ─┘              ║              └─ leaf2
                        ║
                       pe3 ─┬─ lan3
                            └─ leaf3
```

The Linux kernel cannot forward any of these services: it has no action
that pops an MPLS label into a bridge or onto a port. So every router,
P included, runs the cradle eBPF engine (`system ebpf enabled`), and three
protocols compose:

* **IS-IS SR-MPLS** gives each loopback a prefix SID (index = node
  number, SRGB 16000), and so the transport LSPs between the PEs;
* **iBGP EVPN** under `encapsulation mpls` gives every service a
  **dynamic service label** in place of a VNI;
* the engine pushes the service label under the transport label, and
  P label-switches the transport label, popping it as the penultimate hop.

P carries no BGP and no EVPN state.

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
* turns kernel IPv4 forwarding off on the PEs and P;
* computes TCP checksums in software on the PEs' core veths. A PE's
  iBGP segments cross P's XDP forwarding with deferred checksums that an
  XDP redirect never resolves.

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
router:
  bgp:
    afi-safi:
    - name: evpn
      advertise-all-vni: true
      encapsulation: mpls
      evi:
      - id: 100
        bridge: br100
      - id: 200
        bridge: br200
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
two differences:

* `encapsulation mpls`, and
* with no VXLAN device to declare a VNI, the `evi` list pins each
  bridge-domain EVI to its bridge.

The `vpws` and `etree` statements are identical. No label appears in the
configuration: each one is drawn from the dynamic label block.

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
                    Extended community: RT:65000:100
 *>  [3]:[0]:[32]:[10.0.0.1]
                    10.0.0.1                   0         32768 i
                    Extended community: RT:65000:100
                    PMSI: ingress-replication endpoint:10.0.0.1 label:24000
...
Route Distinguisher: 10.0.0.2:0
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[4294967295]
                    10.0.0.2                   0    100      0 i
                    Extended community: RT:65000:200 etree:leaf-label:24003
...
Route Distinguisher: 10.0.0.2:200
 *>  [2]:[0]:[48]:[02:00:00:00:03:02]
                    10.0.0.2                   0    100      0 i
                    Extended community: RT:65000:200 etree:leaf
 *>  [3]:[0]:[32]:[10.0.0.2]
                    10.0.0.2                   0    100      0 i
                    Extended community: RT:65000:200
                    PMSI: ingress-replication endpoint:10.0.0.2 label:24001
...
```

Note what is **absent**: no Encapsulation EC (RFC 8365 §5.1.3 makes MPLS
the default, signalled by omission), and the PMSI reads `label:`, not
`vni:`. Note also a route the VXLAN lab does not have:

* **The leaf-label route** (RFC 8317 §4.2.1). Each PE with a leaf AC draws
  one more label, its **leaf label**, and advertises it on an Ethernet A-D
  route with ESI 0 and the MAX-ET tag, under RD `<router-id>:0`. The route
  carries the RT of every EVI that has a leaf AC. pe2's leaf label is
  24003 and pe3's is 24002.

The E-LINE's Type-1 carries its own per-service label:

```shell
pe1>show bgp evpn vpws
VPWS service: eline1
  EVI: 300
  Service ID: local 1, remote 2
  Interface: pe1-line1
  Local Label: 24002
  Remote PE: 10.0.0.2 (label 24002) (via 10.0.0.2)
  State: up
```

On every PE the bridge-domain labels decapsulate into their EVI's bridge
domain:

```shell
pe1>show mpls ilm
...
*> i 115  16002  16002       SR Pfx (idx 2  )   pe1-p        10.9.1.2
*> i 115  16003  16003       SR Pfx (idx 3  )   pe1-p        10.9.1.2
...
*> B 20   24000  Pop         EVPN Decap (bd 100 ) -
*> B 20   24001  Pop         EVPN Decap (bd 200 ) -
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

BUM follows RFC 8317 §4.2 as written. A copy of a leaf's BUM toward a PE
that has a leaf label carries that label **under** the EVI's BUM label.
The receiving PE recognises its own leaf label and delivers the frame to
its roots only:

```shell
pe2>show bgp evpn etree
EVPN E-Tree (RFC 8317)
  Leaf interfaces: 1
    pe2-leaf2        ifindex 5      EVI 200        local MACs 1
  Remote leaf MACs:
    EVI 200        1
  Leaf label:      24003
  Remote leaf labels:
    10.0.0.3         24002
```

pe1 has no leaf of its own, so it has no leaf label. It knows both other
PEs' labels:

```shell
pe1>show bgp evpn etree
EVPN E-Tree (RFC 8317)
  Leaf interfaces: 0
  Remote leaf MACs:
    EVI 200        2
  Leaf label:      none
  Remote leaf labels:
    10.0.0.2         24003
    10.0.0.3         24002
```

The counters show the label at work. Each leaf ARP broadcast pe2 floods
toward pe3 is pushed with pe3's leaf label (`mpls_l2_leaf_push` on pe2).
pe3 pops the label (`mpls_l2_leaf_pop`) and keeps the copy away from
leaf3 (`l2_drop_etree_bum`). The two numbers match:

```shell
pe2>show ebpf stats
...
mpls_l2_leaf_push 15
...
pe3>show ebpf stats
...
mpls_l2_leaf_pop 15
l2_drop_etree_bum 15
```

The copy toward pe1 goes unmarked: pe1 advertised no leaf label, so it
has no leaves to protect, and root1 gets the broadcast.

P label-switched all of it without a single EVPN route:

```shell
p>show ebpf stats
...
mpls_pop       303
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| p | transit LSR | `lo` 10.0.0.9/32 (SID index 9), `p-pe1` 10.9.1.2/30, `p-pe2` 10.9.2.2/30, `p-pe3` 10.9.3.2/30 |
| pe1 | PE, E-TREE root site | `lo` 10.0.0.1/32 (SID index 1), `pe1-p` 10.9.1.1/30 |
| pe2 | PE, E-TREE leaf site | `lo` 10.0.0.2/32 (SID index 2), `pe2-p` 10.9.2.1/30 |
| pe3 | PE, E-TREE leaf site | `lo` 10.0.0.3/32 (SID index 3), `pe3-p` 10.9.3.1/30 |
| line1, line2 | E-LINE CEs | 172.16.1.1/24, 172.16.1.2/24 |
| lan1, lan2, lan3 | E-LAN hosts | 172.16.2.1/24, .2, .3 |
| root1 | E-TREE root | 172.16.3.1/24 |
| leaf2, leaf3 | E-TREE leaves | 172.16.3.2/24, 172.16.3.3/24 |
