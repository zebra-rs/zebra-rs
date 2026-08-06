# EVPN VPWS: E-Line over VXLAN

This demo runs a point-to-point **E-Line** (EVPN VPWS, RFC 8214) over a
plain VXLAN fabric (RFC 8365 §6) — no SRv6 locator, no MPLS, and under the
**default** `encapsulation vxlan`, so the whole configuration is the
service itself. Two CEs are cross-connected as a transparent wire: no MAC
learning, no FDB, no flooding.

Each PE advertises a per-EVI Ethernet A-D route (Type-1) with its **service
VNI in the label field**, the VXLAN Encapsulation extended community, and
its loopback VTEP as next hop. The VNIs are deliberately **asymmetric**:
pe1 pins `vni 5001`, pe2 lets its VNI default to the EVI (100) — the label
field is downstream-assigned, so each PE simply encapsulates with what its
peer advertised. Forwarding runs on the eBPF data plane
(`system ebpf enabled` spawns the cradle engine) — the kernel has no
VNI-to-port E-Line disposition.

```
 c1 ── pe1 ══════════ pe2 ── c2      c1/c2: 10.0.0.1/24, 10.0.0.2/24
        10.0.12.0/24                 pe1: lo/VTEP 192.0.2.1, vni 5001
       IPv4 underlay                 pe2: lo/VTEP 192.0.2.2, vni = evi = 100
   vpws eline1: evi 100, pe1 svc-id 101 ⇄ pe2 svc-id 102
```

The VTEPs are the loopbacks and BGP peers over them, so the advertised
Type-1 next hop *is* the VTEP; a static /32 toward the peer's VTEP resolves
the datapath encapsulation, and the underlay ARP the BGP session performs
seeds the engine's neighbor table — everything the datapath needs arrives
over the tee.

## Bring up all nodes

```shell
$ ./up.sh
...
seed config: c2
...
start zebra-rs: c2
sleep 3sec
```

## Take a look at the YAML configuration

`pe1.yaml` in full — `pe2.yaml` mirrors it without the `vni` leaf:

```yaml
system:
  hostname: pe1
  ebpf:
    enabled: true
interface:
- if-name: lo
  ipv4:
    address: 192.0.2.1/32
- if-name: pe1-pe2
  ipv4:
    address: 10.0.12.1/24
  ebpf:
    enabled: true
- if-name: pe1-c1
  ebpf:
    enabled: true
router:
  static:
    ipv4:
      route:
      - prefix: 192.0.2.2/32
        nexthop:
        - address: 10.0.12.2
  bgp:
    global:
      as: 65001
      router-id: 192.0.2.1
    timer:
      adv-interval:
        ibgp: 1
    afi-safi:
    - name: evpn
      vpws:
      - name: eline1
        evi: 100
        local-service-id: 101
        remote-service-id: 102
        interface: pe1-c1
        vni: 5001
    neighbor:
    - remote-address: 192.0.2.2
      remote-as: 65001
      update-source: 192.0.2.1
      enabled: true
      afi-safi:
      - name: evpn
        enabled: true
```

* No `encapsulation` leaf: `vxlan` is the default.
* `vni 5001` is what pe1 advertises — the VNI the *remote* encapsulates
  toward pe1 with, and pe1's decap identity. Unset (as on pe2) it defaults
  to the EVI.
* The router-id is the loopback VTEP and the session runs over it
  (`update-source`), so the address the peer sends VXLAN to and the
  address this PE accepts can never disagree.

## The E-Line comes up — with a different VNI per direction

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: pe1-c1
  Local VNI: 5001
  Remote VTEP: 192.0.2.2 (VNI 100) (via 192.0.2.2)
  State: up
```

pe2 shows the mirror image — it advertised the EVI default and bound pe1's
explicit 5001:

```shell
pe2>show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 102, remote 101
  Interface: pe2-c2
  Local VNI: 100
  Remote VTEP: 192.0.2.1 (VNI 5001) (via 192.0.2.1)
  State: up
```

On the wire the Type-1s carry the VXLAN Encapsulation extended community
(`ET:8`, RFC 9012 tunnel type 8) — the marker that distinguishes this
E-Line from the MPLS form, which signals by the EC's *absence*:

```shell
pe1>show bgp evpn
   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 192.0.2.1:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[101]
                    192.0.2.1                  0         32768 i
                    Extended community: RT:65001:100 ET:8 l2-attr:P:mtu0
Route Distinguisher: 192.0.2.2:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[102]
                    192.0.2.2                  0    100      0 i
                    Extended community: RT:65001:100 ET:8 l2-attr:P:mtu0
```

## Ping across the wire

Kernel forwarding is off on both PEs, so this — ARP included — rides the
eBPF cross-connect as VXLAN end to end:

```shell
$ sudo ip netns exec c1 ping -c 3 10.0.0.2
...
3 packets transmitted, 3 received, 0% packet loss, time 612ms
```

The counters show the two E-Line legs and, just as telling, what stayed at
zero: an E-Line never floods and never touches the bridged-VXLAN path:

```shell
pe1>show ebpf stats
...
vxlan_encap    4
vxlan_decap    0
vxlan_flood    0
vxlan_dx2      4
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| c1 | CE | `c1-pe1` 10.0.0.1/24 |
| pe1 | PE / VTEP | `lo` 192.0.2.1/32, `pe1-pe2` 10.0.12.1/24, VNI 5001 |
| pe2 | PE / VTEP | `lo` 192.0.2.2/32, `pe2-pe1` 10.0.12.2/24, VNI 100 (= EVI) |
| c2 | CE | `c2-pe2` 10.0.0.2/24 |
