# EVPN VPWS: E-Line over SRv6

This demo runs a point-to-point **E-Line** (EVPN VPWS, RFC 8214) over an
SRv6 data plane. Two CEs are cross-connected as a transparent wire: no MAC
learning, no FDB, no flooding — they share a subnet and resolve each other
by ARP straight through the service.

Each PE advertises a per-EVI Ethernet A-D route (Type-1) whose Ethernet Tag
is its local service instance id, carrying an **End.DX2 L2-Service
Prefix-SID** (RFC 9252 §6.3) carved from its SRv6 locator. Importing the
peer's Type-1 binds the remote SID as the attachment circuit's
cross-connect target. Forwarding runs on the eBPF data plane —
`system ebpf enabled` makes zebra-rs spawn and supervise the cradle engine
(`/usr/bin/cradle`, from the co-distributed cradle-rs package) — because
the kernel has no End.DX2 action.

```
 c1 ── pe1 ══════════ pe2 ── c2      c1/c2: 10.0.0.1/24, 10.0.0.2/24
       2001:db8:0:12::/64            pe1: lo 2001:db8::1, LOC1 fcbb:bbbb:1::/48
       IS-IS SRv6 underlay           pe2: lo 2001:db8::2, LOC2 fcbb:bbbb:2::/48
   vpws eline1: evi 100, pe1 svc-id 101 ⇄ pe2 svc-id 102
```

IS-IS carries the loopbacks and locators; the iBGP L2VPN-EVPN session runs
between the loopbacks. The CE-facing ports (`pe1-c1`, `pe2-c2`) carry no
address and no bridge — they are pure attachment circuits.

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

`pe1.yaml` in full — `pe2.yaml` mirrors it, and the CEs are plain hosts
with one address each:

```yaml
system:
  hostname: pe1
  ebpf:
    enabled: true
interface:
- if-name: lo
  ipv6:
    address: 2001:db8::1/128
- if-name: pe1-pe2
  ipv6:
    address: 2001:db8:0:12::1/64
  ebpf:
    enabled: true
- if-name: pe1-c1
  ebpf:
    enabled: true
segment-routing:
  locator:
  - name: LOC1
    prefix: fcbb:bbbb:1::/48
    behavior: usid
router:
  isis:
    net: 49.0000.0000.0000.0001.00
    hostname: pe1
    is-type: level-2-only
    segment-routing:
      srv6:
        locator: LOC1
    interface:
    - if-name: lo
      ipv6:
        enabled: true
    - if-name: pe1-pe2
      network-type: point-to-point
      metric: 1
      ipv6:
        enabled: true
  bgp:
    global:
      as: 65001
      router-id: 10.0.0.1
    timer:
      adv-interval:
        ibgp: 1
    segment-routing:
      srv6:
        locator: LOC1
    afi-safi:
    - name: evpn
      encapsulation: srv6
      vpws:
      - name: eline1
        evi: 100
        local-service-id: 101
        remote-service-id: 102
        interface: pe1-c1
    neighbor:
    - remote-address: 2001:db8::2
      remote-as: 65001
      update-source: 2001:db8::1
      enabled: true
      afi-safi:
      - name: evpn
        enabled: true
```

* `system ebpf enabled` spawns the cradle engine and implies the FIB tee;
  the two `ebpf enabled` interface leaves attach the underlay port and the
  attachment circuit to it.
* `encapsulation srv6` makes the vpws Type-1 carry an End.DX2 SID carved
  dynamically from `LOC1` — no manual SID configuration.
* The service ids cross: pe1's `local-service-id 101` is pe2's
  `remote-service-id`, and vice versa.

## The E-Line comes up

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: pe1-c1
  Local SID (End.DX2): fcbb:bbbb:1:40::
  Remote SID: fcbb:bbbb:2:40:: (via 2001:db8::2)
  State: up
```

Both Type-1 routes are in the EVPN table, each carrying its End.DX2 SID
and the RFC 8214 §3.1 Layer-2 Attributes extended community:

```shell
pe1>show bgp evpn
   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 10.0.0.1:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[101]
                    10.0.0.1                   0         32768 i
                    Local SID: fcbb:bbbb:1:40:: (End.DX2)
                    Extended community: RT:65001:100 l2-attr:P:mtu0
Route Distinguisher: 10.0.0.2:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[102]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:40:: (End.DX2)
                    Extended community: RT:65001:100 l2-attr:P:mtu0
```

## Ping across the wire

Kernel forwarding is off on both PEs, so this ping — ARP included — rides
the eBPF cross-connect end to end:

```shell
$ sudo ip netns exec c1 ping -c 3 10.0.0.2
...
3 packets transmitted, 3 received, 0% packet loss, time 609ms
```

The engine counters show both legs: MAC-in-SRv6 encapsulation at the AC
ingress, and the End.DX2 raw emit at the egress:

```shell
pe1>show ebpf stats
...
srv6_l2_encap  5
srv6_dx2       5
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| c1 | CE | `c1-pe1` 10.0.0.1/24 |
| pe1 | PE | `lo` 2001:db8::1/128, `pe1-pe2` 2001:db8:0:12::1/64, LOC1 `fcbb:bbbb:1::/48` |
| pe2 | PE | `lo` 2001:db8::2/128, `pe2-pe1` 2001:db8:0:12::2/64, LOC2 `fcbb:bbbb:2::/48` |
| c2 | CE | `c2-pe2` 10.0.0.2/24 |
