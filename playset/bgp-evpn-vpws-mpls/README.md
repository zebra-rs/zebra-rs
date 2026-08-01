# EVPN VPWS: E-Line over MPLS

This demo runs a point-to-point **E-Line** (EVPN VPWS, RFC 8214) over
RFC 7432's original encapsulation — MPLS — with a pure-transit **P router**
between the PEs. It is the encapsulation the Linux kernel cannot forward at
all: no kernel action pops an MPLS label and emits the exposed Ethernet
frame raw on a port, so the eBPF data plane is the E-Line end to end.

Three layers compose, each from a different protocol:

* **IS-IS SR-MPLS** distributes the transport labels to the PE loopbacks;
* **iBGP L2VPN-EVPN** under `encapsulation mpls` advertises a
  **per-service label** on each vpws Type-1 — allocated dynamically from
  the same block VRF and EVI labels come from, with **no Encapsulation
  extended community** (its absence is the MPLS signal, RFC 8365 §5.1.3);
* the FibHandle tee programs the eBPF cross-connect: label imposition
  under the FIB-resolved transport LSP at the ingress AC, and a pop-to-AC
  disposition at the label this PE advertised.

The P router carries **no EVPN state whatsoever** — no BGP, no vpws. It
label-switches the transport label and, as penultimate hop for both
loopbacks, pops it, exposing the service label to the egress PE. That
layering is the demo: BGP advertises a PE, IS-IS supplies the label to
reach it, and the data plane composes the two.

```
 c1 ── pe1 ═══════ p ═══════ pe2 ── c2     c1/c2: 10.0.0.1/24, 10.0.0.2/24
     10.250.0.0/30   10.250.0.4/30         pe1: lo 1.1.1.1, SID index 1
        IS-IS SR-MPLS underlay             p:   lo 3.3.3.3, SID index 3
                                           pe2: lo 2.2.2.2, SID index 2
   vpws eline1: evi 100, pe1 svc-id 101 ⇄ pe2 svc-id 102
```

## Bring up all nodes

```shell
$ ./up.sh
...
apply config: c2
applied
```

(`up.sh` also turns kernel forwarding off on pe1/p/pe2 and computes TCP
checksums in software on the PEs' core veths — router-originated TCP
entering an XDP-forwarded core carries deferred checksums that an XDP
redirect never resolves, which would stall the BGP session while ICMP
flows fine.)

## Take a look at the YAML configuration

`pe1.yaml` in full — `pe2.yaml` mirrors it, `p.yaml` is IS-IS only:

```yaml
system:
  hostname: pe1
  ebpf:
    enabled: true
interface:
- if-name: lo
  ipv4:
    address: 1.1.1.1/32
- if-name: pe1-p
  ipv4:
    address: 10.250.0.1/30
  ebpf:
    enabled: true
- if-name: pe1-c1
  ebpf:
    enabled: true
router:
  isis:
    net: 49.0000.0000.0000.0001.00
    hostname: pe1
    is-type: level-2-only
    segment-routing: mpls
    te-router-id: 1.1.1.1
    interface:
    - if-name: lo
      ipv4:
        enabled: true
        prefix-sid:
          index: 1
    - if-name: pe1-p
      network-type: point-to-point
      metric: 10
      ipv4:
        enabled: true
  bgp:
    global:
      as: 65000
      router-id: 1.1.1.1
    timer:
      adv-interval:
        ibgp: 1
    afi-safi:
    - name: evpn
      encapsulation: mpls
      vpws:
      - name: eline1
        evi: 100
        local-service-id: 101
        remote-service-id: 102
        interface: pe1-c1
    neighbor:
    - remote-address: 2.2.2.2
      remote-as: 65000
      update-source: 1.1.1.1
      enabled: true
      afi-safi:
      - name: evpn
        enabled: true
```

* `encapsulation mpls` — the vpws needs no locator and no VNI; its service
  label is allocated dynamically.
* The next hop is the router-id: the loopback the transport LSP resolves
  on, carried by IS-IS SR-MPLS (`prefix-sid index 1`), with BGP peering
  over it — the classic MPLS-VPN shape.

## The E-Line comes up

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn vpws
VPWS service: eline1
  EVI: 100
  Service ID: local 101, remote 102
  Interface: pe1-c1
  Local Label: 16
  Remote PE: 2.2.2.2 (label 16) (via 2.2.2.2)
  State: up
```

Both labels came from each PE's dynamic block (both happen to draw 16 —
per-PE label spaces are independent). On the wire the Type-1s carry **no**
Encapsulation extended community — compare the VXLAN playset's `ET:8` —
which is exactly RFC 8365 §5.1.3's "absent means MPLS":

```shell
pe1>show bgp evpn
   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 1.1.1.1:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[101]
                    1.1.1.1                    0         32768 i
                    Extended community: RT:65000:100 l2-attr:P:mtu0
Route Distinguisher: 2.2.2.2:100
 *>  [1]:[00:00:00:00:00:00:00:00:00:00]:[102]
                    2.2.2.2                    0    100      0 i
                    Extended community: RT:65000:100 l2-attr:P:mtu0
```

## Ping across the wire

Kernel forwarding is off on all three core nodes, so this — ARP included —
rides `[transport label][service label]` through the P router end to end:

```shell
$ sudo ip netns exec c1 ping -c 3 10.0.0.2
...
3 packets transmitted, 3 received, 0% packet loss, time 611ms
```

The PE counters show the imposition and the pop-to-AC disposition — and an
E-Line never floods (`mpls_l2_bum 0`) and never bridges (`mpls_l2_decap
0`, the EVI path):

```shell
pe1>show ebpf stats
...
mpls_l2_encap  4
mpls_l2_decap  0
mpls_l2_bum    0
mpls_dx2       4
```

The P router did all its work with zero EVPN state — pure label switching,
popping the transport label as penultimate hop:

```shell
p>show ebpf stats
...
mpls_pop       29
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| c1 | CE | `c1-pe1` 10.0.0.1/24 |
| pe1 | PE | `lo` 1.1.1.1/32, `pe1-p` 10.250.0.1/30, SID index 1 |
| p | transit LSR | `lo` 3.3.3.3/32, `p-pe1` 10.250.0.2/30, `p-pe2` 10.250.0.5/30, SID index 3 |
| pe2 | PE | `lo` 2.2.2.2/32, `pe2-p` 10.250.0.6/30, SID index 2 |
| c2 | CE | `c2-pe2` 10.0.0.2/24 |
