# EVPN over MPLS: a stretched segment in eBPF

This demo stretches one L2 segment (E-LAN) between two hosts over
**MPLS** — RFC 7432's original encapsulation, and the one the Linux
kernel cannot forward at all: no kernel action pops an MPLS label and
hands the exposed Ethernet frame to a bridge. The eBPF data plane is the
service end to end, with a pure-transit **P router** between the PEs.

Three layers compose, each from a different protocol:

* **IS-IS SR-MPLS** distributes the transport labels to the PE loopbacks;
* **iBGP L2VPN-EVPN** under `encapsulation mpls` gives the `evi 100`
  instance a dynamic **per-EVI service label**, advertised on its Type-2
  and Type-3 routes (in the PMSI for the BUM tunnel) instead of a VNI,
  and installs the bridge-domain decap ILM at it;
* the FibHandle tee programs the engine: remote MACs impose the far PE's
  service label under the transport LSP, the Type-3 becomes a
  replication slot, and the ILM pops arriving service labels into bridge
  domain 100.

The P router carries no EVPN state whatsoever — no BGP, no EVI. It
label-switches the transport label and, as penultimate hop for both
loopbacks, pops it, exposing the service label to the egress PE.

```
 h1 ── pe1 ═══════ p ═══════ pe2 ── h2     h1/h2: 172.16.10.1/24, .2/24
     10.250.0.0/30   10.250.0.4/30         pe1: lo 1.1.1.1, SID index 1
        IS-IS SR-MPLS underlay             p:   lo 3.3.3.3, SID index 3
                                           pe2: lo 2.2.2.2, SID index 2
             EVI 100 / bridge domain 100 stretched across
```

## Bring up all nodes

```shell
$ ./up.sh
...
start zebra-rs: h2
sleep 3sec
```

(`up.sh` also turns kernel forwarding off on pe1/p/pe2 and computes TCP
checksums in software on the PEs' core veths — router-originated TCP
entering an XDP-forwarded core carries deferred checksums that an XDP
redirect never resolves, which would stall the BGP session while ICMP
flows fine.)

## Take a look at the YAML configuration

`pe1.yaml` in full — `pe2.yaml` mirrors it, `p.yaml` is IS-IS only, and
the hosts are plain tenants:

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
- if-name: pe1-h1
  bridge: br100
  ebpf:
    enabled: true
bridge:
- name: br100
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
      advertise-all-vni: true
      encapsulation: mpls
      evi:
      - id: 100
        bridge: br100
    neighbor:
    - remote-address: 2.2.2.2
      remote-as: 65000
      update-source: 1.1.1.1
      enabled: true
      afi-safi:
      - name: evpn
        enabled: true
```

* `encapsulation mpls` + the `evi` list: there is no VXLAN device to read
  a VNI from, so an MPLS bridge domain is declared explicitly — `id 100`
  is the RD/RT number *and* the bridge domain, pinned to `br100`.
* The service label is dynamic (drawn from the same block VRF labels come
  from); nothing about labels appears in the configuration.

## Ping, then look at what it built

Fully dynamic — no static ARP, labels, or FDB anywhere. h1's first ARP
floods over the ingress-replication slot toward pe2's BUM label; the
learned MACs come back as Type-2s carrying the EVI service label:

```shell
$ sudo ip netns exec h1 ping -c 3 172.16.10.2
...
3 packets transmitted, 3 received, 0% packet loss, time 614ms
```

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn
   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 1.1.1.1:100
 *>  [2]:[0]:[48]:[92:bb:f8:55:7b:35]
                    1.1.1.1                    0         32768 i
                    Extended community: RT:65000:100
 *>  [3]:[0]:[32]:[1.1.1.1]
                    1.1.1.1                    0         32768 i
                    Extended community: RT:65000:100
                    PMSI: ingress-replication endpoint:1.1.1.1 label:16
Route Distinguisher: 2.2.2.2:100
 *>  [2]:[0]:[48]:[5e:22:85:78:70:06]
                    2.2.2.2                    0    100      0 i
                    Extended community: RT:65000:100
 *>  [3]:[0]:[32]:[2.2.2.2]
                    2.2.2.2                    0    100      0 i
                    Extended community: RT:65000:100
                    PMSI: ingress-replication endpoint:2.2.2.2 label:16
```

Note what is **absent**: no Encapsulation extended community — RFC 8365
§5.1.3 makes MPLS the default, signalled by omission (compare the
`ET:8` in the [VXLAN](../bgp-evpn-vxlan4/README.md) and
[SRv6](../bgp-evpn-srv6/README.md) labs) — and the PMSI's 24-bit field
reads `label:`, not `vni:`. The decap side is the EVI's ILM:

```shell
pe1>show mpls ilm
*> B 20   16     Pop         EVPN Decap (bd 100 ) -
```

The counters on pe1 show the service legs, and the P router did all its
work with zero EVPN state — pure label switching, popping the transport
label as penultimate hop:

```shell
pe1>show ebpf stats
...
mpls_l2_encap  1
mpls_l2_decap  11
mpls_l2_bum    10
```

```shell
p>show ebpf stats
...
mpls_pop       52
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| h1 | tenant host | `h1-pe1` 172.16.10.1/24 |
| pe1 | PE | `lo` 1.1.1.1/32, `pe1-p` 10.250.0.1/30, SID index 1 |
| p | transit LSR | `lo` 3.3.3.3/32, `p-pe1` 10.250.0.2/30, `p-pe2` 10.250.0.5/30, SID index 3 |
| pe2 | PE | `lo` 2.2.2.2/32, `pe2-p` 10.250.0.6/30, SID index 2 |
| h2 | tenant host | `h2-pe2` 172.16.10.2/24 |
