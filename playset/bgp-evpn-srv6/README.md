# EVPN over SRv6: a stretched segment in eBPF

This demo stretches one L2 segment (E-LAN) between two hosts over an
**SRv6** data plane — the eBPF counterpart of
[bgp-evpn-vxlan4](../bgp-evpn-vxlan4/README.md). The EVPN control plane is
the same (Type-2 MAC/IP + Type-3 IMET, ingress replication); what changes
is the service binding: under `encapsulation srv6` the routes carry **SRv6
L2 Service SIDs** (RFC 9252) carved from each PE's locator — a per-VNI
**End.DT2U** on the Type-2 and an **End.DT2M** on the Type-3 — instead of
the VXLAN encapsulation, and every frame rides MAC-in-SRv6.

The kernel cannot forward this (no End.DT2U/DT2M action), so
`system ebpf enabled` makes zebra-rs spawn the cradle engine: the host
ports become its L2 ports in bridge domain 100, MACs are learned in XDP
and streamed back over WatchFdb (each becoming a Type-2), and remote MACs
install as eBPF FDB entries pointing at the peer's service SID. The
`vxlan100` device enslaved to `br100` is only the VNI declaration — the
kernel path stays inert.

```
 h1 ── pe1 ══════════ pe2 ── h2      h1/h2: 172.16.10.1/24, .2/24
       2001:db8:0:12::/64            pe1: lo 2001:db8::1, LOC1 fcbb:bbbb:1::/48
       IS-IS SRv6 underlay           pe2: lo 2001:db8::2, LOC2 fcbb:bbbb:2::/48
             VNI 100 / bridge domain 100 stretched across
```

## Bring up all nodes

```shell
$ ./up.sh
...
apply config: h2
applied
```

## Take a look at the YAML configuration

`pe1.yaml` in full — `pe2.yaml` mirrors it, and the hosts are plain
tenants with one address each:

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
- if-name: pe1-h1
  bridge: br100
  ebpf:
    enabled: true
bridge:
- name: br100
vxlan:
- name: vxlan100
  vni: 100
  local-address: 2001:db8::1
  bridge: br100
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
      advertise-all-vni: true
      encapsulation: srv6
    neighbor:
    - remote-address: 2001:db8::2
      remote-as: 65001
      update-source: 2001:db8::1
      enabled: true
      afi-safi:
      - name: evpn
        enabled: true
```

* `encapsulation srv6` swaps the service binding: DT2U/DT2M SIDs from
  `LOC1` instead of VNIs-with-VXLAN-EC. `advertise-all-vni` originates for
  every declared VNI.
* The host port is enslaved to `br100` and marked `ebpf enabled` — that is
  what makes it the engine's L2 port in bridge domain 100 (the bd follows
  the bridge's VXLAN slave VNI).

## Ping, then look at what it built

Everything is dynamic — no static ARP, no static FDB anywhere. h1's first
ARP floods over the ingress-replication tunnel (End.DT2M), the engine
learns both hosts' MACs in XDP, and each becomes a Type-2:

```shell
$ sudo ip netns exec h1 ping -c 3 172.16.10.2
...
3 packets transmitted, 3 received, 0% packet loss, time 618ms
```

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn
   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 10.0.0.1:100
 *>  [2]:[0]:[48]:[ce:c5:b5:8f:b5:e4]
                    2001:db8::1                0         32768 i
                    Local SID: fcbb:bbbb:1:41:: (End.DT2U)
                    Extended community: RT:65001:100 ET:8
 *>  [3]:[0]:[128]:[2001:db8::1]
                    2001:db8::1                0         32768 i
                    Local SID: fcbb:bbbb:1:40:: (End.DT2M)
                    Extended community: RT:65001:100 ET:8
                    PMSI: ingress-replication endpoint:2001:db8::1 vni:100
Route Distinguisher: 10.0.0.2:100
 *>  [2]:[0]:[48]:[ca:c4:f0:78:ef:a5]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:41:: (End.DT2U)
                    Extended community: RT:65001:100 ET:8
 *>  [3]:[0]:[128]:[2001:db8::2]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:40:: (End.DT2M)
                    Extended community: RT:65001:100 ET:8
```

The engine's FDB shows the split: locally-learned MACs with an age, remote
MACs bound to the peer's End.DT2U SID:

```shell
pe1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
ce:c5:b5:8f:b5:e4    100        2 learned       4418
ca:c4:f0:78:ef:a5    100        0 remote           0 fcbb:bbbb:2:41::
```

And the counters carry the whole story — BUM flooded over the tunnel,
unicast switched locally or MAC-in-SRv6 encapsulated, everything decapped
on the way in:

```shell
pe1>show ebpf stats
...
l2_forward     5
l2_flood       12
srv6_l2_encap  1
srv6_l2_decap  13
srv6_l2_bum    12
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| h1 | tenant host | `h1-pe1` 172.16.10.1/24 |
| pe1 | PE | `lo` 2001:db8::1/128, `pe1-pe2` 2001:db8:0:12::1/64, LOC1 `fcbb:bbbb:1::/48` |
| pe2 | PE | `lo` 2001:db8::2/128, `pe2-pe1` 2001:db8:0:12::2/64, LOC2 `fcbb:bbbb:2::/48` |
| h2 | tenant host | `h2-pe2` 172.16.10.2/24 |
