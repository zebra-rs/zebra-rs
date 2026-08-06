# EVPN over MPLS between IPv6 PEs: no IGP, no IPv4

The [bgp-evpn-mpls](../bgp-evpn-mpls/README.md) demo re-run on an
**IPv6-only core with no IGP at all**: the same stretched L2 segment
(E-LAN), the same dynamic per-EVI service label, the same pure-transit
**P router** — but every underlay address is IPv6 and the transport
labels are static. MPLS imposes no outer IP header, so the PEs' address
family lives only in the control plane and the adjacencies; RFC 7432
never required an IPv4 core, and here there isn't one.

Three pieces replace the IPv4 lab's IS-IS SR-MPLS:

* **`vtep-source`** names the v6 loopback each PE's EVPN routes advertise
  as next hop and Originating Router IP — the router-id fallback can only
  express IPv4;
* a **labeled static v6 route** per PE supplies the transport LSP toward
  the far loopback (the `label` list on an ipv6 nexthop — IS-IS
  prefix-SIDs are IPv4-only today);
* the P's **static MPLS label bindings with v6 nexthops** pop the
  transport label toward each PE (PHP). Their explicit `interface` leaf
  opts the pop onto the eBPF XDP fast path — the operator's assertion of
  a core-facing hop, since the P holds **no route** for what the pop
  exposes and the XDP redirect delivers only between XDP-attached ports.

The P carries no BGP, no EVPN state, no routes — it label-switches
between v6 adjacencies, entirely in eBPF. Even the PEs' own iBGP session
rides the LSP: pe1's kernel imposes label 100 on the TCP toward pe2's
loopback, the P's eBPF stage pops it, pe2's stack receives it plain.

```
 h1 ── pe1 ═══════ p ═══════ pe2 ── h2     h1/h2: 172.16.10.1/24, .2/24
   2001:db8:12::/64  2001:db8:23::/64      pe1: lo 2001:db8:255::1
     static labels 100 → / ← 101           pe2: lo 2001:db8:255::2
             EVI 100 / bridge domain 100 stretched across
```

## Bring up all nodes

```shell
$ ./up.sh
...
start zebra-rs: h2
sleep 3sec
```

(`up.sh` also turns kernel forwarding off — both families — on pe1/p/pe2,
computes TCP checksums in software on the PEs' core veths, and warms up
the P's neighbor entries with one ping per adjacency.)

## Ping, then read the three layers back

```shell
$ sudo ip netns exec h1 ping -c 3 172.16.10.2
...
3 packets transmitted, 3 received, 0% packet loss
```

The EVPN routes carry v6 next hops and a label (not a VNI):

```shell
$ sudo ip netns exec pe1 vty
pe1>show bgp evpn
Route Distinguisher: 1.1.1.1:100
 *>  [2]:[0]:[48]:[b6:73:86:a6:62:60]
                    2001:db8:255::1            0         32768 i
                    Extended community: RT:65000:100
 *>  [3]:[0]:[128]:[2001:db8:255::1]
                    2001:db8:255::1            0         32768 i
                    Extended community: RT:65000:100
                    PMSI: ingress-replication endpoint:2001:db8:255::1 label:16
Route Distinguisher: 2.2.2.2:100
 *>  [2]:[0]:[48]:[de:5e:45:63:20:cc]
                    2001:db8:255::2            0    100      0 i
                    Extended community: RT:65000:100
 *>  [3]:[0]:[128]:[2001:db8:255::2]
                    2001:db8:255::2            0    100      0 i
                    Extended community: RT:65000:100
                    PMSI: ingress-replication endpoint:2001:db8:255::2 label:16
```

pe1's ILM table holds its own EVI decap; the P's holds the two transport
pops with their v6 nexthops and named interfaces:

```shell
pe1>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> B 20   16     Pop         EVPN Decap (bd 100 ) -
```

```shell
$ sudo ip netns exec p vty
p>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> S 1    100    Pop         -                  p-pe2        2001:db8:23::2
*> S 1    101    Pop         -                  p-pe1        2001:db8:12::1
```

The engine's FDB binds the remote MAC to the far PE natively in its
16-byte slot, and the P's counters show the transit pops:

```shell
pe1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
b6:73:86:a6:62:60    100        2 learned         46
de:5e:45:63:20:cc    100        0 remote           0 2001:db8:255::2
```

```shell
p>show ebpf stats
...
mpls_pop       48
```

## Tear down

```shell
$ ./down.sh
```

## Appendix: Addresses

| Node | Role | Addresses |
|---|---|---|
| h1 | tenant host | `h1-pe1` 172.16.10.1/24 |
| pe1 | PE, EVI 100 | `lo` 2001:db8:255::1/128, `pe1-p` 2001:db8:12::1/64 |
| p | transit LSR | `p-pe1` 2001:db8:12::2/64, `p-pe2` 2001:db8:23::1/64 |
| pe2 | PE, EVI 100 | `lo` 2001:db8:255::2/128, `pe2-p` 2001:db8:23::2/64 |
| h2 | tenant host | `h2-pe2` 172.16.10.2/24 |
