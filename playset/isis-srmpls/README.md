# IS-IS SR-MPLS & TI-LFA & SRLG & FlexAlgo

This is IS-IS SR-MPLS playset. Every single core node has loopback address with
Prefix SID Index so that all node can reach to the prefix with SR-MPLS. The
topology is taken from TI-LFA RFC9855. All core & edge node runs in separate
namespaces. Each node runs zebra-rs and YAML config is injected by `vtyctl
apply` command.

## Topology

<img src="../images/TI-LFA.svg" alt="My diagram">

## Up all nodes

`./up.sh` will set up all namespaces and routing daemon zebra-rs and inject
initial configration.

``` shell
$ ./up.sh
bring up
teardown: stop zebra-rs
teardown: delete namespace e1
teardown: delete namespace e2
teardown: delete namespace s
...
apply config: r3
applied
apply config: d
applied
```

Then you can examine namespaces by:

``` shell
$ ip netns
d
r3
r2
r1
n3
n2
n1
s
e2
e1
```

## Exmine routes in node `s`

Let's take a look into routing table of node `s`. Following command take you
into the node `s`'s vty shell.

``` shell
$ sudo ip netns exec s vty
```

`show ip route` command shows all of IPv4 routing information.

``` shell
s>show ip route
Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

C  *> 10.0.0.1/32 is directly connected, lo, 00:11:19
L2 *> 10.0.0.2/32 [115/11] via 192.168.10.2, s-n1, label (16200), 00:11:13
L2 *> 10.0.0.3/32 [115/11] via 192.168.3.2, s-n2, label (16300), 00:11:13
L2 *> 10.0.0.4/32 [115/1010] via 192.168.11.2, s-n3, label (16400), 00:11:13
L2 *> 10.0.0.5/32 [115/12] via 192.168.3.2, s-n2, label 16500, weight 1, 00:11:13
                           via 192.168.10.2, s-n1, label 16500, weight 1, 00:11:13
L2 *> 10.0.0.6/32 [115/12] via 192.168.10.2, s-n1, label 16600, 00:11:12
L2 *> 10.0.0.7/32 [115/13] via 192.168.10.2, s-n1, label 16700, 00:11:10
L2 *> 10.0.0.8/32 [115/12] via 192.168.10.2, s-n1, label 16800, 00:11:12
C  *> 127.0.0.0/8 is directly connected, lo, 00:11:22
C  *> 172.168.0.0/24 is directly connected, s-e1, 00:11:19
S  *> 172.168.1.0/24 [1/0] via 10.0.0.8, s-n1, label 16800, 00:11:19
L2 *> 192.168.2.0/24 [115/2] via 192.168.10.2, s-n1, 00:11:13
C  *> 192.168.3.0/24 is directly connected, s-n2, 00:11:19
L2    192.168.3.0/24 [115/2] via 192.168.3.2, s-n2, 00:11:13
L2 *> 192.168.4.0/24 [115/1002] via 192.168.3.2, s-n2, weight 1, 00:11:13
                                via 192.168.10.2, s-n1, weight 1, 00:11:13
L2 *> 192.168.5.0/24 [115/3] via 192.168.10.2, s-n1, 00:11:12
L2 *> 192.168.6.0/24 [115/2] via 192.168.10.2, s-n1, 00:11:13
L2 *> 192.168.7.0/24 [115/2] via 192.168.3.2, s-n2, 00:11:13
L2 *> 192.168.8.0/24 [115/2] via 192.168.10.2, s-n1, 00:11:13
L2 *> 192.168.9.0/24 [115/1002] via 192.168.10.2, s-n1, 00:11:12
C  *> 192.168.10.0/24 is directly connected, s-n1, 00:11:19
L2    192.168.10.0/24 [115/2] via 192.168.10.2, s-n1, 00:11:13
C  *> 192.168.11.0/24 is directly connected, s-n3, 00:11:19
L2    192.168.11.0/24 [115/2000] via 192.168.11.2, s-n3, 00:11:13
L2 *> 192.168.12.0/24 [115/1002] via 192.168.3.2, s-n2, weight 1, 00:11:13
                                 via 192.168.10.2, s-n1, weight 1, 00:11:13
```

## `ping` to node `d`

## Examine MPLS encapsulated packet on node `n1`

## Take a look into configuration in YAML

We can see the configuration of node `s` in `s.yaml`. When startup, this
configuration is applyed to namespace `s`'s zebra-rs instance with `vtyctl apply
-f s.yaml`. If you are familiar with Kubernetes configuration, it is exactly
same as `kubectl apply -f config.yaml`.

``` yaml
interface:
- if-name: lo
  ipv4:
    address: 10.0.0.1/32
- if-name: s-e1
  ipv4:
    address: 172.168.0.2/24
- if-name: s-n1
  ipv4:
    address: 192.168.10.1/24
- if-name: s-n2
  ipv4:
    address: 192.168.3.1/24
- if-name: s-n3
  ipv4:
    address: 192.168.11.1/24
router:
  isis:
    net: 49.0000.0000.0000.0001.00
    hostname: s
    is-type: level-2-only
    segment-routing:
      mpls: {}
    te-router-id: 10.0.0.1
    interface:
    - if-name: lo
      ipv4:
        enabled: true
        prefix-sid:
          index: 100
    - if-name: s-n1
      ipv4:
        enabled: true
      metric: 1
    - if-name: s-n2
      ipv4:
        enabled: true
      metric: 1
    - if-name: s-n3
      ipv4:
        enabled: true
      metric: 1000
  static:
    ipv4:
      route:
      - prefix: 172.168.1.0/24
        nexthop:
        - address: 10.0.0.8

```

## `show mpls ilm` to examine ILM (Incoming Routing Map)

``` shell
s>show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> i 115  15000  Pop         SR Adj (idx 0  )   s-n1         192.168.10.2
*> i 115  15001  Pop         SR Adj (idx 1  )   s-n2         192.168.3.2
*> i 115  15002  Pop         SR Adj (idx 2  )   s-n3         192.168.11.2
*> i 115  16100  Pop         SR Pfx (idx 100)   lo           10.0.0.1
*> i 115  16200  Pop         SR Pfx (idx 200)   s-n1         192.168.10.2
*> i 115  16300  Pop         SR Pfx (idx 300)   s-n2         192.168.3.2
*> i 115  16400  Pop         SR Pfx (idx 400)   s-n3         192.168.11.2
*> i 115  16500  16500       SR Pfx (idx 500)   s-n2         192.168.3.2
*> i 115  16500  16500       SR Pfx (idx 500)   s-n1         192.168.10.2
*> i 115  16600  16600       SR Pfx (idx 600)   s-n1         192.168.10.2
*> i 115  16700  16700       SR Pfx (idx 700)   s-n1         192.168.10.2
*> i 115  16800  16800       SR Pfx (idx 800)   s-n1         192.168.10.2
```

## Enabling TI-LFA

## Force Backup to be Primary

## `ping` to `d` on Backup

## Examine MPLS Labels on Backup Path

## Appendix: Core Addresses & Prefix SID Index

| name | address         |SID Index|Prefix SID|
|:-----|:----------------|:--|:--|
| s    | 10.0.0.1/32     |100|16100|
| n1   | 10.0.0.2/32     |200|16200|
| n2   | 10.0.0.3/32     |300|16300|
| n3   | 10.0.0.4/32     |400|16400|
| r1   | 10.0.0.5/32     |500|16500|
| r2   | 10.0.0.6/32     |600|16600|
| r3   | 10.0.0.7/32     |700|16700|
| d    | 10.0.0.8/32     |800|16800|

| name | address         |
|:-----|:----------------|
| e1   | 172.168.0.1/32  |
| e2   | 172.168.10.2/32 |

