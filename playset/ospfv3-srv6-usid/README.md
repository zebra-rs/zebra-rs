# OSPFv3 SRv6 (uSID) & TI-LFA

This playset is the **uSID** (compressed SID, NEXT-C-SID flavor — RFC 9800)
variant of the [OSPFv3 SRv6 classic playset](../ospfv3-srv6-classic/README.md),
mirroring what the [IS-IS uSID playset](../isis-srv6-usid/README.md) does
for its classic sibling. The topology, addressing, BGP End.DT6 service
layer, and the walkthrough arc are identical to the OSPFv3 classic lab —
the *only* configuration difference is one line per node:

``` yaml
segment-routing:
  locator:
  - name: LOC1
    prefix: fcbb:bbbb:1::/48
    behavior: usid          # <-- this line
```

The locator's 48 bits split into the domain-wide 32-bit uSID block
(`fcbb:bbbb`) and a 16-bit node id; SIDs become 16-bit micro-instructions
packed into 128-bit carriers. See the IS-IS uSID README for the full
shift-and-forward mechanics (uN on the locator /48, dual addressed/shifted
uA forms) — the kernel state here is identical apart from the `proto ospf`
attribution, advertised through the OSPFv3 RFC 9513 extensions instead of
IS-IS TLVs:

``` shell
s>ip -6 route show fcbb:bbbb:1::/48
fcbb:bbbb:1::/48  encap seg6local action End flavors next-csid lblen 32 nflen 16 dev sr0 proto ospf metric 1024
```

## TI-LFA: packed carriers in the v3 repair list

``` shell
s>configure
s#set router ospfv3 fast-reroute ti-lfa
s#commit
s#exit
s>show ipv6 route
...
O  *> 2001:db8::8/128 [110/2] via fe80::e0e9:7eff:fe20:d4d, s-n1, 00:00:00
   *?                 [110/3] via seg6 [fcbb:bbbb:5:e001:e001::], s-n2, 00:00:00
s>show ospfv3 repair-list
Prefix                         Primary via                Repair via                 Segments
2001:db8::6/128                fe80::e0e9:7eff:fe20:d4d   fe80::2cee:2dff:fed5:6ef2  [fcbb:bbbb:5:e001::]
2001:db8::7/128                fe80::e0e9:7eff:fe20:d4d   fe80::2cee:2dff:fed5:6ef2  [fcbb:bbbb:5:e001:e001::]
2001:db8::8/128                fe80::e0e9:7eff:fe20:d4d   fe80::2cee:2dff:fed5:6ef2  [fcbb:bbbb:5:e001:e001::]
2001:db8:9::/64                fe80::e0e9:7eff:fe20:d4d   fe80::2cee:2dff:fed5:6ef2  [fcbb:bbbb:5:e001::]
2001:db8:11::/64               fe80::e0e9:7eff:fe20:d4d   fe80::2cee:2dff:fed5:6ef2  [fcbb:bbbb:5:e001:e001::]
fcbb:bbbb:6::/48               fe80::e0e9:7eff:fe20:d4d   fe80::2cee:2dff:fed5:6ef2  [fcbb:bbbb:5:e001::]
...
```

Every repair is a **single carrier**: `fcbb:bbbb` + uN(r1) + one or two uA
micro-instructions walking the expensive r-plane links (in the classic v3
lab each of those was its own 128-bit SID; the exact uA function values
are allocated per adjacency and differ between runs).

## Promotion and the wire

``` shell
s>configure
s#set router ospfv3 fast-reroute backup-as-primary
s#commit
s#exit
s>show ipv6 route
...
O  *> 2001:db8::8/128 [110/2] via seg6 [fcbb:bbbb:5:e001:e001::], s-n2, 00:00:05
   *?                 [110/3] via fe80::e0e9:7eff:fe20:d4d, s-n1, 00:00:05
...
B  *> 2001:db8:200::/64 [200/0] via seg6 [fcbb:bbbb:8:40::], s-n2, 00:00:49
```

The BGP service route follows the promoted locator underneath, and the
protected edge-to-edge traffic (e1 → e2, still pinging fine) shows the
compressed repair stacked over the service encapsulation — the repair SRH
is two entries (`len=4, segleft=1`) instead of the classic lab's four:

``` shell
n1>tcpdump -nli n1-s ip6 proto 43
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on n1-s, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:31:53.771652 IP6 2001:db8:1::1 > fcbb:bbbb:5:e001:e001::: RT6 (len=4, type=4, segleft=1, last-entry=1, tag=0, [0]fcbb:bbbb:8:40::, [1]fcbb:bbbb:5:e001:e001::) RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fcbb:bbbb:8:40::) IP6 2001:db8:100::100 > 2001:db8:200::100: ICMP6, echo request, id 31973, seq 4, length 64
```

Read inside-out: the host packet, the End.DT6 service encapsulation
(`segleft=0`), and the inserted TI-LFA repair whose single carrier steers
the whole post-convergence path with the service SID as its final segment.

## Everything else

...is the OSPFv3 classic lab, unchanged: topology and appendix tables, the
RFC 9252 service layer, the convergence notes, the
[static-route walkthrough](../ospfv3-srv6-classic/README.md#static-routes-over-the-srv6-core)
(its commands run identically here — only the locator routes render as
uN carriers), and the walkthrough commands. Run the two side by side
(one at a time) and compare `show ospfv3 repair-list` and the SRH
sizes on the wire.
