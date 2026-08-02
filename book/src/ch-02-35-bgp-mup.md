# BGP Mobile User Plane (MUP) and the MUP Controller

zebra-rs implements **BGP Mobile User Plane** (BGP-MUP, SAFI 85) as
specified in `draft-ietf-bess-mup-safi`. BGP-MUP carries 5G
mobile-backhaul session state in BGP so that a GTP-U tunnel between a
mobile gateway and the radio access network can be stitched into an
**SRv6** transport network — the GTP encap/decap happens at the SRv6
edge instead of on a dedicated mobile gateway.

There are four MUP route types:

| Type | Name | Originated by |
|---|---|---|
| 1 | Interwork Segment Discovery (ISD) | MUP-GW / PE |
| 2 | Direct Segment Discovery (DSD) | MUP-GW / PE |
| 3 | Type-1 Session Transformed (T1ST) | **MUP Controller** |
| 4 | Type-2 Session Transformed (T2ST) | **MUP Controller** |

The **MUP Controller (MUP-C)** is the node that learns per-session
mobile state — the UE address, the GTP-U TEID, the tunnel endpoint, the
QoS flow — and turns each session into a **Session-Transformed** route
(T1ST for the access/downlink side, T2ST for the core/uplink side). The
draft leaves the controller's session source as an out-of-scope
"northbound API"; zebra-rs uses **PFCP / N4** (3GPP TS 29.244) as that
northbound and terminates it as a UP-node — an external SMF programs the
controller exactly as it would a UPF.

```
   SMF ──PFCP/N4──▶ zebra-rs MUP-C ──BGP MUP (SAFI 85)──▶ SRv6 PEs
 (sessions)            learns UE/TEID/NI,                (resolve the
                       originates T1ST/T2ST               segment, install
                       (no SID — see below)               End.DT46 forwarding)
```

The PEs originate the **segment** routes — DSD (`segment direct`) and ISD
(`segment interwork`) — that advertise their per-VRF **End.DT46** SID; the
controller's ST routes carry no SID and a receiving PE derives forwarding by
resolving each ST route against the matching segment (the
draft-ietf-bess-mup-safi default).

The MUP control plane (capability negotiation, Loc-RIB, receive, and
re-advertisement) is always present once the `mup` AFI/SAFI is
negotiated. Route-reflector deployments are supported: a reflected MUP
route is stamped with `ORIGINATOR_ID` / `CLUSTER_LIST` (RFC 4456), and a
received route carrying the local ID is dropped, so SAFI-85 state cannot
loop through a reflector mesh. The **controller** — the PFCP listener
and route origination — is what the `mup-c` block below turns on.

## Enabling the MUP capability

`mup` is a single AFI/SAFI knob that negotiates **both**
IPv4-MUP (AFI 1) and IPv6-MUP (AFI 2). Enable it per neighbor like any
other family:

```
router bgp {
  global {
    as 65001;
    router-id 192.168.0.1;
  }
  neighbor 192.168.0.2 {
    remote-as 65001;
    afi-safi ipv4 {
      enabled true;
    }
    afi-safi mup {
      enabled true;
    }
  }
}
```

## Configuring the controller

The controller's `mup-c` block sits **directly under the BGP instance**
(`router bgp { mup-c { … } }`). It needs three things: a per-VRF `mup`
service that maps a PFCP Network Instance to a Route Distinguisher /
route-targets, the `mup-c` block itself, and — only for the non-default
explicit-SID mode — an SRv6 locator.

```
segment-routing {
  locator LOC1 {
    prefix fcbb:bb01::/48;
  }
}
router bgp {
  global {
    as 65001;
    router-id 192.168.0.1;
  }
  segment-routing {
    srv6 {
      locator LOC1;
    }
  }

  # Map the PFCP Network Instance "access" to a VPN service: the RD
  # stamped on the ST route and the ST route type it originates.
  vrf mobile-up {
    rd 65000:100;
    afi-safi mup {
      route st1 {
        network-instance access;
      }
    }
  }

  # Turn on the controller: the PFCP/N4 listener + route origination.
  # The `mup-c` block sits directly under the BGP instance.
  mup-c {
    enabled true;
    controller-address fcbb:bb01::1;
    pfcp {
      listen-address 192.168.0.1;
      port 8805;
    }
    srv6 {
      locator LOC1;
    }
  }
}

# The route-targets MUP routes carry (export) and pull in (import) live on
# the top-level VRF, the same `route-target {import|export}` framework as
# ipv4 / ipv6.
vrf mobile-up {
  mup {
    route-target {
      export 65000:200;   # stamp this RT on every MUP route this VRF originates
      import 65000:200;   # pull in any MUP route carrying this RT
    }
  }
}
```

* **`enabled true`** spawns the in-process controller. It is configured
  under the BGP instance (not as a separate daemon) so that it is handed
  the BGP instance's own channel, the same way a per-VRF BGP instance is
  — route origination is a direct in-process call, not a cross-process
  hop.
* **`controller-address`** is the IPv6 address advertised as the next
  hop on every originated ST route.
* **`pfcp`** sets the N4 listener bind address and port (default
  `[::]:8805`).
* **`srv6 locator`** is **reserved** for the non-default mode where the
  controller pushes an explicit SID; in the default mode it is unused.
  Per draft-ietf-bess-mup-safi the controller originates ST routes
  **without** a service SID — the receiving PE derives forwarding from
  its own ISD/DSD routes — so no per-session SID is allocated.
* **`upf-address`** / **`upf-teid`** supply a static core (N6/N9) tunnel
  endpoint + TEID for the Type-2 ST when a session carries no learned
  `Dest=Core` F-TEID (the N6-breakout case). With neither set, a node acting
  as the anchor UPF self-allocates its own core receive F-TEID, so an ST2
  still originates. A learned core F-TEID always wins over both.

A VRF binds an ST direction to a PFCP Network Instance under `afi-safi
mup route {st1|st2}` — one entry per direction, and a VRF may carry
**either or both** (see
[the single-N6 UPF](#one-vrf-both-directions--the-single-n6-upf) below
for the both-directions form). The two read identically:

* **Downlink (Type-1 ST).** `afi-safi mup route st1 { network-instance
  <ni>; }` — the N6 VRF originates a **Type-1 ST** route carrying the UE
  prefix and the **access-side** GTP endpoint (the gNB; draft §3.3.7).
* **Uplink (Type-2 ST).** `afi-safi mup route st2 { network-instance <ni>;
  mup-ext-comm <2:4>; }` — the N3 VRF originates a **Type-2 ST** route
  carrying the **core-side** GTP endpoint and the GTP TEID (§3.3.10). The
  optional `mup-ext-comm` is the BGP MUP Extended Community (Direct-segment
  id in RD/RT 2:4 form, e.g. `1:2`) the ST2 resolves to.

The access (Type-1) and core (Type-2) endpoints are **distinct** tunnel
ends, each learned from its own PFCP F-TEID — the downlink FAR's Outer Header
Creation (`Dest=Access`) feeds the Type-1 (gNB) endpoint, a `Dest=Core` FAR
the Type-2 (core / N9) endpoint. The Type-2 **never** borrows the access
tunnel (it is the wrong direction, and a TEID of 0 is invalid per §3.1.4.1):
its `(endpoint, TEID)` resolves in three tiers — a learned core F-TEID, else
the statically configured anchor (`upf-address` + `upf-teid`), else, when this
node is itself the anchor UPF, a **self-allocated** core receive F-TEID at its
own address. So an ST2 always carries a non-zero core TEID.

The configured network-instance is matched exactly against the PFCP
session's Network Instance. The export route-targets the ST route carries
come from the top-level `vrf <name> mup route-target export` — the same
`route-target` framework as `ipv4` / `ipv6`.

A single PFCP session originates **every** matching ST route: each
`route {st1|st2}` entry whose Network Instance matches contributes one —
whether the two directions live on two VRFs (one entry each) or on one
dual-direction VRF (both entries), one session originates both the
Type-1 and the Type-2 ST.

For example, an uplink VRF that also originates the Direct segment it
resolves to:

```
vrf N3 {
  rd 65000:100;
  encapsulation srv6;
  afi-safi mup {
    route st2 {
      network-instance core;   # originate an ST2 for PFCP sessions on NI "core"
      mup-ext-comm 1:2;        # the Direct segment id it resolves to
    }
    segment direct {
      mup-ext-comm 1:2;        # originate the End.DT46 DSD with the same id
    }
  }
}
```

### Selecting the forwarding plane (`dataplane`)

Each MUP VRF chooses its forwarding-plane behaviour with `afi-safi mup
dataplane`:

* **`end-dt46`** (default) — the SRv6 **End.DT46** stand-in. A resolved ST
  route installs a `seg6local End.DT46` decap plus an SRv6 H.Encaps toward the
  segment SID, entirely in the **mainline kernel**. The GTP-U TEID rides the
  control plane only; the subscriber path is L3VPN-over-SRv6. This is what the
  rest of this chapter describes, and it runs on stock Linux.
* **`gtp`** — real **GTP-U**. The tunnel is programmed from the ST route's own
  endpoint and TEID on the [eBPF data plane](ch-16-00-ebpf.md)
  (`system ebpf enabled`). The mainline kernel has no GTP action, so this
  mode requires the eBPF data plane. Both directions are wired, in both
  address families: each Type-2 ST route's `(endpoint, TEID)` becomes a
  GTP-U decap PDR (`H.M.GTP4.D` / `H.M.GTP6.D`) that strips a matching
  G-PDU into the VRF, and each Type-1 ST route installs the downlink
  encap route (`GTP4.E` / `GTP6.E`) — the UE prefix tunneled toward the
  gNB, its outer `(gw, oif)` resolved and kept fresh by Next-Hop
  Tracking.

```
vrf N6 {
  rd 65501:10;
  encapsulation srv6;
  afi-safi mup {
    dataplane gtp;         # program real GTP-U on the eBPF data plane (default: end-dt46)
    segment direct { mup-ext-comm 1:2; }
    route st2 { network-instance core; }
  }
}
```

The **control plane is identical** either way — the same ISD/DSD/ST routes are
signalled — so `dataplane` selects only the endpoint behaviour advertised and
whether the FIB install targets the kernel `seg6local` or the eBPF GTP maps.
`show bgp vrf <name> mup` reports the mode (`dataplane=end-dt46|gtp`). The two
forwarding planes — Plan A (End.DT46, mainline kernel) and Plan B (real GTP-U
on the eBPF data plane) — are **both complete**; the staged design behind them
is in
[`docs/design/bgp-mup-dataplane-plan.md`](https://github.com/zebra-rs/zebra-rs/blob/main/docs/design/bgp-mup-dataplane-plan.md).

### One VRF, both directions — the single-N6 UPF

zebra-rs also supports a single-N6 UPF: uplink and downlink are directions of the
same N6-facing interface, not two separate legs. Because a kernel interface
belongs to exactly one VRF, the older one-direction-per-VRF model forced a
bidirectional GTP UPF into two VRFs — and with them two N6 interfaces.

Since the `route` list holds one entry **per direction**, a single VRF
binds both, and the whole UPF collapses onto one N6 interface. This is
the recommended shape. The complete, validated configuration (the
`bdd/mup-lab` free5GC lab):

```
# The kernel VRF and its single N6 interface. N3 (mun3) sits in the
# GLOBAL table here — the default GTP-U match context, and the simplest
# shape since it also carries PFCP/N4. N3 may instead live in its own
# VRF: see "The faithful interwork/direct split" below.
vrf mobile {
}
interface mun3 {
  ipv4 {
    address 10.0.12.2/24;      # N3 + N4 (also the PFCP listen address)
  }
}
interface mun6 {
  vrf mobile;
  ipv4 {
    address 10.0.60.1/24;      # the ONE N6 leg, in the service VRF
  }
}

router bgp {
  global {
    as 65000;
    router-id 1.1.1.1;
  }
  vrf mobile {
    rd 65000:1;
    afi-safi mup {
      dataplane gtp;           # real GTP-U on the eBPF data plane
      route st1 {
        network-instance internet;   # downlink: UE prefix -> GTP4.E encap
      }
      route st2 {
        network-instance internet;   # uplink: CP-allocated F-TEID -> decap PDR
      }
    }
  }
  mup-c {
    enabled true;
    controller-address 2001:db8::1;
    pfcp {
      listen-address 10.0.12.2;
    }
  }
}
```

Both `route` entries are independent list entries: each carries its own
`network-instance` (here the same DNN, `internet`, so one PFCP session
matches both) and, on the `st2` entry only, an optional `mup-ext-comm`.
Deleting one entry removes only that direction — the sibling binding,
and its originated routes, stay up. A handover (PFCP Modification) that
moves the access tunnel re-exports the affected ST in place without
ever withdrawing the other direction.

One PFCP session then originates **both** Session-Transformed routes
from the one VRF, under its single RD (the two NLRI types have disjoint
keys, so sharing the RD is safe). From the live free5GC validation run:

```
# show bgp mup
MUP VRFs:
  mobile: rd=65000:1 encap/ST1 ni=internet decap/ST2 ni=internet dataplane=gtp route-targets=0

   Network (MUP NLRI)                                   Next Hop
 *> [ST1][65000:1][ue=10.60.0.1/32][teid=1][qfi=0][ep=10.0.1.2:src=10.0.12.2]
       next-hop 2001:db8::1  weight 32768
 *> [ST2][65000:1][ep=10.0.12.2][teid=2]
       next-hop 2001:db8::1  weight 32768
```

With `dataplane gtp`, the VRF's one table now holds the whole
subscriber datapath together:

* the **uplink decap PDR** (`H.M.GTP4.D`, from the ST2's CP-allocated
  `(endpoint, TEID)`) — a matching G-PDU arriving on N3 is stripped and
  its inner packet looked up **in this table**;
* the **downlink encap route** (the ST1's UE `/32` → `GTP4.E` toward
  the gNB, egressing N3);
* the **N6 connected route** (from `mun6`'s address).

So an uplink packet decaps and leaves through the N6 connected route,
and a downlink packet arriving on N6 hits the UE route and tunnels out
N3 — one leg, both directions. (A side effect: UE↔UE traffic hairpins —
a decapped uplink packet whose destination is another UE prefix
re-encapsulates toward that UE's gNB in the same lookup.)

Deployment notes — the Kubernetes/Multus question that motivated this
shape:

* The **N6 interface needs no XDP at all**: downlink ingress is handled
  on the eBPF data plane's TC path, and uplink egress is a plain
  redirect. A macvlan child on a shared host device is fine for N6.
* The **N3 interface performs the XDP GTP decap**, so it should be a
  device with **native XDP** (a host-device or SR-IOV VF). On drivers
  without native XDP the data plane falls back to generic (SKB) mode,
  where the decap stage is skipped for frames redirected by an upstream
  TC hop — keep N3 off macvlan.

The single-N6 datapath is regression-tested by the cradle
`@cradle_mup_gtp_single_n6` BDD (round-trip ICMP plus an iperf3 TCP
scenario) and was validated against real free5GC v4.0.1 +
free-ran-ue (`bdd/mup-lab`): UE ping at 0% loss and iperf3 at
~1.9 Gbit/s uplink / ~2.6 Gbit/s downlink on a single box with debug
builds. The classic two-VRF split (one direction per VRF, two N6 legs)
remains fully supported.

### Segment Discovery routes (`segment direct` / `segment interwork`)

A PE VRF with `encapsulation srv6` carves a per-VRF **End.DT46** SID from
the locator and installs the `seg6local` decap. `afi-safi mup segment`
advertises that segment so a receiving PE can resolve matching ST routes to
it:

* **`segment direct { mup-ext-comm <2:4>; }`** originates a **Direct
  Segment Discovery (DSD, type 2)** route — NLRI = RD + router-id — carrying
  the End.DT46 SID and the Direct-segment id (`mup-ext-comm`). A receiving
  interwork node matches each received **ST2** to the DSD by this
  **Direct-segment id**.
* **`segment interwork { prefix <p>; }`** originates an **Interwork Segment
  Discovery (ISD, type 1)** route — NLRI = RD + the configured `prefix`
  (the locally connected **gNodeB N3 network**; its family selects the AFI) —
  carrying the End.DT46 SID. The ISD does not originate until the prefix is
  set, and carries no `mup-ext-comm`: a receiving interwork node matches each
  received **ST1** to the ISD by **endpoint containment** — the ST1's GTP
  endpoint (gNB) address falling inside the ISD prefix (longest-match when
  several ISDs cover the endpoint).

```
vrf N6 {
  rd 65501:10;
  encapsulation srv6;
  afi-safi mup {
    segment interwork {
      prefix 10.0.0.0/24;      # the gNB N3 network the ST1 endpoints resolve against
    }
  }
}
```

#### Resolving ST routes to a segment (forwarding)

An interwork node imports the ST routes **and** the segment routes into a
forwarding VRF (`encapsulation srv6` + a matching `route-target import`),
resolves each ST route to its segment, and installs an SRv6 **H.Encaps**
route for the ST route's **endpoint** into the VRF table:

* **ST2 → DSD** — matched by Direct-segment id; `dst = the ST2 endpoint
  /32|/128` (the uplink core endpoint; the ST2 carries no UE prefix).
* **ST1 → ISD** — matched by the ST1's gNB **endpoint** contained in the ISD
  prefix (the lookup key, draft §3.3.9); `dst = the ST1 **UE prefix**` (the
  Prefix field, §3.1.3) — downlink traffic to the UE is steered toward the
  gNB's segment.

The segment is **remote** (received from the peer that owns the End.DT46
SID), so the encap resolves through the IS-IS SRv6 underlay via Next-Hop
Tracking toward the segment's next-hop:

```
dst  via <underlay egress> dev <link>  encap seg6 mode encap segs [End.DT46 SID]  table <VRF>
```

`show bgp mup` / `show bgp vrf <name> mup` print the resolution
(`resolved <key> -> End.DT46 <sid> (via [DSD|ISD]…)`), and the entry
re-installs (or withdraws) automatically as the underlay reroutes or the ST
/ segment route comes and goes.

On the mainline-kernel dataplane zebra-rs uses **End.DT46** for both Direct
and Interwork segments — the kernel performs the SRv6 H.Encaps toward the
segment, and the End.DT46 decap at the far end. The draft's GTP-U endpoint
behaviours themselves (GTP4.E / GTP6.E / H.M.GTP4.D / H.M.GTP6.D) are
implemented on the [eBPF data plane](ch-16-00-ebpf.md) — see
[`dataplane gtp`](#selecting-the-forwarding-plane-dataplane) above.

A **GTP-only PE** (`dataplane gtp`, no SRv6 locator and no `encapsulation
srv6`) still originates its DSD/ISD routes — **SID-less**: no SRv6 L3
Service Prefix-SID, next-hop = the `mup-c` `controller-address` (which must
be configured; there is no locator to derive one from). The segments are
then pure correlation objects a peer resolves by Direct-segment id and
prefix containment. Regression-tested by the `bgp_mup_sidless_segment` BDD.

### The faithful interwork/direct split — N3 in a VRF (`dataplane gtp`)

Beyond advertising DSD/ISD routes, `segment direct` / `segment interwork`
declare a **local datapath role**: *this VRF is a direct / interwork
segment*. With `dataplane gtp`, the reconcilers resolve every forwarding
context from those declarations instead of implicit defaults — the MUP
architecture's own mapping, where the **interwork segment is the N3
routing context** (GTP-U terminates there) and the **direct segment is the
N6 routing context** (decapped subscriber traffic routes there):

| Context | Resolved from | Default when undeclared |
|---|---|---|
| Where does GTP-U **match**? | The ST2-holding VRF's own table when it is a `segment interwork` — the decap PDR only matches G-PDUs arriving on that VRF's ports | VRF 0 (N3 ports in the global table) |
| Which table after **decap**? | The direct segment whose `mup-ext-comm` equals the ST2's MUP Extended Community (the DSD correlation) | The ST2-holding VRF's own table |
| Which table resolves the **outer** packet after encap? | The most-specific `segment interwork` prefix containing the ST1's gNB endpoint — the (gw, oif) is NHT-resolved in that VRF's table | The global table |

The complete, validated configuration (the cradle
`@cradle_mup_gtp_n3_vrf` BDD):

```
vrf N3 { }                      # interwork segment: the GTP/N3 routing context
vrf N6 { }                      # direct segment: the N6 routing context
interface z1n3 { vrf N3; ipv4 { address 10.0.12.1/24; } }
interface z1n6 { vrf N6; ipv4 { address 10.0.60.1/24; } }

router bgp {
  global { as 65000; router-id 1.1.1.1; }
  vrf N3 {
    rd 65000:3;
    afi-safi mup {
      dataplane gtp;
      segment interwork {
        prefix 10.0.12.0/24;    # the gNB N3 network
      }
      route st2 {
        network-instance internet;
        mup-ext-comm 1:6;       # resolves the decap target to the N6 segment
      }
    }
  }
  vrf N6 {
    rd 65000:6;
    afi-safi mup {
      dataplane gtp;
      segment direct {
        mup-ext-comm 1:6;       # this VRF's Direct-segment id
      }
      route st1 {
        network-instance internet;
      }
    }
  }
  mup-c { enabled true; controller-address 2001:db8::1;
          pfcp { listen-address 127.0.0.1; } }
}
```

One PFCP session then originates the **ST1 under N6's RD** (`65000:6` —
the UE route belongs to the direct segment) and the **ST2 under N3's RD**
(`65000:3`, stamped `mup:1:6`), and the datapath follows the table above:

* **Uplink**: a G-PDU arriving on `z1n3` — a port bound to N3's kernel
  table — matches the decap PDR *in N3's context* (the same
  `(endpoint, TEID)` may be reused by another slice's interwork VRF), is
  stripped, and its inner packet routes in **N6's table** although it
  arrived on an N3-bound port: the `mup:1:6` correlation picked the direct
  segment, and the decap's table choice takes precedence over the ingress
  port's VRF binding.
* **Downlink**: traffic to the UE hits the ST1 route in **N6's table** and
  is GTP-encapsulated toward the gNB; `10.0.12.2` falls inside the
  interwork prefix, so the outer `(gw, oif)` was resolved in **N3's
  table** — where the gNB's connected route actually lives.

With **no** `segment` declared, all three defaults apply and the behaviour
is exactly the single-N6 shape above — that configuration is the
degenerate case of this one, and remains the recommended simple form.

#### The GTP-gateway variant — `lookup-network-instance`

The service VRF need not be split in two. `segment interwork` may instead
name a **separate VRF as the GTP-side routing context** — the single-N6
shape lifted to N3-in-a-VRF (validated by the cradle
`@cradle_mup_gtp_lookup_ni` BDD; the named VRF needs no `router bgp vrf`
block of its own):

```
vrf N3 { }                      # the GTP-side context — kernel VRF only
vrf mobile { }
interface z1n3 { vrf N3; ipv4 { address 10.0.12.1/24; } }
interface z1n6 { vrf mobile; ipv4 { address 10.0.60.1/24; } }

router bgp {
  vrf mobile {
    rd 65000:1;
    afi-safi mup {
      dataplane gtp;
      segment interwork {
        prefix 10.0.12.0/24;
        lookup-network-instance N3;   # GTP-U matches and resolves in N3
      }
      route st1 { network-instance internet; }
      route st2 { network-instance internet; }
    }
  }
}
```

The ST2's decap PDR is scoped to **N3's** table (where G-PDUs arrive) and
decaps into `mobile`'s own table (the fallback — no Direct-segment id
needed when both directions share one VRF); the ST1's gNB endpoint falls
inside the interwork prefix, so the outer `(gw, oif)` resolves in **N3's**
table. Without the leaf, the declaring VRF is its own GTP context — the
two-VRF split above.

Two deployment notes:

* **N4 stays out of the N3 VRF.** The PFCP endpoint (`pfcp
  listen-address`) is an ordinary socket in the default routing context —
  keep it on loopback (collocated SMF/injector) or on a dedicated N4
  interface in the global table. Placing it on an address inside the N3
  VRF would require VRF-aware control-plane sockets, which the MUP
  controller does not do. Note this is a *control-plane* separation only:
  the UPF's **N3 endpoint address is unchanged** by it, so an SMF that
  CH=0-allocates the UPF's N3 F-TEID keeps allocating at the address that
  now lives inside the N3 VRF.
* A **catalog change on live sessions is handled**: re-scoping a segment
  re-keys the installed PDRs (withdrawing the old match context) and
  migrates the gNB endpoint's NHT registration to its new table.

The datapath is regression-tested by the cradle `@cradle_mup_gtp_n3_vrf`
BDD (dual-segment origination, round-trip ICMP through both re-scoped
lookups, tunnel counters on both ends), and was validated against real
free5GC v4.0.1 + free-ran-ue — the `bdd/mup-lab` N4-separated variant
(`setup-topo-n3vrf.sh` + `upf-n3vrf.yaml` + `smfcfg-n3vrf.yaml`), which
moves N4 onto its own global-table link and puts N3 in a kernel VRF. One
PFCP session originated all four routes across the two segments (ISD +
ST2 under N3's RD, DSD + ST1 under N6's), and the single installed decap
PDR states the whole resolution:

```
key: (vrf 1, 10.0.12.2, TEID 2)   ->   value: vrf 2
      ^ match context = N3's table        ^ decap target = N6's table
        (where the G-PDU arrives)           (picked by the ST2's mup:1:6)
```

UE ping at 0% loss and iperf3 at ~1.6 Gbit/s uplink / ~2.6 Gbit/s
downlink on a single box with debug builds — within noise of the
single-N6 lab's ~1.9 / ~2.6, so the split costs no throughput.

#### IPv6 N3 transport (GTP6) and composing with SRv6 segments

The GTP datapath is **family-complete**: a session whose tunnel endpoints
are IPv6 drives v6-outer GTP-U (`GTP6.E` / `H.M.GTP6.D`) through the same
resolution rules, with any-family UE prefixes (the mixed v4-UE-behind-v6-N3
case included). The v6 outer's UDP checksum is 0 — RFC 6935/6936
zero-checksum tunnel mode, which cradle's own decap never validates;
interop with a non-cradle GTP peer requires zero-checksum acceptance on
their end. Regression: `@cradle_gtp6`, `@cradle_mup_gtp6_zebra`.

A `dataplane gtp` VRF also **composes with remote SRv6 segments** (the
N9/SRGW shape). An ST1 whose gNB endpoint is covered by a *received* ISD —
with a usable End.DT46 SID and resolved transport, and not by this node's
own catalog — steers the UE prefix via SRv6 H.Encaps toward that interwork
segment, which performs the GTP conversion; an ST2 whose Direct-segment id
resolves to a *received* DSD installs default v4+v6 H.Encaps routes in the
VRF table, so GTP-decapped traffic rides SRv6 to the anchor. Local
segments always win, and a SID-less remote segment produces no steer — the
GTP outer then resolves by ordinary FIB toward the peer, which is the N9
GTP-to-GTP case. Regression: `bgp_mup_srgw_gtp`.

## From PFCP session to ST route

When an SMF establishes a session, the controller:

1. extracts the UE IP address, the access-side F-TEID (TEID + GTP
   endpoint), and the Network Instance from the PFCP Session
   Establishment Request;
2. correlates the Network Instance against the per-VRF `mup` config to
   find every matching `route {st1|st2}` binding, and dispatches the
   session to each matching VRF task with its matched direction set —
   one session can map to several VRFs, or to both directions of one
   dual-direction VRF (see the dual-ST note and
   [the single-N6 UPF](#one-vrf-both-directions--the-single-n6-upf)
   above);
3. each VRF task builds the **RD-free** Session-Transformed NLRI and exports
   it to the global instance, which stamps the VRF's RD, its export
   route-targets and the controller-address next hop **at the export
   boundary** (see [VRF-first origination](#vrf-first-origination-and-the-rd)
   below), installs it into the global MUP Loc-RIB — with **no** service SID
   (PE-derived forwarding, the draft default) — and advertises it to every
   `mup` peer.

A Session Deletion withdraws the route. For an IPv6 UE whose GTP
endpoint is IPv4 (IPv4 N3 transport), the endpoint/source address family
is taken from its own length octet, so the route rides the IPv6-MUP AFI
while carrying the IPv4 endpoint.

## VRF-first origination and the RD

zebra-rs organizes MUP routes the same way it organizes L3VPN: the
**Route Distinguisher lives only in the global SAFI-85 table**, applied at
the export boundary — never inside a per-VRF RIB.

* A **per-VRF MUP RIB** holds the routes that belong to that VRF, keyed by
  the VRF's **own RD** (the RD-free NLRI under the VRF's `rd`). This mirrors
  an L3VPN VRF's IPv4 RIB, which drops the VPNv4 RD on import: a route a VRF
  imports from a *different* origin RD is held — and shown — under **this**
  VRF's RD, not the origin RD.
* The **global MUP Loc-RIB** is the SAFI-85 table — keyed by the origin RD —
  and the only BGP-peer advertiser.

Origination is **VRF-first**. A controller ST route (from a PFCP session)
and a PE segment route (DSD/ISD from `afi-safi mup segment`) are built in
the per-VRF task as an **RD-free** NLRI plus only the route-specific extended
communities (the st2 / DSD Direct-segment id). The VRF exports it to the
global instance, which stamps the **infrastructure attributes at the export
boundary**, exactly like the VPNv4 `Export` handler:

* the VRF's **RD** (`vrf <name> rd`, also the global table key);
* its **export route-targets** (`vrf <name> mup route-target export`);
* the **next hop** — the controller-address for ST routes, or the SRv6
  locator's node SID for segments, with the per-VRF **End.DT46** SID attached
  as the segment's Prefix-SID.

The fully-stamped route is advertised to `mup` peers and mirrored back into
the per-VRF tasks, so the originating VRF's `show bgp vrf <name> mup` reflects
it (under its own RD) and any other VRF that imports its RT picks it up.

Segment-origination **gating** — `encapsulation srv6`, a configured RD, the
per-VRF End.DT46 SID, the SR locator, and the kernel VRF being up — is
evaluated on the global side (all of that is global state) before a segment is
dispatched to its VRF.

## Route-target import and cross-VRF import

Per-VRF MUP populates `show bgp vrf <name> mup` two ways, mirroring
VPNv4/v6:

* **Locally-originated routes** always appear in the VRF that originated
  them, **regardless of route-targets** — even with no `mup route-target`
  configured at all. A `route st1`/`st2` ST route and a `segment` DSD/ISD are
  built in their VRF task (see
  [VRF-first origination](#vrf-first-origination-and-the-rd) above), so that
  VRF owns them; they are shown under the VRF's own `rd`.
* **Route-target import** pulls in routes from *other* VRFs and from peers:
  a route also lands in any VRF whose `mup route-target import` set overlaps
  the route's route-targets, regardless of its origin RD. As on the import
  side of L3VPN, the route is re-keyed under the **importing** VRF's own RD.

The second rule is what makes **cross-VRF import** work, exactly as it does
for L3VPN: a route originated under one RD can be imported into a VRF whose
own `rd` is different, purely because the importing VRF's `import` RT matches
an RT the route carries.

```
vrf N6 {                      # rd 65501:20 — originates the ISD
  mup {
    route-target {
      export 65501:10;        # the ISD it originates carries RT 65501:10
    }
  }
}
vrf N3 {                      # rd 65501:10 — a different VRF
  mup {
    route-target {
      import 65501:10;        # N3 imports RT 65501:10 → pulls in N6's ISD
    }
  }
}
```

Here VRF N6 originates an ISD (`segment interwork`); in the global SAFI-85
table it carries N6's origin RD `65501:20` and RT `65501:10`, and `show bgp
vrf N6 mup` shows it under N6's own RD because N6 originated it — no import is
needed. VRF N3's `rd` is `65501:10`, which does **not** match the origin RD,
yet because N3 imports RT `65501:10` the ISD also appears in `show bgp vrf N3
mup` — re-keyed under **N3's own RD** (`[ISD][65501:10][…]`), not the origin
`65501:20`. The `@bgp_mup_vrf_import` BDD feature exercises this cross-RD
import.

## Showing MUP state

`show bgp mup` renders the configured per-VRF services and the
MUP Loc-RIB:

```
# show bgp mup
MUP VRFs:
  mobile-up: rd=65000:100 encap/ST1 ni=access dataplane=end-dt46 route-targets=1

   Network (MUP NLRI)                                   Next Hop
 *> [ST1][65000:100][ue=192.0.2.5/32][teid=305419896][qfi=0][ep=10.0.0.1]
       next-hop fcbb:bb01::1  weight 32768
       rt:65000:200
```

`show bgp vrf <name> mup` renders the MUP routes that belong to one VRF —
the routes that VRF **originated** plus the routes it **imports** by
route-target (see
[Route-target import and cross-VRF import](#route-target-import-and-cross-vrf-import)
above) — all keyed under the VRF's own RD, even those originally advertised
under a different origin RD. The global MUP Loc-RIB (keyed by origin RD)
stays the authoritative advertiser; the per-VRF task holds its own RIB of
these routes so the per-VRF view renders them:

```
# show bgp vrf mobile-up mup
   Network (MUP NLRI)                                   Next Hop
 *> [ST1][65000:100][ue=192.0.2.5/32][teid=305419896][qfi=0][ep=10.0.0.1]
       next-hop fcbb:bb01::1  weight 32768
       rt:65000:200
```

`show bgp mup-c` shows the controller status, and the
`session` / `association` sub-commands show the learned PFCP state:

```
# show bgp mup-c
MUP controller (MUP-C)
  Admin state : enabled
  PFCP listen : 192.168.0.1:8805
  Associations: 1
  Sessions    : 1

# show bgp mup-c session
SEID       UE address     TEID         Endpoint     QFI   Network-Instance
1          192.0.2.5      0x12345678   10.0.0.1     -     access
```

`show bgp neighbor <addr>` reports the negotiated MUP capability:

```
  IPv4 MUP: advertised and received
  IPv6 MUP: advertised and received
```

## Testing with `pfcp-inject`

`tools/pfcp-inject` is a tiny PFCP/N4 SMF simulator used by the
`@bgp_mup_e2e` BDD feature and for manual validation. It sends an
Association Setup followed by a Session Establishment (and, with
`--delete`, a Session Deletion) describing one mobile session:

```
pfcp-inject --target 192.168.0.1 --port 8805 \
            --ue-ipv4 192.0.2.5 --teid 0x12345678 \
            --endpoint 10.0.0.1 --network-instance access
```

After it runs, the session appears under `show bgp mup-c
session` and the controller's ST route appears in `show bgp
mup` on both the controller and its peers.

## Scope and limitations

The control plane is complete: capability negotiation, ISD/DSD/T1ST/T2ST
codec, Loc-RIB receive/store/show, controller ST origination, PE-side
Segment Discovery origination (DSD and ISD, each with the per-VRF End.DT46
SID + `seg6local` decap installed into the kernel FIB), and the interwork
node's resolution of received ST routes to the matching segment.

The **SRv6 forwarding** is installed and validated end-to-end: on a forwarding
VRF (`encapsulation srv6` + `route-target import`) — including a co-located
UPF + controller node — each resolved ST route programs an SRv6 H.Encaps entry
for its destination (ST2 endpoint / ST1 UE prefix) toward the remote segment's
End.DT46 SID, resolved through the underlay via Next-Hop Tracking (`dst via
<underlay egress> encap seg6 segs [SID]`), and the far-end PE's `seg6local
End.DT46` decaps into its VRF. Real bidirectional subscriber traffic across the
End.DT46 datapath is exercised by the `bgp_mup_forwarding` BDD.

The **GTP-U endpoint behaviours** themselves (GTP4.E / GTP6.E /
H.M.GTP4.D / H.M.GTP6.D) have no stock-Linux `seg6local` action, so on the
mainline-kernel dataplane zebra-rs uses **End.DT46 as the stand-in** for the
segment — the whole path is L3VPN-over-SRv6 and the GTP-U TEID is
control-plane metadata only. Real GTP-U forwarding is delivered by the
[eBPF data plane](ch-16-00-ebpf.md) with `dataplane gtp`: encap and decap in
both directions and both address families, the N3-in-a-VRF and GTP-gateway
(`lookup-network-instance`) match contexts, and the N9/SRGW composites that
steer via remote SRv6 segments — validated live against free5GC in both
`bdd/mup-lab` variants. Both stages of
[`docs/design/bgp-mup-dataplane-plan.md`](https://github.com/zebra-rs/zebra-rs/blob/main/docs/design/bgp-mup-dataplane-plan.md)
— **Plan A** (the End.DT46 user plane on stock Linux) and **Plan B** (real
GTP-U on the eBPF data plane) — are complete.

The controller's PFCP northbound handles Association and Session lifecycle
messages; heartbeat-driven eviction of idle associations is a follow-up.
