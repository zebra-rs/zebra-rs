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
negotiated. The **controller** — the PFCP listener and route origination
— is what the `mup-c` block below turns on.

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

A VRF binds one ST direction to a PFCP Network Instance under `afi-safi
mup route {st1|st2}`; the two read identically:

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

A single PFCP session originates **every** matching ST route: if both an
st1 VRF and an st2 VRF bind the same Network Instance, one session
originates both the Type-1 and the Type-2 ST.

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
  endpoint and TEID (`GTP4.E` downlink / `H.M.GTP4.D` uplink) by the **cradle**
  eBPF forwarder, which zebra-rs drives over gRPC (`system cradle grpc-endpoint`). The
  mainline kernel has no GTP action, so this mode requires cradle. The uplink
  decap is wired: each Type-2 ST route's `(endpoint, TEID)` becomes a cradle
  GTP-U PDR (`H.M.GTP4.D`) that strips a matching G-PDU into the VRF. The
  downlink `GTP4.E` encap (the Type-1 ST toward the gNB) follows.

```
vrf N6 {
  rd 65501:10;
  encapsulation srv6;
  afi-safi mup {
    dataplane gtp;         # program real GTP-U via cradle (default: end-dt46)
    segment direct { mup-ext-comm 1:2; }
    route st2 { network-instance core; }
  }
}
```

The **control plane is identical** either way — the same ISD/DSD/ST routes are
signalled — so `dataplane` selects only the endpoint behaviour advertised and
whether the FIB install targets the kernel `seg6local` or the cradle GTP maps.
`show bgp vrf <name> mup` reports the mode (`dataplane=end-dt46|gtp`). The two
forwarding planes — Plan A (End.DT46, mainline kernel) and Plan B (real GTP-U
via cradle) — are scoped in
[`docs/design/bgp-mup-dataplane-plan.md`](https://github.com/zebra-rs/zebra-rs/blob/main/docs/design/bgp-mup-dataplane-plan.md).

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

zebra-rs uses **End.DT46** for both Direct and Interwork segments; the
draft's GTP-U endpoint behaviours (GTP4.E / GTP6.E / H.M.GTP4.D) themselves
are VPP/eBPF and not yet implemented — the kernel dataplane performs the
SRv6 H.Encaps toward the segment, and the End.DT46 decap at the far end.

## From PFCP session to ST route

When an SMF establishes a session, the controller:

1. extracts the UE IP address, the access-side F-TEID (TEID + GTP
   endpoint), and the Network Instance from the PFCP Session
   Establishment Request;
2. correlates the Network Instance against the per-VRF `mup` config to
   find the matching VRF(s) and the ST route type (`st1` / `st2`), and
   dispatches the session to each matching VRF task (one session can map
   to several VRFs — see the dual-ST note above);
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
  mobile-up: rd=65000:100 encap/ST1 ni=access route-targets=1

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

The **GTP-U endpoint behaviours** themselves (GTP4.E / GTP6.E / H.M.GTP4.D)
have no stock-Linux `seg6local` action, so on the mainline-kernel dataplane
zebra-rs uses **End.DT46 as the stand-in** for the segment — the whole path is
L3VPN-over-SRv6 and the GTP-U TEID is control-plane metadata only. Real GTP-U
forwarding is delivered by an **eBPF dataplane** (`cradle`) that zebra-rs
drives over gRPC. The roadmap — **Plan A** (complete the End.DT46 user plane on
stock Linux, done) and **Plan B** (real `H.M.GTP4.D` / `GTP4.E` in the cradle
eBPF forwarder) — is scoped in
[`docs/design/bgp-mup-dataplane-plan.md`](https://github.com/zebra-rs/zebra-rs/blob/main/docs/design/bgp-mup-dataplane-plan.md).

The controller's PFCP northbound handles Association and Session lifecycle
messages; heartbeat-driven eviction of idle associations is a follow-up.
