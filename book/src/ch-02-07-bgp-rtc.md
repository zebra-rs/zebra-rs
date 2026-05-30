# BGP Route Target Constraint (RTC)

zebra-rs implements **Route Target Constraint** as specified in
RFC 4684. RTC lets a router tell its peers which route-targets it
actually imports, so a peer — typically a route reflector — sends it
only the [VPNv4 / VPNv6 L3VPN](ch-02-04-bgp-l3vpn.md) routes that will
be accepted, instead of the entire VPN table.

Without RTC a route reflector advertises every VPN route to every
client, and each client discards the routes whose route-targets match
none of its local VRFs. On an RR with many clients and a large VPN
table that is a lot of wasted advertisement, RIB, and churn. RTC moves
the filter to the *sending* side: the client advertises its import
route-targets, and the RR pre-filters before it ever puts the route on
the wire.

## How zebra-rs models RTC

RTC is a small address family of its own (SAFI 132) whose NLRI carries
route-targets rather than prefixes. zebra-rs splits it per address
family into two independently-enabled families:

* **`rtcv4`** constrains the VPNv4 routes a peer sends us;
* **`rtcv6`** constrains the VPNv6 routes a peer sends us.

> **Note** — the per-AFI split (`rtcv4` / `rtcv6`) is a zebra-rs
> modeling choice; RFC 4684 defines a single RT-Constraint family that
> constrains all VPN address families at once. RTC interop is therefore
> zebra-rs ↔ zebra-rs; enable **both** `rtcv4` and `rtcv6` when you want
> both VPNv4 and VPNv6 constrained.

## Configuration

RTC is enabled per neighbor, alongside the VPN families it constrains.
Enable it on the session toward the route reflector (or any peer that
should pre-filter the VPN routes it sends you):

```
set router bgp neighbor 10.0.0.1 remote-as 65000
set router bgp neighbor 10.0.0.1 afi-safi vpnv4 enabled true
set router bgp neighbor 10.0.0.1 afi-safi vpnv6 enabled true
set router bgp neighbor 10.0.0.1 afi-safi rtcv4 enabled true
set router bgp neighbor 10.0.0.1 afi-safi rtcv6 enabled true
```

* `rtcv4` / `rtcv6` enable RTC for the VPNv4 / VPNv6 families
  respectively; both default to `false`.
* There are **no RTC-specific route-targets to configure** — the
  membership a router advertises is derived automatically from its
  VRFs' `route-target import` sets (see
  [L3VPN](ch-02-04-bgp-l3vpn.md)). Configure the VRFs and the RTC
  membership follows.

## What a router advertises

On session establishment, **before any other address family**, the
router advertises its RTC membership:

* one entry per route-target across the union of every local VRF's
  IPv4 import route-targets (`rtcv4`) and IPv6 import route-targets
  (`rtcv6`);
* sent first so the peer has the constraint in hand before it starts
  sending VPN routes — filtering applies from the very first update.

If the router has **no local VRFs** — e.g. a pure route reflector that
holds no import route-targets — the membership is the RFC 4684 §3.2
*default*: a zero-length wildcard meaning "send me everything". So
enabling RTC on a VRF-less RR is safe; it still receives the full VPN
table.

## What a router filters

The constraint is applied on the **advertising** side. When this router
sends VPN routes to a peer:

* VPNv4 routes whose route-targets are not in the peer's advertised
  `rtcv4` membership are skipped;
* VPNv6 routes are filtered against the peer's `rtcv6` membership.

The filter is per-peer, so two clients of the same RR with different
import-RT sets each receive only their own matching subset. A peer that
advertised an empty / default membership (or none at all) is sent
everything, exactly as it would be without RTC.

## Verification

`show ip bgp neighbors <addr> rtcv4` prints the route-target constraint
sets received from a neighbor, split by family:

```
$ show ip bgp neighbors 10.0.0.1 rtcv4
IPv4 Route Target Constraints for 10.0.0.1
 65000:1
 65000:2
IPv6 Route Target Constraints for 10.0.0.1
 65000:1
```

Once the families negotiate, the capabilities show up as `IPv4/RTC`
and `IPv6/RTC` in the neighbor and summary output.
