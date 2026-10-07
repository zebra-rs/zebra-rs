# EVPN Single-Active Multihoming

A CE attached to two or more PEs on one Ethernet Segment, where **one PE
forwards and the others stand by**. The opposite of all-active, where every
attached PE forwards and a remote PE load-balances across them.

This chapter is about making that behave the way an operator expects, which
takes more than setting the mode. Three things have to line up: which PE is
elected, how remote PEs find out, and when everyone changes over.

```
router bgp 65001 {
  afi-safi {
    name evpn;
    ethernet-segment ES1 {
      esi 00:11:22:33:44:55:66:77:88:99;
      redundancy-mode single-active;
      interface bond0;
      role-signaling l2-attr;
      df-election {
        algorithm preference;
        preference 200;
        fast-recovery {
          peering-time 3;
          skew 10;
        }
      }
    }
  }
}
```

For an E-Line (EVPN VPWS) on a single-active segment, read
[E-Line multihoming](ch-02-38-bgp-evpn-vpws.md#multihoming-rfc-8214-5)
instead: RFC 8214 §5 puts the role on the service's own Type-1, so that half
is settled on the wire and the two sections below do not apply.

## Why the mode alone is not enough

RFC 7432 elects the Designated Forwarder per `<ES, Ethernet Tag>` — per VLAN.
On a two-PE segment, service carving hands the odd VLANs to one PE and the
even ones to the other. That is a load-balancing answer to a redundancy
question, and it is almost never what someone asking for single-active wants.

So the first knob is the **election**:

| `algorithm` | Who wins |
|---|---|
| `default` | `tag mod N` over the address-ordered PEs — spreads VLANs across the PEs |
| `hrw` | a pseudo-random weight per `<PE, tag>` — also spreads, but a PE joining or leaving only moves its own services |
| `preference` | the **highest** `preference` wins **every** tag on the segment (RFC 9785) |
| `lowest-preference` | the same, reversed |

For deterministic active/standby, give every segment on the intended active PE
the better preference. Ties break on the `dont-preempt` bit and then on the
lowest originating address, and the whole segment must advertise the same
algorithm — RFC 8584 negotiation drops a disagreeing segment back to carving,
which `show bgp evpn ethernet-segment` reports rather than hiding.

**What preference does not buy you.** It makes the *election* deterministic,
not the *candidate set*. With AC-DF in effect, a PE whose attachment circuit
for one EVI fails drops out of that EVI's election alone — so "PE-A is the
active PE" is a statement about a healthy fabric, not an invariant. Failing
every segment on a PE over together needs a health policy above the ES, which
zebra-rs does not implement.

## Telling remote PEs who forwards

RFC 7432 leaves this open: the election is local to the segment's PEs and its
outcome is not on the wire. Without help, a remote PE deduces the forwarder
from which PE advertised the segment's MACs — which works, but has nothing to
read before the CE has sourced a frame, and follows a change of forwarder only
as those MACs are relearned.

`role-signaling l2-attr` advertises the answer instead. The per-EVI Ethernet
A-D carries the Layer-2 Attributes extended community with **P=1** on the
Designated Forwarder, **B=1** on the election's runner-up and neither bit on
any other PE (draft-ietf-bess-rfc7432bis §7.11.1). A change of forwarder is
then an attribute update on a route that is already there, so the remote
re-points without a withdraw and a re-selection.

Three things worth knowing before enabling it:

- **Enable it across the whole segment.** Roles are trusted only when every
  member signals one — the same unanimity rule RFC 8584 §4 applies to AC-DF.
  A segment where one PE is silent falls back to the inference, because the
  silent PE might be the forwarder and "nobody claims primary" must not be
  read as "nobody forwards".
- **It is off by default**, because the draft is work in progress and does not
  specify the ingress procedure. The semantics above are zebra-rs's.
- **All-active segments never carry P/B.** Every attached PE forwards there.

On the receiving side, `show bgp evpn ethernet-segment` names how each
forwarder was chosen — `signalled`, `inferred`, `backup-only`, `no forwarder`,
or a conflict — and lists every copy of each member's route:

```
Ethernet Segment nexthop groups (teed to the datapath):
  00:11:22:33:44:55:66:77:88:99 bd 10: single-active primary 192.0.2.1, backup 192.0.2.2 (signalled)
    generation 3
    192.0.2.1: role P, 2 path(s): peer 10.0.0.1 rd 65000:1 [best], peer 10.0.0.2 rd 65000:1
    192.0.2.2: role B, 1 path(s): peer 10.0.0.1 rd 65000:2 [best]
```

That is what makes a two-route-reflector fabric legible. Two copies of one
PE's route — one per RR — show as two paths, so a member that outlives one
RR's withdrawal is explained rather than mysterious, and `generation` counts
how many times this bridge domain's forwarder has actually moved.

If two PEs both claim the role — a misconfiguration, or a control plane
partitioned so that each elects itself — no ingress PE can repair it, since
both believe they forward. zebra-rs keeps sending to the PE it was already
using (`conflict, incumbent kept`) rather than moving an established flow for
nothing, and says so.

## Changing over together

Left alone, a PE joining a segment waits out a local timer and then carves,
while the PEs already there re-carve the moment its routes arrive. The two
ends move at different times, and a single-active segment spends that
difference with either **no** forwarder or **two**. One drops frames for the
window; the other duplicates them and can loop.

`fast-recovery` (RFC 9722) closes it. A joining PE announces *when* it will
carve — a Service Carving Time on its Type-4 — and every PE on the segment
carves at that instant:

- `peering-time` (default 3 s) is how far ahead the instant is announced, and
  also bounds what this PE will wait for: an announcement further ahead than
  this is rejected, so a peer with a skewed clock cannot park the election.
  Raise it where BGP propagation is slow.
- `skew` (default 10 ms) is how far **ahead** of the instant the outgoing
  forwarder steps down. The incoming one steps up at the instant itself. The
  asymmetry guarantees they never overlap, and pays a skew-long gap for it —
  on a bridged segment that is the right trade.
- Like the role signal, it takes effect only once **every** PE on the segment
  advertises the capability. A PE that did not would carve on its own timer
  while the others waited, which opens a longer gap than not synchronizing.
- It is **mutually exclusive with `startup-delay`**, which withholds the very
  Type-4 an announcement has to ride on.

A pending carve is visible, including whose instant it is and how long is
left, because otherwise a segment holding its roles reads as a stuck
election:

```
  Fast recovery: advertised, in effect (2 of 2 PEs advertise it)
    peering-time 3s, skew 10ms
    carving at 1791772800.500000 (2480 ms away, a peer's), roles held until then
```

## Forwarding

The multihoming data plane is **cradle-only**; the kernel VXLAN backend stays
single-homed. A single-active standby blocks its access port in both
directions, not just BUM, and the segment's nexthop group carries the
forwarder in slot 0 with the rest pre-installed behind it, so a mass withdraw
re-points every MAC in one update. See `docs/design/bgp-evpn-multihoming-dataplane.md`.

## Not implemented

- **Non-revertive operation** (RFC 9785 §4.3). `dont-preempt` is the tie-break
  only: with the bit set on every PE at equal preference — the normal way to
  configure it — the tie still falls through to the address, so the
  lowest-address PE reclaims the role when it returns. To pin a forwarder
  across a recovery today, give it the higher `preference`.
- **Port-active redundancy** (RFC 9786). It elects at `<ES>` scope, so a PE
  holding two segments can still be DF for one and non-DF for the other; it is
  not a substitute for the above.
- **ARP/ND synchronization** on the standby PE.
- **Interoperability with other implementations is untested.** Everything here
  is proven zebra-rs against zebra-rs. The wire agreement on the DP tie-break
  and the P/B semantics is the open risk — see
  `docs/design/bgp-evpn-mh-frr-interop-lab.md`.
