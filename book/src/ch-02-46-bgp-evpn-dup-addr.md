# EVPN Duplicate Address Detection

Two hosts configured with the same MAC address, or a loop that reflects a
host's frames into another site, make that address move back and forth
between VTEPs. Every move is a Type-2 route with a higher MAC Mobility
sequence number (RFC 7432 §7.7), so the fabric keeps re-learning the address
and every PE keeps re-programming it. RFC 7432 §15.1 asks each PE to notice
this: an address that moves `N` times within `M` seconds is a **duplicate**.

zebra-rs detects duplicates the way FRR's zebra does, and it is on by default
with RFC 7432's values: 5 moves within 180 seconds.

```
router bgp 65001 {
  afi-safi {
    name evpn;
    advertise-all-vni true;
    dup-addr-detection {
      max-moves 5;
      time 180;
      freeze 300;
    }
  }
}
```

| Leaf | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run detection. `false` releases every detected address and forgets every move counted. |
| `max-moves` | `5` | Moves within the window that make a duplicate (2–1000). |
| `time` | `180` | The window, in seconds (2–1800). |
| `freeze` | unset | `permanent`, or seconds (30–3600). Unset, detection only warns. |

## What counts as a move

Each PE counts the moves it takes part in:

* A MAC **learned locally while a remote route had it** is a move. The first
  such learn opens the window.
* A **remote route taking a MAC over from this PE** is a move, but only
  while a window opened by a local learn is still open.

A MAC learned locally for the first time is not a move. Nor is one learned
after the remote route was withdrawn, a remote route moving between two other
VTEPs, or a change of sequence number alone. A MAC learned here while a
remote PE advertises it as **sticky** is an operator error: it is logged and
not counted.

An **IP** is counted separately, but only when it moves to a *different* MAC:
a host that keeps its MAC as it moves is already counted by the MAC. An IP
bound to a duplicate MAC is a duplicate as well, for as long as it stays
bound to it. As in FRR, an IP that moves to a MAC that is not a duplicate
leaves the hold, and its own detection starts over.

When an address reaches `max-moves`, zebra-rs logs a warning:

```
VNI 100: MAC 02:00:00:00:01:01 detected as duplicate during local update, last VTEP 10.0.0.11
```

## Freeze

Without `freeze`, detection only warns. Routes keep flowing, and the address
stays marked until it is cleared.

With `freeze`, a duplicate is held in its last state. This PE withdraws its own
route for the address and stops advertising it, and stops installing remote
routes for it. The kernel keeps whatever it had: a frozen local MAC stays on
its access port, and a frozen remote MAC stays pointing at the VTEP it last
had. The rest of the fabric settles on the other PE's route, and the
churn stops.

A frozen address is released when:

* the freeze time elapses (`freeze <seconds>`),
* an operator clears it, or
* detection is turned off, or the freeze is removed.

On release, zebra-rs re-runs the address's routes. A MAC last learned here
is advertised again with a sequence number above the remote one. A MAC last
learned remotely is installed from the remote route.

Changing `freeze` also applies to addresses already detected. Enabling a
freeze withdraws their local advertisements immediately. A timed freeze starts
from the configuration change, including when changing from warn-only or
permanent. Changing the time of a freeze restarts its recovery deadline;
changing only `max-moves` or the detection window leaves that deadline alone.

## Show and clear

```
> show evpn dup-addr
Duplicate address detection: max-moves 5 within 180s, freeze 300s

VNI       MAC               IP                                      State      Moves Location                 Detected
100       02:00:00:00:01:01 -                                       duplicate  5     local                    12s ago, recovers in 288s
100       02:00:00:00:01:01 10.10.0.101                             dup (MAC)  0     local                    -
100       02:00:00:00:02:02 -                                       counting   2     remote 10.0.0.12         -
```

The list shows detected addresses and addresses whose moves are still being
counted in an open window. `dup (MAC)` marks an IP that is a duplicate because
its MAC is. `show evpn dup-addr json` gives the same data as JSON.

```
> clear bgp evpn dup-addr vni all
> clear bgp evpn dup-addr vni 100
> clear bgp evpn dup-addr vni 100 mac 02:00:00:00:01:01
> clear bgp evpn dup-addr vni 100 ip 10.10.0.101
```

Clearing releases the named duplicates, and their routes are re-run as on a
timed release. Clearing a MAC also releases the IPs bound to it.

## Differences from FRR

* The commands live under `router bgp afi-safi evpn dup-addr-detection`
  rather than `dup-addr-detection` in `address-family l2vpn evpn`.
  `clear evpn dup-addr` is `clear bgp evpn dup-addr`.
* FRR does nothing when only the freeze is removed: held addresses stay held
  until something else changes them. zebra-rs re-runs them at once.
* Detection applies to every EVPN encapsulation, because zebra-rs counts the
  moves in BGP, where the mobility sequence numbers are decided.
