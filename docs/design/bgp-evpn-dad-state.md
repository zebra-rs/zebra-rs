# EVPN Duplicate Address Detection: Deriving Where an Address Lives

Status: **design note, deferred.** Finding 14 of the #2502 review. Nothing
here is implemented; the tracked model below stays until one of the
triggers in §5 comes up.

Read together with:
- `zebra-rs/src/bgp/evpn_dad.rs`: the detection state and its hooks.
- [`bgp-evpn-ethernet-segment.md`](bgp-evpn-ethernet-segment.md): the
  segments a sync route is on.

## 1. What detection keeps

`EvpnDad` keeps, per MAC and per IP, a `Probe`:

| Field | What it is | Also known from |
| ----- | ---------- | --------------- |
| `count`, `start` | moves in the current window, and when a local learn opened it | nowhere: detection's own |
| `duplicate` | the detection mark and its recovery deadline | nowhere: detection's own |
| `owner` | `Local`, or `Remote { vtep, sticky, es }` | `Bgp::local_fdb` (local), the selected remote MAC/IP routes in `local_rib.evpn` (remote) |
| `remote_routes` | the remote routes installed or held for the address, with each one's sequence number, VTEP, sticky flag and segment: while the address is remote, `owner` is the newest of them, and it stops being remote when the last one goes | the same selected remote routes |

and per IP, `IpProbe::mac`, the MAC the IP is bound to, also known from the
`local_fdb` row binding it or the newest remote route binding it.

Only the counters and the marks are detection's own. `owner`,
`remote_routes` and `IpProbe::mac` are copies of where the address lives,
kept by hooks on every event that moves it:

| Event | Hook |
| ----- | ---- |
| local learn (`RibRx::FdbAdd`, and every re-origination) | `local_learn` |
| local row gone (`RibRx::FdbDel`) | `local_gone` |
| remote route installed (or held) | `remote_takeover` |
| remote route withdrawn, or beaten by ours | `remote_gone`, at two sites in `route_evpn_export_selected` |
| IP rebound to another MAC | `ip_leaves_duplicate_mac`, from both `local_learn` and `remote_takeover` |

## 2. Why it is fragile

Each copy is right only while every event that moves an address has its
hook, and each hook does the right thing. Four of the #2502 review's
findings were a hook missing or wrong:

- **1, 2.** An IP rebound from a duplicate MAC kept its earlier moves:
  the rebinding hook did not reset them (fixed in #2502 by
  `ip_leaves_duplicate_mac`).
- **4.** `RibRx::FdbDel` had no hook, so state for every MAC that ever came
  and went stayed (fixed in #2502 by `local_gone`).
- **5.** `Owner` did not record the Ethernet Segment, so a host moving
  between two PEs on one segment counted as moves (fixed by `Owner::Remote
  { es }` and `RemoteRoute::es`).
- **6.** A re-run of an older (MAC, IP) route overwrote `IpProbe::mac`.
  The first fix compared each route with the highest sequence number ever
  seen for the IP, which a withdrawal never lowers, so a withdrawn route
  still pinned the IP; and a withdrawn sync route left its segment on the
  owner. Both were the copy outliving the routes it came from. #2511 now
  keeps the live remote routes in `remote_routes` and recomputes `owner`
  and `IpProbe::mac` from them when a route comes, goes or changes its
  number: derivation, but only over the routes detection has seen.

A new event that moves an address (a new re-origination path, a new
reconcile) needs a new hook, and nothing fails when it is missing: the
copy goes stale, and a later move counts wrongly or not at all.

## 3. Deriving instead

Detection could keep only the counters and the marks, and work out the
address's previous location when an event arrives:

- **Local:** `local_fdb` has a row for `(vni, mac)` (a MAC), or a row
  binding the IP (an IP; the IP index of `LocalFdb` answers this).
- **Remote:** a selected, not originated MAC/IP route for the address is
  installed, that is, it beats our own route by `evpn_local_path_wins`.
  Its next hop, sticky flag and segment come from the route itself.
- **The IP's MAC:** the `local_fdb` row binding it, else the installed
  remote route binding it with the highest sequence number.

Detection's rules then read as FRR's do (`zebra_evpn_mac.c`,
`zebra_evpn_neigh.c`): a local learn is a move if a remote route held the
address; a remote takeover is a move if no remote route held it and a
window is open.

## 4. What it costs

- **A remote-route index.** The remote routes of one MAC are spread over
  one table per RD. `evpn_reconcile_remote_mac` scans every RD's selected
  table today; derivation would do that on every event. An index of the
  selected remote MAC/IP routes by `(vni, mac)` and `(vni, ip)`, kept where
  `route_evpn_export_selected` installs and removes, comes first. The
  reconcile would use it too.
- **Installed versus selected.** A remote route that lost to ours is
  selected but not installed. Derivation must apply `evpn_local_path_wins`
  per route, or the index must record which routes are installed.
- **Held routes.** Today a held (frozen) takeover still moves the owner to
  remote, though the route is not installed. Derivation must either keep
  that (count held routes as holding the address) or define the new rule
  and test it.
- **Tests.** The unit tests in `evpn_dad.rs` drive `EvpnDad` alone, through
  `local_learn` and `remote_takeover`. Derived state needs `local_fdb` and
  the Loc-RIB, so they would move to the `Bgp`-level fixture (`Flap` in
  `evpn_vtep_tests.rs`).
- **Event order.** Kernel FDB events and BGP UPDATEs arrive on different
  channels. Derivation sees the location as of the event being processed;
  so does the tracked model. Neither changes the order.

## 5. Plan, when it is taken up

1. Add the remote MAC/IP index to `LocalRib`, kept by
   `route_evpn_export_selected` and its withdraw arm, and use it in
   `evpn_reconcile_remote_mac`.
2. Add the derivations next to the tracked fields and check them against
   each other in debug builds, under the unit and BDD tests.
3. Switch the rules to the derivations, then remove `owner`,
   `remote_routes`, `IpProbe::mac` and the hooks that kept them.

Take it up when:
- an event that moves an address needs a new hook, or a hook is found
  wrong again; or
- the remote-route index is wanted for its own sake (the reconcile's scan).
