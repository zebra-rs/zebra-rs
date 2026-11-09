# Native DHCP client (DHCPv4, DHCPv6, RA host)

**Status: design. Nothing here is implemented.**

zebra-rs gets its own DHCP client: a `dhcpc` task that leases IPv4
addresses, and IPv6 addresses and delegated prefixes, on WAN interfaces. It
also gets a host side for the `nd` task, which turns received Router
Advertisements into a default route and SLAAC addresses. Everything a lease
produces goes through the RIB like any other route source: addresses,
default routes, classless routes, discard routes for delegated prefixes, and
the LAN addresses carved out of them. So distance, VRF, `show ip route` and
recovery all behave the same way. No external client (dhcpcd,
systemd-networkd, dhclient) is involved.

The configuration surface is VyOS's (`address dhcp`, `dhcp-options`,
`address dhcpv6`, `dhcpv6-options pd`, `ipv6 address autoconf`), moved under
zebra-rs's per-family containers. §16 lists the deviations.

---

## 1. Goals and non-goals

**Goals**

- An IPv4 WAN: a lease, the default route, RFC 3442 classless routes, and
  renew, rebind, expiry and release.
- An IPv6 WAN, as RFC 7084 asks of a CE router:
  - RA processing: the default route, SLAAC (WAA-1), and the on-link
    prefix only from the L flag (WAA-2);
  - DHCPv6 IA_NA (WAA-3, WAA-4) and stateless mode;
  - IA_PD in the same session (WPD-1, WPD-6), a discard route for the
    delegated prefix (WPD-5), and one /64 per LAN interface from it (L-2).
- Per-VRF behaviour: a WAN interface in VRF `red` leases into `red`'s
  table.
- Several DHCP WANs at once, ordered by `default-route-distance`.
- Leases that survive a zebra-rs restart without dropping the address.
- `show dhcp client leases`, `show dhcpv6 client leases`, and
  `renew|release dhcp[v6] interface <if>`.

**Non-goals for the first cut** (§14 phase 5, or never):

- DHCPv6 Reconfigure, authentication, IA_TA / `temporary` addresses, and
  the prefix-exclude option (RFC 6603, WPD-8).
- The RA Route Information option (RFC 4191), stable-privacy interface
  identifiers (RFC 7217), and privacy addresses (RFC 8981).
- Writing the system resolver. Lease DNS servers are stored and shown, and
  §13 has the later plan.
- DHCPv4 over PPPoE, and IPv4 link-local (RFC 3927).
- Starting DHCPv6 because of the RA M/O flags (D7).

---

## 2. Where things stand

**In zebra-rs**

- `interface <if> ipv4 address dhcp` is an enum arm of the address union,
  gated on `if-feature feat:insomnia` (`zebra-rs/yang/config.yang:5866-5889`).
  - The link handler reads the value and does nothing with it
    (`zebra-rs/src/rib/link.rs:1618-1637`).
  - It has to read it anyway: a value left unread turns a delete into
    "remove every address on the interface".
  - Two tests pin the gate (`zebra-rs/src/config/manager.rs:7228`, `:7243`).
- `interface <if> ipv6 address` is a plain `inet:ipv6-prefix` leaf-list,
  with no `autoconf` or `dhcpv6` value (`config.yang:5892`).
- **Addresses** can be added and removed only from inside the RIB task:
  - `link_config_exec` (`rib/link.rs:1601`) calls
    `FibHandle::addr_add_ipv4` (`fib/netlink/handle.rs:4012`). That sends
    `CREATE|EXCL` with `IFA_LOCAL` only: no lifetimes, flags or broadcast.
  - `Message` has no address variant for other tasks.
  - `LinkAddr` (`rib/link.rs:260`) does read lifetimes and flags back from
    the kernel. It tells a configured address (`config`) from a
    kernel-present one (`fib`), and has no other owner.
- **A configured address deleted by the kernel is re-installed**
  (`addr_recover_if_configured`, `rib/route.rs:387`; also on `link_up`). A
  lease marked `config=true` would therefore be brought back after it
  expired.
- **`RibType::Dhcp` exists but is learn-only.**
  - Kernel routes with `proto dhcp` are imported as `D`
    (`fib/netlink/handle.rs:6308`). insomnia's DHCPv6-server delegated-prefix
    routes are such routes.
  - `is_protocol()` is `Static | Ospf | Isis | Bgp` (`rib/entry.rs:91`), so
    `Dhcp` entries are never installed.
  - Learned Kernel/Dhcp entries have distance 0 (`rib/entry.rs:71`).
  - Every route zebra-rs does install uses `proto zebra`, except BGP, OSPF
    and IS-IS (`route_protocol`, `fib/netlink/handle.rs:366`).
- **The kernel's own RA processing is off.**
  - zebra-rs sets `net.ipv6.conf.all.forwarding=1`
    (`fib/netlink/sysctl.rs:16`).
  - With forwarding on, the kernel ignores `accept_ra=1`.
  - Nothing sets `accept_ra` or `autoconf`.
- **`nd` parses received RAs but only records them**
  (`nd/engine.rs:659-737`): flags and router lifetime per source, and the
  BGP-unnumbered neighbor event.
  - `NdSend::RouterSolicit` is wired (`nd/network.rs:179`) but nothing
    produces it.
  - `nd-packet` types the SLLA, PIO and MTU options. RDNSS and DNSSL come
    through as `NdOption::Unknown`.
  - The RAs zebra-rs sends carry no PIO (`nd/config.rs:133`, `nd/send.rs:92`).
- There is no resolver, NTP or domain config. zebra-rs writes no
  resolv.conf. `system hostname` is internal only (`config.yang:610`).
- **Show routing.** `show dhcp …` / `show dhcpv6 …` are routed whole to the
  external insomnia provider (`is_dhcp`, `config/manager.rs:2050`).
  - The exec containers are insomnia-gated (`yang/exec.yang:529`, `:541`).
  - A second `"dhcp"` show key would overwrite the first
    (`manager.rs:1871`).

**Elsewhere**

- insomnia's `dhcp-packet` crate is a no-I/O DHCPv4/DHCPv6 framing codec
  (header plus raw options, total parse, property-tested) used by its relay
  agent.
  insomnia's design (`design/dhcp.md` §13) already expects it to move here
  for a client.
- The relay's `sys.rs` / `v4.rs` have the `AF_PACKET` send path and the
  IPv4+UDP framing a client needs before it has an address.
- Kea has no client. Ubuntu's clients are built into systemd-networkd and
  NetworkManager, and dhcpcd stands alone. All of them configure the kernel
  themselves, behind zebra-rs's back. That is the case
  `rib/route.rs:423` warns about ("NetworkManager? dhcpcd?").

---

## 3. Decisions

### D1. An in-process task, not an external client

- A `dhcpc` tokio task, spawned lazily like `nd` (`config/manager.rs:1111`)
  on the first configuration that needs it.
- It talks to the RIB through `RibClient` like any protocol.

**Rejected**

- **dhcpcd driven like Kea:** it would need a no-configure mode, an event
  channel and per-VRF process management, and the kernel and the RIB would
  still disagree about who owns the address.
- **systemd-networkd:** it owns whole links.
- **insomnia:** it has no RIB, and lease state is routing state.

### D2. The codec moves to zebra-rs

- `dhcp-packet` moves to `crates/dhcp-packet`, next to `nd-packet`.
- It gains a typed option layer (`v4::params`, `v6::params`, `name`, §12)
  on top of the existing framing, keeping its properties: no I/O, total
  parse, no dependencies, and the deterministic `parse_is_total` property
  tests. (`v4::opt` / `v6::opt` already held the option-code constants.
  insomnia's design mentions cargo-fuzz targets; none were ever written.)
- insomnia keeps a vendored copy, synced like its `proto/`. The relay only
  needs the framing, so its goldens do not change.

**Rejected:** a git dependency, because the deb builds are offline.

### D3. DHCPv4 and DHCPv6 in one task; the RA host goes in `nd`

- `dhcpc` runs both DHCP families.
- `nd` gains a host side: it sends Router Solicitations and turns RAs into
  a default route, SLAAC addresses and on-link prefixes. It already owns
  the ICMPv6 socket and the RA parser.
- The two tasks share no state (D7); each talks to the RIB.

### D4. The kernel's RA processing stays off

- On every interface where the RA host runs, `nd` writes
  `net.ipv6.conf.<if>.accept_ra=0` and `autoconf=0`, so a later
  per-interface forwarding change cannot revive it.

**Rejected:** VyOS's `accept_ra=2`. The kernel would install a `proto ra`
default route that zebra-rs imports as a distance-0 Kernel route. It would
beat an operator's static default (distance 1) in the RIB, sit at
metric 1024 in the kernel beside zebra-rs's routes, and SLAAC addresses
would bypass the RIB.

### D5. A lease is not configuration

- `LinkAddr` gains `dynamic: Option<AddrOrigin>`, one of `Dhcp4`, `Dhcp6`,
  `Slaac` or `Pd`. A dynamic address:
  - is never `config=true`;
  - is never re-installed by `addr_recover_if_configured` or `link_up`;
  - is installed with kernel lifetimes, so it expires on time even if
    zebra-rs is not running.
- New netlink call: `addr_replace(ifindex, prefix, AddrOpts { valid,
  preferred, noprefixroute, broadcast })`. It uses `NLM_F_REPLACE` so a
  renewal updates lifetimes in place, and carries `IFA_CACHEINFO`,
  `IFA_FLAGS` and `IFA_BROADCAST`.
- New `Message` variants for tasks outside the RIB:
  `AddrDynAdd { ifindex, addr, origin, opts }` and
  `AddrDynDel { ifindex, addr, origin }`.
- An `AddrDynAdd` for an address the operator also configured keeps
  `config=true`, and the configuration wins on delete.
- `RibRx::AddrAdd` must also fire when only the lifetimes change. Today it
  is silent (`AddrUpdate::Unchanged`), and `nd` needs the new lifetimes to
  advertise PIOs (D14).

### D6. Lease routes are protocol routes

- `RibType::Dhcp` covers DHCPv4 lease routes and DHCPv6 discard routes.
- A new `RibType::Ra` (shown `A`) covers RA default routes and on-link
  prefixes.
- Both are protocol routes when `dhcpc` or `nd` submits them:
  - installed with `proto zebra`, as every zebra-rs route is, so echo
    suppression and the startup leftover handling are unchanged;
  - `is_protocol()` is keyed on how the entry arrived, not on its
    `rtype`.
- Kernel-learned `proto dhcp` routes stay learn-only at distance 0. This
  covers insomnia's delegated-prefix routes. insomnia sweeps only inside
  its configured ranges (insomnia `src/pd_routes.rs:24-30`), so it cannot
  touch a client's routes.
- **One entry per (prefix, rtype, ifindex)**, like
  `rib_rtype_ifindex` (`rib/route.rs:2493`). Two DHCP WANs give two
  default-route candidates, and the RIB picks by distance. That is VyOS's
  dual-WAN recipe: a different `default-route-distance` per WAN. When a
  link goes down, the RIB invalidates its nexthop and the other candidate
  takes over without `dhcpc` doing anything.
- **Default distance 210** for both types (VyOS's `default-route-distance`
  default). That is above iBGP (200), OSPF (110) and IS-IS (115), so any
  routed default wins over a leased one.

### D7. DHCPv6 starts only from configuration

- A DHCPv6 exchange runs only for `ipv6 address dhcpv6`, `dhcpv6-options pd`
  or `parameters-only`.
- The RA M/O flags are shown (`show ipv6 nd` already shows them) and never
  acted on.
- This deviates from RFC 7084 WAA-6 and WPD-4, which start DHCPv6 on the
  flags. A configured router should do what it was told, as VyOS does.

### D8. Identity

**DUID**

- One per system, generated once as a DUID-LLT from the first Ethernet
  MAC.
- Stored in `/var/lib/zebra-rs/dhcp/duid`, next to
  `/var/lib/zebra-rs/checkpoint`. RFC 7084 W-5: the DUID "MUST NOT change
  between network-interface resets or IPv6 CE router reboots".
- `dhcpv6-options duid` overrides it per interface (VyOS).

**IAIDs**

- IA_NA: a stable 32-bit hash of the interface name. The ifindex is not
  stable across reboots.
- IA_PD: the `pd <id>` number, as VyOS uses it.

**DHCPv4 client identifier**

- Default: no option 61, so the server keys the lease on the MAC in
  `chaddr`. That is ISC dhclient's default, which VyOS keeps.
- `dhcp-options client-id` sets one: hex `xx:xx:…` is sent raw, any other
  string as type 0 plus the bytes.
- RFC 4361's DUID-based identifier is not the default (§16).

**Host name (option 12):** `dhcp-options host-name`, else `system hostname`
if it is set. Debian's stock `dhclient.conf` sends `gethostname()` the
same way.

### D9. Leases persist

- Each binding is written to `/var/lib/zebra-rs/dhcp/<ifname>.v4.json` /
  `.v6.json`: lease, server, timers and the routes and addresses it
  produced.
- **At start**, a still-valid lease is applied at once:
  - the address is usually still in the kernel thanks to its lifetime, and
    `dhcpc` adopts it;
  - its routes are re-submitted;
  - then the lease is verified: INIT-REBOOT for DHCPv4, Confirm for an
    IA_NA-only DHCPv6 binding, Rebind if it holds an IA_PD (RFC 8415's
    link-change rule).
- RFC 2131 §3.2 lets the client keep an unverified lease until it expires
  if no server answers.
- **Release:** stopping zebra-rs releases nothing. A deleted configuration
  or the `release` verb does.

### D10. Carrier and VRF changes

**Carrier**

- The lease is kept when the carrier goes down. The RIB already
  invalidates nexthops on a down link.
- When the carrier comes up, the lease is verified as in D9, and `nd`
  sends Router Solicitations.

**VRF**

- Moving the interface to another VRF drops the binding without a
  Release: the old addresses and routes are withdrawn, and the client
  starts again in INIT in the new VRF.
- `pd … interface <lan>` must name an interface in the WAN interface's VRF.
  Anything else is skipped with a warning (the rule insomnia's per-VRF
  backends follow, insomnia `design/process.md` §4.9).

### D11. Sockets

**DHCPv4**

- Before the client has an address (INIT, SELECTING, REQUESTING,
  INIT-REBOOT): an `AF_PACKET`/`SOCK_DGRAM` socket bound to the ifindex,
  following `isis_socket` (`isis/socket.rs:31`).
  - A classic BPF filter accepts IPv4, UDP, destination port 68 and
    BOOTREPLY.
  - It sends whole IPv4+UDP datagrams to the broadcast MAC (the relay's
    framing).
- Once bound: a UDP socket on `<lease>:68`, with `SO_BINDTODEVICE` on the
  interface and `SO_BROADCAST`. It is used for unicast RENEWING and
  broadcast REBINDING.

**DHCPv6**

- One UDP socket per interface on `[::]:546` with `SO_BINDTODEVICE`.
  Sockets bound to different devices do not conflict.
- It sends to `ff02::1:2` from the interface's link-local address, and
  waits until that address is no longer tentative.
  - `AddrFlags` must carry `tentative` and `dadfailed`; add them if they
    are missing.

**VRF:** an `AF_PACKET` socket does not care about VRFs, and a UDP socket
bound to an enslaved port does its route lookups in the VRF's table.
`ProtoContext` binds only to a VRF master (`context/proto.rs`), so a
per-interface helper is new.

### D12. Show and exec routing

- In `exec.yang`, the `if-feature feat:insomnia` moves from the `dhcp` and
  `dhcpv6` containers down to their `server` and `relay` children, and an
  ungated `client` child is added.
- `SHOW_PROTOS` gains `is_dhcp_client` (the path has `dhcp` or `dhcpv6`
  followed by `client`, or starts with `renew`/`release`), placed before
  `is_dhcp`. The local `dhcpc` answers those, and insomnia keeps the rest.
- `renew` and `release` are top-level exec verbs. `parse.rs:862` routes
  them like `start|stop|restart process`, so they answer with text instead
  of being fire-and-forget like `clear`.

### D13. Feature gate

- `ipv4 address dhcp` loses `if-feature feat:insomnia` in the phase that
  makes it work.
- The new `ipv6 address` values (`autoconf`, `dhcpv6`) and the option
  containers land ungated, each with the phase that implements it.
- The two pinning tests become positive parse tests. The enum-arm gating
  mechanism stays covered by the augment fixture (`manager.rs:7001`).

### D14. What the client hands to others

- **`nd` (RA sending).** LAN prefixes reach `nd` through the RIB, as
  ordinary dynamic addresses with lifetimes. `nd` must:
  - advertise a PIO for each global /64 on an advertising interface,
    counting the lifetimes down from the address's (L-2, L-3, L-6);
  - advertise a removed prefix with preferred lifetime 0 and valid
    lifetime min(remaining, 2 h) (L-13).

  Today `nd` sends no PIO. This is a dependency, ND-PIO (§14).
- **Show JSON** carries everything a consumer needs: address, gateway, DNS
  and delegated prefixes.
- **Other zebra-rs code** gets a read-only handle,
  `dhcpc::Leases::gateway(ifname)`. That is what insomnia's WAN load
  balancing plan expects for `nexthop dhcp` (insomnia
  `design/plans/wan-load-balancing.md` W-7: "zebra-rs fills in the route
  itself").
- **IPsec `dhcp-interface`** already follows the interface's kernel
  address (insomnia `design/plans/ipsec-syntax-parity.md` D-dhcp), so it
  needs nothing.

---

## 4. Configuration

The full surface, with VyOS's leaf names inside zebra-rs's per-family
containers:

```
interface <if>
  ipv4
    address dhcp                         # exists; ungated (D13)
    dhcp-options
      client-id <string>
      host-name <string>
      vendor-class-id <string>           # option 60
      user-class <string>                # option 77
      default-route-distance <1-255>     # default 210
      no-default-route                   # empty
      reject <ipv4-prefix>*              # ignore offers from these servers
      mtu                                # empty: apply option 26
  ipv6
    address autoconf                     # new enum arm: RA host + SLAAC
    address dhcpv6                       # new enum arm: IA_NA
    ra-options                           # zebra-rs extension (VyOS has none)
      default-route-distance <1-255>     # default 210
      no-default-route
    dhcpv6-options
      duid <hex>                         # overrides the system DUID
      parameters-only                    # Information-Request only
      rapid-commit
      no-release
      pd <0-4294967295>                  # IAID of this IA_PD
        length <32-64>                   # hint; default 64
        interface <lan-if>
          sla-id <0-4294967295>
          address <1-18446744073709551615>   # host part; absent: EUI-64
```

**How the RA host is enabled:** it runs on an interface with any of
`address autoconf`, `address dhcpv6` or `dhcpv6-options pd`, because each
of them needs the RA default route. SLAAC addresses are made only with
`autoconf`.

**Commit-time checks**

| Condition | Severity | Effect |
|---|---|---|
| `address dhcp` beside static addresses | – | allowed (VyOS); the lease is one more address |
| `dhcp-options` / `dhcpv6-options` / `ra-options` without the address value that uses them | warning | stored, unused |
| `parameters-only` with `address dhcpv6` or `pd` | error | an Information-Request carries no IAs |
| `pd … interface X` where X is the WAN interface itself | error | |
| one LAN interface under two `pd` ids, or two `sla-id`s per interface | error | |
| `sla-id` that cannot fit the hint `length` | warning | checked again against the actual delegation at bind time (WPD-3) |

The IPv6 link handler must read `autoconf` and `dhcpv6` the way the IPv4
handler reads `dhcp` (`rib/link.rs:1618`), or a delete wipes the
interface's addresses.

### VyOS mapping

| VyOS (`interfaces ethernet <if> …`) | zebra-rs (`interface <if> …`) |
|---|---|
| `address dhcp` | `ipv4 address dhcp` |
| `dhcp-options <leaf>` | `ipv4 dhcp-options <leaf>` (same leaves) |
| `address dhcpv6` | `ipv6 address dhcpv6` |
| `ipv6 address autoconf` | `ipv6 address autoconf` |
| `dhcpv6-options <leaf>` | `ipv6 dhcpv6-options <leaf>` (same leaves, without `temporary`) |
| (kernel `accept_ra=2`, metric 1024) | `ipv6 ra-options` |
| `ipv6 address eui64 <prefix>` | not in this design |

A config-migration tool only has to move paths. No values change.

---

## 5. RIB and kernel

| Lease item | RIB | Kernel |
|---|---|---|
| DHCPv4 address | `AddrDynAdd(Dhcp4)` | `addr_replace`, valid = preferred = remaining lease, `IFA_BROADCAST` (option 28, else computed) |
| DHCPv4 default route (option 3, first router) | `Dhcp`, `default-route-distance` | `proto zebra` |
| DHCPv4 option 121 routes (option 3 ignored when present, RFC 3442) | `Dhcp`, same distance; router `0.0.0.0` → `Nexthop::Link` | `proto zebra` |
| Gateway outside the leased subnet (a /32 lease) | `Dhcp` host route to the gateway, `Nexthop::Link`, then the default via it | |
| SLAAC address | `AddrDynAdd(Slaac)`, `noprefixroute` | RFC 4862 lifetimes |
| RA default route | `Ra`, `ra-options default-route-distance`, via the router's link-local | `proto zebra` |
| RA on-link prefix (L=1) | `Ra`, `Nexthop::Link`, lives as long as the PIO's valid lifetime | |
| IA_NA address | `AddrDynAdd(Dhcp6)`, /128, `noprefixroute` | IA lifetimes |
| Delegated prefix | `Dhcp` unreachable route (WPD-5); `Nexthop` gains an unreachable form if it lacks one, because WPD-5(a) wants ICMPv6 Destination Unreachable and a blackhole sends nothing | |
| LAN /64 from a delegation | `AddrDynAdd(Pd)` on the LAN interface, prefix route kept (connected) | delegated lifetimes |

**Withdrawal** happens on expiry, NAK, Release, a deleted configuration, a
VRF move, or a router lifetime of 0. A withdrawal sends the matching
`*Del`.

**Routes and the VRF:** routes go to the interface's VRF with the existing
`Ipv4AddVrf` / `Ipv6AddVrf` messages. `dhcpc` subscribes with
`global_links` and learns each interface's VRF from `RibRx::LinkAdd`
(`master`).

---

## 6. DHCPv4 client

The RFC 2131 states: INIT → SELECTING → REQUESTING → BOUND → RENEWING →
REBINDING, plus INIT-REBOOT and REBOOTING. Everything runs as a sans-I/O
state machine (§12).

**What it sends**

- Options 53, 12 (D8) and 57 (the interface MTU), plus 61, 60 and 77 when
  configured.
- Option 55, the parameter request list: 1, 3, 6, 15, 28, 42, 119, 121,
  plus 26 when `mtu` is set.
- Option 50 in SELECTING and INIT-REBOOT, and option 54 in REQUESTING.

**Offers**

- The first acceptable offer wins.
- An offer is unacceptable when its server identifier (option 54) or
  source falls in `reject`, or when it has no yiaddr or lease time.
- A missing subnet mask gets the classful mask and a warning.

**Address conflict detection**

- Before binding a new address (not on a renewal), the client sends two
  ARP probes one second apart. This is an abridged RFC 5227 probe.
  - Kea 2.4.1 has no ping-check, so the server will not catch a conflict
    either.
- On a conflict: DECLINE, then wait 10 s before INIT (RFC 2131 §3.1).

**Timers (RFC 2131 §4.1 and §4.4.5)**

- Retransmissions: 4 s doubling to 64 s, ±1 s.
- T1 is option 58, else 0.5 × lease. T2 is option 59, else 0.875 × lease.
- RENEWING unicasts to the server and retries after half the time left to
  T2.
- REBINDING broadcasts and retries after half the time left on the lease.
- Both retry no sooner than every 60 s.
- When the lease expires, everything it produced is withdrawn and the
  client starts again in INIT.

**NAK:** the lease is withdrawn and the client restarts in INIT. A backoff
of 1, 2, 4 … up to 64 s stops a server that NAKs everything from causing a
tight loop.

**MTU (option 26)**

- Applied only with `dhcp-options mtu` and no `interface <if> mtu`
  configured. The configuration wins.
- Values below 576 are ignored.

**Release:** a deleted `address dhcp`, or `release dhcp interface <if>`,
sends a RELEASE to the server and withdraws everything. After the verb,
the client stays released until `renew` or a configuration change.

---

## 7. RA host (`nd`)

**Starting up**

- The RA host turns on with any of the three configurations in §4. It
  writes `accept_ra=0` and `autoconf=0` (D4).
- It sends up to three Router Solicitations, 4 s apart after a random
  delay of up to 1 s (RFC 4861 §6.3.7). It does this at start, on carrier
  up and on a VRF move, through the existing `NdSend::RouterSolicit`.

**What each RA does**

- **Router lifetime > 0:** the router becomes a default-route candidate.
  With `no-default-route` it is listed but not installed.
  - Candidates are ordered by RA router preference (RFC 4191: high,
    medium, low).
  - Equal-preference routers on one interface become one `Ra` entry with
    several nexthops.
  - Router lifetime 0, or the lifetime running out, removes the router.
- **PIO with L=1:** an on-link `Ra` route for the prefix's valid lifetime.
  A prefix with L=0 gets no on-link route (RFC 5942, WAA-2), which is why
  SLAAC and IA_NA addresses are `noprefixroute`.
- **PIO with A=1, a /64, and `autoconf` configured:** a SLAAC address
  made from the prefix and the EUI-64 of the interface MAC.
  - Lifetimes follow RFC 4862 §5.5.3, including the two-hour rule of (e).
  - The kernel runs DAD on it. On `dadfailed` the address is removed and
    logged; there is no retry with a new identifier (RFC 7217) in this
    design.
- **RDNSS (25) and DNSSL (31):** become typed options in `nd-packet`. They
  are stored with their lifetimes and shown (§13).
- **MTU option:** shown, not applied.
- **M/O flags:** shown, not acted on (D7).

---

## 8. DHCPv6 client

**One session per interface**

- It holds the IA_NA (if `address dhcpv6`) and every `pd` IA_PD. Requesting
  them together is what RFC 7084 WPD-6 asks for.
- An Advertise or Reply with only some of the IAs is accepted (WPD-6). The
  missing IAs are asked for again at the next Renew.
- `parameters-only` uses Information-Request instead. It refreshes at
  option 32, else every 86400 s, never sooner than 600 s (RFC 8415).

**What it sends**

- Client ID (D8), Elapsed Time, and Rapid Commit with `rapid-commit`.
- An ORO asking for 23 (DNS), 24 (domain list), 56 (NTP), 82 (SOL_MAX_RT),
  83 (INF_MAX_RT) and 32 (information refresh time).
- IA_NA. IA_PD with an IAPREFIX hint of `::/<length>`.

**Choosing a server**

- Advertises are collected during the first retransmission period, and the
  highest preference wins.
- Preference 255 is taken at once.
- A Reply to a Solicit sent with Rapid Commit binds directly.

**Timers**

- RFC 8415's transmission parameters, with option 82 raising or lowering
  SOL_MAX_RT (WAA-8).
- T1/T2 come from each IA. When the server sets them to 0, the client uses
  0.5 / 0.8 of the shortest preferred lifetime in the IA.

**Status codes**

| Code | Response |
|---|---|
| NoAddrsAvail / NoPrefixAvail | that IA is retried at the next Renew; the others bind |
| NoBinding on a Renew or Rebind | Request |
| NotOnLink on a Confirm | Solicit |
| UseMulticast | resend multicast |

**Delegated prefixes**

- Each delegated prefix gets the unreachable route (§5).
- Each `interface <lan> sla-id N` gets the /64 made of the prefix with N in
  the bits from the delegated length up to 64.
  - The LAN address is that /64 plus `address` (else the EUI-64 of the LAN
    interface's MAC).
  - An `sla-id` that does not fit the actual delegated length is skipped
    and logged (WPD-3).
- A changed delegation withdraws the old LAN addresses and discard route
  before the new ones are added. ND-PIO deprecates the old prefix (L-13).
- WAA-7 (an internal address from the delegation when the WAN has no
  global address) is not automatic. `pd … interface lo sla-id …` does it
  explicitly.

**Release and Decline**

- A deleted configuration or `release dhcpv6 interface <if>` sends a
  Release, unless `no-release` is set.
- A DAD failure on an IA_NA address sends a Decline.

**Reconfigure:** no Reconfigure Accept is sent, so servers will not
reconfigure the client (§16).

---

## 9. Identity and persistence

| File | Contents | Lifetime |
|---|---|---|
| `/var/lib/zebra-rs/dhcp/duid` | the system DUID (D8) | created once, never rewritten |
| `/var/lib/zebra-rs/dhcp/<if>.v4.json` | lease, server id, T1/T2/expiry as wall-clock times, routes and address produced | written at bind and renew, deleted on release, expiry or deleted configuration |
| `/var/lib/zebra-rs/dhcp/<if>.v6.json` | server DUID, IAs with addresses and prefixes, LAN assignments | same |

- Files are written atomically (a temporary file, then a rename).
- A file that is unreadable, or that names another interface MAC, is
  ignored and logged.
- `/var/lib` is the path insomnia's Kea leases already use for state that
  must survive an image update.

---

## 10. VRF

- The client's sockets bind to the interface (D11), so a WAN interface in
  VRF `red` leases through `red` without a VRF-specific code path.
- Routes go to `red`'s table (§5).
- The same lease in two VRFs is impossible: one interface, one VRF.
- `show … vrf` filtering is a column, not a grammar (§11): a client is
  named by its interface, not by its VRF.

---

## 11. Show and exec

```
show dhcp client leases [interface <if>]
show dhcpv6 client leases [interface <if>]
show ipv6 nd interface <if>              # gains an "RA host" section
renew dhcp interface <if>
release dhcp interface <if>
renew dhcpv6 interface <if>
release dhcpv6 interface <if>
```

**`show dhcp client leases`** prints one block per interface:

- interface, VRF, state, address/mask, gateway (or "classless routes: N");
- server, lease time, T1, T2, remaining;
- DNS, domain, NTP;
- the routes it installed and their distance.

**`show dhcpv6 client leases`** prints:

- the DUID and the server DUID;
- per IA: the IAID, T1/T2 and each address or prefix with its preferred
  and valid lifetimes;
- for each prefix, its LAN assignments;
- DNS and NTP.

**`show ipv6 nd interface <if>`** adds default routers (preference,
lifetime), prefixes (L/A flags, lifetimes), SLAAC addresses and
RDNSS/DNSSL.

**All of these:**

- Every show answers in JSON with `-j`, under keys that stay stable for
  consumers (D14).
- `renew` on a released or idle client starts it. On a bound client it
  sends a Renew at once.
- An interface with no client answers "No DHCP client on <if>".

---

## 12. Module layout

```
crates/dhcp-packet/            moved from insomnia (D2; done in P0)
  src/v4.rs, v6.rs             framing; + all option and message codes,
                               v4 merged_options (RFC 3396 + overload),
                               v6 ClientMessage::new/option/emit
  src/name.rs                  RFC 1035 names, compressed (119) or not (24,
                               NTP FQDN); pointers only move backwards
  src/v4/params.rs             Params::from_packet: mask, routers, dns,
                               domain, search, ntp, mtu, broadcast,
                               lease/T1/T2, server id, classless routes,
                               message, client id; DhcpOption and
                               Packet::request constructors
  src/v6/params.rs             IaNa, IaPd, IaAddress, IaPrefix, StatusCode,
                               NtpServer, DUIDs; Params::from_options;
                               Dhcp6Option constructors (ORO, elapsed time,
                               rapid commit)
crates/nd-packet/              + typed RDNSS, DNSSL, router preference
zebra-rs/src/config/dhcpc.rs   spawn_dhcpc (lazy, like spawn_nd)
zebra-rs/src/dhcpc/
  inst.rs                      the task: select! over sockets, timers, RIB,
                               config, show
  config.rs                    callbacks for /interface/ipv4/address (dhcp),
                               …/dhcp-options, /interface/ipv6/address
                               (dhcpv6), …/dhcpv6-options
  v4/fsm.rs, v6/fsm.rs         sans-I/O: handle(now, Event) -> Vec<Action>
  v4/socket.rs, v6/socket.rs   AF_PACKET + BPF, per-interface UDP (D11)
  v6/pd.rs                     sub-prefix arithmetic, LAN assignments
  apply.rs                     Action -> RIB messages
  ident.rs                     DUID, IAIDs, client id
  lease.rs                     persistence (§9)
  show.rs                      §11 views and verbs
zebra-rs/src/nd/host.rs        RS, RA -> routes and SLAAC addresses (§7)
zebra-rs/src/rib/              AddrOrigin, AddrDynAdd/Del, addr_replace,
                               RibType::Ra, origin-keyed is_protocol,
                               per-ifindex Dhcp/Ra entries, lifetime-change
                               AddrAdd
```

**The state machines do no I/O.**

- The events are a packet, a timer, link up or down, an address change, a
  configuration change, and renew or release.
- The actions are send, add or delete address, add or delete route, save
  or delete lease, and log.
- The task supplies the clock and performs the actions. That keeps every
  RFC timer and transition testable without sockets or sleeps (§15).

---

## 13. Later: resolver, NTP, MTU

zebra-rs writes no resolver files today, and on Ubuntu `resolv.conf`
belongs to systemd-resolved.

- **Resolver.** The planned shape is an explicit
  `system name-server dhcp <if>` (VyOS's `system name-server <interface>`).
  It pushes that interface's lease DNS servers and domains to resolved
  per link (`SetLinkDNS` / `SetLinkDomains`, what networkd does). zebra-rs
  never writes the file.
- **NTP** follows the same pattern if zebra-rs ever manages time.
- **The RA MTU option** gets an `ra-options mtu` leaf if it is needed.

---

## 14. Phases

| Phase | Content | Depends on |
|---|---|---|
| P0 | Codec move + typed options + property tests; insomnia switches to the vendored copy (relay goldens unchanged) | – |
| P1 | RIB plumbing (D5, D6); `dhcpc` task; DHCPv4 state machine, sockets, ACD, persistence; `show dhcp client leases`, `renew/release dhcp`; ungate `address dhcp` | P0 |
| P2 | RA host in `nd`: RS, default route, on-link prefixes, `ipv6 address autoconf`, `ra-options`, `accept_ra=0`; show section | P1's RIB plumbing |
| P3 | DHCPv6 IA_NA and `parameters-only`; DUID; `show dhcpv6 client leases`, `renew/release dhcpv6` | P0, P2 |
| P4 | IA_PD: discard route, LAN assignment, prefix change | P3 |
| ND-PIO | `nd` advertises PIOs for LAN /64s with counted-down lifetimes, deprecates removed ones (L-13), `RibRx::AddrAdd` on lifetime change | P1's RIB plumbing; parallel to P2–P4 |
| P5 | Resolver integration, MTU options, Reconfigure, IA_TA, prefix exclude, RFC 4191 routes, stable-privacy identifiers, `redistribute dhcp` | as needed |

Each phase is one PR, or a short series, with its own BDD feature.

---

## 15. Testing

**Unit tests (CI)**

- **State machines.** Each one is driven by scripted packets and a fake
  clock:
  - DHCPv4: DORA, NAK and its backoff, the renew/rebind/expiry timers, and
    INIT-REBOOT from a persisted lease.
  - DHCPv4 options: 121 overriding 3, an off-subnet gateway on a /32
    lease, and a server in `reject`.
  - DHCPv6: Advertise preference and 255, Rapid Commit, a PD-only Reply,
    NoPrefixAvail on one IA, SOL_MAX_RT, T1/T2 = 0, Confirm vs Rebind
    after a restart, and a prefix change.
- **Arithmetic:** sub-prefixes and `sla-id` overflow; IAID stability;
  DUID created once.
- **Codec:** typed-option round trips, plus the existing `parse_is_total`
  property tests extended to them. Cases cover option 119's compression
  pointers, including loops and pointer chains.
- **RIB:**
  - a dynamic address is not resurrected after it expires;
  - an operator-configured duplicate survives a Release;
  - two `Dhcp` defaults at 210 and 220 select by distance and fail over
    on link down;
  - a native `Dhcp` route is installed with `proto zebra` and its echo is
    suppressed;
  - a kernel `proto dhcp` route stays learn-only.
- **Config:** the `address dhcp` gate tests become positive, and deleting
  an `ipv6 address dhcpv6` value removes no static address.

**BDD (`bdd/`, not CI)**

Test servers: Kea through insomnia's `kea_server.sh` shape covers DHCPv4,
IA_NA and PD. dnsmasq (present on Ubuntu as `dnsmasq-base`) covers
DHCPv4, IA_NA and RAs, but not PD.

| Feature | Checks |
|---|---|
| `dhcp_client` | lease → address and `D>* 0.0.0.0/0 [210/0]`; renew; `release`; server gone → expiry withdraws everything; zebra-rs restart keeps the address and re-verifies |
| `dhcp_client_vrf` | WAN in VRF `red`; the route is in `red`'s table only |
| `dhcp_client_dual_wan` | two leases at 210 / 220; link down on the first → the second's default is selected |
| `ra_host` | RA default route `A`, SLAAC with `autoconf`, router lifetime 0 withdraws, `accept_ra` is 0 |
| `dhcpv6_client` | IA_NA /128, on-link prefix from the RA, `parameters-only` |
| `dhcpv6_client_pd` | PD → discard route, LAN /64 address; prefix change replaces both; with ND-PIO, a LAN host SLAACs from it |
| `dhcpv6_pd_insomnia` | a zebra-rs + insomnia router serving PD (insomnia's existing DHCPv6 server) to a zebra-rs client router: both sides of the feature in one topology |

---

## 16. Deviations

| Item | Reference | zebra-rs | Why |
|---|---|---|---|
| DHCPv6 started by RA M/O flags | RFC 7084 WAA-6, WPD-4 | configuration only (D7) | a configured router is deterministic; VyOS does the same |
| Reconfigure Accept | RFC 7084 WAA-4 (MUST) | not sent | needs Reconfigure authentication; P5 |
| RA processing | VyOS: kernel `accept_ra=2` | userspace in `nd`, `accept_ra=0` (D4) | RIB ownership, distance, VRF |
| RA default route | VyOS: kernel metric 1024 | `Ra`, distance 210, `ra-options` | parity with DHCPv4 defaults |
| DHCPv4 client identifier | RFC 4361: DUID-based (SHOULD) | none unless configured; the server keys on `chaddr` | dhclient's and VyOS's behaviour, which ISP servers are provisioned for |
| `temporary` (IA_TA) | VyOS `dhcpv6-options temporary` | not supported | not needed on a router WAN |
| Prefix exclude | RFC 7084 WPD-8 (SHOULD) | not supported | P5 |
| Internal address from PD | RFC 7084 WAA-7 | explicit `pd … interface lo` | no implicit interfaces |
| IPv6-only preferred (option 108) | RFC 8925 | not requested | a dual-stack WAN wants its IPv4 lease |
| ACD | RFC 5227: 3 probes, 1–2 s apart | 2 probes, 1 s apart | bounded bind delay |

---

## 17. Open questions

1. **`RibType::Ra` or reuse `Dhcp`?** A separate type tells the operator
   which source the default came from, but costs a show letter (`A` is
   proposed). FRR has neither.
2. **Equal distances on two WANs.** Per-ifindex entries (D6) give one
   selected default, while FRR staticd (VyOS) would install ECMP. Should
   the RIB merge equal-distance `Dhcp` entries into one multipath?
3. **DUID type.** DUID-LLT (proposed) survives an image reinstall only
   through `/var/lib`. DUID-UUID from `/etc/machine-id` survives a NIC swap
   but not a reinstall. ISPs that bind PD to the DUID care about both.
4. **Should `release` survive a zebra-rs restart** (a marker in the lease
   file), or does a restart renew?
5. **Feeding LAN /64s to insomnia's DHCPv6 server.** Kea's subnets are
   static configuration today; VyOS doesn't do it either. A dynamic subnet
   is a later insomnia feature.
6. **Keeping the DHCPv4 lease on carrier loss** (D10) matches
   systemd-networkd, while dhcpcd drops it. Confirm against the ISPs we
   care about.
