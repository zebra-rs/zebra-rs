# Native DHCP client (DHCPv4, DHCPv6, RA host)

**Status: P0 (the codec), P1 (the RIB plumbing and the DHCPv4 client)
and P2 (the RA host) are implemented. Of P3, the protocol half is
implemented: the DHCPv6 state machine, the DUID and the IAIDs. The task
does not run it yet. The rest of P3 and what follows is design.** Where a
phase found the code to be different from what this document assumed, the
text below says what was built and why.

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
- **An address both leased and configured belongs to the
  configuration**, which outlives the lease:
  - `AddrDynAdd` for a configured address only marks it; its kernel entry
    stays permanent.
  - Configuring an address a lease already holds takes the lease's
    lifetime off it (`Rib::addr_make_permanent`). Otherwise it would
    expire at the lease's old deadline, since renewals no longer refresh
    a configured address.
  - When the lease ends, the address stays. When the configuration is
    deleted while the lease holds, the RIB tells the client, which puts
    the lease's lifetime back.
- `RibRx::AddrAdd` must also fire when only the lifetimes change. Today it
  is silent (`AddrUpdate::Unchanged`), and `nd` needs the new lifetimes to
  advertise PIOs (D14).

### D6. Lease routes are protocol routes

- **A type of their own.** `RibType::DhcpClient` covers DHCPv4 lease
  routes (and later DHCPv6 discard routes). It is shown `D`, like the
  existing `RibType::Dhcp`, which stays what it was: a route the kernel
  reports under `RTPROT_DHCP` that zebra-rs did not install. Keeping the
  two apart leaves every kernel-route path treating `Dhcp` as learned.
  - `RibType::Ra` (shown `A`, installed as `proto ra`) covers RA default
    routes and on-link prefixes (P2). A kernel route under `RTPROT_RA`
    that zebra-rs did not install stays a learned `Kernel` route; the RIB
    records it (`Rib::learned_ra`), and the RA host takes it over when it
    installs a route at the same table, prefix and priority
    (`Rib::adopt_learned`), as the DHCP client does a learned `Dhcp`
    route.
- **Installed as `proto dhcp`**, what `ip route` shows for any DHCP
  client's routes.
  - Not `proto zebra`, as first planned: echo suppression and the
    startup leftover handling map each kernel protocol number to one RIB
    type, and `proto zebra` is the statics'.
  - A kernel event under `RTPROT_DHCP` is the client's own echo when the
    client has that route installed at that priority; otherwise it is a
    learned `Dhcp` route.
- **Kernel-learned `proto dhcp` routes stay learn-only** at distance 0.
  This covers insomnia's delegated-prefix routes. insomnia sweeps only
  inside its configured ranges (insomnia `src/pd_routes.rs:24-30`), so it
  cannot touch a client's routes.
- **Restart.** zebra-rs leaves its routes in the kernel when it stops.
  - They cannot be swept blindly like a static's leftovers:
    `RTPROT_DHCP` is not ours alone (nor is `RTPROT_RA`, the RA host's).
  - So the RIB keeps a record of the client's and the RA host's routes
    beside the leases (`<state dir>/routes.json`, `rib/route_record.rs`):
    type, table, prefix, kernel priorities and distance, rewritten as
    they change. The next run's startup dump reads a route the record
    names as a stale leftover of its type, which the owner's route
    replaces in place when it installs it again, and the leftover sweep
    (`--leftover-sweep-time`) removes otherwise: a lease gone, or
    `no-default-route` set, while zebra-rs was down. At the sweep the
    record also drops what nothing installed again, including a route
    already gone from the kernel when the run started, so a later run
    cannot take another program's route at that key for its own. Routes
    the record does not name stay learned `Dhcp` (or `Kernel`) routes.
  - A learned route the record does not name (an older run's, before the
    record) is still taken over when the client hands over a route at the
    same table, prefix and priority (`Rib::adopt_learned`).
- **One entry per prefix, chosen by the client.** The RIB keeps one entry
  per protocol for a prefix, so `dhcpc` gathers every interface's lease
  routes (`dhcpc/routes.rs`) and hands over the legs at the lowest
  `default-route-distance`, from interfaces whose link is up:
  - one leg is a plain route;
  - several at one distance are ECMP, what VyOS gets from FRR for two
    DHCP uplinks left at the default;
  - a higher distance is a backup. It takes over when the better
    uplink's lease ends or its link goes down, and gives way again
    when it returns.
  - Not per-interface RIB entries, as first planned (the RIB would need
    a new entry key), and not the RIB's multi-metric "floating" entry:
    that has one distance for all its members and tells them apart by
    metric, where the uplinks differ in distance, the value that ranks a
    leased route against the other protocols' routes.
- **Default distance 210** (VyOS's `default-route-distance` default).
  That is above iBGP (200), OSPF (110) and IS-IS (115), so any routed
  default wins over a leased one.

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
  - The file is one line of text, `xx:xx:…`, the form the configuration
    takes, so an operator can read it or put a chosen DUID there.
  - A file that holds no DUID is replaced, with a warning. A file that
    cannot be read is left alone: the error says nothing about what is
    in it.
- `dhcpv6-options duid` overrides it per interface (VyOS).

**IAIDs**

- IA_NA: a stable 32-bit hash of the interface name (FNV-1a, written
  out in `dhcpc/ident.rs` so that no compiler or library version can
  change it). The ifindex is not stable across reboots.
- IA_PD: the `pd <id>` number, as VyOS uses it.

**DHCPv4 client identifier**

- Default: no option 61, so the server keys the lease on the MAC in
  `chaddr`. That is ISC dhclient's default, which VyOS keeps.
- `dhcp-options client-id` sets one: hex `xx:xx:…` is sent raw, any other
  string as type 0 plus the bytes.
- RFC 4361's DUID-based identifier is not the default (§16).

**The identity of a lease does not change.** A lease belongs to the
hardware address and client identifier it was taken with (RFC 2131 §4.2
has the client use the same identifier in every message about it).

- A `Client` has one identity for its whole life; a changed `client-id`
  or hardware address never reaches a running one.
- When either changes, the task stops the client, which releases the
  lease as who took it, and starts a new client that asks as the new
  identity.
- The lease file records the identity. At start, a lease the current
  identity took is resumed. One taken under another identity is resumed
  as that identity just long enough to be released and withdrawn.
  - The RELEASE leaves from the lease's address, which after a reboot is
    not on the interface until the RIB has installed it. So the release
    waits until a datagram can leave from that address for the server
    (the address is local and there is a route), then is sent, and only
    then is the lease forgotten and the new identity's client started.
  - With the link down it waits for the link. With the link up it waits
    10 s for the RIB, then gives up with a warning and leaves the lease
    to run out at the server.
  - Meanwhile the old identity's client takes no protocol events (it is
    shown as `releasing`), and `renew` only looks whether the release
    can go now. `release` ends the transition there: the RELEASE goes out
    as well as it can, and the interface is left released as its current
    identity, not started on a new lease.
  - The wait is looked at on every event that may end it and on a
    250 ms tick whose deadline other events do not push back.

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
- Once bound: a UDP socket on `0.0.0.0:68`, with `SO_BINDTODEVICE` on the
  interface and `SO_BROADCAST`. It is used for unicast RENEWING,
  broadcast REBINDING and RELEASE.
  - **Bound to `0.0.0.0`, not to the leased address.** A server
    broadcasts a DHCPNAK (RFC 2131 §4.1, when `giaddr` is zero), and a
    socket bound to a unicast address is not given broadcasts: a refused
    renewal would go unheard and the client would keep a lease the server
    has taken back.
  - **Each message names its source** with `IP_PKTINFO`
    (`ipi_spec_dst`): the leased address, which is the message's
    `ciaddr`. Left to choose, the kernel takes the interface's primary
    address, which is another one when addresses are configured beside
    the lease, and the source would contradict `ciaddr`.

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
      reject <ipv4-address|prefix>*      # ignore offers from these servers
      mtu                                # empty: apply option 26 (P5, not in the schema yet)
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
| `address dhcp` beside static addresses | error | an interface is addressed by DHCP or statically: the `must` on the `address` list, enforced by `config::check::address_dhcp_exclusive` (a startup config only warns, and the lease is then one more address) |
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
| DHCPv4 default route (option 3, first router) | `DhcpClient`, `default-route-distance` | `proto dhcp` |
| DHCPv4 option 121 routes (option 3 ignored when present, RFC 3442) | `DhcpClient`, same distance. A router of `0.0.0.0` (an on-link destination) is not installed and is logged: the RIB has no protocol route without a gateway | `proto dhcp` |
| Gateway outside the leased subnet (a /32 lease) | nothing extra: the nexthop names the lease's interface, and the RIB installs every nexthop object on-link | |
| SLAAC address | `AddrDynAdd(Slaac)`, `noprefixroute` | RFC 4862 lifetimes |
| RA default route | `Ra`, `ra-options default-route-distance`, via the router's link-local | `proto ra` |
| RA on-link prefix (L=1) | `Ra`, lives as long as the PIO's valid lifetime. Built (P2) as a nexthop with no gateway pinned to the interface, not `Nexthop::Link`, which the RIB does not install for a protocol route; the FIB installs it as `dev <if>` with no nexthop object | `proto ra` |
| IA_NA address | `AddrDynAdd(Dhcp6)`, /128, `noprefixroute` | IA lifetimes |
| Delegated prefix | `DhcpClient` unreachable route (WPD-5); `Nexthop` gains an unreachable form if it lacks one, because WPD-5(a) wants ICMPv6 Destination Unreachable and a blackhole sends nothing | |
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
- Each of these transmissions has a transaction id of its own, taken with
  the time it is sent, and the lease an ACK grants counts from the
  REQUEST it answers. With one id across retransmissions, a late answer
  to an earlier copy would be timed from the latest and keep the lease
  past what the server granted.
- When the lease expires, everything it produced is withdrawn and the
  client starts again in INIT.

**NAK:** the lease is withdrawn and the client restarts in INIT. A backoff
of 1, 2, 4 … up to 64 s stops a server that NAKs everything from causing a
tight loop.

**MTU (option 26)** is P5: the state machine can ask for it and keeps it
in the lease, but there is no `mtu` leaf yet and nothing applies it.

- It will be applied only with `dhcp-options mtu` and no
  `interface <if> mtu` configured. The configuration wins.
- Values below 576 are ignored.

**Release:** a deleted `address dhcp`, or `release dhcp interface <if>`,
sends a RELEASE to the server and withdraws everything. After the verb,
the client stays released until `renew`, or until `address dhcp` or the
`client-id` is configured anew (other options do not wake it).

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

**What P2 built** (`zebra-rs/src/nd/host.rs`), beyond the above:

- An RA counts only from a link-local source (RFC 4861 §6.1.2). An RA
  with a non-zero router lifetime ends the solicitation burst.
- A Router Solicitation goes out from a usable link-local, with the
  Source Link-Layer Address option; while the interface's link-local is
  still in DAD it waits, rather than going out from `::`.
- Among an interface's routers, and across interfaces, the default route
  takes the legs at the lowest `default-route-distance` and, among those,
  the best router preference; several left are ECMP. Two interfaces
  advertising one on-link prefix in one VRF: the lower ifindex carries it.
- A SLAAC address is `noprefixroute`, and so the RIB derives no connected
  route from it (`LinkAddr::has_connected_route`): the prefix is on-link
  only through the RA host's own route. An address the kernel reports
  with `noprefixroute` but no component claims keeps its connected route,
  as before. After a restart a SLAAC address is read back unclaimed; when
  the RA host claims it again, the RIB withdraws the connected route it
  had derived, or that route would outrank the on-link `Ra` route.
- A VRF move (the RIB announces it as a delete and an add) gives the
  SLAAC addresses up and starts the host again in the new VRF.

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
- An ORO asking for 23 (DNS), 24 (domain list), 56 (NTP), 82 (SOL_MAX_RT)
  and 83 (INF_MAX_RT). An Information-request also asks for 32
  (information refresh time), and no other message does (RFC 8415
  §21.23). Confirm, Release and Decline carry no ORO.
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
- Lifetimes, T1 and T2 count from when the Reply arrived, not from when
  its request was sent as in DHCPv4.

**Status codes**

| Code | Response |
|---|---|
| NoAddrsAvail / NoPrefixAvail | that IA is retried at the next Renew; the others bind |
| NoBinding on a Renew or Rebind | Request |
| NotOnLink on a Confirm | Solicit |
| UseMulticast, UnspecFail | the message goes out again when its retransmission is due (every message is multicast already) |

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

**What P3 has built so far** (`zebra-rs/src/dhcpc/v6/client.rs`,
`dhcpc/ident.rs`): the state machine for IA_NA and `parameters-only`,
without I/O, and the identity. The socket, the RIB, the configuration,
show and persistence are the rest of P3. Beyond the above:

- **Refusals back off.** When a Request is refused (NoAddrsAvail,
  NotOnLink, no usable address), when a renewal takes the last address
  away, and after a Decline, the client waits 1, 2, 4 … up to 64 s before
  it solicits again. RFC 8415 leaves that pace to the client; the wait
  keeps a server that offers and then refuses from being asked in a
  tight loop, as the NAK backoff does for DHCPv4.
- **A renewal that gives nothing leaves the lease as it is.** On
  NoAddrsAvail, or a Reply without the IA, the Renew or Rebind goes on at
  its retransmission pace (10 s doubling to 600 s), which is the rate
  limit RFC 8415 §18.2.10.1 asks for.
- **NoBinding keeps the address in use** while the Request for the
  binding is out. If that Request is refused or goes unanswered, the
  lease is withdrawn and the client solicits.
- **T1 and T2.** The server's are used when both are set, in order, and
  T1 comes before the last address expires. Otherwise the client takes
  0.5 / 0.8 of the shortest preferred lifetime among the addresses still
  preferred, at least one second (RFC 8415 §14.2: not at once).
- **Addresses expire one by one.** An IA_NA can hold several; each
  leaves the lease at the end of its valid lifetime, and the last takes
  the lease with it. A Reply to a Renew adds, updates and (valid
  lifetime 0) removes addresses; what it does not name keeps its
  lifetimes.
- **Release and Decline are exchanges.** Each is sent up to four times,
  a second apart and doubling, until the server replies. The address is
  out of use before the Release is first sent. After a deleted
  configuration the client is finished only when that exchange is over
  (`Client::finished`); the task keeps it and its socket until then.
  `renew` during a `release` cuts the exchange short and starts over.
- **A lease resumed past T2 is rebound, not confirmed**: any server is
  asked about it anyway.
- **The link.** The client is told when the interface can carry DHCPv6:
  the link is up and has a link-local address past DAD. Without it a
  held lease stays and only its lifetimes run; nothing is sent. With
  `parameters-only`, a link that comes back is asked again, since it may
  be another link (RFC 8415 §18.2.6).
- **`parameters-only` is fixed for a client**, like the DUID and the
  IAID: it decides which of two protocols is spoken. When any of the
  three changes, the task stops the client, which releases as who it
  was, and starts another.
- **Not used:** the Server Unicast option (every message goes to
  `ff02::1:2`), and Reconfigure.

---

## 9. Identity and persistence

| File | Contents | Lifetime |
|---|---|---|
| `/var/lib/zebra-rs/dhcp/duid` | the system DUID (D8), as `xx:xx:…` text | created once; rewritten only when it holds no DUID |
| `/var/lib/zebra-rs/dhcp/<if>.v4.json` | the lease, when it began, and the identity that took it (hardware address, client identifier) | written at bind and renew, deleted on release, expiry or deleted configuration |
| `/var/lib/zebra-rs/dhcp/<if>.v6.json` | server DUID, IAs with addresses and prefixes, LAN assignments | same |

- `ZEBRA_DHCP_STATE_DIR` overrides the directory, as
  `ZEBRA_OSPF_CHECKPOINT_DIR` does for checkpoints: for tests, and for
  several daemons on one host (the BDD harness sets one per namespace).
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
zebra-rs/src/dhcpc/            (P1: the DHCPv4 parts)
  inst.rs                      the task: select! over sockets, timers, RIB,
                               config, show; Action -> sockets, RIB, disk
  config.rs                    callbacks for /interface/ipv4/address (dhcp),
                               …/dhcp-options, /system/hostname; later
                               /interface/ipv6/address (dhcpv6),
                               …/dhcpv6-options
  v4/client.rs                 sans-I/O: handle(Event, now) -> Vec<Action>
  v4/frame.rs                  IPv4+UDP framing, ARP probes
  v4/socket.rs                 AF_PACKET + BPF, ARP, per-interface UDP (D11)
  routes.rs                    lease routes -> RIB entries (D6)
  lease.rs                     persistence (§9)
  show.rs                      §11 view; the verbs are in inst.rs
  v6/client.rs                 sans-I/O, as v4/client.rs: IA_NA and
                               parameters-only (P3; the task does not run
                               it yet). IA_PD is P4
  ident.rs                     the DUID file, DUID text form, IAID (P3)
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
| P0 (done) | Codec move + typed options + property tests; insomnia switches to the vendored copy (relay goldens unchanged) | – |
| P1 (done) | RIB plumbing (D5, D6); `dhcpc` task; DHCPv4 state machine, sockets, ACD, persistence; `show dhcp client leases`, `renew/release dhcp`; ungate `address dhcp` | P0 |
| P2 (done) | RA host in `nd`: RS, default route, on-link prefixes, `ipv6 address autoconf`, `ra-options`, `accept_ra=0`; show section | P1's RIB plumbing |
| P3 (state machine and identity done) | DHCPv6 IA_NA and `parameters-only`; DUID; `show dhcpv6 client leases`, `renew/release dhcpv6`. Left: the socket, `AddrOrigin::Dhcp6`, the schema, the RA host started by `address dhcpv6`, show and exec, persistence, the BDD feature | P0, P2 |
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
| On-link classless routes | RFC 3442 routes whose router is `0.0.0.0` | not installed, logged | the RIB has no protocol route without a gateway; an off-subnet gateway still works, because nexthops are installed on-link |

---

## 17. Open questions

1. ~~`RibType::Ra` or reuse `Dhcp`?~~ Settled in P2: `RibType::Ra`,
   shown `A` (D6).
2. ~~Equal distances on two WANs.~~ Settled in P1: ECMP, as VyOS has it
   (D6).
3. ~~DUID type.~~ Settled for P3: DUID-LLT (D8). It survives an image
   reinstall only through `/var/lib`; `dhcpv6-options duid`, or a DUID
   written into the file by hand, covers the operator whose ISP binds a
   delegation to a particular one.
4. **Should `release` survive a zebra-rs restart** (a marker in the lease
   file), or does a restart renew?
5. **Feeding LAN /64s to insomnia's DHCPv6 server.** Kea's subnets are
   static configuration today; VyOS doesn't do it either. A dynamic subnet
   is a later insomnia feature.
6. **Keeping the DHCPv4 lease on carrier loss** (D10) matches
   systemd-networkd, while dhcpcd drops it. Confirm against the ISPs we
   care about.
