# Native DHCP client (DHCPv4, DHCPv6, RA host)

**Status: P0 (the codec), P1 (the RIB plumbing and the DHCPv4 client),
P2 (the RA host), P3 (the DHCPv6 client for an address and for
`parameters-only`) and P4 (prefix delegation) are implemented:
`dhcpv6-options pd <id>` asks for a delegated prefix, which is held,
saved, shown and given a discard route, and `pd <id> interface <lan>`
numbers an interface behind the router from it. ND-PIO is implemented
too: an advertising interface names the /64s of its addresses in its
Router Advertisements, those of a delegated prefix among them. What
follows that is design.** Where a
phase found the code to be different from what this document assumed,
the text below says what was built and why.

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
- Writing `resolv.conf`. The name servers of a DHCPv4 lease, of a
  DHCPv6 server and of Router Advertisements go to systemd-resolved,
  unless `no-name-server` keeps them back (§13).
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
  - The RAs zebra-rs sends carried no PIO (`nd/config.rs:133`,
    `nd/send.rs:92`). They do since ND-PIO (D14).
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
- A change of lifetimes alone must reach `nd`, which needs the new
  lifetimes to advertise PIOs (D14). As built it is not an
  `RibRx::AddrAdd`, as first planned, but a message of its own,
  `RibRx::AddrRenewed`, sent to the `global_links` subscribers only:
  - an `AddrAdd` has a protocol that advertises an interface's
    addresses originate anew, and a renewal comes with every lease and
    every Router Advertisement heard (the reason
    `AddrUpdate::Unchanged` was silent);
  - `link_addr_update` so tells a renewal (`AddrUpdate::Renewed`) from
    a notification that changes nothing. By when the lifetimes end,
    not by their numbers: `LinkAddr` keeps when its lifetimes were
    noted (`lft_noted`), since they are what was left at that moment
    and are not counted down in the RIB. A server that gives the same
    lifetimes with every renewal moves their end each time, and the
    kernel's word on a renewal a second later, with a second less, does
    not. `LinkAddr::ends` is what a subscriber reads: a link described
    anew (a move to another VRF is a `LinkDel` and a `LinkAdd`) hands
    out the numbers as they were noted, and counted from the moment
    they arrive they would end too late.
  - A dynamic address that is renewed is replaced in the kernel in
    place and goes through no duplicate address detection. The RIB
    noted it as tentative like a new one, which the kernel's
    notification then took back: every renewal was two changes of the
    address's state to every protocol. It keeps the state the kernel
    last reported.

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

- One per system, generated once as a DUID-LLT from an Ethernet MAC:
  that of the first interface to run a DHCPv6 client, or else the first
  hardware address there is. The address only goes into a DUID made
  then; one on disk stays what it is, and is read without a hardware
  address, so an interface that has none (a tunnel, a PPP link) gets its
  client all the same. Only making a DUID waits for an address, and a
  client that waits starts when any interface brings one.
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

  As built (ND-PIO, `nd/prefix.rs`):
  - **Which prefixes.** The /64 of each global address of the
    interface that is in the kernel and brings its connected route: a
    configured one, and one from a delegated prefix. That is RFC 4861
    §6.2.1's default for `AdvPrefixList`. Not a SLAAC or a leased
    address (`noprefixroute`: another router's prefix), not one that
    failed DAD, and not a prefix of another length, which no host
    forms an address from. Both flags, L and A, are set.
  - **No configuration.** `send-advertisements true` is all there is:
    an interface that advertises names what it has. An interface with
    link-local addresses alone (BGP unnumbered) names nothing, as
    before.
  - **Lifetimes.** RFC 4861's defaults (30 days valid, 7 preferred)
    for an address that never ends, the same in every advertisement.
    What is left of them, to the second, for an address that has
    lifetimes: `nd` notes when they end as the RIB reports the address
    (`RibRx::AddrAdd`, `AddrRenewed`, D5) and works out the rest when
    an advertisement is built, not when it is scheduled.
  - **A prefix that came or went is told at once**, as a router that
    starts advertising tells what it has: the initial advertisements
    again (RFC 4861 §6.2.4), the first within half a second. **A
    lifetime that moved is told once, soon**: the old one may run out
    before the next periodic advertisement, which can be ten minutes
    away. Both keep to the three seconds between advertisements.
  - **A prefix that went** (the delegation changed or was given back,
    or the address was deleted) is advertised with both lifetimes 0
    and its flags as they were, until the longest valid lifetime an
    advertisement ever gave it is over: `nd` notes what each
    advertisement that went out said (`Prefixes::sent`). The longest
    and not the last, since a host does not take a valid lifetime that
    is shortened to under two hours, and one that missed the
    advertisement which shortened it knows nothing of it. A prefix no
    advertisement named is not withdrawn: no host holds it. What the
    hosts were told goes with a link that is deleted, since another
    device that has its index later has other hosts. It is kept for a
    link that moves to another VRF, which the RIB reports as a delete
    and an add and now announces as that (`RibRx::LinkMoving`, to
    `global_links` subscribers): a prefix the link comes back without
    is withdrawn. That is RFC 9096 §3.5, which
    replaces the L-13 of RFC 7084 this document first went by (a
    preferred lifetime of 0, and a valid one of the remaining lifetime
    or two hours). A host that hears it deprecates its address, no
    longer takes the prefix for on-link, and keeps the address for two
    hours at most (RFC 4862 §5.5.3); one that was away meanwhile still
    hears it when it is back. When the prefix comes back it is itself
    again.
  - **Shown** in `show ipv6 nd interface`, with the lifetimes of the
    moment, and on one that went `(withdrawn, named for another …)`.
  - Not kept across a restart: a prefix that went while zebra-rs was
    down is not advertised as gone (§16).
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
      no-name-server                     # empty: name servers shown, not the host's (§13)
      reject <ipv4-address|prefix>*      # ignore offers from these servers
      mtu                                # empty: apply option 26 (P5, not in the schema yet)
  ipv6
    address autoconf                     # new enum arm: RA host + SLAAC
    address dhcpv6                       # new enum arm: IA_NA
    ra-options                           # zebra-rs extension (VyOS has none)
      default-route-distance <1-255>     # default 210
      no-default-route
      no-name-server                     # RDNSS/DNSSL shown, not the host's (§13)
    dhcpv6-options
      duid <hex>                         # overrides the system DUID
      parameters-only                    # Information-Request only
      rapid-commit
      no-release
      no-name-server                     # name servers shown, not the host's (§13)
      pd <0-4294967295>                  # IAID of this IA_PD
        length <32-64>                   # hint; default 64
        interface <lan-if>               # numbered from the prefix: one /64 of it
          sla-id <0-4294967295>          # which /64; default 0, the first
          address <1-18446744073709551615>   # host part; absent: EUI-64
```

**How the RA host is enabled:** it runs on an interface with any of
`address autoconf`, `address dhcpv6` or `dhcpv6-options pd`, because each
of them needs the RA default route. SLAAC addresses are made only with
`autoconf`.

- Built for `autoconf` (P2), `address dhcpv6` (P3) and `pd` (P4).
  `parameters-only` alone does not start it: it asks for no address,
  and goes with `autoconf` where routes are wanted.
- A host that goes on running for `address dhcpv6` follows `autoconf`
  coming and going: its SLAAC addresses are given up when `autoconf` is
  deleted, and the routers are solicited again when it is set, since
  the prefixes an address is formed from come with their answer.
- `show ipv6 nd interface` says what asked for the host:
  `RA host: enabled (autoconf, dhcpv6, pd)`.

**Commit-time checks**

| Condition | Severity | Effect |
|---|---|---|
| `address dhcp` beside static addresses | error | an interface is addressed by DHCP or statically: the `must` on the `address` list, enforced by `config::check::address_dhcp_exclusive` (a startup config only warns, and the lease is then one more address) |
| `dhcp-options` / `dhcpv6-options` / `ra-options` without the address value that uses them | warning | stored, unused |
| `parameters-only` with `address dhcpv6` or `pd` | error | an Information-Request carries no IAs (`config::check::dhcpv6_parameters_only_exclusive`: one error for each of the two the interface has); a startup config only warns, and the client then asks for what is to be leased |
| `dhcpv6-options duid` that is not 3 to 130 hex octets | error | the schema's pattern says what an octet is and that there are three; the count is checked at commit (`config::check`) |
| `pd … interface X` where X is the WAN interface itself | error | a delegated prefix must not number the link it is delegated on (RFC 8415 §6.3). `config::check::dhcpv6_pd_interfaces`; a startup config only warns, and the client leaves that entry alone |
| two interfaces of one `pd` with the same `sla-id` (0 for one that names none) | error | they would share a /64. The same check; a startup config only warns. One interface under two `pd` ids is not refused, as first planned: the prefixes differ, so the /64s do |
| `sla-id` beyond what a prefix of the `length` asked for holds | warning, in the log | said when a commit brings it, and only when `length` is set: without it there is nothing to compare with. The server decides what it delegates, so the client looks again at the prefix it gets (WPD-3) |

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
| Delegated prefix | `DhcpClient` discard route at distance 210, in the WAN interface's VRF (WPD-5). Built as `Nexthop::Blackhole`: the RIB has no unreachable form, so the packet is dropped without the ICMPv6 Destination Unreachable that WPD-5(a) asks for (§16). An unreachable form of `Nexthop` is what would send it | `blackhole <prefix> proto dhcp` |
| LAN /64 from a delegation | `AddrDynAdd(Pd)` on the LAN interface, with its prefix route: the /64 is a connected route. When the address is given up, the RIB makes it permanent before it deletes it (`Rib::addr_dyn_del`): the kernel removes an IPv6 address's prefix route with the address only when the address is permanent, and one with a lifetime would leave its /64 on-link until that lifetime ran out. The kernel reports that step as it reports any change to an address, after the address is gone from the RIB; that notification is dropped (`Rib::addr_withdrawing`), or the address would be back for a moment, as a permanent one, and every subscriber told of it | the prefix's lifetimes; `<subnet>/64 dev <lan> proto kernel` |

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
- No message is longer than 548 bytes: with the IP and UDP headers that
  is the 576-byte datagram every host takes (RFC 791), and nothing tells
  a client that the servers and relay agents on its link take more
  (RFC 2131 §2 gives the client the same figure; option 57 raises it for
  replies only). The options go in the order 53, 61, 50, 54, 55, 57, then
  12, 60, 77. The first six always fit in the options field. One of the
  last three that the options field has no room for goes whole into
  `file`, then `sname`, which option 52 hands over to options (RFC 2131
  §4.1). One that fits in none of the three is not sent, and the log
  names it once.

**Offers**

- The first acceptable offer wins.
- An offer is unacceptable when its server identifier (option 54) or
  source falls in `reject`, or when it has no yiaddr or lease time.
- A missing subnet mask gets the classful mask and a warning.

**Which replies count**

- A reply carries the transaction id and the hardware address of the
  request.
- One that carries a client identifier (option 61) other than the one the
  client sent is ignored, and so is any identifier when the client sends
  none. RFC 6842 §3: a server returns the identifier it was sent and none
  otherwise, and a client discards a reply whose identifier is not its
  own.
- In REQUESTING, only the selected server's ACK or NAK counts: the
  REQUEST names that server, and the others take it as a refusal of their
  offers (RFC 2131 §3.1). A lease being verified (INIT-REBOOT) or
  extended names no server, so any server's NAK ends it.

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
  are stored with their lifetimes and shown, in the order RFC 8106 §6.2
  has a host use them: a server or domain heard of for the first time
  goes in first, those of one option in the option's order, and one
  that is refreshed stays where it is. Of one RA, what it withdraws (a
  lifetime of zero) is taken in before what it gives, and no more than
  64 of each are held: both as systemd-networkd has them (§16). The
  resolver task is told of every change (§13), unless `ra-options
  no-name-server` keeps them from the host.
- **The leaves of one commit take effect together.** `address
  autoconf`, `address dhcpv6` and the `ra-options` leaves are noted as
  the commit's lines come in and applied at its end, as the DHCP client
  applies its own. Applied one at a time, a host would run for a moment
  under half of what was committed: the task takes in a Router
  Advertisement between two lines if one is waiting. `address autoconf`
  committed with `no-name-server` handed an advertised name server to
  the system until the second leaf took it back, and with
  `no-default-route` the router became the default route.
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
| NotOnLink on a Confirm | Solicit, when the Confirm exchange ends and no server has said Success |
| UseMulticast, UnspecFail | the message goes out again when its retransmission is due (every message is multicast already) |

**Delegated prefixes**

- Each delegated prefix gets the discard route (§5), for as long as the
  lease holds it.
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

**What P3 built** (`zebra-rs/src/dhcpc/v6/`, `dhcpc/ident.rs`). First
the state machine (`v6/client.rs`), beyond the above:

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
- **T1 and T2.** A time the server sets is used as it is (RFC 8415
  §21.4, a MUST), "never" included (§7.7), and also when it comes after
  the addresses have run out: the lease then ends unrenewed, as the
  server chose.
  - A time left 0 is the client's: 0.5 / 0.8 of the shortest preferred
    lifetime among the addresses still preferred, at least one second
    (§14.2: not at once).
  - When the server sets only one of the two, the other is chosen to go
    with it: T1 no later than 5/8 of the server's T2 (the proportion of
    0.5 to 0.8, so the lease's own server is asked before any other),
    T2 no earlier than 8/5 of the server's T1.
- **A Confirm is decided when its exchange ends, unless a server says
  Success first** (RFC 8415 §18.2.10.3). One Success, from any server,
  keeps the lease at once. NotOnLink is noted and the Confirm goes on
  being sent, because the server that would say Success may have missed
  it on a link that has only just come up. When the ten seconds are
  over, a lease that only NotOnLink was said about is withdrawn and the
  client solicits; one that nothing was said about is kept.
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

Then the task (`v6/inst.rs`), which runs the clients beside the DHCPv4
ones in `dhcpc`:

- **A leased address is a /128 with `noprefixroute`**, claimed in the
  RIB as `AddrOrigin::Dhcp6` and installed with the lease's preferred
  and valid lifetimes. The client installs no route: the default route
  and the on-link prefixes are the RA host's.
- **The client talks when the link is up and has a link-local address
  past DAD** (the RIB's address events carry `tentative` and
  `dadfailed`). The socket is one UDP socket per interface on port 546,
  bound to the device; the kernel picks the link-local source for
  `ff02::1:2`.
- **A leased address that fails DAD** (`dadfailed`) is withdrawn and
  declined; one the kernel drops is taken out of the lease.
- **Retiring.** When the configuration gives an interface another DUID
  or the other mode, or is deleted, its client is stopped: the address
  is withdrawn at once and the Release goes out as who took the lease.
  That client stays, beside its successor and on the same socket, until
  the server has answered or the Release has been sent as often as it is
  to be. It stops under the options as the commit leaves them:
  `no-release` set together with the deletion means no Release.
- **A lease saved under another identity** (the DUID or the mode changed
  while zebra-rs was down) is resumed as who took it, which claims its
  address so that it can be withdrawn, and released as that identity
  once the link can carry the Release. If the link never can, it is
  withdrawn when its lifetime ends. `release dhcpv6 interface` ends the
  wait: no lease is wanted on the interface, so that one is withdrawn
  too, and released if the link allows.
- **Only the current client's lease is on disk.** A retiring client's
  is on its way out: when it changes (one of its addresses goes) it is
  not written again, or the next start would take it for a lease to
  resume.
- **`release` does not survive a restart**, as for DHCPv4: the lease
  file is gone, and the next start asks for a lease (open question 4).
- **What `parameters-only` learns is not kept on disk**: it is asked for
  again at start.

**What P4 built**: the state machine (`v6/client.rs`) asks for
delegated prefixes and holds them, alone or with the address, and the
task (`v6/inst.rs`) asks for what `dhcpv6-options pd` configures, keeps
the lease on disk, shows it, gives each prefix its discard route and
numbers the interfaces `pd <id> interface` names. The state machine
first, then the task.

- **What a client asks for is part of who it is.** The IA_NA and each
  IA_PD (its IAID and the length hinted at) are fixed for a client's
  life, like the DUID (`Asks`). When the configuration asks for
  something else, the task stops the client, which releases what it
  holds, and starts another. So adding a `pd` to an interface that
  already leases an address gives the address back and asks for both
  anew; and a changed `length` takes effect at once, in the Solicit of
  the new client, where a hint counts.
  - A client that asks for nothing speaks Information-request: that is
    `parameters-only`, which is no longer an option of its own in the
    state machine.
- **One exchange for all of it.** Every message that asks names every
  identity association: what is held of each, and for one that holds
  nothing an empty IA_NA or an IA_PD with the hint `::/<length>`. What a
  server withholds (NoAddrsAvail, NoPrefixAvail, or silence about it) is
  so asked for again with every Renew and Rebind, while the rest binds
  (WPD-6).
- **Each identity association has its own T1 and T2**, worked out as
  for an address, and each is kept (RFC 8415 §21.4): a Renew from its
  T1, with its server and about all that server leases (§18.2.4), and
  the Rebind from its T2 (§18.2.5).
- **A Reply that leaves an identity association out** extends the rest,
  which is in use at once (RFC 8415 §18.2.10.1). The one left out keeps
  its lifetimes and its own T1 and T2, and the Renew or Rebind goes on
  for it at its retransmission pace, which is the rate limit the RFC
  asks for. A Renew is over when everything it asks about has been
  answered in it, by one Reply or by several, or is past its T2 and so
  the Rebind's to ask about, or was given by another exchange since the
  Renew went out.
  - A Rebind in a Confirm's place goes on to the end of the Confirm's
    ten seconds. An answer for the address says nothing of whether the
    prefix is right for the link.
  - If no server extends what was left out, it runs out, the lease goes
    on without it, and the exchange is over.
  - This is about what is held. An identity association that holds
    nothing and gets no answer is asked for again with the next Renew.
- **The server that offers more is asked.** Among Advertises, the one
  that offers more of the identity associations asked for wins, then
  the higher preference, then the first to arrive; and preference 255
  ends the wait only from a server that offers all of them. An address
  without the prefix is half a lease for a CE router (§16).
- **A lease with a prefix is verified with a Rebind**, not a Confirm,
  which speaks of addresses only (RFC 8415 §18.2.12). It runs in a
  Confirm's time: again after a second, over in ten, and the lease is
  then used as it is. A prefix that is not right for the link comes back
  with a valid lifetime of 0 and is dropped.
- **Prefixes run out one by one**, like addresses: each leaves the lease
  at the end of its valid lifetime, and the lease ends when it holds
  neither an address nor a prefix. A prefix is what its length says:
  bits a server leaves set past it are dropped.
- **Decline is about addresses.** An address that fails DAD is declined
  and the prefixes stay; Release names everything held.
- **NoBinding for any identity association** asks for all of them again
  with a Request (RFC 8415 §18.2.10.1). What the same Reply says of the
  others is applied first, a valid lifetime of 0 included, so the
  Request names the lease as it then is. What is held stays in use
  meanwhile. Then, in the Reply to that Request:
  - an identity association the server had no record of is what the
    Reply makes of it. What was held of it and is not given again has
    no server behind it, and goes;
  - every other one is updated as a renewal updates it: what the Reply
    does not name stays.

  A Request that is refused, or never answered, ends the same way: what
  the server had no record of goes, and the rest of the lease goes on.
  With nothing left the client starts over.

  When such a round leaves something of that server's still to renew, a
  Renew for it goes out again, and the server may say NoBinding again.
  It is then not sent another Request for a while, which doubles from
  one second to 64: until then its NoBinding is a Reply that leaves
  that identity association out. Otherwise a server that says NoBinding
  and then gives nothing would be asked in a tight loop.
- **Each identity association has its server.** A lease is one
  server's when it is taken. A Rebind is for any server to answer, and
  one may answer for a part of the lease only, so each identity
  association records the server that last gave something of it:
  - a Reply that only takes away (a valid lifetime of 0, which any
    server may say of what is not right for the link) changes no
    server;
  - a Renew is for one server (RFC 8415 §18.2.4). It speaks of what is
    leased from that server and of what nobody has filled, never of
    another server's, and its Reply has no say there either. The Request
    after NoBinding likewise;
  - each server has a Renew of its own. It begins when an identity
    association leased from that server reaches its T1, is sent again
    at its own pace, and is over when the server has answered for all
    that is leased from it. So a server that does not answer holds up
    nobody else's renewal, and every T1 a server names is kept (RFC
    8415 §21.4). `renew` by hand asks every server at once;
  - what is past its T2 is asked about with the Rebind: one, for any
    server, about that alone. A Renew goes on beside it for what a
    server leases that is not past its T2. The Rebind goes on until
    nothing is past its T2 any more: extended, or run out. A Reply to
    it has no say about what is not past its T2 when the Reply comes:
    something a Request has given again since, for one;
  - the Request after NoBinding is one more exchange, with the server
    that said it. The Renews with the other servers, or the Rebind, go
    on beside it, and their Replies are taken: it holds up neither a T1
    nor a T2. The state shows `requesting` while one is out. A server
    that says NoBinding again to the Rebind gets no second Request
    while the first is out;
  - what one server answers moves no other server's times: the lease's
    times go on counting from where they did;
  - a Request has no say about what another exchange has given since
    it went out. When an identity association its server had no record
    of is given again, by whatever server, it is no longer that
    Request's to restore or to drop, and a Request with nothing left to
    recover is over. Nor can a late Reply to the Request take it away,
    though its own server gave it: the Request no longer names it, and
    what a Reply says of it is an answer to a question from before. A
    Request names what is held when it is sent, not when it first went
    out;
  - a Renew leaves out likewise what another exchange has given since
    it went out, and does not wait for an answer about it;
  - whatever is between its T1 and its T2 and is asked about by no
    exchange under way gets a Renew with its server. So for what a
    Request leaves out since another exchange gave it again: a Renew
    with the same server goes out beside the Request, about that. A
    Renew leaves to a Request that is out what the Request asks about.
    And so for what
    a Renew leaves out: a new Renew with that server takes its place,
    and asks about all that server leases. No other server's Renew is
    touched;
  - a Request to a server takes the place of a Renew with it, whichever
    exchange the NoBinding came to: the Request asks about all that
    server leases. One Request asks a server about all it has no record
    of: when it says NoBinding for something a Request that is out does
    not ask for, a new Request takes that one's place and asks for
    both. NoBinding for what the Request is out for already brings no
    other;
  - a Release goes to each server for its own, one after another, and a
    Decline to the server of the addresses. A Decline is exchanged
    alone: the Renews under way begin again when it is over, which is
    15 s at most;
  - the other configuration (DNS, NTP) is that of the server the
    addresses are leased from, or without an address the first prefix.

The task's part (`v6/inst.rs`):

- **`pd <id>` is the IAID of an IA_PD**, and `length` its hint, 64 when
  it is not set (VyOS's default). An interface asks for its address,
  for prefixes, or for both, and a client runs for any of them.
- **The discard route follows what is bound** (`sync_pd_routes`). After
  every event, the prefixes the clients hold are compared with the
  routes the RIB was last told of, and the difference is sent. That
  covers a bind, a renewal that brings another prefix, a prefix that
  runs out, a release, deleted configuration and a deleted link without
  a place of its own for each.
  - The route is in the table of the VRF the WAN interface is in. A VRF
    the task hears of after its member moves the route there.
  - A client on its way out counts while it still holds its lease (one
    read back from disk under another identity, until the link can
    carry its Release).
- **The route stays while the link is down.** A DHCPv4 default route is
  taken back on link down, so that a backup uplink takes over. A
  delegated prefix is still this router's then: the LAN goes on using
  it, and a packet for an unused part of it has nowhere better to go.
- **A lease of prefixes alone is a lease**: saved, resumed after a
  restart and verified by a Rebind, with no address on the interface.
  An address the kernel drops leaves the prefixes leased, and the file
  is written again without it.
- **The lease file names what was asked for**, with the DUID: the
  IA_NA's IAID and each `pd` with its hint. A file taken as another
  identity, which now includes another set of delegations or another
  hint, is not resumed as the interface's own: it is given back as who
  took it. A file written before delegations has no `pd` and is read as
  asking for the address alone.
- **Across a restart** the route is still in the kernel. A lease that
  is resumed installs it again over the one that is there; without a
  lease the RIB's record of its own DHCP routes (`rib/route_record.rs`)
  has it swept after the restart, like a DHCPv4 lease's routes.
- **`pd <id> interface <lan>` numbers an interface from the
  delegation** (`sync_pd_lan`). For each prefix the delegation holds,
  the interface gets one address: in the /64 its `sla-id` numbers (the
  bits from the prefix's length up to the 64th; 0 when not set), with
  the host part `address` names, or else the modified EUI-64 of its
  hardware address.
  - It is a dynamic address (`AddrOrigin::Pd`) with the prefix's
    preferred and valid lifetimes. Unlike a leased address it brings
    its connected route, which is what takes the /64 off the prefix's
    discard route.
  - Like the discard routes it follows what is bound: after every
    event, the addresses wanted are compared with those the RIB was
    last told of. The kernel counts the lifetimes down, so an address
    is handed over again only when the lease's times move (a renewal,
    or a prefix that ran out), and when its link comes up.
  - **A link that comes up is told again.** The kernel takes a link's
    IPv6 addresses away when it is set down, and an address added to a
    link that is down has no route to its /64. An address the kernel
    loses otherwise (an operator deletes it) comes back with the next
    renewal.
  - **An interface that cannot be numbered is left alone**, which is
    logged once and shown with the reason:
    - it is not there (not logged: a configuration may come before
      its interfaces);
    - it is the interface the prefix is delegated on;
    - it is in another VRF (D10). The VRF's own device counts as in
      the VRF;
    - the prefix is longer than a /64;
    - the `sla-id` needs more bits than the prefix leaves (WPD-3);
    - it has no `address` and no hardware address to make one from. A
      loopback is such an interface: `pd … interface lo address 1` is
      WAA-7 done by hand.
  - **The interfaces are not part of what is asked for.** Adding,
    changing or deleting one leaves the client and its lease as they
    are, and only the addresses move.
  - Only the current client's lease numbers anything. A client on its
    way out holds its lease to give it back.
- **The lease file names the addresses given**, each with the name of
  the interface it is on, and is written again when they change while
  the lease stays what it is (`Store::set_lan6`). At a restart they are
  still in the kernel, where the RIB reads them back as nobody's:
  - the ones still wanted are claimed with the times they now have;
  - the others are claimed and removed. That is an interface taken out
    of the delegation while zebra-rs was down, and every address of a
    lease that is given back because another identity took it;
  - an address of a prefix that ran out meanwhile is not looked for:
    the kernel dropped it when the prefix ended.

  Not covered: the WAN interface's whole DHCPv6 configuration deleted
  while zebra-rs was down. No client starts, so the file is not read,
  and the addresses go when their lifetime ends. A leased address is
  in the same position (P3).

---

## 9. Identity and persistence

| File | Contents | Lifetime |
|---|---|---|
| `/var/lib/zebra-rs/dhcp/duid` | the system DUID (D8), as `xx:xx:…` text | created once; rewritten only when it holds no DUID |
| `/var/lib/zebra-rs/dhcp/<if>.v4.json` | the lease, when it began, and the identity that took it (hardware address, client identifier) | written at bind and renew, deleted on release, expiry or deleted configuration |
| `/var/lib/zebra-rs/dhcp/<if>.v6.json` | the lease (server DUID and address, the IA_NA's addresses and each IA_PD's prefixes with their lifetimes and the DUID of the server they are leased from, DNS and NTP), when the server last confirmed it, and the identity that took it (DUID, the IA_NA's IAID, each `pd` with its hint), and the addresses its prefixes have given other interfaces, each with its interface's name (`lan`), for the next run to claim or remove | same |

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

As built in P3, one block per interface: VRF, state, DUID, IAID (not
with `parameters-only`), the server's address and DUID, each address as
`<address>/128 preferred <n>s valid <n>s`, `Renew in` / `Rebind in`
(`never` when the server said so), DNS servers, search list and NTP
servers. It lists no routes: the lease gives none.

As built in P4, each delegation asked for follows the addresses:
`Prefix: <prefix> preferred <n>s valid <n>s (pd <id>)` for each prefix
it holds, or `none (pd <id>)`. `Renew in` and `Rebind in` are those of
whatever is due first. In JSON, `pd` is a list of `id`, `prefixes`
(empty while nothing is delegated) and, of a delegation that holds
something, its own `server_duid`, `renew_in` and `rebind_in`. The
discard routes are in `show ipv6 route`, like any route.

Under a prefix comes one line for each interface configured to be
numbered from it: `on <if>: <address>/64`, or `on <if>: none (<why>)`.
In JSON a prefix has `interfaces`, a list of `interface` with its
`address` or the `reason` it has none. The address itself is in `show
interface`, marked `dhcpv6-pd`.

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
                               parameters-only (P3), IA_PD (P4)
  v6/inst.rs                   the DHCPv6 clients in the task: link
                               readiness, RIB addresses, retiring, DUID
  v6/socket.rs                 per-interface UDP socket on port 546 (D11)
  v6/show.rs                   `show dhcpv6 client leases`
  ident.rs                     the DUID file, DUID text form, IAID (P3)
zebra-rs/src/nd/host.rs        RS, RA -> routes and SLAAC addresses (§7)
zebra-rs/src/config/resolver.rs  spawn_resolver (with the first source)
zebra-rs/src/resolver/         (§13)
  inst.rs                      the task: what the sources report, what
                               resolved holds; the difference as
                               commands, retried
  resolvectl.rs                the commands as `resolvectl` runs, the
                               namespace check, $ZEBRA_RESOLVECTL
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

## 13. Resolver, and later NTP and MTU

On Ubuntu `resolv.conf` belongs to systemd-resolved, so zebra-rs never
writes it. A lease's name servers go to resolved as the DNS
configuration of the lease's link.

**Built: DHCPv4 leases, DHCPv6 (a lease's, and what `parameters-only`
is given), and Router Advertisements (RDNSS, DNSSL).**

- **By default.** The name servers an interface learns are the host's
  to use, as its leased address and its routes are: `address dhcp` is
  all it takes for a DHCPv4 lease's, `ipv6 address dhcpv6` or
  `dhcpv6-options parameters-only` for the ones a DHCPv6 server names,
  and the RA host running (`ipv6 address autoconf` or `address dhcpv6`)
  for the ones Router Advertisements name. That is what netplan does
  unless told otherwise
  (`dhcp4-overrides: use-dns`), with networkd (`UseDNS=`) as with
  NetworkManager, and an uplink that leases an address and a default
  route and then resolves no name is a surprise.
  - `no-name-server` turns it off for an interface, by source:
    `dhcp-options no-name-server` for its DHCPv4 lease's name servers,
    `dhcpv6-options no-name-server` for the ones its DHCPv6 server
    names, `ra-options no-name-server` for the advertised ones. They
    are then only shown.
  - It was explicit at first: `system name-server dhcp <if>`, after
    VyOS's `system name-server <interface>`, named the interfaces, on
    account of the two hazards below. That list is gone. The namespace
    hazard is refused by the task itself, and the VRF one has the
    leaves.
- **A task of its own**, `resolver`. A source reports what the host is
  to use of what it learns on an interface, and says the interface by
  its index (below). The task merges an interface's sources and makes
  resolved hold the result.
  - It has no configuration. Whether an interface's name servers are
    reported is its source's to say: each `no-name-server` is its
    source's, as each `no-default-route` is.
  - So the sources there are (the DHCP client, once for DHCPv4 and
    once for DHCPv6, and the RA host) need nothing of each other. The
    first two are one task and report apart all the same: a DHCPv6
    lease that ends leaves the DHCPv4 lease's servers set.
- **DHCP ahead of Router Advertisements** (RFC 8106 §5.3.1), and a
  DHCPv4 lease ahead of a DHCPv6 one. No RFC orders those two: it is
  the order systemd-networkd hands them to resolved in (`link_put_dns`:
  DHCPv4, DHCPv6, NDisc). Each source's servers are in its own order,
  and what several sources name is given once. The RA host's order is
  the RFC's (§6.2, §6.3; see §7): the newly heard first. One source
  losing its servers, or keeping them back, leaves the interface set
  with the others'.
- **DHCPv6** reports what its current client holds: the servers of
  option 23 and the search list of option 24, of a lease or of the
  answer to an Information-request (`parameters-only`), which is held
  with no lease. A client on its way out (another DUID was configured,
  §8) holds its lease only to release it and reports nothing; its
  successor reports once it has an answer of its own.
- **RA lifetimes** end what they gave like a lease's end does: a
  lifetime of zero at once, another when it has run out. The RA host
  wakes for that also when no route or address times out with it.
- **Per link, by running `resolvectl`:** `dns <index> …`, `domain
  <index> …` and `revert <index>`. They are the bus calls `SetLinkDNS`,
  `SetLinkDomains` and `RevertLink`, which is how NetworkManager feeds
  resolved. A command and not a D-Bus library: the calls are the same,
  it adds no dependency, and a stand-in program makes it testable.
  - **The interface is said by its index, never by its name.**
    `resolvectl` takes a number in place of a name and passes it on as
    it is, with no lookup of its own (`rtnl_resolve_interface`; every
    release since the first, systemd 239, takes one). A name it would
    look up itself when it comes to run, and a name can be another
    interface's by then: given up by one that was renamed or deleted,
    and taken by another. So a command reaches the interface it was
    started for, or resolved answers that it knows no such link.
- **What resolved does by itself** (checked on systemd 255). It keeps a
  link's settings while the link exists, across link down and up, and
  saves them in `/run/systemd/resolve/netif/`. It uses them only while
  the link is up with a routable address, and drops them with the link.
  So the servers are set when a lease is bound and reverted when it
  ends, and carrier loss needs nothing from us (D10 keeps the lease).
- **Search domains** are the domain name (option 15, split on spaces:
  some servers put several names there) and then the search list
  (option 119), and of DHCPv6 the search list (option 24). They go
  with the servers, as NetworkManager has it;
  networkd uses a lease's domains only with `UseDomains=`.
  `no-name-server` keeps both back.
- **Checked before use.** An unspecified, loopback, multicast or
  broadcast address is not a name server. A search domain must be a
  plain domain name: resolved reads `~name` as "route these names to
  this link" and `~.` as every name, and a lease must not get to say
  that. Servers with no usable address set nothing.
- **Failure.** `dns` runs first, then `domain`. A command that fails is
  tried again 5 s after it failed, then at doubling intervals up to
  5 min, so a resolved that starts after zebra-rs still gets its
  servers. The wait counts from the end of the command: one that runs
  into its time limit takes longer than the first waits are. A revert
  that fails is retried while the interface it was for exists; when
  that interface is gone, so are its settings.
- **What resolved holds is not always known**, and whatever may be ours
  is reverted once it is no longer wanted. Only a command that could
  not be started is known to have changed nothing. One that ran and did
  not report success says nothing about what the interface holds:
  - cut short, by the time limit or a signal, it may have made its call
    first;
  - an error from resolved can come after the change. Replacing a list
    (`SetLinkDNS`, `SetLinkDomains`), resolved 255 drops the whole list
    when it cannot add one of the new entries, and reports the error
    after that.

  After such a command, setting or reverting, the interface holds
  "something": it is set again if wanted, also with the servers that
  were set last, and reverted if not. The same holds between a `dns`
  that worked and a `domain` that did not.
- **An interface is its index, from the report to the command.** A
  source says the index of the interface it runs on: a DHCP client the
  one its lease is held on, the RA host the one its host runs on. Each
  has it from the RIB, with the link its sockets, its addresses and its
  routes are on. The resolver task keeps what is learned and what is
  held by that index, every command says it, and resolved keeps a
  link's settings by it. So no name is looked up anywhere on the way,
  and none can be another interface's by the time it is used. A name is
  only what the log and the record call an interface: the task asks the
  system for it when it has something to say.
  - **Deleted and made again**, a name is another interface, with
    another index, which holds nothing whatever the one before it held.
    Its source says so of each: the first has nothing any more, and the
    second what is learned on it, also when the lease that comes back
    says nothing new. And nothing is reverted on it that this run did
    not set: no command ever says an index that was given nothing.
  - **Gone**, an interface took its settings with it, and there is
    nothing to say to an index that is nobody's. The task asks whether
    the interface is there before every command, the first try and each
    later one, which can be 5 min after the one that failed, and after
    a command that failed. One that is gone is dropped without a
    command and without another try: what comes under its name is
    another interface, and its source reports that one. Only the
    system's word that no interface has the index makes one gone
    (`ENXIO`). Where the question itself fails, with no file descriptor
    left to ask with, the interface is taken to be there: taken for
    gone, what it holds would be forgotten and never taken back.
  - **Renamed**, an interface keeps its index, and resolved keeps its
    settings (it holds its links by index, and only changes the name it
    shows). It is the same interface to the task and to its source:
    what is wanted on it, what it holds and whether it is still waited
    for after a restart need no moving, and nothing is said to it for
    the change of name. Its name servers stay with the lease they came
    with. zebra-rs does not follow a rename yet: the RIB goes on
    calling the link what it was first called, so a DHCP client stays
    on the renamed interface, lease and all, and so do the name
    servers. Once it does follow, whether the lease stays is the
    client's to say, by what is configured for the new name, and the
    name servers go where the lease goes.
  - **While a command runs**, a rename, or two interfaces exchanging
    their names, changes nothing. The command reaches the interface its
    source reported, whatever that one is called by then, or no
    interface at all.
- **A restart of zebra-rs** leaves resolved as it is, as it leaves the
  lease's routes in the kernel. The resumed lease is reported and set
  again. What the earlier run set and this one does not learn again is
  taken back:
  - **A record** (`<state dir>/resolver.json`, `resolver/record.rs`)
    names the interfaces that hold something of ours, each with its
    index, and where it was written: the boot and the network
    namespace. It does not say what they hold: what is learned again is
    set again whatever it is. It is kept by index, as everything else
    is. The name beside an index is for a person who reads the file: the
    one the interface had when it was last set, or taken over from an
    earlier run.
  - **Written ahead.** An interface is named before any command that
    may give it something is started, and until a revert has worked or
    the interface is gone. A run ended while `resolvectl` is under way
    cannot say how that went, and the next one must find the interface
    named.
  - **The program is looked for before every command** (`$PATH`, as
    `execvp` looks; the file found is the one run). With none there is
    nothing to start: no command is made and nothing is named. So a
    host without `resolvectl` writes no record at all, where naming an
    interface ahead and taking it off again would write the file with
    every try. Whether a command can start is seen by looking, each
    time, and not taken from how the last one went: a try that can
    start is on record first, also after one that could not. What is
    left is a program that is found and cannot be started (no process
    to be had, or a file the kernel will not run): the interface is
    named, the failure takes it off again, and that repeats with every
    try.
  - **A record that cannot be written** (a full disk, a state directory
    that is not there yet) does not keep the name servers from the
    host: they are set all the same. But an interface that is set and
    not on disk is one the next run would not take back. So the record
    stays unsaved until a write has worked, also when nothing more
    changes in it, and the write is tried again like a failed command,
    5 s later and then at doubling intervals up to 5 min.
  - **The next run** reads it at startup, before the configuration, and
    starts the resolver task for it when it names any interface: a
    configuration with no source of name servers any more (`address
    dhcp` deleted while zebra-rs was down) spawns none of the tasks the
    resolver otherwise comes with. Each interface named is noted as
    holding something unknown. A file that is not there is the ordinary
    case. One that is there and cannot be read, or is no record, is
    said in the log: what it named is not taken back.
  - **A wait for the sources**, `--leftover-sweep-time` (120 s), the
    time the RIB waits before it sweeps the routes of an earlier run.
    A lease is resumed at once, but a Router Advertisement has to be
    heard again. An interface a source has name servers for within it
    is set and is this run's from then on, also when it loses them
    again before the wait is over. The others are reverted when it is
    over: a lease lost, a router gone, or `no-name-server` set, while
    zebra-rs was down. A time no clock counts to (the largest number,
    for "never") is a wait without an end: nothing is taken back, and
    the log says of each interface that it keeps what it holds, where
    it otherwise says in how many seconds that is taken back. A
    report that is waiting when the wait ends is heard first, as before
    every look: the interface it claims is not taken back only to be
    set again a moment later.
  - **By index, by boot and by namespace.** An interface whose index
    is gone (at startup, at the end of the wait, or before a later try
    of a revert that failed) holds nothing and is dropped without a
    revert: there is nothing to say to an index that is no interface's,
    and one made since under that name has another. One that was
    renamed, while zebra-rs was down or since, is the same interface
    under another name: it is taken over, and taken back, by its index.
    A record of another boot names nothing: resolved keeps its links'
    settings under `/run`, and the indexes of the boot before are other
    interfaces' now, or the same ones' by chance. Nor does one of
    another network namespace (`/proc/self/ns/net`), whose indexes are
    its own. Where the boot or the namespace cannot be read, no record
    is kept at all.
  - **Only where resolved is ours to configure.** The state directory
    is the host's whatever the network namespace, so a second zebra-rs
    in a namespace finds the first one's record there unless
    `ZEBRA_DHCP_STATE_DIR` says otherwise. One that is refused (see the
    hazards below) has set nothing: it takes nothing over and never
    writes the file, which would lose the other's interfaces. The
    number that names a namespace can be used again once that one is
    gone, so it is this, and not the namespace in the record, that
    keeps the two apart for good.
  - A run of a version before the record left none: what it set and
    the next run does not learn stays, as it did.

**Hazards.**

- **Network namespaces.** `resolvectl` sends an interface index over
  the system bus. The bus is one per host; the indexes are one set per
  namespace. From another namespace the command reads, and would set,
  whichever host interface has that index (seen: a new namespace's
  `wanx`, index 2, answered with the host's uplink). So `resolvectl` is
  run only when
  `/proc/self/ns/net` is `/proc/1/ns/net`, and otherwise the task says
  so once and stops. `$ZEBRA_RESOLVECTL` names a program to run in its
  place, without that check: the BDD harness gives every daemon a
  stand-in (`bdd/tests/scripts/resolvectl_stub.sh`). The check is by
  PID 1, so a container with its own PID namespace passes it; there the
  command finds no resolved, unless the host's bus socket was mounted
  into the container, which the check cannot see. Name servers being
  set without a word of configuration, such a container has to say
  `no-name-server` for each source of its uplinks.
- **VRF.** resolved is not VRF-aware. It sends from a socket that is
  not bound to the VRF, with `IP_UNICAST_IF` naming the link. Such a
  socket gets no reply through an interface in a VRF unless
  `net.ipv4.udp_l3mdev_accept` is 1 (seen with a socket made that way,
  not with resolved itself), and TCP needs `tcp_l3mdev_accept`. The
  servers of a VRF interface are set all the same: with those sysctls
  they answer, and where the host is not to ask them, the
  `no-name-server` leaves say so.
- **Not root.** Configuring resolved takes root, and so does reading
  PID 1's namespace.
  - A zebra-rs that has file capabilities and is not root (`make run`)
    fails the check above. It says `cannot tell whether this is the
    host's network namespace (…; zebra-rs is not root)` once and sets
    nothing. The lease, its address and its routes are as ever; the
    host has no name server from it.
  - Where the check is not made (`$ZEBRA_RESOLVECTL`), the bus does
    not refuse an unauthorised caller at once. It waits for a
    password, and `resolvectl` 255 has no switch against that (259 has
    `--no-ask-password`). Every command therefore has a time limit of
    10 s.

**Not built yet.**

- **Without root.** resolved's link calls are polkit actions
  (`org.freedesktop.resolve1.set-dns-servers`, `.set-domains`,
  `.revert`), which ask a caller that is not root for an
  administrator's password. A rule that grants them to the daemon's
  user, and a namespace check that does not read PID 1's link, would
  let a zebra-rs with file capabilities alone set them. For the check:
  newer kernels give the initial network namespace a fixed inode
  number (`NET_NS_INIT_INO` in `linux/nsfs.h`, seen on 7.0), which
  `/proc/self/ns/net` shows to anybody.
- **A show command** for what was set and what failed. `resolvectl
  status <if>` shows what resolved holds.
- **Hosts without resolved.** The command fails and is retried at the
  5 min interval. Where `resolvectl` is there and resolved is not, so is
  the revert once the servers are no longer wanted, for as long as the
  interface exists: a command that ran may have set something. A
  `resolvconf` backend would cover them.
- **NTP** follows the same pattern if zebra-rs ever manages time.
- **The RA MTU option** gets an `ra-options mtu` leaf if it is needed.

---

## 14. Phases

| Phase | Content | Depends on |
|---|---|---|
| P0 (done) | Codec move + typed options + property tests; insomnia switches to the vendored copy (relay goldens unchanged) | – |
| P1 (done) | RIB plumbing (D5, D6); `dhcpc` task; DHCPv4 state machine, sockets, ACD, persistence; `show dhcp client leases`, `renew/release dhcp`; ungate `address dhcp` | P0 |
| P2 (done) | RA host in `nd`: RS, default route, on-link prefixes, `ipv6 address autoconf`, `ra-options`, `accept_ra=0`; show section | P1's RIB plumbing |
| P3 (done) | DHCPv6 IA_NA and `parameters-only`; DUID; `show dhcpv6 client leases`, `renew/release dhcpv6` | P0, P2 |
| P4 (done) | IA_PD: discard route, LAN assignment, prefix change. The state machine, `dhcpv6-options pd <id> [length]`, the discard route, `pd <id> interface <lan>` with `AddrOrigin::Pd` and the `sla-id` arithmetic, prefixes and the addresses they give in the lease file and in show, `dhcpv6_client_pd`, `dhcpv6_client_pd_lan`. Left: an unreachable form of the route (§16), `dhcpv6_pd_insomnia` | P3 |
| ND-PIO (done) | `nd` advertises PIOs for LAN /64s with counted-down lifetimes, deprecates removed ones (L-13 as RFC 9096 has it), `RibRx::AddrRenewed` on lifetime change; `ra_prefix` | P1's RIB plumbing; parallel to P2–P4 |
| Resolver (the three sources done) | The `resolver` task; the name servers of a DHCPv4 lease, of a DHCPv6 server and of Router Advertisements to systemd-resolved by default, `no-name-server` under `dhcp-options`, `dhcpv6-options` and `ra-options` to keep them back; what an earlier run set and the next does not learn again taken back after `--leftover-sweep-time` (§13) | P1; P2 and P3 for their sources |
| P5 | MTU options, Reconfigure, IA_TA, prefix exclude, RFC 4191 routes, stable-privacy identifiers, `redistribute dhcp` | as needed |

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
- **Resolver:** against a scripted backend, what is set and reverted for
  every order of report, withdrawal and failure; the commands'
  arguments; the namespace check on made-up links, and what it says
  when zebra-rs is not root; a program that fails, is missing, or does
  not answer. In the DHCP client, for DHCPv4 and for DHCPv6, and in
  the RA host: what each reports, and that under its `no-name-server`
  it reports nothing, whether the leaf is set before the name servers
  come or after.

**BDD (`bdd/`, not CI)**

Test servers: Kea through insomnia's `kea_server.sh` shape covers DHCPv4,
IA_NA and PD. dnsmasq (present on Ubuntu as `dnsmasq-base`) covers
DHCPv4, IA_NA and RAs, but not PD.

As built, PD is served by `tests/scripts/dhcpv6_server.py`: a delegating
router in the Python standard library, which the development hosts have
where they have no Kea. It gives each IA_PD the prefix configured for
its IAID, tells any other NoPrefixAvail, routes what it delegates to the
client, and logs each message, which is what a scenario reads.

| Feature | Checks |
|---|---|
| `dhcp_client` | lease → address and `D>* 0.0.0.0/0 [210/0]`; renew; `release`; server gone → expiry withdraws everything; zebra-rs restart keeps the address and re-verifies |
| `dhcp_client_vrf` | WAN in VRF `red`; the route is in `red`'s table only |
| `dhcp_client_dual_wan` | two leases at 210 / 220; link down on the first → the second's default is selected |
| `dhcp_client_dns` | against a stand-in for `resolvectl`, which keeps an interface's settings by its index as resolved does and refuses a name in its place: the lease's servers and domains set with nothing configured but `address dhcp`; reverted on `release` and on setting `no-name-server`, and set again when that is deleted; nothing set for a lease taken, or resumed after a restart, under `no-name-server`; replaced at a renewal; retried after a failure; servers set last are set again after an error that came with the old list already dropped; servers set by a command that got no answer are reverted; an interface deleted and made again is set again; one renamed under the running daemon keeps its lease's name servers, which `no-name-server` takes back from it and gives it again; set again after a restart; what an earlier run set is kept past the leftover time by a run that resumes the lease, and taken back by one under `no-name-server`, by one with no DHCP client at all, and from an interface renamed while zebra-rs was down, which the stand-in shows with its settings under the new name until then; kept, and said to be kept, by a run told to wait without end |
| `ra_host` | RA default route `A`, SLAAC with `autoconf`, router lifetime 0 withdraws, `accept_ra` is 0 |
| `ra_host_dns` | against a stand-in for `resolvectl`: RDNSS and DNSSL set with nothing configured but `address autoconf`, the newly heard first and an option in its own order; a lifetime of zero and a lifetime run out take one away; a DHCPv4 lease's server goes ahead and its end leaves the advertised ones; `ra-options no-name-server` takes the advertised ones back and leaves the lease's, what is heard under it is only shown, and deleting it sets what is held; stopping the RA host reverts |
| `dhcpv6_client` | IA_NA /128 with `noprefixroute`; default route and on-link prefix from the RA, and no SLAAC address unless `autoconf` is set too; renew; `release`; zebra-rs restart keeps the address and confirms it; `parameters-only`; deleted configuration releases |
| `dhcpv6_client_dns` | against a stand-in for `resolvectl`, and a server whose lease and whose Router Advertisements name different name servers: the lease's servers and search list set with nothing configured but `address dhcpv6`, ahead of the advertised ones and behind a DHCPv4 lease's; reverted on `release` and on setting `dhcpv6-options no-name-server`, which leaves the advertised ones, and set again when that is deleted; nothing set for a lease taken, or resumed after a restart, under `no-name-server`; set again after a restart; what `parameters-only` is given set with no lease and no RA host; deleted configuration reverts |
| `dhcpv6_client_pd` | As built: the address and the prefix in one exchange, with the hint on the wire; the discard route in the RIB and in the kernel, and that it ends a packet which a routed prefix without one sends round between the two routers; renew; a restart resumes the prefix and its route and verifies them by a Rebind; a second `pd`, and one the server has nothing for; a prefix without an address; `parameters-only` refused beside `pd`; deleted configuration releases and withdraws |
| `dhcpv6_client_pd_lan` | As built: two interfaces numbered from one delegation, one by `address` and one by EUI-64, each with the prefix's lifetime and the route to its /64; a host behind the router reached from the delegating router through the prefix; a link set down and up has its address again; a renewal that brings other lifetimes moves the addresses'; another prefix replaces the discard route and the addresses, and the old /64 is on-link no longer; an `sla-id` moved, one beyond the prefix (no address, and said), two interfaces on one /64 and the upstream interface refused, none of it a new lease; a restart keeps the addresses and removes that of an interface no longer configured; an interface, then the delegation, deleted |
| `ra_prefix` | As built: a router that numbers an interface from a delegated prefix, has an address of its own on it and advertises there; a host with nothing configured forms an address in both /64s, takes the router for its default and reaches the delegating router; the configured prefix has RFC 4861's lifetimes and the delegated one the lease's; a renewal with longer lifetimes reaches the host without waiting for the periodic advertisement; a renewal with the same lifetimes as before still moves their end; another prefix from the server gives the host a new address, deprecates the old one and takes its on-link route away, and the old one is named for as long as its longest lifetime, though its lease was cut short since; an interface moved to another VRF than its delegation's withdraws the prefix on its hosts, and moved back has it again; a configured address deleted deprecates its prefix, and set again restores it; so does a delegation given back; an interface that stops advertising names nothing |
| `dhcpv6_pd_insomnia` | a zebra-rs + insomnia router serving PD (insomnia's existing DHCPv6 server) to a zebra-rs client router: both sides of the feature in one topology |

---

## 16. Deviations

| Item | Reference | zebra-rs | Why |
|---|---|---|---|
| DHCPv6 started by RA M/O flags | RFC 7084 WAA-6, WPD-4 | configuration only (D7) | a configured router is deterministic; VyOS does the same |
| Choice of DHCPv6 server | RFC 8415 §18.2.9: the highest preference, though a client MAY take a server with "a better set of options" | the server offering more of the IAs asked for, then the preference | a CE router needs the prefix as well as the address |
| Reconfigure Accept | RFC 7084 WAA-4 (MUST) | not sent | needs Reconfigure authentication; P5 |
| RA processing | VyOS: kernel `accept_ra=2` | userspace in `nd`, `accept_ra=0` (D4) | RIB ownership, distance, VRF |
| RA default route | VyOS: kernel metric 1024 | `Ra`, distance 210, `ra-options` | parity with DHCPv4 defaults |
| DHCPv4 client identifier | RFC 4361: DUID-based (SHOULD) | none unless configured; the server keys on `chaddr` | dhclient's and VyOS's behaviour, which ISP servers are provisioned for |
| `temporary` (IA_TA) | VyOS `dhcpv6-options temporary` | not supported | not needed on a router WAN |
| Prefix exclude | RFC 7084 WPD-8 (SHOULD) | not supported | P5 |
| Route for a delegated prefix | RFC 7084 WPD-5: discard, and (a) SHOULD answer with ICMPv6 Destination Unreachable | a blackhole route: the packet is dropped and nothing is sent | the RIB has no unreachable nexthop; the loop WPD-5 is there to prevent is prevented either way |
| Internal address from PD | RFC 7084 WAA-7 | explicit `pd … interface lo` | no implicit interfaces |
| PIO lifetimes of a delegated prefix | RFC 9096 §3.4 (L-16, SHOULD): at most 45 min preferred and 90 min valid, whatever the lease says | the lease's remaining lifetimes, which is what §3.3 (L-15, MUST) asks: never past them | D14's rule; the caps cost the hosts their addresses when the router is away for 90 minutes, and are for the operator to choose. Not built |
| A prefix that went while zebra-rs was not running | RFC 9096 §3.5 (SHOULD): record the prefixes advertised on stable storage, and deprecate them after a restart | not advertised as gone: `nd` learns the prefixes from the addresses the interface has when it starts | needs a record on disk, as the routes and the name servers have; the hosts keep such a prefix for what was left of its lifetime |
| IPv6-only preferred (option 108) | RFC 8925 | not requested | a dual-stack WAN wants its IPv4 lease |
| ACD | RFC 5227: 3 probes, 1–2 s apart | 2 probes, 1 s apart | bounded bind delay |
| A full RDNSS or DNSSL list | RFC 8106 §6.2 (d): make room by dropping the entry that expires first | a new entry past 64 held is ignored | what systemd-networkd does, with its bound (`NDISC_RDNSS_MAX`, `NDISC_DNSSL_MAX`): whoever advertises last does not get to push the others out |
| RDNSS and DNSSL options of one RA | RFC 8106 §6.2: each option in turn | the options with a lifetime of zero first, then the others | systemd-networkd's two passes: an RA that withdraws an entry and names it leaves it in, and what it withdraws makes room for what it brings |
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
