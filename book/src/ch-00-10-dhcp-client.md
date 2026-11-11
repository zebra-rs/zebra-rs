# DHCP Client

`interface <name> ipv4 address dhcp` leases an IPv4 address from a DHCP
server. zebra-rs runs the client itself; no dhclient, dhcpcd or
systemd-networkd is involved, and none should manage the same interface.

```
interface wan0 {
  ipv4 {
    address dhcp;
  }
}
```

What the lease gives goes through the routing table like any other route
source:

- **The address** is installed with the lease's lifetime, so the kernel
  removes it on time even if zebra-rs is not running. `show interface`
  tags it `dhcp`. `address dhcp` is the interface's only IPv4 address
  entry: an interface is addressed by DHCP or statically, not both, and
  a commit holding `dhcp` beside a static address is refused (`dhcp
  cannot be combined with a static address`) — delete the one before
  setting the other. The client always talks to the server from the
  leased address, also when an address added outside zebra-rs is the
  interface's primary.
- **The default route** is a `D` route through the lease's router, at
  administrative distance 210. That is above every routing protocol, so a
  default learned from BGP or OSPF, or a static one, wins over it.
- **Classless static routes** (option 121) are installed the same way.
  When the server sends them, the router option is ignored (RFC 3442).

```
router> show ip route
D  *> 0.0.0.0/0 [210/0] via 192.0.2.1, wan0, 00:01:12
C  *> 192.0.2.0/24 is directly connected, wan0, 00:01:12

router> show interface wan0
  inet 192.0.2.117/24 dhcp valid-lft 3600 preferred-lft 3600
```

In the kernel the route shows as `proto dhcp`.

## Options

| YANG leaf (under `/interface/<name>/ipv4/dhcp-options`) | Notes |
|---|---|
| `client-id` | Option 61. `xx:xx:…` is sent as those bytes; any other value is text. Unset, no identifier is sent and the server keys the lease on the MAC address. Changing it releases the lease and asks for a new one as the new identity. |
| `host-name` | Option 12. Defaults to `system hostname`. |
| `vendor-class-id` | Option 60. |
| `user-class` | Option 77. |
| `default-route-distance` | Distance of the lease's routes, 1..255. Default 210. |
| `no-default-route` | Do not install a default route from the lease. |
| `reject` | A server address or prefix whose offers are ignored. Repeatable. |

The options take effect without `address dhcp` being re-entered. A
changed `default-route-distance` re-installs the routes at once, a
changed `client-id` starts a new lease, and the others apply from the
client's next message.

The client sends no message longer than 548 bytes, the size every server
and relay agent takes (a 576-byte IP datagram). `client-id`, `host-name`,
`vendor-class-id` and `user-class` of about 260 characters together
always fit. Past that, the client moves `host-name`, `vendor-class-id` or
`user-class` into the message's `file` and `sname` fields (option 52),
and an option too long for those as well is not sent. The log then says
which:

```
dhcp client: eth0: host-name not sent: the options together are too long for a DHCP message
```

The `client-id` is always sent.

## Two uplinks

Each DHCP interface has its own `default-route-distance`:

- **Different distances**: the lower one carries the traffic. The other
  is a backup: it takes over when the first interface's link goes down or
  its lease ends, and gives way again when it returns.
- **The same distance** (two interfaces left at the default): one ECMP
  default route over both.

```
interface wan0 {
  ipv4 { address dhcp; }
}
interface wan1 {
  ipv4 {
    address dhcp;
    dhcp-options {
      default-route-distance 220;
    }
  }
}
```

## VRF

A DHCP interface in a VRF leases through that VRF: its routes go to the
VRF's table and nothing reaches the default table.

## Lifetime of a lease

- The client renews at T1 and rebinds at T2 (the server's values, else
  half and seven eighths of the lease). A lease no server renews expires:
  the address and its routes are withdrawn and discovery starts again.
- A new address is ARP-probed before use. If another host answers, the
  lease is declined and the client asks again after 10 seconds.
- **Link down.** The lease is kept, its routes are withdrawn, and the
  lease is verified with the server when the link returns.
- **Restart.** Leases are kept in `/var/lib/zebra-rs/dhcp/`. A restart of
  zebra-rs keeps the address and its route in place, resumes the lease
  and verifies it with the server. A route the lease no longer gives (the
  lease is gone, or `no-default-route` was set while zebra-rs was down)
  is removed once `--leftover-sweep-time` has passed (120 s by default).
- **Deleting `address dhcp`** releases the lease.

## Commands

```
show dhcp client leases [interface <name>]
renew dhcp interface <name>
release dhcp interface <name>
```

```
router> show dhcp client leases
Interface: wan0
  VRF:          default
  State:        bound
  Address:      192.0.2.117/24
  Server:       192.0.2.1
  Gateway:      192.0.2.1
  DNS servers:  198.51.100.53
  Domain:       example.com
  Lease time:   3600s
  Renew in:     1790s
  Rebind in:    3140s
  Expires in:   3590s
  Routes:       0.0.0.0/0 via 192.0.2.1 [210]
```

`renew` asks the server for the lease again now. `release` gives the
lease back and leaves the client idle until `renew`, or until
`address dhcp` or the `client-id` is configured anew. `show -j` gives the
same fields as JSON.

## IPv6: Router Advertisements and SLAAC

`interface <name> ipv6 address autoconf` makes zebra-rs a host on that
interface as well as a router: it sends Router Solicitations, and turns the
Router Advertisements it hears into routes and addresses. zebra-rs does
this itself; the kernel's own RA processing is turned off on the interface
(`accept_ra` and `autoconf` 0), so nothing is installed behind the routing
table's back.

```
interface wan1 {
  ipv6 {
    address autoconf;
  }
}
```

- **The default route** is an `A` route through each router that
  advertises a non-zero router lifetime, at administrative distance 210.
  Routers of the best RA preference (RFC 4191: high, medium, low) are
  used; several left are ECMP. A router lifetime of 0, or the lifetime
  running out, takes the router away.
- **On-link prefixes**: a prefix advertised with the L flag is an `A`
  route out of the interface for as long as the prefix is valid. Only the
  L flag makes a prefix on-link (RFC 5942).
- **SLAAC addresses**: a /64 advertised with the A flag gives an address
  made from the prefix and the interface's MAC (EUI-64), with the
  prefix's lifetimes (RFC 4862, including the two-hour rule). `show
  interface` tags it `slaac`. An address that fails duplicate address
  detection is removed and not formed again.
- **DNS servers and search domains** (RDNSS, DNSSL) and the MTU option
  are kept with their lifetimes and shown, not applied.
- The M and O flags are shown and not acted on: DHCPv6 is not started
  by them.

```
router> show ipv6 route
A  *> ::/0 [210/0] via fe80::2, wan1, 00:00:12
A  *> 2001:db8:1::/64 [210/0] via ::, wan1, 00:00:12

router> show interface wan1
  inet6 2001:db8:1:0:5054:ff:fe12:3456/64 noprefixroute slaac valid-lft 3599 preferred-lft 1799

router> show ipv6 nd interface wan1
Interface wan1 (ifindex 3)
  Router advertisement: disabled
  RA host: enabled (autoconf)
    default route distance 210
    router solicitations sent 1, done
    Default routers (1):
      fe80::2 preference high, lifetime 1800s, expires in 29m48s, installed
    On-link prefixes (1):
      2001:db8:1::/64 valid 59m48s
    SLAAC addresses (1):
      2001:db8:1:0:5054:ff:fe12:3456 valid 59m48s, preferred 29m48s
    DNS servers: 2001:db8::53
    DNS search: example.com
```

In the kernel the routes show as `proto ra`. `show ipv6 nd interface
<name> json` has the same under `ra_host`.

| YANG leaf (under `/interface/<name>/ipv6/ra-options`) | Notes |
|---|---|
| `default-route-distance` | Distance of the RA's routes, 1..255. Default 210. |
| `no-default-route` | List the routers, but install no default route from them. |

Two interfaces with `autoconf` work like two DHCP uplinks: the lower
`default-route-distance` carries the default, and at one distance the
router preference decides, then ECMP. While a link is down its routes are
withdrawn; when it comes back the host solicits again. An interface in a
VRF installs its routes in that VRF's table. After a restart of zebra-rs
the routes left in the kernel are taken over as the first RAs arrive, and
those no RA gives any more are removed once `--leftover-sweep-time` has
passed.

## Not done yet

- The DNS servers, domain and NTP servers of a lease are shown but not
  applied to the system.
- The interface MTU option (26) is not applied.
- A classless route whose router is `0.0.0.0` (an on-link destination)
  is not installed; a log line says so.
- DHCPv6 (stateful addresses and prefix delegation).
- The RA host does not advertise the prefixes it learns on other
  interfaces, and does not use stable-privacy or temporary addresses.
