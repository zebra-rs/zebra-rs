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
| `no-name-server` | Do not give the lease's name servers and search domains to the router's own resolver ([Name servers](#name-servers)). |
| `reject` | A server address or prefix whose offers are ignored. Repeatable. |

The options take effect without `address dhcp` being re-entered. A
changed `default-route-distance` re-installs the routes at once,
`no-name-server` takes the name servers back or gives them at once, a
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

## Name servers

A DHCPv4 lease names name servers and search domains, and so do a
DHCPv6 server ([below](#ipv6-dhcpv6)) and Router Advertisements where
the RA host runs (RDNSS and DNSSL, see
[below](#ipv6-router-advertisements-and-slaac)). The router itself uses
them: `address dhcp` is all it takes for a DHCPv4 lease's, `address
dhcpv6`, `dhcpv6-options pd` or `dhcpv6-options parameters-only` for a
DHCPv6 server's, and `address autoconf`, `address dhcpv6` or
`dhcpv6-options pd` for the advertised ones.

The DHCPv4 lease's name servers (option 6) and search domains (the
domain name, option 15, then the search list, option 119), behind them
the DHCPv6 server's (options 23 and 24), and behind those the ones
Router Advertisements name, are given to systemd-resolved as that
link's DNS configuration: what `resolvectl dns wan0 …` and
`resolvectl domain wan0 …` set, and `resolvectl status wan0` shows.
zebra-rs does not write `/etc/resolv.conf`.

`/etc/resolv.conf` is systemd-resolved's own file and names its local
listener (`nameserver 127.0.0.53`) whatever it has been given: it does
not show an interface's name servers. `resolvectl status` does.

`no-name-server` keeps an interface's name servers from the router, by
where they come from: under `dhcp-options` the DHCPv4 lease's, under
`dhcpv6-options` the DHCPv6 server's, under `ra-options` the advertised
ones. They are then only shown (`show dhcp client leases`, `show dhcpv6
client leases`, `show ipv6 nd interface`):

```
interface wan1 {
  ipv4 {
    address dhcp;
    dhcp-options {
      no-name-server;
    }
  }
  ipv6 {
    address dhcpv6;
    dhcpv6-options {
      no-name-server;
    }
    ra-options {
      no-name-server;
    }
  }
}
```

```
router> show dhcp client leases
Interface: wan0
  ...
  DNS servers:  198.51.100.53
  Domain:       example.com

$ resolvectl status wan0
Link 3 (wan0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 198.51.100.53
       DNS Servers: 198.51.100.53
        DNS Domain: example.com
```

- **They follow the lease.** They are set when the lease is bound,
  replaced when a renewal names others, and taken back
  (`resolvectl revert`) when the lease is released or expires, when
  `address dhcp` is deleted, and when `dhcp-options no-name-server` is
  set. Deleting that gives the held lease's name servers to the router
  at once. A DHCPv6 lease's follow it the same way, with `release
  dhcpv6`, `address dhcpv6` and `dhcpv6-options no-name-server`; the
  ones `parameters-only` was given are taken back when it is deleted.
- **Advertised ones follow their lifetimes.** A name server or domain
  from a Router Advertisement is taken back when its lifetime runs out,
  at once when it is advertised with a lifetime of zero, when the RA
  host stops (`address autoconf`, `address dhcpv6` and every
  `dhcpv6-options pd` deleted),
  and when `ra-options no-name-server` is set. Deleting that gives the
  ones still held to the router at once.
- **Order.** What DHCP names goes ahead of what Router Advertisements
  name, and a DHCPv4 lease's ahead of a DHCPv6 server's. Among the
  advertised ones, a server or domain heard of for the first time goes
  ahead of those already held, and the entries of one RDNSS or DNSSL
  option keep the option's order (RFC 8106). A server or domain several
  of them name is given once, where the first names it. When one of
  them ends, or its name servers are kept back, those of the others
  stay.
- **Link down.** The lease is kept and so are its name servers:
  systemd-resolved itself leaves a link without carrier alone.
- **Two uplinks.** Each link gets its own servers, and systemd-resolved
  asks those of every link that is up. `no-name-server` on one of them
  leaves the router with the other's.
- **Addresses and names are checked.** A loopback, unspecified,
  multicast or broadcast address is not used as a name server, and a
  search domain that is not a plain domain name is dropped.
- **If the command fails** (systemd-resolved is not running yet, or is
  not installed) the lease is unaffected. A log line says so once, and
  the command is tried again: after 5 seconds at first, then at growing
  intervals up to 5 minutes.

What it needs:

- systemd-resolved, and `resolvectl` on the path.
- zebra-rs running as root, which the packaged service does. Started
  with file capabilities alone (`make run`), it leases the address and
  the routes as ever, logs `cannot tell whether this is the host's
  network namespace (…; zebra-rs is not root): the system resolver is
  left alone` and sets no name server.
- zebra-rs in the host's network namespace. `resolvectl` identifies an
  interface to systemd-resolved by its index, and the indexes of another
  namespace are those of other interfaces on the host. Run in another
  network namespace, zebra-rs logs `this is not the host's network
  namespace: the system resolver is left alone` and sets nothing.
- No other network manager setting the interface's DNS.

**VRF.** systemd-resolved does not know about VRFs. The name servers of
an interface in a VRF are set all the same, but its queries to them are
answered only with `net.ipv4.udp_l3mdev_accept` and
`net.ipv4.tcp_l3mdev_accept` set to 1. Without them, `no-name-server`
on that interface keeps the router from asking servers that will not
answer it.

**Restart.** zebra-rs leaves the name servers set when it stops, and
sets them again from the resumed lease when it starts. What it does not
learn again is taken back once `--leftover-sweep-time` has passed
(120 s by default), like the routes of a lease that was not resumed: a
lease that ran out, a router that no longer advertises, `no-name-server`
set, or `address dhcp` deleted, while zebra-rs was not running. Until
then the interface keeps the name servers it had.

zebra-rs knows which interfaces it had set from a record beside the
leases (`resolver.json`). A reboot ends the record with the settings
themselves, and an interface that was deleted and made again in the
meantime is left alone. Name servers set by a version of zebra-rs that
kept no record are not taken back: `resolvectl revert <name>` does it by
hand.

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
- **DNS servers and search domains** (RDNSS, DNSSL) are kept with their
  lifetimes and shown, the most recently learned first. The router uses
  them itself, unless `ra-options no-name-server` says not to ([Name
  servers](#name-servers)).
- **The MTU option** is shown, not applied.
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
| `no-name-server` | List the advertised name servers and search domains, but do not give them to the router's own resolver ([Name servers](#name-servers)). |

The options committed together with `address autoconf` or `address
dhcpv6` are in force from the start: the host does not run without them
first.

Two interfaces with `autoconf` work like two DHCP uplinks: the lower
`default-route-distance` carries the default, and at one distance the
router preference decides, then ECMP. While a link is down its routes are
withdrawn; when it comes back the host solicits again. An interface in a
VRF installs its routes in that VRF's table. After a restart of zebra-rs
the routes left in the kernel are taken over as the first RAs arrive, and
those no RA gives any more are removed once `--leftover-sweep-time` has
passed.

## IPv6: DHCPv6

`interface <name> ipv6 address dhcpv6` starts zebra-rs's own DHCPv6
client on the interface. It leases an address and puts it on the
interface as a /128, which brings no connected route: which prefixes are
on-link, and the default route, are for Router Advertisements to say.
So `address dhcpv6` runs the RA host too
([above](#ipv6-router-advertisements-and-slaac)), without forming a
SLAAC address unless `address autoconf` is set as well.

```
interface wan1 {
  ipv6 {
    address dhcpv6;
  }
}
```

`dhcpv6-options parameters-only` asks the server for the other
configuration alone (name servers, the search list, NTP servers) and
for no address. It does not go together with `address dhcpv6` on one
interface, and it does not run the RA host.

| YANG leaf (under `/interface/<name>/ipv6/dhcpv6-options`) | Notes |
|---|---|
| `duid` | The DUID this interface's client presents, as colon-separated hex octets. Unset, the system's DUID is used, made once and kept across restarts. Changing it gives the lease back and asks again as another client. |
| `parameters-only` | Ask for the configuration parameters only, and no address. |
| `rapid-commit` | Accept the two-message exchange (Rapid Commit) from a server that offers it. |
| `no-release` | Do not release the lease when the client stops. |
| `no-name-server` | Show the server's name servers and search domains, but do not give them to the router's own resolver ([Name servers](#name-servers)). |
| `pd <id>` | Ask for a delegated prefix, under this identifier ([Prefix delegation](#ipv6-prefix-delegation)). |
| `pd <id> length` | The prefix length to hint at, 32..64. Default 64. |

```
show dhcpv6 client leases [interface <name>]
renew dhcpv6 interface <name>
release dhcpv6 interface <name>
```

```
router> show dhcpv6 client leases
Interface: wan1
  VRF:          default
  State:        bound
  DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56
  IAID:         1194042915
  Server:       fe80::1
  Server DUID:  00:03:00:01:02:00:00:00:00:fe
  Address:      2001:db8:1::100/128 preferred 3000s valid 6600s
  Renew in:     1200s
  Rebind in:    2400s
  DNS servers:  2001:db8:53::53
  Search:       example.com

router> show interface wan1
  inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft 6600 preferred-lft 3000
```

`renew` and `release` work as they do for DHCPv4. After a restart of
zebra-rs the client takes the lease from disk, uses it at once and asks
the server whether it is still right for the link. With
`parameters-only` the state is `informed` and no address is shown.

## IPv6: prefix delegation

`dhcpv6-options pd <id>` asks the DHCPv6 server for a prefix to use
behind the router (RFC 8415), beside the address `address dhcpv6` asks
for or without one. `<id>` names the delegation to the server (it is
the IAID of the request), so an interface can ask for several. `length`
is a hint: the server delegates what it sees fit.

```
interface wan1 {
  ipv6 {
    address dhcpv6;
    dhcpv6-options {
      pd 1 {
        length 56;
      }
    }
  }
}
```

- **The prefix is held by a discard route**, a `D` route at
  administrative distance 210 in the VRF of the interface. A packet for
  a part of the prefix that nothing uses must not follow the default
  route back to the provider, who routes the whole prefix here and
  would send it back again. In the kernel it is a `blackhole` route
  with `proto dhcp`. It stays while the link is down, and goes when the
  prefix is given back or runs out.
- **The default route** comes from Router Advertisements: `pd` runs the
  RA host like `address dhcpv6` does, without forming a SLAAC address.
- **What an interface asks for is asked for together.** Adding or
  deleting a `pd`, or changing its `length`, gives the lease back and
  asks again for everything the interface asks for, the address
  included.
- **Not with `parameters-only`**, which asks for nothing to lease.

```
router> show dhcpv6 client leases
Interface: wan1
  VRF:          default
  State:        bound
  DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56
  IAID:         1194042915
  Server:       fe80::1
  Server DUID:  00:03:00:01:02:00:00:00:00:fe
  Address:      2001:db8:1::100/128 preferred 3000s valid 6600s
  Prefix:       2001:db8:100::/56 preferred 3000s valid 6600s (pd 1)
  Renew in:     1200s
  Rebind in:    2400s

$ ip -6 route show 2001:db8:100::/56
blackhole 2001:db8:100::/56 dev lo proto dhcp metric 1024 pref medium
```

A delegation that holds nothing shows as `none (pd <id>)`. In `json`,
`pd` lists each delegation with its prefixes and, once it holds one,
its own server and renewal times. After a restart of zebra-rs the lease
is taken from disk with its prefixes, the discard routes are back at
once, and the server is asked whether the lease still stands.

## Not done yet

- The NTP servers of a lease are shown but not applied to the system.
- The interface MTU option (26) is not applied.
- A classless route whose router is `0.0.0.0` (an on-link destination)
  is not installed; a log line says so.
- A delegated prefix is held, and that is all: no address from it is
  put on a LAN interface, and it is not advertised to the LAN.
- The discard route of a delegated prefix drops a packet without the
  ICMPv6 Destination Unreachable that RFC 7084 asks for.
- The RA host does not advertise the prefixes it learns on other
  interfaces, and does not use stable-privacy or temporary addresses.
