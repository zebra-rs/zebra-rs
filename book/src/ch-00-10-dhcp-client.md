# DHCP Client

zebra-rs can take an interface's addresses, routes and name servers
from the network. It runs the clients itself: a DHCPv4 client, a DHCPv6
client, and a host for IPv6 Router Advertisements. No dhclient, dhcpcd,
systemd-networkd or NetworkManager is involved, and none should manage
the same interface.

All of it is configured on the interface, and all of it is part of
every zebra-rs. No `--feature` flag turns it on. The DHCP *server* and
relay are another matter: they are the insomnia daemon's, and their
commands need
[`--feature insomnia`](ch-00-05-command-line-options.md#--feature-modulefeature).

| Under `interface <name>` | What it does | Section |
|---|---|---|
| `ipv4 address dhcp` | Leases an IPv4 address, with its default route and classless routes. | [IPv4: DHCP](#ipv4-dhcp) |
| `ipv4 dhcp-options …` | Tunes that client. | [Options](#options) |
| `ipv6 address autoconf` | Takes the default route, the on-link prefixes and SLAAC addresses from Router Advertisements. | [IPv6: Router Advertisements and SLAAC](#ipv6-router-advertisements-and-slaac) |
| `ipv6 ra-options …` | Tunes what Router Advertisements give. | the same |
| `ipv6 address dhcpv6` | Leases an IPv6 address. Its routes come from Router Advertisements. | [IPv6: DHCPv6](#ipv6-dhcpv6) |
| `ipv6 dhcpv6-options pd <id>` | Has a prefix delegated, to number the interfaces behind the router from. | [IPv6: prefix delegation](#ipv6-prefix-delegation) |
| `ipv6 dhcpv6-options parameters-only` | Asks a DHCPv6 server for name servers and the like, and for nothing to lease. | [IPv6: DHCPv6](#ipv6-dhcpv6) |

An uplink that takes everything from its provider, and numbers one
interface behind the router from the prefix it is delegated:

```
interface wan0 {
  ipv4 {
    address dhcp;
  }
  ipv6 {
    address dhcpv6;
    dhcpv6-options {
      pd 1 {
        length 56;
        interface lan0 {
          sla-id 1;
          address 1;
        }
      }
    }
  }
}
```

**The name servers an interface learns are the router's own, by
default.** A lease's, a DHCPv6 server's and the ones Router
Advertisements name are handed to systemd-resolved with nothing more
configured, and `no-name-server` keeps them back: see
[Name servers](#name-servers).

## IPv4: DHCP

`interface <name> ipv4 address dhcp` leases an IPv4 address from a DHCP
server.

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

**The router uses the name servers it learns, by default.** Nothing is
configured for it: what gets an interface its address also gets the
router its name servers and search domains, as it gets it a default
route. No `--feature` flag is involved.

| Learned from | On an interface with | Kept back with |
|---|---|---|
| A DHCPv4 lease: the name servers (option 6), and as search domains the domain name (option 15), then the search list (option 119) | `ipv4 address dhcp` | `ipv4 dhcp-options no-name-server` |
| A DHCPv6 server ([below](#ipv6-dhcpv6)): the name servers (option 23) and the search list (option 24), with a lease or without one | `ipv6 address dhcpv6`, `dhcpv6-options pd` or `dhcpv6-options parameters-only` | `ipv6 dhcpv6-options no-name-server` |
| Router Advertisements ([below](#ipv6-router-advertisements-and-slaac)): RDNSS and DNSSL | `ipv6 address autoconf`, `address dhcpv6` or `dhcpv6-options pd` | `ipv6 ra-options no-name-server` |

zebra-rs gives them to systemd-resolved as that link's DNS
configuration: what `resolvectl dns wan0 …` and `resolvectl domain
wan0 …` set, and `resolvectl status wan0` shows. It does not write
`/etc/resolv.conf`. It does not touch systemd-resolved's own settings
either, nor an interface it has learned nothing on.

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

### Keeping them back

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

### How they follow what is learned

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

### Setting up the host

What zebra-rs needs for it. A stock Ubuntu installation has the first
two in place.

- **systemd-resolved running, and `resolvectl` on the path.** On Ubuntu
  24.04 both are in the `systemd-resolved` package.

  ```
  $ systemctl is-active systemd-resolved
  active
  ```

- **`/etc/resolv.conf` pointing at systemd-resolved**, so that the
  programs on the router ask it. The usual form is a symbolic link to
  its stub file:

  ```
  $ readlink /etc/resolv.conf
  ../run/systemd/resolve/stub-resolv.conf
  ```

  That file names systemd-resolved's local listener (`nameserver
  127.0.0.53`) and the search domains in use, whatever name servers it
  has been given. It does not list an interface's name servers;
  `resolvectl status` does.
- **zebra-rs running as root**, which the packaged service does. Started
  with file capabilities alone (`make run`), it leases the address and
  the routes as ever, logs `cannot tell whether this is the host's
  network namespace (…; zebra-rs is not root): the system resolver is
  left alone` and sets no name server.
- **zebra-rs in the host's network namespace.** `resolvectl` identifies
  an interface to systemd-resolved by its index, and the indexes of
  another namespace are those of other interfaces on the host. Run in
  another network namespace, zebra-rs logs `this is not the host's
  network namespace: the system resolver is left alone` and sets
  nothing.
- **No other network manager on the interface.** netplan,
  systemd-networkd and NetworkManager set an interface's DNS
  themselves, and systemd-resolved takes nobody else's word for an
  interface systemd-networkd manages: the command fails with `Link wan0
  is managed.` Leave the interfaces zebra-rs leases on out of their
  configuration.

### Name servers of your own

zebra-rs has no command for a fixed name server: it passes on what an
interface learns, and nothing else. A name server that no lease names
is systemd-resolved's own configuration:

```
# /etc/systemd/resolved.conf.d/dns.conf
[Resolve]
DNS=192.0.2.53 2001:db8::53
Domains=example.net
```

```
$ sudo systemctl restart systemd-resolved
```

- **Both are asked.** For a name that is under none of the search
  domains, systemd-resolved asks its own servers (`DNS=`) and those of
  every link that has some, and takes the first answer that succeeds.
  A name under a search domain goes to the servers that domain came
  with. So a fixed server does not replace an uplink's: to have the
  router ask the fixed ones alone, set `no-name-server` on the uplinks
  as well.
- **`FallbackDNS=`** is used only while no other name server is known.
  With a lease that names one, it is not asked.
- **Restarting systemd-resolved** keeps what zebra-rs has set:
  systemd-resolved saves each link's settings and reads them again when
  it starts.
- **An interface zebra-rs has learned nothing on** is not touched, so
  `resolvectl dns lan0 …` by hand stays as it is set. On an interface
  that leases, zebra-rs sets the link's list anew whenever what is
  learned changes: name servers added to it by hand do not last.

This is about the router's own lookups. Handing name servers to the
hosts behind the router is the DHCP server's part (the insomnia daemon,
[`--feature insomnia`](ch-00-05-command-line-options.md#--feature-modulefeature));
the Router Advertisements zebra-rs sends name none.

### Checking

What each source has learned, whether the router uses it or not:

```
router> show dhcp client leases
router> show dhcpv6 client leases
router> show ipv6 nd interface wan0
```

What systemd-resolved holds for the link, and a lookup with the link
that answered it:

```
$ resolvectl status wan0
$ resolvectl query www.example.com
```

What zebra-rs did is in its log (`journalctl -u zebra-rs` with the
packaged service):

| Log line | What it says |
|---|---|
| `resolver: wan0: name servers 198.51.100.53, search example.com` | Set. |
| `resolver: wan0: name servers withdrawn` | Taken back: what named them ended, or `no-name-server` was set. |
| `resolver: wan0: name servers not set: resolvectl: No such file or directory …` | `resolvectl` is not installed. Install systemd-resolved; zebra-rs tries again by itself. |
| `resolver: wan0: name servers not set: resolvectl: … Link wan0 is managed.` | systemd-networkd manages the interface. Take it out of the netplan or networkd configuration. |
| `resolver: this is not the host's network namespace: the system resolver is left alone` | zebra-rs runs in another network namespace, and sets nothing until it is started in the host's. |
| `resolver: cannot tell whether this is the host's network namespace (…; zebra-rs is not root): the system resolver is left alone` | zebra-rs is not root, and sets nothing until it is started as root. |

A failure is said once for an interface, and the command is tried again
as described above. The lease, its address and its routes do not depend
on it.

### In a VRF, and after a restart

**VRF.** systemd-resolved does not know about VRFs. The name servers of
an interface in a VRF are set all the same, but its queries to them are
answered only with `net.ipv4.udp_l3mdev_accept` and
`net.ipv4.tcp_l3mdev_accept` set to 1. Without them, `no-name-server`
on that interface keeps the router from asking servers that will not
answer it.

**Restart.** A restart of zebra-rs leaves what was set in place and sets
it again from the resumed lease. `no-name-server` set while zebra-rs is
not running takes nothing back: `resolvectl revert <name>` does it by
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
| `pd <id> interface <name>` | Give this interface an address in one /64 of the delegated prefix ([Numbering the interfaces behind the router](#numbering-the-interfaces-behind-the-router)). |
| `pd <id> interface <name> sla-id` | Which /64 of the prefix: its number among them. Default 0, the first. |
| `pd <id> interface <name> address` | The host part of the address. Default: made from the interface's hardware address (EUI-64). |

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

- **The prefix is held by an unreachable route**, a `D` route at
  administrative distance 210 in the VRF of the interface. A packet for
  a part of the prefix that nothing uses must not follow the default
  route back to the provider, who routes the whole prefix here and
  would send it back again. It is dropped here, and its sender is told
  with an ICMPv6 Destination Unreachable ("no route to destination"),
  so a host behind the router does not wait for an answer that cannot
  come. In the kernel it is an `unreachable` route with `proto dhcp`.
  It stays while the link is down, and goes when the prefix is given
  back or runs out.
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

router> show ipv6 route 2001:db8:100::/56
Routing entry for 2001:db8:100::/56
  Known via "dhcp client", distance 210, metric 0
  Last update 00:00:12 ago
  Routing Descriptor Blocks
    discard (unreachable)

$ ip -6 route show 2001:db8:100::/56
unreachable 2001:db8:100::/56 dev lo proto dhcp metric 1024 pref medium
```

A delegation that holds nothing shows as `none (pd <id>)`. In `json`,
`pd` lists each delegation with its prefixes and, once it holds one,
its own server and renewal times. After a restart of zebra-rs the lease
is taken from disk with its prefixes, the unreachable routes are back
at once, and the server is asked whether the lease still stands.

### Numbering the interfaces behind the router

`pd <id> interface <name>` gives an interface behind the router an
address in one /64 of the delegated prefix. `sla-id` says which /64:
the bits between the prefix's length and 64, so a /56 has 256 of them,
0 to 255. `address` is the host part; without it the address is made
from the interface's hardware address (EUI-64).

```
interface wan1 {
  ipv6 {
    dhcpv6-options {
      pd 1 {
        length 56;
        interface lan1 {
          sla-id 1;
          address 1;
        }
        interface lan2 {
          sla-id 2;
        }
      }
    }
  }
}
```

With `2001:db8:100::/56` delegated, `lan1` gets `2001:db8:100:1::1/64`
and `lan2` an address in `2001:db8:100:2::/64`.

- **The address has the prefix's lifetimes** and follows the lease. A
  renewal moves its lifetimes, another prefix from the server replaces
  it, and it goes when the prefix is given back or runs out. `show
  interface` marks it `dhcpv6-pd`.
- **Its /64 is a connected route** on the interface, which takes that
  part of the prefix off the unreachable route. The rest stays there.
- **Each interface of a delegation needs its own /64.** A commit that
  gives two of them the same `sla-id` is refused, and so is one that
  names the interface the prefix is delegated on.
- **The server decides how long the prefix is.** An `sla-id` that the
  delegated prefix has no room for leaves that interface without an
  address; the log and `show dhcpv6 client leases` say why. The same
  goes for an interface in another VRF than the WAN interface, and for
  one without a hardware address and without `address` (a loopback).
- **Changing the interfaces does not touch the lease.** Only adding or
  deleting the `pd` itself, or changing its `length`, asks the server
  again.
- **Hosts on the interface get their addresses from it** when the
  interface sends Router Advertisements (`ipv6 router-advertisements
  send-advertisements true`): the /64 is named in them with the
  prefix's lifetimes, and a prefix that the server replaces is taken
  out of use on the hosts at once. See
  [Router Advertisements](ch-00-02-interface-configuration.md#router-advertisements).

```
router> show dhcpv6 client leases
Interface: wan1
  VRF:          default
  State:        bound
  DUID:         00:01:00:01:32:85:1b:00:52:54:00:12:34:56
  Server:       fe80::1
  Server DUID:  00:03:00:01:02:00:00:00:00:fe
  Prefix:       2001:db8:100::/56 preferred 3000s valid 6600s (pd 1)
    on lan1:    2001:db8:100:1::1/64
    on lan2:    2001:db8:100:2:5054:ff:fe12:3456/64
  Renew in:     1200s
  Rebind in:    2400s

router> show interface lan1
  inet6 2001:db8:100:1::1/64 dhcpv6-pd valid-lft 6600 preferred-lft 3000
```

After a restart of zebra-rs the addresses are still on their
interfaces, and stay with the lease that is taken from disk. One whose
interface was taken out of the configuration meanwhile is removed.

## Not done yet

- The NTP servers of a lease are shown but not applied to the system.
- Name servers reach the router only through systemd-resolved. On a
  host without it they are shown and not used.
- No fixed name server can be configured in zebra-rs, and no show
  command says what was handed to systemd-resolved: `resolvectl status`
  does ([Name servers](#name-servers)).
- The interface MTU option (26) is not applied.
- A classless route whose router is `0.0.0.0` (an on-link destination)
  is not installed; a log line says so.
- A delegated prefix that changed while zebra-rs was not running is
  not taken out of use on the hosts behind the router: they keep their
  old addresses until the lifetime they last heard runs out.
- The RA host does not advertise the prefixes it learns on other
  interfaces, and does not use stable-privacy or temporary addresses.
