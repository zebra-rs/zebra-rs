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
  and verifies it with the server.
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

## Not done yet

- The DNS servers, domain and NTP servers of a lease are shown but not
  applied to the system.
- The interface MTU option (26) is not applied.
- A classless route whose router is `0.0.0.0` (an on-link destination)
  is not installed; a log line says so.
- DHCPv6 and IPv6 autoconfiguration.
