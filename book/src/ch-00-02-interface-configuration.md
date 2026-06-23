# Interface Configuration

Interface attributes that are independent of any routing protocol live
under the top-level `interface` list, keyed by the kernel interface
name:

```
interface enp0s6 {
  mtu 1400;
  ipv4 {
    address 10.0.0.1/24;
  }
}
```

| YANG leaf | Type | Notes |
|---|---|---|
| `/interface/<name>/if-name` | `string` | List key — the kernel interface name. |
| `/interface/<name>/mtu` | `uint32` (68..65535) | Maximum transmission unit in bytes. See below. |
| `/interface/<name>/vrf` | leafref `/vrf/name` | Enslave the interface to a VRF master device. |
| `/interface/<name>/bridge` | leafref `/bridge/name` | Enslave the interface to a bridge master device. See below. |
| `/interface/<name>/ipv4/address` | `inet:ipv4-prefix` | IPv4 address (with prefix length). |
| `/interface/<name>/ipv6/address` | `inet:ipv6-prefix` | IPv6 address (with prefix length). |

The list entry itself is not a separate "create interface" operation —
it just attaches configuration to a kernel device that already exists
(or appears later). zebra-rs does not create physical or virtual links
from this block.

## Bridge and VRF enslavement

The `bridge` and `vrf` leaves enslave the interface to a master device —
the equivalent of `ip link set <name> master <master>`:

```
interface enp0s6 {
  bridge br0;     # make enp0s6 a port of the Linux bridge br0
}
interface enp0s7 {
  vrf CUST-A;     # move enp0s7 into the VRF CUST-A
}
```

Both write the kernel `IFLA_MASTER`, so they are mutually exclusive — an
interface has exactly one master. `bridge` is a leafref to
`/bridge/name` and `vrf` a leafref to `/vrf/name`; the referenced device
is the one zebra-rs creates from its own
[`bridge`](ch-00-04-bridge-configuration.md) / `vrf` block.

The bind is **staged**, the same way the configured MTU is: it is held
as durable desired-state and applied once *both* the interface and the
master device exist in the kernel, so the order of configuration and
device creation is irrelevant. If the bridge is configured after the
interface, the enslavement fires when the bridge appears; if the bridge
is later deleted, the kernel releases the port and zebra-rs re-applies
the bind automatically when the bridge is re-created.

Remove the binding with the master name as the argument:

```
no interface enp0s6 bridge br0
```

## MTU

The `mtu` leaf sets the interface MTU on the kernel. zebra-rs issues a
netlink `RTM_NEWLINK` (`IFLA_MTU`) — the equivalent of
`ip link set <name> mtu <n>`.

```
interface enp0s6 {
  mtu 1400;
}
```

### Default and range

When `mtu` is unset, the interface keeps whatever MTU the kernel
assigned it — typically **65536** for loopback devices and **1500**
for everything else.

The YANG schema constrains the configurable value to **68..65535**,
which is the IPv4 lower bound (RFC 791) up to the 16-bit ceiling.
The IPv6 minimum link MTU is **1280** (RFC 8200 §5): zebra-rs does not
reject sub-1280 values up front, because whether they are legal depends
on the interface's runtime state. Instead, the kernel is the authority
— see *Apply failures* below.

### Deleting the configuration

Deleting the leaf restores the MTU the interface had **before** it was
first configured (the value zebra-rs observed when it first learned the
interface), not a hard-coded default:

```
no interface enp0s6 mtu
```

If, for example, the kernel reported 1500 when the daemon started and
the operator configured 9000, then `no interface enp0s6 mtu` returns
the interface to 1500.

### Apply failures

A value the kernel refuses — most commonly an MTU below the IPv6
minimum of 1280 on an interface that has IPv6 enabled — is reported by
`show interface`. The live MTU line continues to show the value the
kernel actually has; a second line records the rejected attempt:

```
Interface: enp0s6
  Hardware is Ethernet 52:54:00:11:22:33
  index 2 metric 1 mtu 1500
  MTU set to 1000 is failed due to Invalid argument (os error 22)
  Link is Up
  ...
```

The failure note clears automatically the next time a set on that
interface succeeds.

### Configuring before the interface exists

The configured MTU is durable desired-state: it is kept even if the
named interface is absent, and re-applied automatically when a matching
interface appears (or re-appears after being removed and recreated).
This makes the order of `interface` configuration and device creation
irrelevant.

## Protocol synchronisation

Several protocols use the interface MTU when building packets, so a
change must reach them rather than being a kernel-only setting:

- **OSPF** stamps the Database Description packet's `Interface MTU`
  field with it (RFC 2328 §10.6); a mismatch with a neighbour stalls
  the adjacency in `ExStart` unless `mtu-ignore` is set.
- **IS-IS** pads Hello PDUs up to the MTU (RFC 1195 §8) and sizes LSP
  fragmentation against it.

When the MTU of a known interface changes — whether through this
configuration or an external `ip link set` — the RIB fans the new value
out to every protocol that has the interface. They update their cached
value in place, leaving adjacencies and state machines untouched, so
the change is non-disruptive. Each protocol's interface view reflects
the same value:

```
# show interface          → live kernel MTU
# show ospf interface  → "ifindex 2, MTU 1400 bytes, BW 0 Mbit ..."
# show isis interface detail → "Type: ..., SNPA: ..., MTU: 1400"
```

If these ever disagree it indicates the notification path was missed —
they are sourced from one RIB-driven update, not independent reads.

## Cross-reference — FRR / iproute2

| zebra-rs | FRR `interface` / iproute2 |
|---|---|
| `interface <n> mtu <v>` | `mtu <v>` (interface) / `ip link set <n> mtu <v>` |
| `no interface <n> mtu` | restore original — no direct FRR equivalent (FRR leaves the last value) |
| `interface <n> ipv4 address <p>` | `ip address <p>` (interface) |
| `interface <n> vrf <name>` | `ip link set <n> master <name>` (VRF master) |
| `interface <n> bridge <name>` | `ip link set <n> master <name>` (bridge master) |

Note the delete semantics differ: zebra-rs restores the
originally-observed MTU, whereas iproute2/FRR simply leave whatever was
last set in place.
