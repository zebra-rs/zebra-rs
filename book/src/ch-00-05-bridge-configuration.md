# Bridge Configuration

zebra-rs can create a **Linux bridge device** from configuration. Like
the [`vxlan`](ch-00-04-vxlan-configuration.md) block — and unlike
[`interface`](ch-00-03-interface-configuration.md), which only attaches
attributes to an existing device — the top-level `bridge` list
**creates** the kernel bridge netdevice (`ip link add <name> type
bridge`) and tears it down when the entry is removed.

A bridge is the L2 forwarding domain an EVPN deployment binds a
[VXLAN](ch-00-04-vxlan-configuration.md) device into: the VXLAN tunnel
and the local access ports are enslaved to the same bridge, and the
control plane drives the forwarding database.

## Configuration

The `bridge` list is keyed by the device name:

```
bridge br550 {
  address-gen-mode none;
}
```

or, in command form:

```
set bridge br550
set bridge br550 address-gen-mode none
```

| YANG leaf | Type | Required | Notes |
|---|---|---|---|
| `/bridge/<name>/name` | `string` | — | List key — the kernel device name (e.g. `br550`). |
| `/bridge/<name>/address-gen-mode` | `enum {none, eui64, random, stable-secret}` | no | IPv6 link-local address generation mode. Defaults to `none`. |

## Defaults applied automatically

When zebra-rs creates the bridge it applies the same device-bring-up
defaults as for a VXLAN. Neither has a config knob beyond the
`address-gen-mode` leaf — they are fixed for every bridge this daemon
creates.

| Default | Netlink | `ip link` equivalent | Why |
|---|---|---|---|
| **Brought up** | `IFF_UP` set on create | `ip link add ... up` | The bridge is operational immediately, without a separate `ip link set <dev> up`. |
| **`address-gen-mode none`** | `IFLA_INET6_ADDR_GEN_MODE = 1` | `ip link set <dev> addrgenmode none` | Suppresses the kernel's automatic link-local on the bridge. Applied as a follow-up `RTM_NEWLINK` after creation. |

> The kernel's own default for address-gen-mode is `eui64` (it would
> derive a link-local from the MAC). zebra-rs overrides this to `none`
> unless the operator sets `address-gen-mode` explicitly — an explicit
> value always wins.

Together these reproduce the canonical bridge bring-up:

```
ip link add br550 type bridge
ip link set br550 addrgenmode none
ip link set br550 up
```

## Deleting the configuration

Removing the list entry deletes the kernel device (`RTM_DELLINK`, the
equivalent of `ip link del br550`):

```
no bridge br550
```

## Cross-reference — iproute2

| zebra-rs | iproute2 |
|---|---|
| `bridge <n>` | `ip link add <n> type bridge` |
| `bridge <n> address-gen-mode <m>` | `ip link set <n> addrgenmode <m>` |
| *(automatic)* device up | `ip link set <n> up` |
| `no bridge <n>` | `ip link del <n>` |
