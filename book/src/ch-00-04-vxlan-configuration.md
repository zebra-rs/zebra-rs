# VXLAN Configuration

zebra-rs can create a **VXLAN tunnel device** from configuration. Unlike
the [`interface`](ch-00-03-interface-configuration.md) block — which
only attaches attributes to a device that already exists — the
top-level `vxlan` list **creates** the kernel VXLAN netdevice (the
equivalent of `ip link add <name> type vxlan ...`) and tears it down
when the entry is removed.

A VXLAN device is the data-plane endpoint (VTEP) for an EVPN overlay:
once it is enslaved to a Linux [bridge](ch-00-05-bridge-configuration.md)
it carries the L2 service, and the
control plane (BGP [EVPN Type-5](ch-02-06-bgp-evpn-type5.md) and the L2
Type-2 / Type-3 routes) populates the forwarding database. Because the
overlay relies on a BGP control plane rather than data-plane
flood-and-learn, zebra-rs applies a set of EVPN-appropriate **defaults**
automatically so the operator does not have to spell each one out.

## Configuration

The `vxlan` list is keyed by the device name:

```
vxlan vni550 {
  vni 550;
  local-address 10.0.0.1;
  dest-port 4789;
}
```

or, in command form:

```
set vxlan vni550 vni 550
set vxlan vni550 local-address 10.0.0.1
set vxlan vni550 dest-port 4789
```

| YANG leaf | Type | Required | Notes |
|---|---|---|---|
| `/vxlan/<name>/name` | `string` | — | List key — the kernel device name (e.g. `vni550`). |
| `/vxlan/<name>/vni` | `uint32` | **yes** | VXLAN Network Identifier → `IFLA_VXLAN_ID`. |
| `/vxlan/<name>/local-address` | `inet:ipv4-address` \| `inet:ipv6-address` | no | Source VTEP address → `IFLA_VXLAN_LOCAL` / `IFLA_VXLAN_LOCAL6`. |
| `/vxlan/<name>/dest-port` | `uint16` | no | UDP destination port → `IFLA_VXLAN_PORT`. Defaults to `4789`. |
| `/vxlan/<name>/address-gen-mode` | `enum {none, eui64, random, stable-secret}` | no | IPv6 link-local address generation mode. Defaults to `none`. |
| `/vxlan/<name>/bridge` | leafref `/bridge/name` | no | Enslave the VXLAN to a bridge master → `IFLA_MASTER`. Triggers the bridge-slave defaults below. |

## Defaults applied automatically

When zebra-rs creates the VXLAN device it bakes in the settings that an
EVPN deployment would otherwise have to configure by hand. None of these
have a config knob — they are the fixed default for every VXLAN this
daemon creates.

### At device creation

These are part of the `RTM_NEWLINK` that creates the device:

| Default | Netlink | `ip link` equivalent | Why |
|---|---|---|---|
| **MAC learning off** (`nolearning`) | `IFLA_VXLAN_LEARNING = 0` | `... type vxlan ... nolearning` | The BGP control plane owns the FDB; kernel flood-and-learn must be off so it does not fight the control plane. |
| **VNI-aware device** (`external vnifilter`) | `IFLA_VXLAN_COLLECT_METADATA = 1` + `IFLA_VXLAN_VNIFILTER = 1`; each VNI via `RTM_NEWTUNNEL` | `... type vxlan external vnifilter` then `bridge vni add vni <id> dev <dev>` | The device carries no fixed VNI (`id 0`); configured VNIs are registered explicitly and stamped on every FDB/MDB entry as `src_vni`. This VNI-aware model is what enables per-VTEP EVPN multicast — the kernel VXLAN MDB `dst` (see [IGMP/MLD Proxy](ch-02-32-bgp-evpn-igmp-mld-proxy.md)). |
| **`dest-port 4789`** | `IFLA_VXLAN_PORT = 4789` | `... type vxlan ... dstport 4789` | The IANA-assigned VXLAN port, used when `dest-port` is unset — Linux would otherwise fall back to the legacy 8472. An explicit value always wins. |
| **Brought up** | `IFF_UP` set on create | `ip link add ... up` | The device is operational immediately, without a separate `ip link set <dev> up`. |
| **`address-gen-mode none`** | `IFLA_INET6_ADDR_GEN_MODE = 1` | `ip link set <dev> addrgenmode none` | Suppresses the kernel's automatic link-local on the VTEP. Applied as a follow-up `RTM_NEWLINK` after creation. |

> The kernel's own default for address-gen-mode is `eui64` (it would
> derive a link-local from the MAC). zebra-rs overrides this to `none`
> unless the operator sets `address-gen-mode` explicitly — an explicit
> value always wins.

### When the device joins a bridge

A VXLAN device only carries an L2 service once it is enslaved to a Linux
bridge. Enslave it with the `bridge` leaf — the equivalent of
`ip link set vni550 master <bridge>`:

```
vxlan vni550 {
  vni 550;
  local-address 10.0.0.1;
  bridge br550;
}
```

`bridge` is a leafref to `/bridge/name`, and the bind is **staged** — it
is applied once both the VXLAN and the bridge exist in the kernel, so
the order of configuration is irrelevant. This is the same deferred
mechanism as [`interface <name>
bridge`](ch-00-03-interface-configuration.md#bridge-and-vrf-enslavement),
which the VXLAN binding reuses directly. zebra-rs also still
**observes** enslavement performed externally
(`ip link set vni550 master <bridge>`), so either path works.

The moment a VXLAN device gains a bridge master — by config or by an
external action — zebra-rs applies the bridge-slave defaults to the
port:

| Default | Netlink | `ip link` equivalent | Why |
|---|---|---|---|
| **Neighbour suppression on** | `IFLA_BRPORT_NEIGH_SUPPRESS = 1` | `ip link set <dev> type bridge_slave neigh_suppress on` | ARP / ND requests are answered locally from the FDB instead of being flooded across the overlay. |
| **Bridge-port learning off** | `IFLA_BRPORT_LEARNING = 0` | `ip link set <dev> type bridge_slave learning off` | The bridge must not learn MACs from the data plane on this port — the control plane installs them. |

(If the master a VXLAN gains is not actually a bridge, the kernel
rejects the bridge-port attributes and the attempt is logged at `info`;
nothing else is affected.)

## The full sequence

Taken together, configuring a VXLAN in zebra-rs and enslaving it to a
bridge reproduces the canonical EVPN-VXLAN bring-up. The manual commands

```
ip link add vni550 type vxlan local 10.0.0.1 dstport 4789 external vnifilter nolearning
bridge vni add vni 550 dev vni550
ip link set vni550 master br550 addrgenmode none
ip link set vni550 type bridge_slave neigh_suppress on learning off
ip link set vni550 up
```

map onto zebra-rs as:

```
set bridge br550
set vxlan vni550 vni 550
set vxlan vni550 local-address 10.0.0.1
set vxlan vni550 dest-port 4789
set vxlan vni550 bridge br550
```

* the `vxlan` leaves create the device as an `external vnifilter` VXLAN
  with `nolearning`, register the configured VNI (`bridge vni add`), and
  apply `addrgenmode none` and `up` automatically (the first two commands
  plus the `addrgenmode`/`up` parts);
* `set vxlan vni550 bridge br550` enslaves it — the equivalent of
  `ip link set vni550 master br550` (the second command);
* on gaining that master, zebra-rs applies `neigh_suppress on` and
  `learning off` automatically (the third command).

So the operator supplies the VNI / VTEP / port and names the bridge;
zebra-rs creates the devices, performs the enslavement, and fills in
every EVPN-correct default.

## Deleting the configuration

Removing the list entry deletes the kernel device (`RTM_DELLINK`, the
equivalent of `ip link del vni550`):

```
no vxlan vni550
```

## `dest-port` default

`dest-port` is optional. When it is unset, zebra-rs sends
`IFLA_VXLAN_PORT = 4789` — the **IANA-assigned** VXLAN port. This is a
deliberate override of the kernel's own fallback, which is the
pre-standardisation Linux port **8472**; defaulting to 4789 keeps the
device interoperable with other EVPN/VXLAN implementations out of the
box. An explicit `dest-port` always takes precedence.

## Cross-reference — iproute2

| zebra-rs | iproute2 |
|---|---|
| `vxlan <n> vni <id>` | `ip link add <n> type vxlan external vnifilter` + `bridge vni add vni <id> dev <n>` |
| `vxlan <n> local-address <ip>` | `... type vxlan local <ip>` |
| `vxlan <n> dest-port <p>` | `... type vxlan dstport <p>` |
| `vxlan <n> address-gen-mode <m>` | `ip link set <n> addrgenmode <m>` |
| `vxlan <n> bridge <name>` | `ip link set <n> master <name>` |
| *(automatic)* `nolearning` | `... type vxlan ... nolearning` |
| *(automatic)* device up | `ip link set <n> up` |
| *(automatic on bridge-join)* `neigh_suppress on` | `ip link set <n> type bridge_slave neigh_suppress on` |
| *(automatic on bridge-join)* `learning off` | `ip link set <n> type bridge_slave learning off` |
| `no vxlan <n>` | `ip link del <n>` |
