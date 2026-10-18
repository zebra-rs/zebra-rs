# Bridge Configuration

zebra-rs can create a **Linux bridge device** from configuration. Like
the [`vxlan`](ch-00-03-vxlan-configuration.md) and
[`vlan`](ch-00-08-vlan-configuration.md) blocks — and unlike
[`interface`](ch-00-02-interface-configuration.md), which only attaches
attributes to an existing device — the top-level `bridge` list
**creates** the kernel bridge netdevice (`ip link add <name> type
bridge`) and tears it down when the entry is removed.

A bridge is the L2 forwarding domain an EVPN deployment carries. Over
[VXLAN](ch-00-03-vxlan-configuration.md) that means binding a VXLAN device
into it — the tunnel and the local access ports are enslaved to the same
bridge, and the control plane drives the forwarding database. Over
[SRv6](ch-02-41-bgp-evpn-srv6.md) the shape is the same — a vxlan slave
declares the VNI that names the instance — but the kernel VXLAN path
stays inert: the device is only the declaration, and forwarding runs
MAC-in-SRv6 on the [eBPF data plane](ch-16-00-ebpf.md). Over
[MPLS](ch-02-40-bgp-evpn-mpls.md) there is no tunnel device at all: the
bridge is named directly by an `evi <id> { bridge <name> }` entry, and the
transport is a service label rather than an enslaved netdevice.

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

## Enslaving ports to the bridge

Ports are enslaved from *their own* config block — not the bridge's —
each with a `bridge` leafref to `/bridge/name` (the equivalent of
`ip link set <port> master <bridge>`):

```
interface enp0s6 {
  bridge br550;        # a local access port
}
vxlan vni550 {
  vni 550;
  bridge br550;        # the EVPN VXLAN tunnel
}
```

The bind is staged the same way for both: it is applied once the port
*and* the bridge exist in the kernel, so the bridge may be configured
before or after its members, and a deleted-and-recreated bridge
re-acquires them automatically. Enslaving a VXLAN additionally triggers
the EVPN bridge-slave defaults (`neigh_suppress on`, `learning off`) on
the port.

See [Interface Configuration](ch-00-02-interface-configuration.md#bridge-and-vrf-enslavement)
and [VXLAN Configuration](ch-00-03-vxlan-configuration.md#when-the-device-joins-a-bridge)
for the full details.

## Deleting the configuration

Removing the list entry deletes the kernel device (`RTM_DELLINK`, the
equivalent of `ip link del br550`):

```
no bridge br550
```

## Show commands

The examples come from two iBGP EVPN PEs, r1 (192.168.0.1) and r2
(192.168.0.2), each with VXLAN VNI 10 enslaved to a bridge `br10` and an
access port `host0` holding one station: aa:bb:cc:dd:ee:01 on r1 and
aa:bb:cc:dd:ee:02 on r2.

### `show l2 mac table`

The MACs EVPN has learned from other PEs, one entry per VNI and MAC:

- **`Encap` and `Tunnel Endpoint`:** where the MAC is. That is the remote
  VTEP for EVPN over VXLAN, the remote PE's `End.DT2U` SID for EVPN over
  SRv6 (RFC 9252), or `<PE>:<label>` for EVPN over MPLS. An IPv6 endpoint
  alone would be ambiguous, since VXLAN also runs over an IPv6 underlay,
  so `Encap` names the kind. A MAC advertised by more than one PE on a
  multihomed segment shows the first, with `(+<n>)` for the others.
- **`Flags`:** `S` sticky (RFC 7432 §15.2), `G` default gateway, `R`
  router, `L` behind an E-Tree leaf (RFC 8317), or `-`.
- **`Seq`:** the MAC Mobility sequence number.
- **`Installed`:** whether the MAC is programmed in the data plane.

```
r2> show l2 mac table
VNI    MAC Address         Encap Tunnel Endpoint       Flags Seq    Installed
------ ------------------- ----- --------------------- ----- ------ ---------
10     aa:bb:cc:dd:ee:01   vxlan 192.168.0.1           -     0      Yes
```

JSON: `{ "entries": [ { "vni", "mac", "tunnel_endpoint", "encap",
"flags", "seq", "installed" } ] }`.

For one line per VNI instead of per MAC, use
[`show evpn vni all`](ch-02-48-bgp-show.md#show-evpn-vni-all).

### `show l2 neighbor`

The kernel's bridge forwarding database (FDB), as zebra-rs sees it: one
row per MAC, interface and VLAN, with its VNI, remote VTEP, neighbor
state and `NTF_*` flags in hex (`0x02` self, `0x10` externally learned).
Where `show l2 mac table` is EVPN's view, this is the kernel's. It
includes the bridge's and the ports' own addresses, the VXLAN device's
rows, and the multicast addresses of other interfaces.

```
r1> show l2 neighbor
 MAC                Interface         VLAN         VNI  Dst                                      State          Flags
 ------------------ ---------------- -----  ----------  ---------------------------------------- -------------- ----------
...
 00:00:00:00:00:00  vxlan10              -          10  192.168.0.2                              Permanent      0x12
 92:ba:75:d4:40:d0  vxlan10              -           -  -                                        Permanent      0x00
 92:ba:75:d4:40:d0  vxlan10              1           -  -                                        Permanent      0x00
 aa:bb:cc:dd:ee:02  vxlan10              -          10  192.168.0.2                              Permanent      0x12
 aa:bb:cc:dd:ee:02  vxlan10              1           -  -                                        Reachable      0x10
 02:00:00:00:fe:01  br10                 -           -  -                                        Permanent      0x00
 02:00:00:00:fe:01  br10                 1           -  -                                        Permanent      0x00
 02:00:00:00:0a:01  host0                -           -  -                                        Permanent      0x00
 02:00:00:00:0a:01  host0                1           -  -                                        Permanent      0x00
 aa:bb:cc:dd:ee:01  host0                -           -  -                                        Noarp          0x00
 aa:bb:cc:dd:ee:01  host0                1           -  -                                        Noarp          0x00
```

The VXLAN device's own rows (`0x12`: self, externally learned) carry
the VNI and the remote VTEP: `00:00:00:00:00:00` sends broadcast,
unknown-unicast and multicast traffic to r2, and `aa:bb:cc:dd:ee:02` is
r2's station.

JSON: `{ "entries": [ { "mac", "interface", "vlan", "vni", "dst",
"state", "flags" } ] }`, with `flags` as a number.

## Cross-reference — iproute2

| zebra-rs | iproute2 |
|---|---|
| `bridge <n>` | `ip link add <n> type bridge` |
| `bridge <n> address-gen-mode <m>` | `ip link set <n> addrgenmode <m>` |
| *(automatic)* device up | `ip link set <n> up` |
| `interface <p> bridge <n>` | `ip link set <p> master <n>` (enslave a port) |
| `vxlan <p> bridge <n>` | `ip link set <p> master <n>` (enslave a VXLAN) |
| `no bridge <n>` | `ip link del <n>` |
