# VLAN Sub-interface Configuration

zebra-rs can create an **802.1Q VLAN sub-interface** from configuration.
Like the [`bridge`](ch-00-04-bridge-configuration.md) and
[`vxlan`](ch-00-03-vxlan-configuration.md) blocks — and unlike
[`interface`](ch-00-02-interface-configuration.md), which only attaches
attributes to an existing device — the top-level `vlan` list **creates**
the kernel device (`ip link add link <parent> name <name> type vlan id
<vid>`) and tears it down when the entry is removed.

## Configuration

The `vlan` list is keyed by the device name; the parent interface and
the 802.1Q id are both mandatory:

```
vlan eth0.100 {
  interface eth0;
  vlan-id 100;
}
interface eth0.100 {
  ipv4 {
    address 10.100.0.1/24;
  }
}
```

or, in command form:

```
set vlan eth0.100 interface eth0
set vlan eth0.100 vlan-id 100
set interface eth0.100 ipv4 address 10.100.0.1/24
```

| YANG leaf | Type | Required | Notes |
|---|---|---|---|
| `/vlan/<name>/name` | `string` | — | List key — the kernel device name. A free-form label: `eth0.100` is only a convention, `set vlan customer-a ...` works the same. |
| `/vlan/<name>/interface` | `string` | yes | Parent (lower) device the VLAN rides on. May name an interface that does not exist yet. |
| `/vlan/<name>/vlan-id` | `uint16` (1..4094) | yes | The 802.1Q tag. |

The name is never parsed — the parent and the id come exclusively from
the two leaves, matching how the kernel itself works (the VLAN id lives
in the `IFLA_VLAN_ID` netlink attribute, not in the name). This also
sidesteps the 15-character `IFNAMSIZ` limit: a parent with a long name
simply gets a sub-interface with a shorter label.

Once created, the sub-interface is an ordinary kernel device: address,
`vrf`, `mtu` and protocol configuration attach to it through the normal
[`interface`](ch-00-02-interface-configuration.md) list, and its
operational state follows the parent (the kernel clears `LOWER_UP` on
the child when the parent goes down).

## Lifecycle

- **Deferred creation.** If the parent is not in the kernel yet, the
  entry is held as desired state and the device is created the moment
  the parent appears. Configuration order is free.
- **Parent deletion.** The kernel removes VLAN children together with a
  deleted parent. zebra-rs re-creates the sub-interface automatically
  when the parent returns.
- **Adoption.** A pre-existing kernel device with the same name, parent
  and id (left over from a previous run, or created with `ip link`) is
  adopted as-is.
- **Re-creation on change.** The kernel refuses to change the parent or
  the VLAN id of a live device, so modifying either leaf deletes and
  re-creates the sub-interface.
- **Collision safety.** If a kernel link with the configured name exists
  but is *not* a VLAN device (say the entry accidentally names a
  physical NIC), zebra-rs logs a warning and leaves it untouched.

One ordering caveat: an `interface` address for a device created in the
**same commit** is dropped, because addresses apply immediately while
device creation completes asynchronously (this limitation is shared with
`bridge` and `vxlan` devices). Apply the address in a follow-up commit —
staged bindings (`vrf`, `bridge`) are exempt and may share the commit.

Deleting the entry deletes the kernel device, and its addresses and
connected routes go with it:

```
delete vlan eth0.100
```

`show interface <name>` reports the id and parent of any VLAN device,
whether zebra-rs created it or learned it from the kernel:

```
Interface: eth0.100
  Hardware is Ethernet 02:42:ac:11:00:02
  index 12 metric 1 mtu 1500
  VLAN id 100 parent eth0 (index 2)
  ...
```

## Cross-reference — FRR / iproute2

| zebra-rs | iproute2 |
|---|---|
| `vlan <n> interface <p>` + `vlan <n> vlan-id <v>` | `ip link add link <p> name <n> type vlan id <v>` |
| *(automatic)* device up | `ip link set <n> up` |
| `delete vlan <n>` | `ip link del <n>` |

FRR has no equivalent configuration: its zebra daemon never creates
interfaces of any kind. It only *learns* VLAN devices the kernel
already has (netlink kind `vlan`, `IFLA_LINK`, `IFLA_VLAN_ID`) and
reports them in `show interface`. zebra-rs behaves the same way for
externally-created devices — the `vlan` list is the additional,
configuration-driven creation path.
