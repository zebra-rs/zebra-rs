# Selection of the Router-ID

In many routing protocols, such as OSPF and BGP, the router-id is used to uniquely identify each router. Although it is recommended to configure the router-id manually, if not set, the router automatically selects one from the available interfaces.

For example, in the widely referenced Cisco IOS implementation, if one or more Loopback interfaces have IP addresses configured, the router selects the highest IP address among all Loopback interfaces. If none of the Loopback interfaces have an IP address configured, then among the IP addresses on the other interfaces that are in the Up state, the highest one is chosen.

In Cisco IOS-XE, if one or more Loopback interfaces have IP addresses configured, the selection process is the same as in IOS. However, when considering physical interfaces, the router examines all such interfaces and chooses the one with the highest IP address, regardless of whether the interface is up or down. Notably, if after a reboot the physical interface with the highest IP address is in the Down state, the device does not select that interface’s IP address as the router-id; instead, it selects the IP address of the first physical interface that becomes operational.

In Juniper’s JunOS, if one or more Loopback interfaces have IP addresses configured, the router selects the smallest IP address among them. If no Loopback interface has an IP address configured, then among all physical interfaces, the smallest IP address is chosen as the router-id.

It is important to note that Cisco and Juniper differ in that one selects the highest IP address while the other selects the lowest.

To avoid confusion among operators who are familiar with existing router implementations, this implementation follows these rules:

1. If one or more Loopback interfaces have an IP address configured, the highest among them is selected (`127.0.0.1` is never a candidate).
2. If not, then if one or more physical interfaces have an IP address configured, the highest among them is selected regardless of the interface's state.
3. Otherwise, the router-id remains unset.

Interfaces that are enslaved to a VRF are excluded from this default-instance selection — their addresses participate in the per-VRF selection instead (see below). Interfaces enslaved to a bridge remain candidates, since a bridge master does not move its ports out of the default routing table.

Once a router-id has been selected it is *sticky*: if the address it was derived from later disappears and no other candidate exists, the previously selected value is retained rather than reverting to unset. This avoids churning every protocol session over a transient address removal.

## Configuring the global Router-ID

The automatic pick can be overridden with the top-level `router-id` command:

```
set router-id 10.255.0.1
```

The configured value always wins over the automatic pick. Deleting it falls back to the automatic selection again:

```
delete router-id 10.255.0.1
```

The effective value and its origin are visible with `show router-id`:

```
> show router-id
Router ID: 10.255.0.1 (configured)
> delete router-id 10.255.0.1
> show router-id
Router ID: 192.0.2.200 (automatic)
```

## Per-VRF Router-ID

Each VRF has its own router-id, resolved independently of the default instance:

1. The configured `vrf <name> router-id`, if present.
2. Otherwise, the automatic pick among the VRF's member interfaces (the same loopback-first, highest-address rules as above).
3. Otherwise, the global effective router-id.

```yaml
vrf:
- name: cust-a
  router-id: 11.11.11.11
```

The per-VRF values appear in `show vrf`:

```
> show vrf
 Name                      Table-ID  Router-ID        Members
 ------------------------  ----------  ---------------  ----------------
 cust-a                           1  11.11.11.11      ce1
 cust-b                           2  10.99.0.1        ce2
```

Here `cust-a` uses its configured override while `cust-b` derived `10.99.0.1` from its member interface. Deleting a per-VRF `router-id` falls back to the derived value, then to the global one.

## Distribution to routing protocols

The RIB pushes the effective router-id to every routing protocol: default-instance protocols receive the global value, per-VRF protocol instances receive their VRF's value. A change (an interface address appearing, an interface moving into a VRF, a configuration edit) is propagated to running instances immediately.

Every protocol can still override the distributed value with its own configuration. The protocol-local value always wins; deleting it falls back to the RIB-distributed value. The knobs are deliberately named uniformly:

| Protocol | Default instance | Per-VRF instance |
|---|---|---|
| BGP | `set router bgp global router-id A.B.C.D` | `set router bgp vrf <name> router-id A.B.C.D` |
| OSPFv2 | `set router ospf router-id A.B.C.D` | `set router ospf vrf <name> router-id A.B.C.D` |
| OSPFv3 | `set router ospfv3 router-id A.B.C.D` | `set router ospfv3 vrf <name> router-id A.B.C.D` |
| IS-IS | `set router isis te-router-id A.B.C.D` | `set router isis vrf <name> te-router-id A.B.C.D` |

Notes:

* **BGP** — the knob was previously named `identifier`, following the IETF BGP YANG model; it has been renamed to `router-id` for consistency with every other knob in this table. It sets the BGP Identifier carried in OPEN messages. A per-neighbor `local-identifier` override also exists for individual sessions. A per-VRF BGP instance captures its router-id when it starts (the `vrf` value, falling back to the global one); later RIB updates are not yet applied to running per-VRF BGP instances.
* **OSPFv2/v3** — the Router ID keys the router's LSAs. When neither a protocol-local nor a RIB-distributed value exists, OSPF instances fall back to the constructor default `10.0.0.1`; relying on that default is not recommended, since two routers sharing it can never form an adjacency.
* **IS-IS** — IS-IS does not use an IPv4 router-id for its own identity (the NET supplies the system-id). `te-router-id` sets the stable Traffic Engineering Router ID advertised in TLV 134 and the Router Capability TLV; when it is not configured, the RIB-distributed router-id is advertised instead. Changing it re-originates the LSP immediately. (On a per-VRF instance the value is stored but only goes on the wire once per-VRF segment routing is available, since both TLVs are emitted by the SR machinery.)

In summary, the value a protocol instance actually uses resolves through this chain, with configuration always beating derivation and every delete falling back to the next step:

```
protocol-local router-id
  > VRF router-id            (configured, else derived from VRF members)
  > global router-id         (configured, else derived from interfaces)
  > protocol default         (e.g. 10.0.0.1 for OSPF)
```
