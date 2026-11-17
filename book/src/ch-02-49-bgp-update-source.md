# update-source (the session's source address)

`update-source` says where a neighbor's TCP session is sourced from.
Without it the kernel picks the source by the route to the neighbor,
which is the address of the outgoing link. A session between loopbacks
needs the loopback's address instead, or the neighbor does not know who
is calling.

It takes an address or the name of an interface:

```
router bgp {
  neighbor 10.255.0.2 {
    remote-as 65001;
    update-source 10.255.0.1;
  }
  neighbor 10.255.0.3 {
    remote-as 65001;
    update-source lo;
  }
}
```

This mirrors FRR's `neighbor PEER update-source <A.B.C.D|X:X::X:X|IFNAME>`.
The IETF spelling `transport local-address` is the same statement.

## By address

The address is bound as it is before the session connects. Its address
family must be the neighbor's: an IPv4 source on an IPv6 neighbor is
refused.

## By interface

An interface name stands for **that interface's address of the
neighbor's address family**. The configuration then names the loopback
and never its address, so renumbering the loopback needs no change to
BGP, and a template can be written before the address is known. SONiC's
`neighbor BGPMON update-source Loopback4096` is this form.

Which address is taken:

- An address of the neighbor's family. An IPv4 neighbor takes an IPv4
  address of the interface, an IPv6 neighbor an IPv6 one.
- Of several, the one that shares the most leading bits with the
  neighbor's address, and the lowest of equals. On an interface in two
  subnets this is the address in the neighbor's subnet.
- For IPv6, a global address the kernel lets a socket bind: never a
  link-local one, nor one that is still tentative or that failed
  duplicate address detection. A deprecated or temporary address is
  taken only when the interface has no other.

The choice follows the interface. It is made again whenever the
interface, or one of its addresses, comes or goes.

- **While the interface gives no address, the neighbor is not dialed.**
  This is so when no interface of that name exists, and when it has no
  usable address of the neighbor's family. The session is never sourced
  from an address the statement did not name. An inbound connection from
  the neighbor is still accepted. The neighbor is dialed as soon as the
  interface gives an address.
- **A session that is up keeps the address it was opened with.** When
  the interface's address changes, the next connect uses the new one. If
  the old address was removed, the session ends by its hold timer, or at
  once with `clear bgp ipv4 neighbor <X>`.

The name must start with a letter. An interface whose name starts with
a digit cannot be named here; this is what keeps a mistyped address
(`10.0.0`) an error instead of the name of an interface that never
appears.

## On a neighbor-group

`update-source` can be set on a
[neighbor-group](ch-02-26-bgp-neighbor-group.md) and is inherited by
every member; a statement on the neighbor itself wins.

An address serves the members of its own address family only. An
interface name serves all of them, each with the interface's address of
its own family:

```
router bgp {
  neighbor-group BGPMON {
    remote-as 65001;
    update-source Loopback4096;
  }
  neighbor 10.0.0.57 {
    neighbor-group BGPMON;
  }
  neighbor fc00::72 {
    neighbor-group BGPMON;
  }
}
```

## In a VRF

A per-VRF neighbor takes the same statement. The interface is then one
of **that VRF**:

```
router bgp {
  vrf vrf-cust {
    rd 65000:1;
    neighbor 10.1.0.2 {
      remote-as 65001;
      update-source ce-lo;
    }
  }
}
```

An interface is looked for in the neighbor's own VRF only: the default
VRF for a neighbor of `router bgp`, VRF `<name>` for a neighbor of
`router bgp vrf <name>`. One that is in another VRF is not found, and
the neighbor is not dialed, as when no interface of that name exists.
When an interface moves into or out of the VRF, the choice is made
again. A name a neighbor inherits from a neighbor-group is read the same
way, by each member in its own VRF.

## Limits

- An interface name is not applied to a neighbor reached over an IPv6
  link-local address, an [`interface-neighbor`](ch-02-27-bgp-unnumbered.md)
  among them. Such a neighbor is sourced from the link it is on.
- Changing `update-source` does not reset a session that is up. Reset it
  with `clear bgp ipv4 neighbor <X>` to apply the change now.

## Related

- [BFD](ch-02-08-bgp-bfd.md) takes the neighbor's source as the local
  address of its session. With an interface name there is no BFD session
  until the interface gives an address.
- [`ip-transparent`](ch-02-29-bgp-ip-transparent.md) lets the source be
  an address the host does not own.
- A single-hop eBGP session between loopbacks also needs
  [`disable-connected-check`](ch-02-16-bgp-disable-connected-check.md).

## Verification

`show bgp neighbor <addr>` names the source. For an interface it also
gives the address that was taken:

```
  Update source is lo (10.255.0.1)
```

or says why the neighbor stays down:

```
  Update source is lo (no usable IPv4 address; neighbor is not dialed)
```

`show bgp neighbor-group <name>` shows the group's statement as it was
written (`Update-source: lo`).
