## Separation of Reachability Information and Forwarding Decision

Since the wide spread of SD-WAN services, there has been an increase in use
cases that cannot be handled by traditional routing based solely on destination
addresses. In the case of Hybrid WAN, there are often multiple upstream WAN
routes, and decisions must be made on which upstream route to use based on the
quality of the connections. In traditional routing, even if multiple upstream
routes are available, it is difficult to operate in an Active-Active manner as
in Hybrid WAN. At best, one WAN route could be selected based on metrics.

Furthermore, many advanced SD-WAN services allow you to choose the next hop
based on traffic from specific services, such as Office 365 or Zoom, or to
configure a primary/backup setup.

Traditionally, when BGP was used for routing control, if there were multiple
next hops for the same destination, the BGP path selection mechanism would
choose one next hop, which would then be registered in the FIB (Forwarding
Information Base). All next hops received via BGP contain reachable information,
but which one to use, that is, the forwarding decision, was made within BGP
itself.

``` console
*> 10.0.0.0/8 192.168.0.1 Primary
   10.0.0.0/8 192.168.0.2
   10.0.0.0/8 192.168.0.3
```

However, this method does not work well to meet SD-WAN use cases. All next hops
obtained via BGP must be registered in the FIB, and the final decision of which
next hop to use needs to be made within the forwarder. Thanks to [BGP
AddPath](https://datatracker.ietf.org/doc/html/rfc7911), we can now suppress
path selection in BGP, allowing BGP to focus only on reachability information
and deferring the forwarding decision. If all next hops are registered in the
FIB, it might look like this:

``` console
*> 10.0.0.0/8 192.168.0.1 Primary
*> 10.0.0.0/8 192.168.0.2 Secondary
*> 10.0.0.0/8 192.168.0.3 Office 365/Zoom
```

[BGP Community Attribute](https://datatracker.ietf.org/doc/html/rfc1997) allows
us to add additional information to routes, which could be used to assist in
forwarding decisions, such as determining primary/secondary paths based on the
values of the community attribute.

When registering route information from BGP into the RIB (Routing Information
Base), if part of the BGP attribute is exported, the RIB/FIB might look like
this:

``` console
*> 10.0.0.0/8 192.168.0.1 [PathId 1][Community 100:100] Primary
*> 10.0.0.0/8 192.168.0.2 [PathId 2][Community 100:90]  Secondary
*> 10.0.0.0/8 192.168.0.3 [PathId 3]                    Office 365/Zoom
```

To support such use cases, Zebra has implemented a rich export function from
various routing protocols to the RIB/FIB.
