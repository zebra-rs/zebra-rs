# Recursive Static Route

Recursive static routes are a type of static routing configuration where the
next-hop address is not directly connected to the router, but is instead
resolved through another routing table entry.

The purpose of recursive static routes is to simplify the routing configuration
and provide a more efficient way to reach remote networks. Instead of
configuring a static route for every possible destination, you can use a
recursive static route to reach those destinations through an intermediate
router or gateway.

Let's consider a scenario where a router has a direct connection to a local
network and needs to reach a remote network through an intermediate router.

``` console
interfaces {
    interface eth0 {
	    ip {
		    address 192.168.1.1/24;
		}
	}
    interface eth1 {
	    ip {
		    address 10.0.0.1/24;
		}
	}
}
routing {
    static {
        route 172.16.0.0/0 {
            nexthop 10.0.0.254;
			recursive true;
        }
    }
}
```

In this example:

The router has a direct connection to the local network 192.168.1.0/24 on the
Ethernet0/0 interface. The router needs to reach the remote network
172.16.0.0/16, which is not directly connected. Instead of configuring a static
route for every possible destination within the 172.16.0.0/16 network, a
recursive static route is configured. The recursive static route has a
destination of 172.16.0.0/16 and a next-hop of 10.0.0.254, which is the address
of the intermediate router. When the router receives a packet destined for the
172.16.0.0/16 network, it will first look up the recursive static route. The
router will then use the routing table to determine how to reach the next-hop
address of 10.0.0.254, which is the intermediate router. The packet will then be
forwarded to the intermediate router, which will be responsible for forwarding
the packet to the final destination within the 172.16.0.0/16 network.

This approach simplifies the routing configuration and reduces the number of
static routes that need to be configured on the router. It also allows the
routing table to be more efficient, as the router only needs to maintain a
single entry for the remote network instead of multiple entries.

Recursive static routes can be particularly useful in scenarios where the
network topology is complex, or when the remote networks are subject to frequent
changes. By using recursive static routes, the router can adapt to these changes
without requiring extensive modifications to the routing configuration.
