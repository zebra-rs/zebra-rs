# Static Route

A static route is a type of routing configuration where the network path between
a source and a destination is manually defined by a network administrator.
Unlike dynamic routing protocols, which automatically adjust routes based on
changing network conditions, static routes are manually configured and remain
fixed until the network administrator makes a change.

The key characteristics of static routes are:

1. Manual Configuration: The network administrator manually defines the next-hop
   router or interface to reach a specific destination network. This is done
   through the configuration interface of a router or network device.

2. Fixed Routing: Once configured, the static route does not automatically
   adjust to changes in the network topology. The path remains fixed until the
   administrator updates the static route.

3. Simplicity: Static routes are simple to configure and maintain, making them
   suitable for small, stable networks where the network topology is well-known
   and unlikely to change frequently.

4. Limited Scalability: As the network grows in size and complexity, managing a
   large number of static routes can become cumbersome and error-prone. Dynamic
   routing protocols are better suited for larger, more complex networks.

5. Reliability: Static routes can provide a reliable and predictable routing
   path, as long as the configured next-hop router or interface remains
   available and the network topology does not change.

Suppose you have a small office network with the following setup:

The main office has a router (Router A) with the IP address 192.168.1.1 on the
local network. There is a remote branch office that needs to be accessed from
the main office network. The remote branch office has a router (Router B) with
the IP address 10.0.0.1 on its local network. The network between the main
office and the remote branch office is a wide-area network (WAN) with the IP
subnet 172.16.0.0/24. In this scenario, you would need to configure a static
route on Router A to reach the remote branch office network. The steps would be
as follows:

On Router A, you would configure a static route for the remote branch office
network, which is 10.0.0.0/24. The command to add the static route would be
something like:

``` console
interfaces {
    interface eth0 {
	    ip {
		    address 172.16.0.1/24;
		}
	}
    interface eth1 {
	    ip {
		    address 192.168.1.1/24;
		}
	}
}
routing {
    static {
        route 10.0.0.0/24 {
            nexthop 172.16.0.2;
        }
    }
}
```

ip route 10.0.0.0 255.255.255.0 172.16.0.2

This command tells Router A that to reach the 10.0.0.0/24 network, it should
forward the traffic to the next-hop router at 172.16.0.2, which is the WAN
interface of Router B. On Router B, you would need to configure a static route
for the main office network, 192.168.1.0/24. The command would be:

``` console
interfaces {
    interface eth0 {
	    ip {
		    address 172.16.0.2/24;
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
        route 192.168.0.0/24 {
            nexthop 172.16.0.1;
        }
    }
}
```

This tells Router B that to reach the 192.168.1.0/24 network, it should forward
the traffic to the next-hop router at 172.16.0.1, which is the WAN interface of
Router A. Now, when a device on the main office network (192.168.1.0/24) needs
to communicate with a device on the remote branch office network (10.0.0.0/24),
the traffic will be forwarded to Router A, which will then use the static route
to send the traffic to Router B, and vice versa.

This static route configuration ensures that the two networks can communicate
with each other, even though they are physically separate and connected through
a WAN link. The static routes provide a fixed and predictable path for the
traffic to flow between the two networks.
