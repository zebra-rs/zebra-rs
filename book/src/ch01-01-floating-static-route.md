# Floating Static Route

Floating static routes, also known as backup static routes, are a type of static
routing configuration that provides an alternative path for network traffic in
the event of a primary route failure. These routes are considered "floating"
because they have a higher administrative distance than the primary route, which
means they are only used when the primary route becomes unavailable.

The purpose of floating static routes is to provide redundancy and improve
network reliability. When the primary route becomes unavailable, the floating
static route is used as a backup, ensuring that network traffic can still reach
its destination.

Let's consider a scenario where a router has two uplink interfaces, one
connected to an Internet Service Provider (ISP) and the other connected to a
backup ISP. The primary route to the internet is through the primary ISP, while
the floating static route is configured to use the backup ISP.

``` console
interface
 ip address 192.168.1.1 255.255.255.0
interface Ethernet0/1
 ip address 10.0.0.1 255.255.255.0

ip route 0.0.0.0 0.0.0.0 192.168.1.254 100
ip route 0.0.0.0 0.0.0.0 10.0.0.254 200
```

The primary route to the internet is configured with a destination of 0.0.0.0/0
(default route) and a next-hop of 192.168.1.254, which is the gateway to the
primary ISP. This route has an administrative distance of 100. The floating
static route is also configured with a destination of 0.0.0.0/0 (default route)
and a next-hop of 10.0.0.254, which is the gateway to the backup ISP. This route
has an administrative distance of 200. The administrative distance of the
floating static route (200) is higher than the administrative distance of the
primary route (100). This means that the primary route will be preferred and
used for forwarding network traffic as long as it is available.

If the primary route becomes unavailable (e.g., the link to the primary ISP
fails), the router will automatically start using the floating static route with
the higher administrative distance (200) as the backup path to the internet.
This ensures that network connectivity is maintained, even in the event of a
primary route failure.

It's important to note that the administrative distance can be adjusted based on
the specific requirements of your network. A lower administrative distance
indicates a preferred route, while a higher administrative distance indicates a
less preferred route.
