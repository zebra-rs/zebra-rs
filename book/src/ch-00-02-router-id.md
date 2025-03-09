# Selection of the Router-ID

In many routing protocols, such as OSPF and BGP, the router-id is used to uniquely identify each router. Although it is recommended to configure the router-id manually, if not set, the router automatically selects one from the available interfaces.

For example, in the widely referenced Cisco IOS implementation, if one or more Loopback interfaces have IP addresses configured, the router selects the highest IP address among all Loopback interfaces. If none of the Loopback interfaces have an IP address configured, then among the IP addresses on the other interfaces that are in the Up state, the highest one is chosen.

In Cisco IOS-XE, if one or more Loopback interfaces have IP addresses configured, the selection process is the same as in IOS. However, when considering physical interfaces, the router examines all such interfaces and chooses the one with the highest IP address, regardless of whether the interface is up or down. Notably, if after a reboot the physical interface with the highest IP address is in the Down state, the device does not select that interface’s IP address as the router-id; instead, it selects the IP address of the first physical interface that becomes operational.

In Juniper’s JunOS, if one or more Loopback interfaces have IP addresses configured, the router selects the smallest IP address among them. If no Loopback interface has an IP address configured, then among all physical interfaces, the smallest IP address is chosen as the router-id.

It is important to note that Cisco and Juniper differ in that one selects the highest IP address while the other selects the lowest.

To avoid confusion among operators who are familiar with existing router implementations, this implementation follows these rules:

1. If one or more Loopback interfaces have an IP address configured, the highest among them is selected.
2. If not, then if one or more physical interfaces have an IP address configured, the highest among them is selected regardless of the interface's state.
3. Otherwise, the router-id remains unset.
