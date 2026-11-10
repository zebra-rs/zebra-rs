@serial
@dhcp_client
Feature: DHCPv4 client on a WAN interface (interface ipv4 address dhcp)

  `interface <if> ipv4 address dhcp` starts zebra-rs's own DHCP client
  (the dhcpc task, docs/design/dhcp-client.md). Everything the lease gives
  goes through the RIB: the address is a dynamic address with kernel
  lifetimes (`show interface` tags it `dhcp`), and the default route is a
  `D` route at distance 210, installed as `proto dhcp`.

  Topology: s1 is the ISP side, a dnsmasq with one address to lease
  (192.0.2.100, and 192.0.2.101 once it has been renumbered), itself as
  the router, and 198.51.100.1 on its loopback: an address r1 reaches
  only through the default route the lease gives.

      s1 (dnsmasq) srv0 192.0.2.1/24 ──── wan0 (address dhcp) r1 (zebra-rs)
      lo 198.51.100.1/32

  dnsmasq's shortest lease is two minutes, which is what the server uses;
  the expiry scenario waits that long. Requires dnsmasq and nft on the
  host (tests/scripts/dhcp_server.sh).

  Config files:
  - r1.yaml: `address dhcp` on wan0.
  - r1-options.yaml: the same with `dhcp-options default-route-distance
    220` and `host-name edge1`.
  - r1-id3.yaml: the same as r1.yaml with `dhcp-options client-id
    aa:bb:cc:dd:ee:03`.
  - r1-no-default.yaml: the same as r1.yaml with `dhcp-options
    no-default-route`.

  Scenario: Setup the server and a router with a DHCP WAN
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    And I start zebra-rs in namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should contain "DHCP client is not configured or running"
    When I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"

  Scenario: The lease gives the address, the default route and the server's options
    Given the test topology exists
    Then show command "show dhcp client leases" in namespace "r1" should contain "Address:      192.0.2.100/24"
    And show command "show dhcp client leases" in namespace "r1" should contain "Server:       192.0.2.1"
    And show command "show dhcp client leases" in namespace "r1" should contain "DNS servers:  198.51.100.53"
    And show command "show dhcp client leases" in namespace "r1" should contain "Domain:       example.com"
    And show command "show dhcp client leases" in namespace "r1" should contain "0.0.0.0/0 via 192.0.2.1 [210]"
    And show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show interface wan0" in namespace "r1" should contain "dhcp valid-lft"
    And ping from "r1" to "198.51.100.1" should eventually succeed
    And show command "show dhcp client leases interface wan0" in namespace "r1" should contain "State:        bound"
    And show command "show dhcp client leases interface lo" in namespace "r1" should contain "No DHCP client on lo"

  Scenario: Renew by hand keeps the lease
    Given the test topology exists
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing the DHCP lease on wan0"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "renew dhcp interface lo" in namespace "r1" should contain "No DHCP client on lo"
    And ping from "r1" to "198.51.100.1" should succeed

  Scenario: Release withdraws everything until the next renew
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        released"
    And show command "show ip route" in namespace "r1" should eventually not contain "0.0.0.0/0"
    And show command "show interface wan0" in namespace "r1" should eventually not contain "192.0.2."
    And ping from "r1" to "198.51.100.1" should fail
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: A static address beside the lease is refused
    Given the test topology exists
    # An interface is addressed by DHCP or statically, not both (the
    # `must` on the address list). The commit is refused and discarded:
    # nothing of it reaches the running config or the interface, and the
    # lease it would have sat beside is as it was.
    Then applying command "set interface wan0 ipv4 address 192.0.2.5/24" in namespace "r1" should be rejected with "interface wan0 ipv4 address: dhcp cannot be combined with a static address (192.0.2.5/24); delete one or the other"
    And show command "show running-config formal" in namespace "r1" should contain "set interface wan0 ipv4 address dhcp"
    And show command "show running-config formal" in namespace "r1" should not contain "192.0.2.5/24"
    And show command "show interface wan0" in namespace "r1" should not contain "192.0.2.5/24"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        bound"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: With another address ahead of it, the client still talks from the leased address
    Given the test topology exists
    # An address zebra-rs did not configure (one of its own beside
    # `address dhcp` is refused, above) goes in first, so it is the
    # interface's primary address and the lease is a secondary: what the
    # kernel would pick as the source if the client did not name the
    # leased one. The server drops DHCP from any other source.
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released"
    And show command "show interface wan0" in namespace "r1" should eventually not contain "192.0.2.100"
    When I execute "ip addr add 192.0.2.5/24 dev wan0" in namespace "r1"
    Then show command "show interface wan0" in namespace "r1" should eventually contain "inet 192.0.2.5/24"
    When I execute "tests/scripts/dhcp_server.sh dhcp_client require-source 192.0.2.100" in namespace "s1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet 192.0.2.100/24 secondary dhcp"
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And ping from "r1" to "198.51.100.1" should eventually succeed
    # Deleting the primary makes the kernel purge its secondaries, the
    # lease's address among them: the client notices and leases again.
    When I execute "tests/scripts/dhcp_server.sh dhcp_client any-source" in namespace "s1"
    And I execute "ip addr del 192.0.2.5/24 dev wan0" in namespace "r1"
    Then show command "show interface wan0" in namespace "r1" should eventually contain "inet 192.0.2.100/24 dhcp valid-lft"
    And show command "show interface wan0" in namespace "r1" should not contain "192.0.2.5/24"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: A renewal the server refuses ends the lease at once
    Given the test topology exists
    # The server comes back with another address to lease and no memory of
    # the old one: it answers the renewal with a DHCPNAK, and a server
    # broadcasts those.
    When I execute "tests/scripts/dhcp_server.sh dhcp_client stop" in namespace "s1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client start srv0 192.0.2.1/24 192.0.2.101 192.0.2.101 120" in namespace "s1"
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And daemon log in namespace "r1" should eventually contain "refused the lease"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "Address:      192.0.2.101/24"
    And show command "show interface wan0" in namespace "r1" should not contain "192.0.2.100"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: A changed client-id gives the lease back and asks again as the new identity
    Given the test topology exists
    # The server has one address to lease. The new identity gets it only
    # if the lease was released as the identity that took it.
    When I apply command "set interface wan0 ipv4 dhcp-options client-id aa:bb:cc:dd:ee:01" in namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "client-id aa:bb:cc:dd:ee:01); the lease taken under the old one is released"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    When I apply command "set interface wan0 ipv4 dhcp-options client-id aa:bb:cc:dd:ee:02" in namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "client-id aa:bb:cc:dd:ee:02); the lease taken under the old one is released"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: A reboot under another client-id releases the saved lease
    Given the test topology exists
    # As after a host reboot: the lease file is there, the address is not.
    # The RELEASE leaves from that address, so it has to wait until the
    # address is back on the interface. The server has one address, and
    # the new identity gets it only if that RELEASE arrived.
    When I stop zebra-rs in namespace "r1"
    And I execute "ip addr flush dev wan0" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1-id3.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "wan0: the saved lease was taken under another identity; releasing it"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show ip route" in namespace "r1" should eventually contain "D  *> 0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "r1" should not contain "0.0.0.0/0 [0/0]"
    And ping from "r1" to "198.51.100.1" should eventually succeed
    When I apply command "delete interface wan0 ipv4 dhcp-options client-id" in namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "no client-id); the lease taken under the old one is released"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"

  Scenario: A release by hand while a saved lease is being given back leaves the interface released
    Given the test topology exists
    # A reboot under another identity again, with the link down this time:
    # the saved lease waits for the link before it can be released.
    When I stop zebra-rs in namespace "r1"
    And I execute "ip addr flush dev wan0" in namespace "r1"
    And I make namespace "s1" interface "srv0" down
    And I start zebra-rs in namespace "r1"
    And I apply config "r1-id3.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        releasing"
    # The operator wants no lease: the wait ends, and nothing asks for
    # one when the link returns.
    And show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        released"
    When I make namespace "s1" interface "srv0" up
    And I wait 5 seconds
    Then show command "show dhcp client leases" in namespace "r1" should contain "State:        released"
    And show command "show interface wan0" in namespace "r1" should not contain "192.0.2."
    # Until `renew`.
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    When I apply command "delete interface wan0 ipv4 dhcp-options client-id" in namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "no client-id); the lease taken under the old one is released"
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: A restart of zebra-rs resumes the lease
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "wan0: resumed 192.0.2."
    And show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show ip route" in namespace "r1" should eventually contain "D  *> 0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "r1" should not contain "0.0.0.0/0 [0/0]"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: A restart without the default route takes the earlier run's away
    Given the test topology exists
    # The lease's default route outlives the daemon in the kernel. Started
    # again with no-default-route, the client never installs it, so only
    # the route record can tell that `proto dhcp` route is zebra-rs's own
    # leftover, not another program's: the leftover sweep takes it.
    When I stop zebra-rs in namespace "r1"
    Then command "ip route show default" in namespace "r1" should eventually contain "proto dhcp"
    When I start zebra-rs in namespace "r1" sweeping leftovers after 15 seconds
    And I apply config "r1-no-default.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "ip route show default" in namespace "r1" should eventually not contain "proto dhcp"
    And show command "show ip route" in namespace "r1" should eventually not contain "0.0.0.0/0"
    When I apply config "r1.yaml" to namespace "r1"
    Then show command "show ip route" in namespace "r1" should eventually contain "D  *> 0.0.0.0/0 [210/0] via 192.0.2.1, wan0"

  Scenario: dhcp-options change the route's distance and the host name sent
    Given the test topology exists
    When I apply config "r1-options.yaml" to namespace "r1"
    Then show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [220/0] via 192.0.2.1, wan0"
    And show command "show dhcp client leases" in namespace "r1" should contain "0.0.0.0/0 via 192.0.2.1 [220]"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: Deleting address dhcp releases the lease
    Given the test topology exists
    When I apply command "delete interface wan0 ipv4 address dhcp" in namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "wan0: stopped"
    And show command "show ip route" in namespace "r1" should eventually not contain "0.0.0.0/0"
    And show command "show interface wan0" in namespace "r1" should eventually not contain "192.0.2."
    And show command "show dhcp client leases interface wan0" in namespace "r1" should contain "State:        stopped"
    When I apply config "r1-options.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [220/0] via 192.0.2.1, wan0"

  Scenario: A lease the server no longer renews expires
    Given the test topology exists
    Then show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    When I execute "tests/scripts/dhcp_server.sh dhcp_client stop" in namespace "s1"
    And I wait 100 seconds
    Then daemon log in namespace "r1" should eventually contain "wan0: lease expired"
    And show command "show ip route" in namespace "r1" should eventually not contain "0.0.0.0/0"
    And show command "show interface wan0" in namespace "r1" should eventually not contain "192.0.2."
    And show command "show dhcp client leases" in namespace "r1" should contain "State:        selecting"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client stop" in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
