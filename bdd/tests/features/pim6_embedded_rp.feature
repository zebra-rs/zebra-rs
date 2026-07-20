@serial
@pim6_embedded_rp
Feature: PIMv6 Embedded-RP (RFC 3956) ASM with no RP configuration
  As a network operator
  I want an IPv6 multicast group that embeds its RP address in its own
  bits (RFC 3956, ff70::/12) to run the full ASM control loop with no
  static RP and no BSR — every router derives the same RP straight from
  the group address.

  The group ff7e:240:2001:db8:22::9 embeds RP 2001:db8:22::2 (flags R=P=T,
  RIID 2, prefix length 64, network prefix 2001:db8:22::). r2 owns that
  address and therefore acts as the RP purely by derivation. No router
  carries any `rp static` or `bsr` config.

  Test Topology:
  ```
    h1 (2001:db8:21::10, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(RP=2001:db8:22::2) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (2001:db8:24::10, receiver)
                                       2001:db8:21::1   2001:db8:22::1/.2         2001:db8:23::1/.2         2001:db8:24::1
  ```

  Scenario: The embedded RP is derived and the ASM loop runs
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "h1"
    And I create namespace "h2"
    And I connect namespace "h1" interface "eth0" to namespace "r1" interface "eth1"
    And I connect namespace "r1" interface "eth2" to namespace "r2" interface "eth3"
    And I connect namespace "r2" interface "eth4" to namespace "r3" interface "eth5"
    And I connect namespace "r3" interface "eth6" to namespace "h2" interface "eth7"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I add address "2001:db8:21::10/64" to interface "eth0" in namespace "h1"
    And I add address "2001:db8:24::10/64" to interface "eth7" in namespace "h2"

    # Neighborship on both transit links.
    Then show command "show pim ipv6 neighbor" in namespace "r1" should eventually contain "fe80"
    And show command "show pim ipv6 neighbor" in namespace "r3" should eventually contain "fe80"

    # h2 joins the embedded-RP group: r3 derives RP 2001:db8:22::2 from the
    # group bits and builds the shared tree toward it — no RP config exists.
    When I spawn "timeout 160 python3 tests/scripts/asm_recv6.py ff7e:240:2001:db8:22::9 eth7 5001 /tmp/pim6_erp_rx" in namespace "h2"
    Then show command "show pim ipv6 upstream" in namespace "r3" should eventually contain "(*, ff7e:240:2001:db8:22::9)"
    And show command "show pim ipv6 mroute" in namespace "r2" should eventually contain "(*, ff7e:240:2001:db8:22::9)"

    # h1 sends: r1 (FHR) registers to the derived RP and settles in
    # suppression once the RP has joined the source tree.
    When I spawn "timeout 130 python3 tests/scripts/mcast_send6.py ff7e:240:2001:db8:22::9 5001 eth0 100" in namespace "h1"
    Then show command "show pim ipv6 mroute" in namespace "r2" should eventually contain "2001:db8:21::10"
    And show command "show pim ipv6 upstream" in namespace "r1" should eventually contain "RegPrune"

    # The datapath proof: h1's datagrams reach h2 via the derived-RP tree.
    And command "cat /tmp/pim6_erp_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim6_erp_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
