@serial
@bgp_mup_runtime_enable
Feature: BGP MUP capability (re)negotiates when enabled on a live session
  An AFI/SAFI is a BGP Multiprotocol *capability*, advertised once in the
  OPEN — the negotiated set is fixed for the life of the session. So
  enabling `afi-safi mobile-uplane` (RFC 9833, which turns on BOTH IPv4-MUP
  and IPv6-MUP) on an already-Established neighbor has no effect until the
  session renegotiates. zebra-rs therefore bounces the session on the
  change — the same teardown `clear bgp ... hard` uses — so the new MUP
  capability is advertised and received without an operator clear.

  This regressed silently before: the config was recorded but the live
  session was never bounced, so `show bgp neighbor` kept showing the old
  capability set (no MUP).

  Test Topology:
  ```
   z1 (AS65001, 192.168.0.1) ── br0 ── z2 (AS65001, 192.168.0.2)
   both start IPv4-unicast only; mobile-uplane is enabled at runtime.
  ```

  Scenario: Enabling mobile-uplane at runtime renegotiates the MUP capability
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    # Not configured yet: the OPEN carried no MUP capability.
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "IPv4 MUP"
    # Enable mobile-uplane on BOTH live sessions; each change bounces its
    # session so the capability is renegotiated on reconnect.
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi mobile-uplane enabled true" in namespace "z1"
    And I apply command "set router bgp neighbor 192.168.0.1 afi-safi mobile-uplane enabled true" in namespace "z2"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv4 MUP: advertised and received"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv6 MUP: advertised and received"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "IPv4 MUP: advertised and received"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "IPv6 MUP: advertised and received"
    # The new `show bgp mobile-uplane summary` lists the MUP-capable neighbor.
    And show command "show bgp mobile-uplane summary" in namespace "z1" should contain "IPv4 MUP Summary"
    And show command "show bgp mobile-uplane summary" in namespace "z1" should contain "192.168.0.2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
