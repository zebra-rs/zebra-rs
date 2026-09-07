@serial
@bgp_withdraw_packing
Feature: Bulk withdrawals are packed per peer and stay coherent with the Adj-RIB-Out
  Two scripted iBGP clients connect to a zebra-rs route reflector. The source
  announces 1000 routes per family and withdraws them in a burst; the observer
  parses the reflector's raw TCP stream and checks that the withdrawals arrive
  packed into a bounded number of UPDATEs within the negotiated message size,
  with no stale announcement overtaking a withdrawal. It then sends
  announce+withdraw and withdraw+announce back to back and checks the observer
  settles absent / present respectively — a queued withdrawal must neither
  overtake the announcement it races nor outlive a re-advertise. IPv4, IPv6,
  VPNv4, VPNv6 and EVPN are covered at both message limits.

  Scenario: Setup a reflector and two scripted clients
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "h1"
    And I connect namespace "z1" interface "eth0" to namespace "h1" interface "eth0"
    And I execute "ip addr add 192.0.2.1/24 dev eth0" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8::1/64 dev eth0 nodad" in namespace "z1"
    And I execute "ip addr add 192.0.2.2/24 dev eth0" in namespace "h1"
    And I execute "ip addr add 192.0.2.3/24 dev eth0" in namespace "h1"
    And I execute "ip -6 addr add 2001:db8::2/64 dev eth0 nodad" in namespace "h1"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"

  Scenario: Pack withdrawals without extended messages
    Given the test topology exists
    When I execute "timeout 300 python3 tests/scripts/bgp_withdraw_packing.py 4096" in namespace "h1"

  Scenario: Pack withdrawals with extended messages after reconnect
    Given the test topology exists
    When I wait 6 seconds for BGP to operate
    When I execute "timeout 300 python3 tests/scripts/bgp_withdraw_packing.py 65535" in namespace "h1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "h1"
    Then the test environment should be clean
