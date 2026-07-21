@serial
@bgp_mp_reach_ipv4
Feature: BGP IPv4 unicast carried in MP_REACH_NLRI / MP_UNREACH_NLRI
  As a network operator
  I want IPv4 unicast encoded in the RFC 4760 multiprotocol attributes
  (AFI=1/SAFI=1 — reachability in MP_REACH_NLRI §3 with the next-hop inside
  the attribute, withdrawals in MP_UNREACH_NLRI §4) to be treated
  identically to the traditional NLRI and Withdrawn Routes fields, because
  RFC 4760 senders such as xk6-bgp encode it that way while zebra-rs, FRR
  and GoBGP use the traditional fields — so only a scripted speaker can
  produce these shapes.

  Both directions were broken, and both failure modes are covered here:
  - MP_REACH (fixed by PR #2045): the UPDATE was accepted without error but
    had no effect — no Loc-RIB entry, no FIB install, no re-advertisement,
    no log line.
  - MP_UNREACH: AFI=1/SAFI=1 had no arm in the parser at all, so the whole
    UPDATE failed to parse. That error is not on the RFC 7606 recoverable
    lists, so the peer reader **tore the session down** — a sender that
    announced via MP_REACH reset the session on its first withdrawal.

  The scripted speaker also sends a decoy NEXT_HOP attribute; per RFC 4760
  the next-hop inside MP_REACH supersedes it, which the next-hop assertions
  pin down.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │ RFC4760 │─eBGP────▶│ AS65030 │◀────eBGP─│ AS65032 │
     │ AS65031 │          │192.168. │          │192.168. │
     │ .30.2/24│          │ 30.1/24 │          │ 30.3/24 │
     └─────────┘          └─────────┘          └─────────┘
  ```

  h1 runs tests/scripts/bgp_mp_reach_send.py: it announces 10.99.0.0/24
  inside MP_REACH_NLRI (next-hop 192.168.30.2, decoy NEXT_HOP attribute
  192.168.30.99) and then acts on trigger files, each consumed when it
  fires so re-touching re-triggers:
  /tmp/bgp_mp_reach_ipv4.announce, .withdraw_traditional, .withdraw_mp.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.30.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.30.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.30.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.30.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_mp_reach_send.py 192.168.30.1 65031 192.168.30.2 10.99.0.0/24 192.168.30.2 192.168.30.99 /tmp/bgp_mp_reach_ipv4" in namespace "h1"
    Then BGP session in "z1" to "192.168.30.2" should eventually be "Established"

  Scenario: MP_REACH-encoded IPv4 unicast enters the Loc-RIB with the MP_REACH next-hop
    Given the test topology exists
    Then show command "show bgp" in namespace "z1" should eventually contain "10.99.0.0/24"
    And BGP route in "z1" has "10.99.0.0/24" with "next_hop" value "192.168.30.2"
    And BGP route in "z1" has "10.99.0.0/24" with "as_path" value "65031"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "192.168.30.2"

  Scenario: The MP_REACH-learned route is re-advertised to a traditional peer
    Given the test topology exists
    Then show command "show bgp" in namespace "z2" should eventually contain "10.99.0.0/24"
    And BGP route in "z2" has "10.99.0.0/24" with "next_hop" value "192.168.30.1"
    And BGP route in "z2" has "10.99.0.0/24" with "as_path" value "65030 65031"

  # The session assertion is the real regression gate: an unparsable
  # MP_UNREACH does not just fail to withdraw, it resets the session.
  Scenario: An MP_UNREACH withdraw removes the route without resetting the session
    Given the test topology exists
    When I execute "touch /tmp/bgp_mp_reach_ipv4.withdraw_mp" in namespace "h1"
    Then show command "show bgp" in namespace "z1" should eventually not contain "10.99.0.0/24"
    And show command "show bgp" in namespace "z2" should eventually not contain "10.99.0.0/24"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually be gone
    And BGP session in "z1" to "192.168.30.2" should be "Established"

  Scenario: A traditional withdraw also removes the MP_REACH-announced route
    Given the test topology exists
    When I execute "touch /tmp/bgp_mp_reach_ipv4.announce" in namespace "h1"
    Then show command "show bgp" in namespace "z1" should eventually contain "10.99.0.0/24"
    When I execute "touch /tmp/bgp_mp_reach_ipv4.withdraw_traditional" in namespace "h1"
    Then show command "show bgp" in namespace "z1" should eventually not contain "10.99.0.0/24"
    And show command "show bgp" in namespace "z2" should eventually not contain "10.99.0.0/24"
    And BGP session in "z1" to "192.168.30.2" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_mp_reach_ipv4.announce /tmp/bgp_mp_reach_ipv4.withdraw_traditional /tmp/bgp_mp_reach_ipv4.withdraw_mp" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
