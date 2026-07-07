@serial
@bgp_network_origin_shard_pet
Feature: BGP IPv4 network origination is advertised under shards + peer-task

  Repro for a reported bug: a speaker with the RIB sharded
  (router bgp sharding rib-sharding 4) AND per-peer egress tasks (router bgp sharding peer-sharding true)
  configured with IPv4 network statements never advertises those networks to
  its neighbor.

  Key fact: IPv4-unicast AFI/SAFI is enabled by DEFAULT on every neighbor,
  even one whose transport address is IPv6 (it is only off when explicitly
  set "afi-safi ipv4 enabled false"). So the iBGP neighbor below — peered over
  an IPv6 transport with the ipv6 family also enabled — negotiates
  IPv4-unicast too and MUST receive the originated IPv4 networks (IPv4 NLRI
  with an IPv4 next-hop carried over the IPv6 session).

  z1 is the device under test, configured exactly like the report: AS 65501,
  shards 4 + peer-task true, originating 0.0.0.0/0 and 5.5.5.0/24, with one
  iBGP neighbor z2 over IPv6.

  Test Topology:
  ```
  z1 (AS65501)  ---- iBGP over IPv6 ----  z2 (AS65501)
  2001:db8::1/64                          2001:db8::8/64
  shards 4 + peer-task
  originates 0.0.0.0/0, 5.5.5.0/24
  ```
  Both on bridge br0.

  Scenario: the speaker and its iBGP neighbor establish over IPv6
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::8/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 15 seconds for BGP to operate
    Then the zebra-rs log in namespace "z1" should contain "BGP RIB sharding: 4 shards (from config)"
    And BGP session in "z1" to "2001:db8::8" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"

  Scenario: z1 originates the IPv4 networks into its own Loc-RIB
    Given the test topology exists
    # Isolates origination from advertisement: route_add must put the
    # network statements into z1's v4 Loc-RIB (the main-shard mirror at N>1),
    # so `show bgp ipv4` on z1 itself lists them. If this fails the bug is in
    # origination; if it passes but the next scenario fails, the bug is in the
    # egress to the peer.
    Then show command "show bgp ipv4" in namespace "z1" should contain "5.5.5.0/24"
    And show command "show bgp ipv4" in namespace "z1" should contain "0.0.0.0/0"

  Scenario: z2 receives the originated IPv4 networks (the reported bug)
    Given the test topology exists
    # The neighbor negotiated IPv4-unicast by default, so z1 must advertise
    # both originated networks to it. They land in z2's v4 Loc-RIB, so
    # `show bgp ipv4` on z2 lists them. This is the assertion the report says
    # fails under shards + peer-task.
    Then show command "show bgp ipv4" in namespace "z2" should eventually contain "5.5.5.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "0.0.0.0/0"

  Scenario: dropping a network statement withdraws it from the neighbor (route_del at N>1)
    Given the test topology exists
    # z1 re-applies its config without 5.5.5.0/24 (keeping 0.0.0.0/0). The
    # config diff calls route_del, which at N>1 retracts the prefix through
    # the pool (OriginateV4 withdraw) so the reduce withdraws it. z2 must lose
    # 5.5.5.0/24 while keeping 0.0.0.0/0 (the positive control proving the
    # withdraw is targeted, not a full session drop).
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z2" should not contain "5.5.5.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "0.0.0.0/0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
