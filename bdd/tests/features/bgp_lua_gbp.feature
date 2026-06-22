@serial
@bgp_lua_gbp
Feature: BGP EVPN Group-Based Policy via Lua scripting
  As a network operator
  I want zebra-rs to carry a Group-Based Policy tag on EVPN Type-2 routes
  and enforce it in the dataplane, driven entirely by embedded Lua hooks,
  so the FRR-scripting "GBP over EVPN" demo runs end to end without any
  blocking I/O on the route path.

  Two iBGP (AS 65001) EVPN speakers on a shared transport bridge br0, each
  with a local VXLAN (VNI 10) enslaved to a per-node bridge br10:
  ```
  ┌───────────────────────────────────────────┐
  │                    br0                     │
  └───────────┬───────────────────┬───────────┘
         ┌────┴────┐         ┌────┴────┐
         │   z1    │         │   z2    │
         │ .0.1/24 │         │ .0.2/24 │
         │  br10   │         │  br10   │
         │ vxlan10 │         │ vxlan10 │
         │  host0  │ <- MAC  │ gbp_filter (nft)
         └─────────┘         └─────────┘
  ```

  Flow: z1 learns local MAC aa:bb:cc:dd:ee:01 and originates an EVPN
  Type-2 route. z1's egress Lua hook looks the MAC up in the `sgt` map
  (-> tag 100) and stamps a Group-Policy-ID extended community. z2's
  import Lua hook recovers the tag and runs `nft add element` to put the
  MAC in set `tag_100`; the withdraw hook removes it. The scripts are the
  shipped /etc/zebra-rs/lua/gbp-example.lua.

  Scenario: Setup topology, EVPN iBGP, GBP scripts, and the enforcement table
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    # Enslave each node's config-created vxlan10 to a learning bridge so a
    # local MAC maps to VNI 10 and originates a Type-2 route.
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    # z2's GBP enforcement table: the import hook adds set elements here.
    And I execute "nft add table bridge gbp_filter" in namespace "z2"
    And I execute "nft add set bridge gbp_filter tag_100 { type ether_addr ; }" in namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: A local MAC makes z1 originate a Type-2 route z2 receives
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"

  Scenario: z2's import hook programs the GBP tag set from the GPI community
    Given the test topology exists
    # The MAC reaches set tag_100 only if z1's egress hook stamped the GPI
    # ext-community (MAC -> tag 100) AND z2's import hook parsed it and ran
    # the nft side-effect — the full receive path.
    Then command "nft list set bridge gbp_filter tag_100" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"

  Scenario: Withdrawing the MAC tears the GBP set element down
    Given the test topology exists
    When I execute "bridge fdb del aa:bb:cc:dd:ee:01 dev host0 master" in namespace "z1"
    # The route leaves z2's Loc-RIB; the withdraw hook reads the stored
    # GPI tag and removes the set element (the half FRR cannot do).
    And I wait 3 seconds
    Then command "nft list set bridge gbp_filter tag_100" in namespace "z2" should not contain "aa:bb:cc:dd:ee:01"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
