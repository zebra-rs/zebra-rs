@serial
@bgp_evpn_spmsi
Feature: BGP EVPN BUM segmentation — selective S-PMSI (RFC 9572 Type-10), Phase 5
  As a network operator
  I want a source PE to advertise a selective per-(S,G) provider tunnel (Type-10
  S-PMSI) for a snooped multicast flow, and a Regional Border Router to re-root
  that selective tunnel per-region — the selective counterpart of the inclusive
  Per-Region I-PMSI (Type-9) aggregation.

  Test Topology — z1 is a source PE in region A with an IGMP-snooping bridge; a
  snooped (*,239.1.1.1) membership makes it originate a Type-10 S-PMSI. z2 is
  the RBR (region A iBGP / region B eBGP); z3 is a PE in region B.
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                            br0                            │
  └─────────┬─────────────────┬─────────────────┬─────────────┘
       ┌────┴────┐ iBGP  ┌────┴────┐ eBGP  ┌────┴────┐
       │   z1    │───────│   z2    │───────│   z3    │
       │region A │       │   RBR   │       │region B │
       │ VNI 10  │       │a:65001  │       │ AS65002 │
       │ snoop   │       │b:65002  │       │  .0.3   │
       │  .0.1   │       └─────────┘       └─────────┘
       └─────────┘
  ```

  Scenario: Setup topology, EVPN sessions, and z1's snooping bridge
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    # z1's snooping bridge: enslave vxlan10 + a host-facing port for membership.
    And I execute "ip link add br10 type bridge mcast_snooping 1" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: A snooped (*,G) makes z1 originate a selective S-PMSI (Type-10)
    Given the test topology exists
    When I execute "bridge mdb add dev br10 port host0 grp 239.1.1.1 permanent" in namespace "z1"
    # z1 advertises the selective provider tunnel for (*,239.1.1.1), rooted at
    # its own VTEP (192.168.0.1).
    Then show command "show bgp evpn route-type s-pmsi" in namespace "z1" should eventually contain "[10]:[0]:[*]:[239.1.1.1]:[192.168.0.1]"

  Scenario: The RBR re-roots the S-PMSI per-region toward region B
    Given the test topology exists
    # z2 receives z1's S-PMSI and re-originates a selective tunnel rooted at
    # itself (Originator 192.168.0.2).
    Then show command "show bgp evpn route-type s-pmsi" in namespace "z2" should eventually contain "[10]:[0]:[*]:[239.1.1.1]:[192.168.0.1]"
    And show command "show bgp evpn route-type s-pmsi" in namespace "z2" should eventually contain "[10]:[0]:[*]:[239.1.1.1]:[192.168.0.2]"

  Scenario: Region B receives the RBR-rooted selective S-PMSI
    Given the test topology exists
    # z3 learns the selective (*,G) tunnel re-rooted at the RBR (192.168.0.2).
    Then show command "show bgp evpn route-type s-pmsi" in namespace "z3" should eventually contain "[10]:[0]:[*]:[239.1.1.1]:[192.168.0.2]"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
