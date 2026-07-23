@serial
@bgp_vrf_neighbor_as_path
Feature: Per-VRF BGP neighbor AS-path knobs (allowas-in, as-override, remove-private-as)
  As an operator of an L3VPN PE
  I want the AS-path manipulation knobs under `router bgp vrf <name>
  neighbor <addr>` to take effect on the per-VRF CE session
  So that allowas-in, as-override, and remove-private-as behave on a CE
  neighbor exactly as on a global neighbor — applied on the per-VRF
  receive / advertise path, not silently dropped.

  One scenario per knob, each on its own CE neighbor:
   * CE1 (AS 65001) — allowas-in. CE1 prepends PE1's own AS 65000 onto
     10.0.1.9/32, so it reaches PE1 with 65000 in the path; only
     allowas-in lets PE1 accept it into the VRF Loc-RIB.
   * CE2 (AS 65001, shared with CE1) — as-override. PE1 rewrites CE1's
     65001 to 65000 on egress toward CE2, so CE2 accepts CE1's
     10.0.1.1/32 (path "65000 65000") instead of dropping its own AS.
   * CE3 (AS 65003) — remove-private-as. The private 65001 is stripped on
     egress toward CE3, so CE3 sees 10.0.1.1/32 with path "65000" only.

  Test Topology (4 namespaces, all CE links in vrf-cust):
  ```
   ce2 (65001)
        \
   ce1 ── pe1 (65000, vrf-cust) ── ce3 (65003)
  (65001)
  ```

  Scenario: Build the AS-path VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I create namespace "ce3"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I connect namespace "pe1" interface "ce3" to namespace "ce3" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I start zebra-rs in namespace "ce3"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I apply config "ce3.yaml" to namespace "ce3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce2" to "10.2.0.1" should eventually be "Established"
    And BGP session in "ce3" to "10.3.0.1" should eventually be "Established"

  Scenario: allowas-in accepts a CE route carrying the PE's own AS
    # CE1 prepends 65000 (PE1's AS) onto 10.0.1.9/32, so it arrives as
    # "65000 65001". The RFC 4271 loop check would drop it; allowas-in on
    # the CE1 neighbor permits it into the VRF Loc-RIB. (The un-prepended
    # 10.0.1.1/32 lands regardless — it is the sanity control.)
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.1/32"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.9/32"

  Scenario: as-override rewrites the shared AS so CE2 accepts the route
    # CE2 is AS 65001, same as CE1. Without as-override the route arrives
    # as "65000 65001" and CE2 drops its own AS; as-override rewrites it to
    # "65000 65000", which CE2 accepts.
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce2" should eventually contain "10.0.1.1/32"
    And show command "show bgp 10.0.1.1/32" in namespace "ce2" should contain "65000 65000"

  Scenario: remove-private-as strips the private AS toward CE3
    # PE1 learns 10.0.1.1/32 with path "65001" (private). On egress toward
    # CE3 the private AS is stripped, so CE3 sees path "65000" only.
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce3" should eventually contain "65000"
    And show command "show bgp 10.0.1.1/32" in namespace "ce3" should not contain "65001"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "ce3"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    And I delete namespace "ce3"
    Then the test environment should be clean
