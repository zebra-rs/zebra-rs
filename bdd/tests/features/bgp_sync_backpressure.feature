@serial
@bgp_sync_backpressure
Feature: BGP IPv4 sync cursor egress backpressure — park + resume (Tier 1b)

  z2 originates 16384 IPv4-unicast routes and runs the resumable cursor
  with a low egress watermark and a slowed egress writer
  (ZEBRA_BGP_WRITER_DELAY_MS — a slow peer simulated at the app layer).
  When the late peer z3 establishes, z2's session-up dump outruns the
  slow writer: the pending-UPDATE queue grows past the watermark and the
  cursor PARKS, then resumes as the writer drains. Pins that the park
  engages (log) and the slowed dump still converges (z3 gets the routes)
  — the proof Tier 1b works.

  Test Topology:
  ```
  z2 (AS65002, cursor, slow egress writer) ── z3 (AS65003) late peer
   16384 routes, sync chunk 500, egress high 4, writer delay 20ms
  ```

  Scenario: z2 comes up with the large RIB and a slowed egress writer
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z2" with sync chunk 500 egress high 4 writer delay 20
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate

  Scenario: late peer z3 triggers a slowed dump; the cursor parks then converges
    Given the test topology exists
    When I start zebra-rs in namespace "z3"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.3" should be "Established"
    And daemon log in namespace "z2" should eventually contain "v4 sync parked"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.0.0.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.63.255.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
