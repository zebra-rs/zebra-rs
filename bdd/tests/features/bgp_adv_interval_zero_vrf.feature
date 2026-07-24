@serial
@bgp_adv_interval_zero_vrf
Feature: Per-VRF BGP neighbor zero adv-interval delivers ipv4/ipv6 unicast
  As an operator of an L3VPN PE
  I want `router bgp vrf <name> neighbor <ce> timers advertisement-interval 0`
  to disable the MRAI for a per-VRF CE neighbor
  So that PE-CE ipv4/ipv6 unicast converges without waiting out the stock
  MRAI — the instance-level `router bgp timer adv-interval` never reaches
  the per-VRF task, so the per-neighbor knob is the only lever.

  Regression guard for wiring the per-neighbor `advertisement-interval`
  into the update-group signature (`adv_interval_override`) and arming
  path: with 0 the per-VRF ipv4/ipv6-unicast advertise debounce arms a
  ~1 ms next-tick timer instead of the stock 30s eBGP one. The CE side
  uses the same knob as a plain global neighbor, so both directions are
  covered.

  Test Topology (2 namespaces, point-to-point, dual-stack):
  ```
   ce1 ───────────────── pe1
   AS 65001            AS 65000
   global              vrf-cust (RD 65000:1)
   lo 10.0.1.1/32      net 10.9.0.0/24
      2001:db8:8::1/128    2001:db8:9::/64
        .2 ── .1   (10.1.0.0/30)
        ::2 ── ::1 (2001:db8:1::/64)
   adv-interval 0      adv-interval 0 (per VRF neighbor)
  ```

  Config files:
  - pe1.yaml: AS 65000, vrf-cust with two CE neighbors (10.1.0.2 ipv4,
    2001:db8:1::2 ipv6), each `timers advertisement-interval 0`. Originates
    vrf-cust networks 10.9.0.0/24 and 2001:db8:9::/64.
  - ce1.yaml: AS 65001, global neighbors to the PE (ipv4 + ipv6), each
    `timers advertisement-interval 0`, redistributing connected loopbacks.

  Scenario: Build the PE-CE dual-stack topology and establish sessions
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    Then show command "show bgp vrf" in namespace "pe1" should eventually contain "vrf-cust"
    And BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce1" to "2001:db8:1::1" should eventually be "Established"

  Scenario: PE advertises its vrf-cust ipv4 network to the CE with adv-interval 0
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "ce1" should eventually contain "10.9.0.0/24"

  Scenario: PE advertises its vrf-cust ipv6 network to the CE with adv-interval 0
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "ce1" should eventually contain "2001:db8:9::/64"

  Scenario: CE advertises its ipv4/ipv6 loopbacks to the PE vrf with adv-interval 0
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.1/32"
    And show command "show bgp vrf vrf-cust ipv6" in namespace "pe1" should eventually contain "2001:db8:8::1/128"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    Then the test environment should be clean
