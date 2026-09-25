@serial
@bgp_med_knobs
Feature: router bgp bestpath always-compare-med and med missing-as-worst (IPv4)
  As a network operator
  I want to choose how MED takes part in best-path selection — compared
  across neighboring ASes or not, and a missing MED read as best or worst
  So I can match the MED semantics of the rest of my network, and have a
  change take effect on the routes I already hold.

  By default MED is compared only between paths from the same neighboring
  AS (RFC 4271 §9.1.2.2 (c)) and a missing MED counts as 0, the best
  value. `router bgp bestpath always-compare-med true` compares MED
  between any two paths; `router bgp bestpath med missing-as-worst true`
  reads a missing MED as the worst value. Changing either re-runs best-path
  selection for the routes already held, so the change is visible at once.

  Test Topology:
  ```
    ┌──────────────────────────────────────────────────────────┐
    │                   br0 192.168.56.0/24                    │
    └─────┬───────────┬───────────┬───────────┬───────────┬────┘
     ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐
     │   h1   │  │   h2   │  │   h3   │  │   z1   │  │   z2   │
     │AS65081 │  │AS65082 │  │AS65081 │  │ (DUT)  │  │AS65090 │
     │   .2   │  │   .3   │  │   .4   │  │AS65001 │  │   .5   │
     │        │  │        │  │        │  │   .1   │  │        │
     └────────┘  └────────┘  └────────┘  └────────┘  └────────┘
  ```
  h1, h2 and h3 run tests/scripts/bgp_attr_inject_send.py; their BGP
  Identifiers order h1 < h2 < h3, and every path has the same AS_PATH
  length. Each path carries its own community, which z2 shows:
  - 10.56.1.0/24 from h1 (MED 10, community 65081:1) and from h2 (MED 5,
    community 65082:2);
  - 10.56.2.0/24 from h1 (no MED, community 65081:11) and from h3 (MED 5,
    community 65081:13).

  - 10.56.1.0/24: h1 and h2 are in different ASes, so by default MED is
    skipped and h1 wins on BGP Identifier; always-compare-med hands it to
    h2 (MED 5 < 10).
  - 10.56.2.0/24: h1 and h3 share an AS; h1's missing MED reads as 0 and
    wins by default; missing-as-worst hands it to h3.

  Config files:
  - z1.yaml: DUT — eBGP to h1, h2, h3 (passive) and to z2; no MED knobs.
  - z2.yaml: z1's downstream eBGP neighbor.

  Scenario: Setup topology and the three speakers
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.56.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.56.2/24" on bridge "br0"
    And I create namespace "h2" with IP "192.168.56.3/24" on bridge "br0"
    And I create namespace "h3" with IP "192.168.56.4/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.56.5/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.56.5" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.56.1 65081 192.168.56.2 4 192.168.56.2 /tmp/bgp_med_knobs_h1 10.56.1.0/24=80:04:0000000a+c0:08:fe390001 10.56.2.0/24=c0:08:fe39000b" in namespace "h1"
    And I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.56.1 65082 192.168.56.3 4 192.168.56.3 /tmp/bgp_med_knobs_h2 10.56.1.0/24=80:04:00000005+c0:08:fe3a0002" in namespace "h2"
    And I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.56.1 65081 192.168.56.4 4 192.168.56.4 /tmp/bgp_med_knobs_h3 10.56.2.0/24=80:04:00000005+c0:08:fe39000d" in namespace "h3"
    Then show command "show bgp 10.56.1.0/24" in namespace "z1" should eventually contain "Paths: (2 available)"
    And show command "show bgp 10.56.2.0/24" in namespace "z1" should eventually contain "Paths: (2 available)"

  Scenario: By default MED is skipped across ASes and a missing MED is best
    Given the test topology exists
    Then show command "show bgp 10.56.1.0/24" in namespace "z2" should eventually contain "Community: 65081:1"
    And show command "show bgp 10.56.2.0/24" in namespace "z2" should eventually contain "Community: 65081:11"

  Scenario: always-compare-med compares MED across neighboring ASes, at once
    Given the test topology exists
    When I apply command "set router bgp bestpath always-compare-med true" in namespace "z1"
    Then show command "show bgp 10.56.1.0/24" in namespace "z2" should eventually contain "Community: 65082:2"
    # h1's missing MED is 0, which still beats h3's 5.
    And show command "show bgp 10.56.2.0/24" in namespace "z2" should contain "Community: 65081:11"

  Scenario: med missing-as-worst makes a path without MED lose, at once
    Given the test topology exists
    When I apply command "set router bgp bestpath med missing-as-worst true" in namespace "z1"
    Then show command "show bgp 10.56.2.0/24" in namespace "z2" should eventually contain "Community: 65081:13"
    And show command "show bgp 10.56.1.0/24" in namespace "z2" should contain "Community: 65082:2"

  Scenario: Deleting the knobs restores the defaults, at once
    Given the test topology exists
    When I apply command "delete router bgp bestpath always-compare-med true" in namespace "z1"
    Then show command "show bgp 10.56.1.0/24" in namespace "z2" should eventually contain "Community: 65081:1"
    # Same AS: missing-as-worst still decides 10.56.2.0/24.
    And show command "show bgp 10.56.2.0/24" in namespace "z2" should contain "Community: 65081:13"
    When I apply command "delete router bgp bestpath med missing-as-worst true" in namespace "z1"
    Then show command "show bgp 10.56.2.0/24" in namespace "z2" should eventually contain "Community: 65081:11"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "h3"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
