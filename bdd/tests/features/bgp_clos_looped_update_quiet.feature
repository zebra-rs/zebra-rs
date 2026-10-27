@serial
@bgp_clos_looped_update_quiet
Feature: A looped UPDATE in a Clos leaves the spines' routes alone
  As a network operator running a Clos whose spines share one AS
  I want a leaf's looped copy of another leaf's route to change nothing
  So the spines and leaves do not reinstall and re-send unchanged routes.

  Every leaf route a spine sends to leaf L1 comes back from L1 toward
  the other spine with the spines' AS in the AS_PATH. That spine treats
  it as a withdraw (RFC 4271 §9.1.2), but it never accepted a path for
  the prefix from L1, so nothing is removed and nothing should change.
  Before #2599 the spine went on anyway: it reinstalled its unchanged
  best in the kernel and re-sent it to its peers, L1 re-sent its own
  best to the spine again, and the next looped UPDATE started it over.
  With the advertisement interval at 0 that was a continuous loop: the
  spines deleted and re-added the leaf loopbacks in the kernel over and
  over, and dropped packets while they did.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.61.0/24                      │
  └─────┬──────────────┬────────────────┬──────────────┬─────────┘
   ┌────┴────┐    ┌────┴────┐      ┌────┴────┐    ┌────┴────┐
   │   s1    │    │   s2    │      │   l1    │    │   l2    │
   │ spine   │    │ spine   │      │  leaf   │    │  leaf   │
   │ AS65000 │    │ AS65000 │      │ AS65011 │    │ AS65012 │
   │  .1     │    │  .2     │      │  .11    │    │  .12    │
   └─────────┘    └─────────┘      └─────────┘    └─────────┘
  ```
  Each leaf has an eBGP session to each spine; the spines do not peer
  with each other, nor the leaves. l1 originates 10.61.0.11/32 and l2
  10.61.0.12/32. Every node runs the eBGP advertisement interval at 0,
  so a re-send loop would run flat out rather than once per MRAI.

  Config files:
  - s1.yaml, s2.yaml: the spines, AS 65000.
  - l1.yaml, l2.yaml: the leaves, ECMP over both spines.

  tests/scripts/route_churn_count.py watches `ip -o monitor route` in a
  namespace for a few seconds and prints `CHURN <n>` if the prefix
  changed in the kernel, `quiet` otherwise.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "s1" with IP "192.168.61.1/24" on bridge "br0"
    And I create namespace "s2" with IP "192.168.61.2/24" on bridge "br0"
    And I create namespace "l1" with IP "192.168.61.11/24" on bridge "br0"
    And I create namespace "l2" with IP "192.168.61.12/24" on bridge "br0"
    And I start zebra-rs in namespace "s1"
    And I start zebra-rs in namespace "s2"
    And I start zebra-rs in namespace "l1"
    And I start zebra-rs in namespace "l2"
    And I apply config "s1.yaml" to namespace "s1"
    And I apply config "s2.yaml" to namespace "s2"
    And I apply config "l1.yaml" to namespace "l1"
    And I apply config "l2.yaml" to namespace "l2"
    Then BGP session in "s1" to "192.168.61.11" should eventually be "Established"
    And BGP session in "s1" to "192.168.61.12" should eventually be "Established"
    And BGP session in "s2" to "192.168.61.11" should eventually be "Established"
    And BGP session in "s2" to "192.168.61.12" should eventually be "Established"

  Scenario: Every leaf loopback reaches both spines and the other leaf
    Given the test topology exists
    Then kernel route "10.61.0.11" in namespace "s1" should eventually contain "proto bgp"
    And kernel route "10.61.0.12" in namespace "s1" should eventually contain "proto bgp"
    And kernel route "10.61.0.11" in namespace "s2" should eventually contain "proto bgp"
    And kernel route "10.61.0.12" in namespace "s2" should eventually contain "proto bgp"
    And kernel route "10.61.0.12" in namespace "l1" should eventually contain "proto bgp"
    And kernel route "10.61.0.11" in namespace "l2" should eventually contain "proto bgp"

  Scenario: After convergence the kernel routes stay put
    Given the test topology exists
    When I wait 3 seconds
    # Pre-fix each spine reinstalled the other leaf's loopback on every
    # looped UPDATE: thousands of delete/add events in this window.
    Then command "python3 tests/scripts/route_churn_count.py 6 10.61.0.12" in namespace "s1" should not contain "CHURN"
    And command "python3 tests/scripts/route_churn_count.py 6 10.61.0.12" in namespace "s2" should not contain "CHURN"
    And command "python3 tests/scripts/route_churn_count.py 6 10.61.0.11" in namespace "s1" should not contain "CHURN"
    And command "python3 tests/scripts/route_churn_count.py 6 10.61.0.11" in namespace "s2" should not contain "CHURN"
    And command "python3 tests/scripts/route_churn_count.py 6 10.61.0.12" in namespace "l1" should not contain "CHURN"
    And command "python3 tests/scripts/route_churn_count.py 6 10.61.0.11" in namespace "l2" should not contain "CHURN"
    # Still converged after the window.
    And kernel route "10.61.0.12" in namespace "s1" should eventually contain "proto bgp"
    And kernel route "10.61.0.11" in namespace "s2" should eventually contain "proto bgp"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "s1"
    And I stop zebra-rs in namespace "s2"
    And I stop zebra-rs in namespace "l1"
    And I stop zebra-rs in namespace "l2"
    And I delete namespace "s1"
    And I delete namespace "s2"
    And I delete namespace "l1"
    And I delete namespace "l2"
    And I delete bridge "br0"
    Then the test environment should be clean
