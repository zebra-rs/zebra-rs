@serial
@ospfv2_spf_interval
Feature: OSPFv2 adaptive SPF throttle (spf-interval)
  As a network operator
  I want `router ospf spf-interval { initial-wait; secondary-wait;
  maximum-wait; }` to configure the IOS-XR-style exponential SPF
  hold-down (RFC-style backoff, mirroring zebra-rs IS-IS) instead of
  the old fixed 1-second coalescing timer, so a churning area backs
  off while a quiet topology still converges quickly.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)
    both routers configure spf-interval 100 / 300 / 4000 ms.
  ```

  Scenario: Configured throttle is applied and the topology still converges
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 20 seconds

    # The configured (non-default) throttle bounds are surfaced verbatim
    # by `show ospf`, proving the config reached the instance.
    Then show command "show ospf" in namespace "a" should contain "SPF timers: initial 100 ms, secondary 300 ms, maximum 4000 ms"
    # Adjacency forms and routes converge under the adaptive scheduler.
    And show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And show command "show ospf route" in namespace "a" should contain "10.0.0.2/32"
    And ping from "a" to "10.0.0.2" should succeed

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
