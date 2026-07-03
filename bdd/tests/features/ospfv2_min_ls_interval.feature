@serial
@ospfv2_min_ls_interval
Feature: OSPFv2 MinLSInterval self-LSA re-origination throttle
  As a network operator
  I want `router ospf min-ls-interval` to bound how often the router
  re-originates the same self-LSA (RFC 2328 §12.4 MinLSInterval, FRR
  `timers throttle lsa all`), so a burst of topology changes coalesces
  into one Router-LSA / Network-LSA update instead of a storm — while
  a stable topology still converges.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)
    both routers set min-ls-interval 1500 ms.
  ```

  Scenario: Configured MinLSInterval is applied and the topology still converges
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 20 seconds

    # The configured (non-default) MinLSInterval is surfaced verbatim by
    # `show ospf`, proving the config reached the instance.
    Then show command "show ospf" in namespace "a" should contain "MinLSInterval (self-LSA re-origination): 1500 ms"
    # Adjacency forms and routes converge under the throttle.
    And show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And show command "show ospf route" in namespace "a" should contain "10.0.0.2/32"
    And ping from "a" to "10.0.0.2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
