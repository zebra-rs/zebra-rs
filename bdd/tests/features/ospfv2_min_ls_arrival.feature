@serial
@ospfv2_min_ls_arrival
Feature: OSPFv2 MinLSArrival received-LSA rate limit is configurable
  As a network operator
  I want `router ospf min-ls-arrival` to set the receive-side rate
  limit (RFC 2328 §13 MinLSArrival, FRR `timers lsa min-arrival`) —
  a flooded LSA instance arriving less than that after the last
  accepted copy is discarded without acknowledgement — so I can tune
  it away from the fixed 1 s default while the topology still
  converges.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)
    both routers set min-ls-arrival 2000 ms.
  ```

  Scenario: Configured MinLSArrival is applied and the topology still converges
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 20 seconds

    # The configured (non-default) MinLSArrival is surfaced verbatim by
    # `show ospf`, proving the config reached the instance.
    Then show command "show ospf" in namespace "a" should contain "MinLSArrival (received-LSA rate limit): 2000 ms"
    # Adjacency forms and routes converge under the configured limit.
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
