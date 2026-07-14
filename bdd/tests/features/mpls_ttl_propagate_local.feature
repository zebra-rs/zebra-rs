@mpls_ttl_propagate_local
Feature: MPLS TTL propagate-local — the RFC 3443 forwarded/local split (kernel half)
  As an operator running MPLS with the RFC 3443 TTL model
  I want to choose the label-TTL model for the router's OWN (locally
  originated) traffic independently of forwarded/transit traffic
  So that I can hide the LSP core from customer traceroutes (forwarded
  `pipe`) while still seeing every P router from the PE itself (local
  `uniform`) — the IOS `mpls ip propagate-ttl [forwarded | local]` split.

  Forwarded traffic is imposed by the cradle eBPF data plane (governed by
  `mpls ttl propagate`). Locally-originated traffic is imposed by the host
  kernel's own MPLS stack (the lwtunnel encap routes zebra installs), so the
  local half is the global `net.mpls.ip_ttl_propagate` sysctl. This feature
  validates that config surface end to end in a running daemon: the YANG
  parses, the callback drives the sysctl, and a live change / delete tracks
  it. `net.mpls.ip_ttl_propagate`: 1 = uniform (propagate), 0 = pipe (hide).

  Scenario: propagate-local pipe seeds the kernel MPLS TTL sysctl to 0
    Given a clean test environment
    When I create namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then command "cat /proc/sys/net/mpls/ip_ttl_propagate" in namespace "r1" should eventually contain "0"

  Scenario: Flipping to uniform live restores propagation (sysctl 1)
    Given the test topology exists
    When I apply command "set mpls ttl propagate-local uniform" in namespace "r1"
    Then command "cat /proc/sys/net/mpls/ip_ttl_propagate" in namespace "r1" should eventually contain "1"

  Scenario: Deleting the leaf restores the uniform default (sysctl 1)
    Given the test topology exists
    When I apply command "set mpls ttl propagate-local pipe" in namespace "r1"
    Then command "cat /proc/sys/net/mpls/ip_ttl_propagate" in namespace "r1" should eventually contain "0"
    When I apply command "delete mpls ttl propagate-local pipe" in namespace "r1"
    Then command "cat /proc/sys/net/mpls/ip_ttl_propagate" in namespace "r1" should eventually contain "1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I delete namespace "r1"
    Then the test environment should be clean
