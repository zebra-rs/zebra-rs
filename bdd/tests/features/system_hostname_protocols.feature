@system_hostname_protocols
Feature: IS-IS and BGP advertise the system hostname
  As a network operator
  I want `set system hostname <name>` to be the name my router goes by in
  the protocols that carry one, the IS-IS dynamic hostname (TLV 137) and
  the BGP FQDN capability, when I have not given them a hostname of their
  own, so that one line names the router everywhere. They used to
  advertise the operating system's host name instead, whatever the
  configuration said.

  The order is: the protocol's own hostname (`router isis hostname`,
  `router bgp global hostname`), then `system hostname`, then the
  operating system's name. A change reaches IS-IS neighbors at once: the
  LSP is regenerated, not left until its refresh 15 minutes later. A BGP
  session keeps the name its OPEN carried, as with BGP's own hostname.

  Test Topology:
  ```
   z1 ───────────── z2
   i2  10.0.12.0/30  i1
   lo 10.0.0.1/32   lo 10.0.0.2/32
  ```
  Both are level-2-only IS-IS routers on a point-to-point link, with an
  iBGP session over it. z1 is `bdd-sys-one`, z2 is `bdd-sys-two`.

  Scenario: Build two routers that have a system hostname and no protocol hostname
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i2" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I wait 2 seconds
    # z2 is named in a commit of its own, before IS-IS and BGP exist. The
    # config below repeats the name, so its commit does not change it:
    # z2's protocols learn it only from being told when they start.
    And I apply command "set system hostname bdd-sys-two" in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then isis neighbor in namespace "z1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "z2" at level 2 on interface "i1" should be up
    And BGP session in "z1" to "10.0.12.2" should eventually be "Established"
    And BGP session in "z2" to "10.0.12.1" should eventually be "Established"

  Scenario: A neighbor learns the system hostname from the IS-IS LSP
    Given the test topology exists
    Then show command "show isis hostname" in namespace "z2" should eventually contain "bdd-sys-one"
    And show command "show isis hostname" in namespace "z1" should eventually contain "bdd-sys-two"

  Scenario: A neighbor learns the system hostname from the BGP OPEN
    Given the test topology exists
    Then show command "show bgp summary" in namespace "z2" should eventually contain "bdd-sys-one"
    And show command "show bgp summary" in namespace "z1" should eventually contain "bdd-sys-two"

  Scenario: A changed system hostname reaches the IS-IS neighbor at once
    Given the test topology exists
    When I apply command "set system hostname bdd-sys-uno" in namespace "z1"
    # Polled for 30 seconds; the LSP's refresh is 15 minutes away.
    Then show command "show isis hostname" in namespace "z2" should eventually contain "bdd-sys-uno"
    And show command "show isis hostname" in namespace "z2" should eventually not contain "bdd-sys-one"

  Scenario: A BGP session keeps the name of its OPEN and the next OPEN has the new one
    Given the test topology exists
    Then show command "show bgp summary" in namespace "z2" should contain "bdd-sys-one"
    When I run "clear bgp ipv4 neighbor 10.0.12.2" in namespace "z1"
    Then show command "show bgp summary" in namespace "z2" should eventually contain "bdd-sys-uno"

  Scenario: The IS-IS hostname wins over the system hostname
    Given the test topology exists
    When I apply command "set router isis hostname bdd-isis-one" in namespace "z1"
    Then show command "show isis hostname" in namespace "z2" should eventually contain "bdd-isis-one"
    And show command "show isis hostname" in namespace "z2" should eventually not contain "bdd-sys-uno"

  Scenario: Without an IS-IS hostname the system hostname is advertised again
    Given the test topology exists
    When I apply command "delete router isis hostname bdd-isis-one" in namespace "z1"
    Then show command "show isis hostname" in namespace "z2" should eventually contain "bdd-sys-uno"
    And show command "show isis hostname" in namespace "z2" should eventually not contain "bdd-isis-one"

  Scenario: Without a system hostname the neighbor stops seeing it
    Given the test topology exists
    When I apply command "delete system hostname bdd-sys-uno" in namespace "z1"
    # What z1 advertises now is the operating system's name, which this
    # test does not know: it is not the one just deleted.
    Then show command "show isis hostname" in namespace "z2" should eventually not contain "bdd-sys-uno"
    # z2's own name is untouched.
    And show command "show isis hostname" in namespace "z2" should contain "bdd-sys-two"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
