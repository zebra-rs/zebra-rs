@serial
@isis_lan_pseudonode
Feature: IS-IS DIS pseudonode LSP lists every LAN member

  Regression for a DIS pseudonode-LSP bug. On a broadcast LAN the
  Designated IS originates a pseudonode LSP whose TLV 22 must list every
  Up IS adjacency on the circuit (ISO 10589 §7.3.16). We previously
  (re)originated it only on a DIS *status* change, so a router that came
  up after DIS election — while the DIS stayed DIS — was never folded
  into the pseudonode's IS-reach list and was unreachable in every
  speaker's SPF.

  Three L2 routers (a1, a2, a3) share one broadcast LAN (br0), with
  loopbacks 10.0.0.{1,2,3}/32. Whichever wins DIS must list all three in
  its pseudonode LSP; the decisive assertion is that every router has an
  IS-IS route to every other loopback — including the last member to
  converge, which the bug dropped.

  Scenario: every router on the LAN reaches every loopback
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "a1" with IP "192.168.100.1/24" on bridge "br0"
    And I create namespace "a2" with IP "192.168.100.2/24" on bridge "br0"
    And I create namespace "a3" with IP "192.168.100.3/24" on bridge "br0"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I start zebra-rs in namespace "a3"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    And I apply config "a3.yaml" to namespace "a3"
    And I wait 20 seconds
    Then show command "show isis route" in namespace "a1" should eventually contain "10.0.0.2/32"
    And show command "show isis route" in namespace "a1" should eventually contain "10.0.0.3/32"
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.3/32"
    And show command "show isis route" in namespace "a3" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a3" should eventually contain "10.0.0.2/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I stop zebra-rs in namespace "a3"
    And I delete namespace "a1"
    And I delete namespace "a2"
    And I delete namespace "a3"
    And I delete bridge "br0"
    Then the test environment should be clean
