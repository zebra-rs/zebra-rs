@serial
@bgp_local_as
Feature: BGP local-as presents a substitute AS to one neighbor (AS migration)
  As a network operator
  I want `neighbor X local-as ASN [no-prepend] [replace-as] [dual-as]`
  So a router migrated to a new global AS keeps its sessions with peers
  that still expect the old AS, and each peer migrates on its own schedule.

  Test Topology (z1 migrated to AS 65100; z2 still expects the old AS 64999):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │
   │ AS65100 │                  │ AS65001 │
   │  .0.1   │   local-as       │  .0.2   │
   └─────────┘   64999 →        └─────────┘
  ```

  z1's global AS is 65100 but z2's `remote-as` names the pre-migration
  AS 64999 — only z1's `local-as 64999` lets the session establish: the
  OPEN carries 64999, outbound routes are prepended "64999 65100"
  (`replace-as` hides the real AS → "64999"), and inbound routes from
  z2 get 64999 prepended at ingress (`no-prepend` turns that off).
  `dual-as` closes the migration: once z2 flips its remote-as to 65100,
  one Bad Peer AS round trip makes z1's next OPEN present the global
  AS. z2 is passive throughout so z1 always dials — the dual-as
  retry exchange stays a single deterministic connection stream.

  Config files:
  - z1-base.yaml:      z1 with bare `local-as 64999`, originates 10.0.0.1/32
  - z1-replace.yaml:   z1 with `local-as 64999 replace-as true`
  - z1-noprepend.yaml: z1 with `local-as 64999 no-prepend true`
  - z1-dualas.yaml:    z1 with `local-as 64999 dual-as true`
  - z2.yaml:           z2 expecting remote-as 64999 (passive), originates 10.0.0.2/32
  - z2-globalas.yaml:  z2 migrated to remote-as 65100 (passive)

  Scenario: Setup topology — the session establishes under the substitute AS
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    # z2 only accepts remote-as 64999, so Established proves the OPEN
    # carried the substitute, not z1's global AS 65100.
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Bare form prepends the substitute on both directions
    Given the test topology exists
    # Egress: z2 sees the substitute stacked over the real AS.
    Then BGP route in "z2" has "10.0.0.1/32" with "as_path" value "64999 65100"
    # Ingress: z1 prepends the substitute to routes received from z2,
    # so the rest of the network still sees the path through the old
    # AS. One occurrence is within the loop-check budget — the route
    # must be accepted.
    And BGP route in "z1" has "10.0.0.2/32" with "as_path" value "64999 65001"
    And show command "show bgp neighbors" in namespace "z1" should contain "Local AS substitution: local-as 64999"

  Scenario: replace-as hides the real AS on egress
    Given the test topology exists
    When I apply config "z1-replace.yaml" to namespace "z1"
    # The modifier doesn't bounce the session; clear it so both
    # directions re-exchange under the new policy.
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP route in "z2" has "10.0.0.1/32" with "as_path" value "64999"
    # Ingress is unaffected by replace-as.
    And BGP route in "z1" has "10.0.0.2/32" with "as_path" value "64999 65001"

  Scenario: no-prepend leaves inbound routes untouched
    Given the test topology exists
    When I apply config "z1-noprepend.yaml" to namespace "z1"
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    # Ingress: no substitute prepend — z2's path arrives as sent.
    And BGP route in "z1" has "10.0.0.2/32" with "as_path" value "65001"
    # Egress went back to the bare two-AS form (apply-replace removed
    # replace-as together with setting no-prepend).
    And BGP route in "z2" has "10.0.0.1/32" with "as_path" value "64999 65100"

  Scenario: dual-as re-establishes under the global AS after the peer migrates
    Given the test topology exists
    When I apply config "z1-dualas.yaml" to namespace "z1"
    # z2 migrates: its remote-as flips to z1's real global AS. z1's
    # next OPEN still carries 64999, draws a Bad Peer AS NOTIFICATION,
    # and the dual-as fallback flips the following OPEN to 65100.
    And I apply config "z2-globalas.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    # The post-notification redial can park on conservative timers;
    # clear restarts the dial immediately with the toggled AS.
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    # With the substitute inactive the session behaves unconfigured:
    # normal real-AS prepend on egress, no ingress prepend.
    And BGP route in "z2" has "10.0.0.1/32" with "as_path" value "65100"
    And BGP route in "z1" has "10.0.0.2/32" with "as_path" value "65001"
    And show command "show bgp neighbors" in namespace "z1" should contain "dual-as fallback active"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only the daemons and namespaces need
  # teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
