@serial
@isis_hello_auth_keychain
@isis
Feature: IS-IS Hello authentication via an RFC 8177 key-chain
  As a network operator
  I want to authenticate IS-IS Hello (IIH) PDUs on a point-to-point link
  by referencing a named key-chain (RFC 8177) instead of an inline
  password, and confirm that two zebra-rs routers sharing the same chain
  form a Level-1 adjacency and exchange dual-stack routes.

  When an interface's `hello-authentication` carries a `key-chain` leaf
  (and no inline `password`), the chain's active key is self-describing:
  it supplies the algorithm (from `crypto-algorithm`), the RFC 5310 Key
  ID, and the key material at both sign and verify time, so no `auth-type`
  leaf is needed. Both ends must define the same chain name with an
  identical key (key-id, crypto-algorithm, key-string) or the IIHs fail
  to verify and the adjacency never forms — so a formed adjacency is
  itself proof that keychain-based Hello auth round-trips correctly.

  Test Topology:
  ```
    z1 --10-- z2     point-to-point veth (10.0.1.0/30, 2001:db8:1::/64)

    loopbacks: z1 -> 10.0.0.1/32  2001:db8:0:ffff::1/128
               z2 -> 10.0.0.2/32  2001:db8:0:ffff::2/128
  ```

  Both routers are is-type level-1 in area 49.0001. On z1 the interface
  toward z2 is "i2"; on z2 the interface toward z1 is "i1". Each carries
  `hello-authentication { key-chain ISIS-HELLO }`, where ISIS-HELLO has a
  single hmac-sha-256 key (key-id 1, key-string "zebra-isis-hello-secret").

  Config files:
  - z1.yaml: z1 with the ISIS-HELLO chain (hmac-sha-256, key-id 1, key-string "zebra-isis-hello-secret").
  - z2.yaml: z2 with the same chain -- matches z1, so the adjacency forms.
  - z2-badkey.yaml: z2 with the chain re-keyed to a value z1 does not share (same name/key-id/algorithm), used to prove a key mismatch tears the adjacency down.

  Scenario: Keychain-authenticated IIH brings up the L1 adjacency
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i2" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds
    # IIHs are signed and verified through the ISIS-HELLO chain on both
    # ends, so the adjacency reaches Up. The peer is rendered by its
    # dynamic hostname, which only resolves once the peer's LSP was
    # received — proving the adjacency formed and the LSDB synced over
    # the authenticated link.
    Then show command "show isis neighbor" in namespace "z1" should contain "z2"
    And show command "show isis neighbor" in namespace "z2" should contain "z1"
    And show command "show isis neighbor" in namespace "z1" should contain "Up"
    # Directly-connected reachability over the authenticated link, dual-stack.
    And ping from "z1" to "10.0.1.2" should succeed
    And ping from "z1" to "2001:db8:1::2" should succeed
    # Loopbacks learned via IS-IS across the authenticated adjacency.
    And show command "show isis route" in namespace "z1" should contain "10.0.0.2/32"
    And show command "show isis route" in namespace "z2" should contain "10.0.0.1/32"
    And ping from "z1" to "10.0.0.2" should succeed
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    And ping from "z2" to "10.0.0.1" should succeed

  Scenario: A mismatched chain key tears the adjacency down
    Given the test topology exists
    # Re-key only z2's ISIS-HELLO chain to a secret z1 doesn't share.
    # z2's IIHs now carry a digest z1 can't verify, and z2 rejects z1's
    # IIHs in turn -- so neither side refreshes the other's hold timer.
    When I apply config "z2-badkey.yaml" to namespace "z2"
    # Wait out the ~30s hold-time (hello-interval 3s x multiplier 10) plus
    # a margin for the SPF recompute and RIB withdrawal that follow.
    And I wait 40 seconds
    # The L1 adjacency expired on both ends. A dropped neighbor is removed
    # from the table, so the peer hostname is gone from each side.
    Then show command "show isis neighbor" in namespace "z1" should not contain "z2"
    And show command "show isis neighbor" in namespace "z2" should not contain "z1"
    # Forwarding over the now-unauthenticated link is broken: the
    # IS-IS-learned loopback is withdrawn and no longer reachable.
    And show command "show isis route" in namespace "z1" should not contain "10.0.0.2/32"
    And ping from "z1" to "10.0.0.2" should fail
    # The link itself is fine -- the directly-connected address still
    # answers, proving it's the adjacency (not the wire) that went away.
    And ping from "z1" to "10.0.1.2" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
