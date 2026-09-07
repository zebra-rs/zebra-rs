@serial
@bgp_ebgp_local_pref_ignore
Feature: LOCAL_PREF received from an eBGP peer is silently ignored
  As a network operator
  I want a LOCAL_PREF attribute arriving over an eBGP session to be
  discarded on ingest (RFC 4271 §5.1.5, RFC 7606 §7.6)
  So that an external neighbor — buggy or hostile — cannot steer my AS's
  best-path selection, and the bogus value is never relayed to my iBGP
  peers.

  RFC 4271 §5.1.5: "A BGP speaker MUST NOT include this attribute in
  UPDATE messages it sends to external peers ... If it is contained in an
  UPDATE message that is received from an external peer, then this
  attribute MUST be ignored by the receiving speaker." Because every real
  router strips LOCAL_PREF on eBGP egress, only a scripted speaker can put
  the DUT's ingress on the spot.

  Three consequences of honoring the attribute are pinned, each in its own
  scenario so the failure names the broken half:
  - the Loc-RIB row carries the foreign LOCAL_PREF (visible in `show bgp`);
  - best-path selection is steered: the eBGP path with LOCAL_PREF 500 beats
    an iBGP path (default 100) that has the shorter AS_PATH, and the FIB
    follows it;
  - the value is relayed AS-wide: z1 re-advertises the route to its iBGP
    peer with LOCAL_PREF 500 instead of the default 100.

  Silently ignored also means the session survives the UPDATE and the
  routes themselves are accepted with their other attributes intact.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │  eBGP   │─eBGP────▶│ AS65030 │◀────iBGP─│ AS65030 │
     │ AS65031 │          │192.168. │          │192.168. │
     │ .40.2/24│          │ 40.1/24 │          │ 40.3/24 │
     └─────────┘          └─────────┘          └─────────┘
  ```

  h1 runs tests/scripts/bgp_ebgp_local_pref_send.py: it announces
  10.98.0.0/24 and 10.99.0.0/24 with next-hop 192.168.40.2, AS_PATH 65031
  and LOCAL_PREF 500, then acts on trigger files, each consumed when it
  fires: /tmp/bgp_ebgp_local_pref_ignore.announce and .withdraw.

  z2 originates 10.99.0.0/24 (`network`), so z1 holds two candidates for
  it: iBGP from z2 (LOCAL_PREF 100 by default, empty AS_PATH) and eBGP
  from h1 (bogus LOCAL_PREF 500, AS_PATH 65031). 10.98.0.0/24 comes from
  h1 only and is relayed to z2.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive), iBGP to z2.
  - z2.yaml: iBGP peer of z1; originates 10.99.0.0/24.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.40.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.40.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.40.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.40.3" should eventually be "Established"
    And show command "show bgp" in namespace "z1" should eventually contain "10.99.0.0/24"
    When I spawn "timeout 600 python3 tests/scripts/bgp_ebgp_local_pref_send.py 192.168.40.1 65031 192.168.40.2 192.168.40.2 500 /tmp/bgp_ebgp_local_pref_ignore 10.98.0.0/24 10.99.0.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.40.2" should eventually be "Established"

  Scenario: The UPDATE is accepted with its other attributes and the session stays up
    Given the test topology exists
    Then show command "show bgp" in namespace "z1" should eventually contain "10.98.0.0/24"
    And BGP route in "z1" has "10.98.0.0/24" with "as_path" value "65031"
    And BGP route in "z1" has "10.98.0.0/24" with "next_hop" value "192.168.40.2"
    And kernel route "10.98.0.0/24" in namespace "z1" should eventually contain "192.168.40.2"
    And BGP session in "z1" to "192.168.40.2" should be "Established"

  Scenario: The eBGP-received LOCAL_PREF is not stored on the Loc-RIB row
    Given the test topology exists
    Then show command "show bgp" in namespace "z1" should eventually contain "10.98.0.0/24"
    And BGP route in "z1" has "10.98.0.0/24" without "local_pref"
    And show command "show bgp ipv4 10.98.0.0/24" in namespace "z1" should eventually contain "BGP routing table entry for 10.98.0.0/24"
    And show command "show bgp ipv4 10.98.0.0/24" in namespace "z1" should not contain "localpref 500"

  Scenario: Best-path selection is not steered by the eBGP LOCAL_PREF
    Given the test topology exists
    # Both candidates present: z2's iBGP origination (next-hop .40.3) and
    # h1's eBGP path (next-hop .40.2). Equal LOCAL_PREF (100 by default)
    # hands the decision to AS_PATH length, and z2's empty path wins.
    Then show command "show bgp" in namespace "z1" should eventually contain "192.168.40.3"
    And show command "show bgp" in namespace "z1" should eventually contain "192.168.40.2"
    And BGP best path in "z1" for "10.99.0.0/24" has next-hop "192.168.40.3"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "192.168.40.3"

  Scenario: The bogus LOCAL_PREF is not relayed to the iBGP peer
    Given the test topology exists
    Then show command "show bgp" in namespace "z2" should eventually contain "10.98.0.0/24"
    And BGP route in "z2" has "10.98.0.0/24" with "as_path" value "65031"
    # z1 stamps the default toward its iBGP peer (RFC 4271 §5.1.5), so z2
    # sees 100 — not the 500 h1 injected.
    And BGP route in "z2" has "10.98.0.0/24" with "local_pref" value "100"

  Scenario: Withdrawing the eBGP routes leaves only z2's origination
    Given the test topology exists
    When I execute "touch /tmp/bgp_ebgp_local_pref_ignore.withdraw" in namespace "h1"
    Then show command "show bgp" in namespace "z1" should eventually not contain "10.98.0.0/24"
    And show command "show bgp" in namespace "z2" should eventually not contain "10.98.0.0/24"
    And BGP best path in "z1" for "10.99.0.0/24" has next-hop "192.168.40.3"
    And BGP session in "z1" to "192.168.40.2" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_ebgp_local_pref_ignore.announce /tmp/bgp_ebgp_local_pref_ignore.withdraw" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
