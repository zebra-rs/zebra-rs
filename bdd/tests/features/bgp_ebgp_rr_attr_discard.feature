@serial
@bgp_ebgp_rr_attr_discard
Feature: ORIGINATOR_ID and CLUSTER_LIST received from an eBGP peer are discarded (IPv4)
  As a network operator
  I want ORIGINATOR_ID and CLUSTER_LIST arriving over an eBGP session to
  be discarded on ingest (RFC 7606 §7.9 / §7.10, "attribute discard")
  So that another AS's route-reflection state can neither make my routers
  drop its routes as reflection loops nor be relayed into my AS.

  Both attributes describe reflection inside the AS that set them. Kept
  from an eBGP peer, they are checked against the local router-id — a
  neighbor AS whose reflector happens to share it (private router-ids
  collide easily) gets its routes dropped at the border — and they ride
  along when the border router hands the route to its iBGP peers, where
  a match on any of their router-ids drops the route there. Every real
  router strips both on eBGP egress, so only a scripted speaker can put
  the DUT's ingress on the spot. A malformed instance from an external
  neighbor is discarded too: it must cost neither the route nor the
  session.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │  eBGP   │─eBGP────▶│ AS65050 │────iBGP─▶│ AS65050 │
     │ AS65051 │          │192.168. │          │192.168. │
     │ .44.2/24│          │ 44.1/24 │          │ 44.3/24 │
     └─────────┘          └─────────┘          └─────────┘
  ```
  h1 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
  announces, with next-hop 192.168.44.2 and AS_PATH 65051:
  - 10.44.0.0/24: no reflection attributes (the control);
  - 10.44.1.0/24: ORIGINATOR_ID 192.168.44.1 (z1's router-id);
  - 10.44.2.0/24: CLUSTER_LIST 192.0.2.99 192.168.44.1 (names z1);
  - 10.44.3.0/24: ORIGINATOR_ID 192.168.44.3 (z2's router-id);
  - 10.44.4.0/24: CLUSTER_LIST 192.0.2.99 192.168.44.3 (names z2).
  On the trigger file /tmp/bgp_ebgp_rr_attr_discard.go it announces
  10.44.5.0/24 with a 3-octet ORIGINATOR_ID and 10.44.6.0/24 with a
  5-octet CLUSTER_LIST.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive), iBGP to z2; not a reflector.
  - z2.yaml: iBGP peer of z1.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.44.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.44.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.44.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.44.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.44.1 65051 192.168.44.2 4 192.168.44.2 /tmp/bgp_ebgp_rr_attr_discard 10.44.0.0/24 10.44.1.0/24=80:09:c0a82c01 10.44.2.0/24=80:0a:c0000263c0a82c01 10.44.3.0/24=80:09:c0a82c03 10.44.4.0/24=80:0a:c0000263c0a82c03 -- 10.44.5.0/24=80:09:c0a82c 10.44.6.0/24=80:0a:c0000263c0" in namespace "h1"
    Then BGP session in "z1" to "192.168.44.2" should eventually be "Established"

  Scenario: The control prefix reaches z1 and z2
    Given the test topology exists
    Then show command "show bgp" in namespace "z1" should eventually contain "10.44.0.0/24"
    And show command "show bgp" in namespace "z2" should eventually contain "10.44.0.0/24"

  Scenario: Reflection attributes naming the DUT itself do not cost the route at the border
    Given the test topology exists
    # Pre-fix z1 kept both attributes and its own inbound loop check
    # (ORIGINATOR_ID == router-id, router-id in CLUSTER_LIST) dropped the
    # routes: a neighbor AS's reflection state was judged as z1's own.
    Then show command "show bgp" in namespace "z1" should eventually contain "10.44.1.0/24"
    And show command "show bgp" in namespace "z1" should eventually contain "10.44.2.0/24"
    And BGP route in "z1" has "10.44.1.0/24" with "as_path" value "65051"
    And BGP route in "z1" has "10.44.2.0/24" with "next_hop" value "192.168.44.2"

  Scenario: Reflection attributes from the eBGP peer are not relayed into the AS
    Given the test topology exists
    # Pre-fix z1 relayed the attributes to z2 verbatim, and z2 dropped the
    # routes as reflection loops because they name its router-id.
    Then show command "show bgp" in namespace "z2" should eventually contain "10.44.3.0/24"
    And show command "show bgp" in namespace "z2" should eventually contain "10.44.4.0/24"
    # z1 holds neither attribute on the rows it learned from h1.
    And show command "show bgp 10.44.3.0/24" in namespace "z1" should not contain "Originator"
    And show command "show bgp 10.44.4.0/24" in namespace "z1" should not contain "Cluster list"

  Scenario: A malformed ORIGINATOR_ID or CLUSTER_LIST from the eBGP peer costs neither route nor session
    Given the test topology exists
    When I execute "touch /tmp/bgp_ebgp_rr_attr_discard.go" in namespace "h1"
    # Pre-fix the malformed attribute was a parse error: z1 reset the
    # session and lost every route h1 had announced.
    Then show command "show bgp" in namespace "z1" should eventually contain "10.44.5.0/24"
    And show command "show bgp" in namespace "z1" should eventually contain "10.44.6.0/24"
    And show command "show bgp" in namespace "z2" should eventually contain "10.44.6.0/24"
    And BGP session in "z1" to "192.168.44.2" should be "Established"
    And show command "show bgp" in namespace "z1" should contain "10.44.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_ebgp_rr_attr_discard.go" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
