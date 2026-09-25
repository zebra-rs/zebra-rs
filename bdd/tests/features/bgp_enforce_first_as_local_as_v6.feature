@serial
@bgp_enforce_first_as_local_as_v6
Feature: enforce-first-as judges the AS_PATH the neighbor sent, not our local-as prepend (IPv6)
  As a network operator
  I want `enforce-first-as` and `local-as` to work together on one neighbor
  So an AS migration does not silently cost me every route from the
  neighbors I have not migrated yet.

  With a bare `local-as` (no `no-prepend`) zebra-rs prepends the
  substitute AS to every route it receives from that neighbor, so the
  rest of the network still sees the path through the old AS. The
  first-AS check must look at the path as the neighbor sent it — FRR runs
  it before the prepend. zebra-rs ran it after, saw the substitute AS
  left-most, and dropped every route from the neighbor with nothing
  logged. RFC 7606 §7.2 also says a route that fails the check "SHOULD"
  be handled as treat-as-withdraw: the failing UPDATE replaces the
  neighbor's earlier path for the prefix, so that path must go too.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                  br0 2001:db8:47::/64                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   z2    │          │   z1    │          │   h3    │
     │ AS65001 │─eBGP────▶│  (DUT)  │◀────eBGP─│scripted │
     │  ::2    │ local-as │ AS65100 │          │ AS65003 │
     │         │  64999   │  ::1    │          │  ::3    │
     └─────────┘          └─────────┘          └─────────┘
  ```
  z1 runs `enforce-first-as` toward both neighbors. Toward z2, which
  still expects z1's pre-migration AS, it also runs bare `local-as 64999`.
  z2 originates 2001:db8:47:2::/64 with a correct first AS.

  h3 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
  announces 2001:db8:47:3::/64 with AS_PATH "65003". On the trigger file
  /tmp/bgp_enforce_first_as_local_as_v6.go it sends, in one write,
  2001:db8:47:3::/64 again with AS_PATH "65099 65003" (a foreign first AS,
  replacing the valid path) and the control prefix 2001:db8:47:4::/64 with
  "65003". A zebra-rs neighbor cannot produce that UPDATE on its own: a
  live policy change there withdraws the prefix before re-announcing it,
  which hides whether z1 kept the superseded path.

  Config files:
  - z1.yaml: DUT — enforce-first-as toward z2 (with local-as 64999) and
    h3 (passive); IPv6 unicast over IPv6 sessions.
  - z2.yaml: the not-yet-migrated neighbor; originates 2001:db8:47:2::/64.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8:47::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8:47::2/64" on bridge "br0"
    And I create namespace "h3" with IP "2001:db8:47::3/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # z2 only accepts remote-as 64999: Established proves the substitute
    # is active on this session.
    Then BGP session in "z1" to "2001:db8:47::2" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 2001:db8:47::1 65003 192.168.47.3 6 2001:db8:47::3 /tmp/bgp_enforce_first_as_local_as_v6 2001:db8:47:3::/64 -- 2001:db8:47:3::/64@65099,65003 2001:db8:47:4::/64" in namespace "h3"
    Then BGP session in "z1" to "2001:db8:47::3" should eventually be "Established"

  Scenario: The neighbor without local-as passes the check with a correct first AS
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:47:3::/64"
    And BGP route in "z1" has "2001:db8:47:3::/64" with "as_path" value "65003"

  Scenario: The local-as ingress prepend does not trip enforce-first-as
    Given the test topology exists
    # z2 sent "65001"; z1's ingress prepend makes it "64999 65001". Pre-fix
    # the check saw 64999 left-most and dropped the route.
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:47:2::/64"
    And BGP route in "z1" has "2001:db8:47:2::/64" with "as_path" value "64999 65001"

  Scenario: A route that fails the check withdraws the neighbor's earlier path
    Given the test topology exists
    When I execute "touch /tmp/bgp_enforce_first_as_local_as_v6.go" in namespace "h3"
    # The control prefix came in the same write, after the failing UPDATE:
    # once it is in, the failing UPDATE has been processed.
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:47:4::/64"
    # Pre-fix z1 dropped the failing UPDATE and kept the "65003" path h3
    # had just replaced.
    And show command "show bgp ipv6" in namespace "z1" should not contain "2001:db8:47:3::/64"
    And BGP session in "z1" to "2001:db8:47::3" should be "Established"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:47:2::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_enforce_first_as_local_as_v6.go" in namespace "h3"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h3"
    And I delete bridge "br0"
    Then the test environment should be clean
