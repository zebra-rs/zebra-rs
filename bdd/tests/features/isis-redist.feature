@serial
@isis_redist
@isis
Feature: IS-IS redistribution of static routes into a Level-1 area
  As a network operator
  I want a border router to redistribute a static route into IS-IS so a
  prefix that lives outside the IS-IS domain (on a host that runs no
  IS-IS) is flooded across the whole Level-1 area, installed into every
  router's RIB as an external reachability, reconverges onto a backup
  path when the primary link drops, and disappears again the moment the
  redistribution is withdrawn.

  All links are point-to-point veth pairs (network-type point-to-point)
  and every "rN" router is is-type level-1 in area 49.0001. The two
  edge hosts e1 and e2 do NOT run IS-IS — they are plain hosts wired to
  the area by a single link and a static default route.

  Test Topology:
  ```
    +----+      +----+      +----+      +----+      +----+
    | e1 |--10--| r1 |--10--| r2 |--10--| r3 |--10--| e2 |
    +----+      +----+      +----+      +----+      +----+
                   \                     /
                   10                  10
                     \                 /
                    +----+   10    +----+
                    | r4 |---------| r5 |
                    +----+         +----+

    loopbacks:  rI -> 10.0.0.I/32     e1 -> 10.1.1.1/32   e2 -> 10.2.2.2/32
    edges:      e1-r1 10.1.0.0/30     r3-e2 10.2.0.0/30
    spine:      r1-r2 10.0.12.0/30    r2-r3 10.0.23.0/30
    backup:     r1-r4 10.0.14.0/30    r4-r5 10.0.45.0/30   r5-r3 10.0.35.0/30
  ```

  There are two equal-metric-per-hop paths between r1 and r3: the short
  top spine r1—r2—r3 (cost 20) and the longer bottom path
  r1—r4—r5—r3 (cost 30). The top spine is the primary; the bottom path
  is the backup the redistributed route falls onto when r1—r2 drops.

  On router rI the interface toward rJ is named "iJ"; the interface
  toward edge host eN is "ieN", and eN's interface toward its router is
  "irK". e1's loopback 10.1.1.1/32 can only enter IS-IS via
  redistribution: r1's edge link "ie1" carries an address but is not an
  IS-IS interface. r3's edge link "ie2", by contrast, IS an IS-IS
  interface so the 10.2.0.0/30 edge subnet is advertised — that gives
  r1 a route back to e2's source address for the e2 -> e1 reply path.

  Scenario: Build the topology and form IS-IS Level-1 adjacencies
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "r4"
    And I create namespace "r5"
    And I create namespace "e1"
    And I create namespace "e2"
    And I connect namespace "e1" interface "ir1" to namespace "r1" interface "ie1"
    And I connect namespace "r1" interface "i2" to namespace "r2" interface "i1"
    And I connect namespace "r2" interface "i3" to namespace "r3" interface "i2"
    And I connect namespace "r3" interface "ie2" to namespace "e2" interface "ir3"
    And I connect namespace "r1" interface "i4" to namespace "r4" interface "i1"
    And I connect namespace "r4" interface "i5" to namespace "r5" interface "i4"
    And I connect namespace "r5" interface "i3" to namespace "r3" interface "i5"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "r4"
    And I start zebra-rs in namespace "r5"
    And I start zebra-rs in namespace "e1"
    And I start zebra-rs in namespace "e2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "r4.yaml" to namespace "r4"
    And I apply config "r5.yaml" to namespace "r5"
    And I apply config "e1.yaml" to namespace "e1"
    And I apply config "e2.yaml" to namespace "e2"
    And I wait 20 seconds
    # Edge links are up and addressed: e1 reaches r1's edge address and
    # e2 reaches r3's edge address (neither edge host speaks IS-IS).
    Then ping from "e1" to "10.1.0.1" should succeed
    And ping from "e2" to "10.2.0.1" should succeed
    # Both the primary spine and the backup path formed adjacencies. A
    # peer renders by dynamic hostname only when its LSP was accepted,
    # so this also proves the LSDB is exchanged on both paths.
    And show command "show isis neighbor" in namespace "r1" should contain "r2"
    And show command "show isis neighbor" in namespace "r1" should contain "r4"
    And show command "show isis neighbor" in namespace "r3" should contain "r2"
    And show command "show isis neighbor" in namespace "r3" should contain "r5"
    And show command "show isis neighbor" in namespace "r4" should contain "r5"

  Scenario: r1 redistributes e1's loopback into IS-IS and it floods across the area
    Given the test topology exists
    # The redistributed prefix is an external IP reachability originated
    # by r1; every other router runs SPF against it and installs it. Its
    # presence in `show isis route` proves the per-level SPF picked it
    # up; in `show ip route` proves it reached the central RIB.
    Then show command "show isis route" in namespace "r2" should contain "10.1.1.1/32"
    And show command "show isis route" in namespace "r3" should contain "10.1.1.1/32"
    And show command "show isis route" in namespace "r5" should contain "10.1.1.1/32"
    And show command "show ip route" in namespace "r3" should contain "10.1.1.1/32"
    And show command "show ip route" in namespace "r4" should contain "10.1.1.1/32"
    # Data plane: every IS-IS router can reach e1's loopback. The reply
    # returns to e1 via its static default route to r1, and r1 forwards
    # back over the IS-IS-learned transit links.
    And ping from "r2" to "10.1.1.1" should succeed
    And ping from "r3" to "10.1.1.1" should succeed
    And ping from "r4" to "10.1.1.1" should succeed
    And ping from "r5" to "10.1.1.1" should succeed

  Scenario: e2 reaches e1 end-to-end across the IS-IS domain
    Given the test topology exists
    # e2 runs no IS-IS — it only has a static default route to r3. It
    # still reaches e1's loopback because r3 learned 10.1.1.1/32 from
    # the redistribution and r1 learned e2's edge subnet (10.2.0.0/30)
    # from r3's IS-IS interface, so both directions resolve.
    Then ping from "e2" to "10.1.1.1" should succeed
    # e2 also reaches the interior IS-IS loopbacks the same way.
    And ping from "e2" to "10.0.0.1" should succeed
    And ping from "e2" to "10.0.0.5" should succeed

  Scenario: The redistributed route reconverges onto the backup path
    Given the test topology exists
    # Baseline: e2 -> e1 works over the primary spine r1—r2—r3.
    Then ping from "e2" to "10.1.1.1" should succeed
    # Drop the r1—r2 link. The only remaining path between r1 and r3 is
    # the backup r1—r4—r5—r3, so the redistributed route must reconverge
    # out r1's other interface.
    When I make namespace "r1" interface "i2" down
    And I wait 10 seconds
    Then show command "show isis route" in namespace "r3" should contain "10.1.1.1/32"
    And ping from "e2" to "10.1.1.1" should succeed
    # Restore the primary spine; the route stays reachable.
    When I make namespace "r1" interface "i2" up
    And I wait 15 seconds
    Then ping from "e2" to "10.1.1.1" should succeed

  Scenario: Withdrawing redistribution removes e1's loopback from the area
    Given the test topology exists
    # Re-apply r1 with the `redistribute static` block removed (the
    # static route to e1 stays). The config diff deletes the
    # redistribution, so r1 re-originates its LSP without the external
    # reachability and the area withdraws 10.1.1.1/32.
    When I apply config "r1-noredist.yaml" to namespace "r1"
    And I wait 10 seconds
    Then show command "show isis route" in namespace "r3" should not contain "10.1.1.1/32"
    And show command "show ip route" in namespace "r3" should not contain "10.1.1.1/32"
    And ping from "e2" to "10.1.1.1" should fail
    # r1 still has the local static route, so e1's loopback is reachable
    # from r1 itself — only the IS-IS advertisement was withdrawn.
    And ping from "r1" to "10.1.1.1" should succeed
    # Re-enable redistribution; the area relearns the prefix and
    # end-to-end reachability returns.
    When I apply config "r1.yaml" to namespace "r1"
    And I wait 10 seconds
    Then show command "show isis route" in namespace "r3" should contain "10.1.1.1/32"
    And ping from "e2" to "10.1.1.1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I stop zebra-rs in namespace "r4"
    And I stop zebra-rs in namespace "r5"
    And I stop zebra-rs in namespace "e1"
    And I stop zebra-rs in namespace "e2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "r4"
    And I delete namespace "r5"
    And I delete namespace "e1"
    And I delete namespace "e2"
    Then the test environment should be clean
