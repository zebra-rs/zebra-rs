@isis_lan_snpa_change
@isis
Feature: IS-IS LAN adjacency survives a change of the interface hardware address
  As a network operator
  I want IS-IS to follow the kernel when an interface's MAC address changes,
  so an adjacency on that circuit stays up (and the SNPA I see in
  `show isis interface detail` is the one on the wire) instead of being pinned
  at Init for the rest of the process.

  Why this can happen without anyone touching the address by hand: the
  kernel recomputes a bridge's MAC from its port set on every enslave or
  release, and a bond adopts its first slave's. Both are ordinary
  results of our own configuration. `ip link set ... address` is the
  operator's version of the same event and is what this feature uses.

  The mechanism it pins: IS-IS caches the interface MAC as the circuit
  SNPA and compares it against the IS Neighbors TLV of every LAN IIH it
  receives (ISO 10589 8.4.2.5). Once the neighbour has learnt our new
  source address, its IIHs list only that, so a stale SNPA fails the
  check on each one: the adjacency drops to Init and never recovers. The
  RIB now fans the kernel's new address out (`RibRx::LinkMac`) and IS-IS
  refreshes the SNPA in place, sends an immediate Hello and re-runs DIS
  election.

  Test Topology:
  ```
   a1 ───────────── a2
   i2  10.0.12.0/30  i1
   lo 10.0.0.1/32   lo 10.0.0.2/32
  ```

  Both routers are level-2-only on a broadcast (LAN) circuit with 1 s
  Hellos and hold-time 5 s, so the fallout of the address change lands
  within seconds either way.

  Scenario: Changing a1's interface address keeps the adjacency up and refreshes the SNPA on both sides
    Given a clean test environment
    When I create namespace "a1"
    And I create namespace "a2"
    And I connect namespace "a1" interface "i2" to namespace "a2" interface "i1"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    Then isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    And ping from "a2" to "10.0.0.1" should eventually succeed
    # Move a1's address. The 10 s wait is twice the hold time: long
    # enough for a2's IS Neighbors TLV to have turned over to the new
    # address and for a1 to have received several IIHs carrying it —
    # every one of which broke the adjacency before the fix.
    When I set mac "02:00:00:00:12:01" on interface "i2" in namespace "a1"
    And I wait 10 seconds
    # a1's own view: the SNPA follows the kernel (colon form in
    # `show isis interface detail`, dotted form in the neighbour table).
    Then show command "show isis interface detail" in namespace "a1" should eventually contain "SNPA: 02:00:00:00:12:01"
    And show command "show isis neighbor" in namespace "a2" should eventually contain "0200.0000.1201"
    # The decisive assertions: a1's adjacency is Up, not pinned at Init,
    # and the LAN still carries traffic in the direction that needs
    # a1's LSP to list a2 (the two-way check on a2's SPF).
    And isis neighbor in namespace "a1" at level 2 on interface "i2" should be up
    And isis neighbor in namespace "a2" at level 2 on interface "i1" should be up
    And ping from "a2" to "10.0.0.1" should eventually succeed
    And ping from "a1" to "10.0.0.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I delete namespace "a1"
    And I delete namespace "a2"
    Then the test environment should be clean
