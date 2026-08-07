@serial
@bgp_opensent_redial
Feature: A BGP connection lost in OpenSent redials on the idle-hold pacer
  As a network operator
  I want a peer whose TCP connection dies after it has sent its OPEN to
  redial on the short idle-hold pacer rather than the ConnectRetryTimer,
  so a transient failure costs seconds instead of minutes.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   h1    │
           │ zebra-rs│     │ scripted│
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │ 40.1/24 │     │ 40.2/24 │
           └─────────┘     └─────────┘
  ```

  `fsm_conn_fail`'s OpenSent arm used to restart the full
  ConnectRetryTimer, while its Connect-state sibling `fsm_dial_fail` uses
  the idle-hold pacer. A peer that lost its TCP after sending OPEN
  therefore sat in Active for up to a ConnectRetryTime — two minutes on
  the old 120s default — before trying again. In the wild that window is
  reached by an RFC 4271 §6.8 collision, where the loser's connection dies
  precisely after it has sent its OPEN.

  h1 runs tests/scripts/bgp_opensent_reset.py, which makes that
  non-deterministic case deterministic: it accepts the DUT's first
  connection, waits for the OPEN so the DUT is provably in OpenSent, then
  aborts with RST; every later connection it serves as a normal speaker.
  So the time from reset to Established is exactly the redial pacer.

  z1.yaml pins connect-retry-time to 120s, an order of magnitude above the
  5s idle-hold default, so the 30s polling assert below can only be
  satisfied by the idle-hold pacer — and the test does not depend on what
  the ConnectRetryTime default happens to be.

  Scenario: The session establishes after a reset taken in OpenSent
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.40.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.40.2/24" on bridge "br0"
    # The listener must be up before the DUT dials: a refused connect
    # fails in Connect and takes the already-correct `fsm_dial_fail`
    # path, which would let this pass regardless of the OpenSent arm.
    And I spawn "timeout 300 python3 tests/scripts/bgp_opensent_reset.py 65002 192.168.40.2 192.168.40.2 /tmp/bgp_opensent_redial.state" in namespace "h1"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    # The peer came back on the short pacer. With the ConnectRetryTimer
    # pacing it instead, this is still ~90s away when the poll gives up.
    Then BGP session in "z1" to "192.168.40.2" should eventually be "Established"
    # ...and it came back *from OpenSent*. The script logs this line only
    # after reading the DUT's OPEN, i.e. once the DUT has provably left
    # Connect, and it only serves a session on the second connection — so
    # reaching Established already implies the first was reset. Without
    # this check a green run could mean the reset landed in Connect and
    # the arm under test was never exercised. `I execute` fails the step
    # on a non-zero exit, so grep is the assertion; no retry is needed
    # because the Established poll above has already ordered it.
    #
    # Written `When`, not `And`: an `And` here would inherit the previous
    # `Then` keyword, and `I execute` is registered only as a `when` step
    # — the step would resolve to nothing at all.
    When I execute "grep -q reset-in-opensent /tmp/bgp_opensent_redial.state" in namespace "h1"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_opensent_redial.state" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
