@serial
@bgp_port
Feature: BGP on a non-default TCP port
  As a network operator
  I want `router bgp port <0-65535>` and `neighbor X port <1-65535>`
  So sessions can run on a non-179 port, and a router can refuse all
  inbound BGP by closing its listener (`port 0`).

  Test Topology (a line):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65003 │
   │  .0.1   │                  │.0.2 .1.2│                  │  .1.3   │
   └─────────┘                  └─────────┘                  └─────────┘
  ```

  z1—z2 exercises the two port knobs together: z2 listens on TCP 1790
  (`port: 1790`) and z1 dials it (`neighbor 192.168.0.2 port 1790`).
  Both ends pin the connection direction so the assertion on the ports
  is deterministic: z1 runs `port: 0` (its dial works fine without any
  listener, and z2's racing dial toward z1:179 is refused) and z2 is
  passive toward z1. The only session that can exist is the one z1
  opened toward 1790. z1 originates 10.10.0.1/32 to prove routes flow
  over it.

  z2—z3 exercises `port 0` on the accept side: z3 starts with
  `port: 0` (no listener) and is passive toward z2, so z2's dials to
  z3:179 are refused and the session must stay down. Re-configuring z3
  to `port: 179` reopens the listener at runtime; a `clear` on z2 then
  redials immediately (a refused connect otherwise parks the peer on
  the 120s connect-retry timer) and the session establishes — the
  close-and-reopen path of a runtime port change.

  Config application order matters once: z3's `port: 0` is applied
  before z2's config exists, so z2 never catches the small window
  between z3's daemon start (default listener on 179) and the apply.

  Config files:
  - z1.yaml: `port: 0`; neighbor z2 with `port: 1790`; originates
    10.10.0.1/32
  - z2.yaml: `port: 1790` listener; passive toward z1; active toward z3
  - z3.yaml: `port: 0` (no listener); passive toward z2
  - z3-listen.yaml: same as z3.yaml with `port: 179` (reopen listener)

  Scenario: Setup line topology with custom ports
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i2" to namespace "z3" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # Let both ends settle (z2's passive peer must be out of Idle —
    # Idle refuses inbound connections), then hard-reset z1 so its
    # dial happens with z2's listener and peer guaranteed ready. z1's
    # own first dial may have fired into the apply gap and parked on
    # the 120s connect-retry timer; the clear redials within seconds.
    And I wait 10 seconds
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Session between z1 and z2 runs on TCP 1790
    Given the test topology exists
    # z1 dialed z2 on the configured neighbor port (z1 cannot have
    # accepted anything: its listener is closed with port 0)...
    Then show command "show bgp neighbor" in namespace "z1" should contain "Foreign port: 1790"
    # ...and z2 accepted it on its non-default listener.
    And show command "show bgp neighbor" in namespace "z2" should contain "Local port: 1790"
    # Routes flow over the non-179 session.
    And BGP route in "z2" has "10.10.0.1/32"

  Scenario: port 0 closes the listener so the z2-z3 session stays down
    Given the test topology exists
    # z3 neither listens (port 0) nor dials (passive): z2's dials to
    # z3:179 are refused, so the session cannot leave Active/Connect.
    Then BGP session in "z2" to "192.168.1.3" should not be "Established"
    And BGP session in "z3" to "192.168.1.2" should not be "Established"

  Scenario: Changing the port reopens the listener and the session comes up
    Given the test topology exists
    # port 0 -> 179 closes nothing but opens a fresh listener.
    When I apply config "z3-listen.yaml" to namespace "z3"
    # z2's last dial was refused, which parks the peer on the 120s
    # connect-retry timer — clear it so it redials now.
    And I run "clear bgp ipv4 neighbor 192.168.1.3" in namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.1.3" should be "Established"
    And BGP session in "z3" to "192.168.1.2" should be "Established"
    # z3 accepted the session on the reopened default listener.
    And show command "show bgp neighbor" in namespace "z3" should contain "Local port: 179"
    # End-to-end: z1's route crossed both custom-port sessions.
    And BGP route in "z3" has "10.10.0.1/32"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only the daemons and namespaces need
  # teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    Then the test environment should be clean
