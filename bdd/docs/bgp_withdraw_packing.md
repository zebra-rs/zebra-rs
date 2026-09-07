# Bulk withdrawals are packed per peer and stay coherent with the Adj-RIB-Out

## Overview

Two scripted iBGP clients connect to a zebra-rs route reflector. The source
announces 1000 routes per family and withdraws them in a burst; the observer
parses the reflector's raw TCP stream and checks that the withdrawals arrive
packed into a bounded number of UPDATEs within the negotiated message size,
with no stale announcement overtaking a withdrawal. It then sends
announce+withdraw and withdraw+announce back to back and checks the observer
settles absent / present respectively — a queued withdrawal must neither
overtake the announcement it races nor outlive a re-advertise. IPv4, IPv6,
VPNv4, VPNv6 and EVPN are covered at both message limits.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup a reflector and two scripted clients | |
| Pack withdrawals without extended messages | |
| Pack withdrawals with extended messages after reconnect | |
| Teardown topology | |
