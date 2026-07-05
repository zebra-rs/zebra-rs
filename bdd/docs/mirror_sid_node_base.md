# IS-IS SRv6 Mirror SID egress NODE protection — stale-route retention

## Overview

TI-LFA and the egress-link redirect both need the protected egress to
stay alive. This feature covers the other failure: the protected
egress's whole NODE goes down. pea is a stub egress reachable only via
the PLR pe1; peb (the protector) is reached directly over pe1-peb and
advertises a Mirror SID (End.M) for pea's locator fcbb:bbbb:3::/48.
While pea is up, pe1 routes to its locator over the pe1-pea adjacency
and carries peb's Mirror SID as the egress-protection backup. When pea's
node fails, that adjacency drops and pea's locator leaves the SPF — the
diff would normally withdraw it, taking the repair with it. Mirror SID
node-protection **stale-route retention** instead keeps the locator
alive as a seg6 H.Encaps route to peb's Mirror SID, so traffic into the
failed egress's locator is carried to the protector and the failover
survives SPF reconvergence (not just the sub-second BFD window). When
pea returns, its real locator route supersedes the retained one.
```
```
The seg6 H.Encaps forwarding the retained route points at is exercised
with live traffic by @mirror_sid_egress_link; here we validate that the
locator route itself survives the node failure and is withdrawn on
recovery.

## Notes

The seg6 H.Encaps forwarding the retained route points at is exercised
with live traffic by @mirror_sid_egress_link; here we validate that the
locator route itself survives the node failure and is withdrawn on
recovery.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and confirm IS-IS SRv6 + Mirror SID exchange | |
| Steady state — pe1 routes to pea's locator over the direct adjacency | |
| Node failure — retention keeps the locator via the Mirror SID | |
| Recovery — pea returns and its real locator route supersedes | |
| Hold-down bounds the retention and withdraws the backup | |
| After the hold-down, a returning egress re-installs the backup | |
| Teardown topology | |
