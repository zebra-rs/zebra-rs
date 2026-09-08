# Binding an outbound policy on a live neighbor must re-form its update-group (IPv4)

## Overview

As a network operator
I want `afi-safi ipv4 policy out` bound (or unbound) on an Established
neighbor to take effect for that neighbor alone
So that its group-mates keep receiving the routes the policy denies
only to it, and the neighbor itself is filtered even when a group-mate
is the one whose UPDATE gets built.

An update-group is keyed by a signature of every per-peer egress input,
and the outbound policy name is one of them. The signature is computed
when a session reaches Established (and on an egress-script rebind),
but binding a policy on a neighbor that is already Established only
rewrote the policy slot: the neighbor stayed in the group its old,
policy-less signature had put it in. From the next best-path change on,
whichever member the memo builds on decides for all: if the bound
neighbor is canonical, its deny is memoized and the plain group-mates
never receive the route; if a plain member is canonical, the bound
neighbor receives what its own policy denies.

## Test Topology

```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │
   │  .2   │      │  .3   │      │  .1   │      │  .4   │
   └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Session addresses are 192.168.70.N; router-ids 10.70.0.N. z2 and z3
share z1's local address, so they start in one IPv4-unicast group; z2
has the lower peer index and is the canonical member.

- z4 originates 10.40.1.0/24 from the start; both z2 and z3 hold it.
- While every session is Established, z1 binds `policy out DENY-P2`
  (deny 10.40.2.0/24, permit the rest) toward z2 only.
- z4 then adds 10.40.2.0/24: z3 must receive it, z2 must not.
- z1 unbinds the policy: z2 rejoins z3's group and receives
  10.40.2.0/24 through the re-sync; z4's third prefix reaches both.

## Config Files

- z1.yaml: no policy; z1-deny-z2.yaml: policy bound toward z2;
  z1-undeny.yaml: policy defined but not bound.
- z2.yaml, z3.yaml: listeners.
- z4.yaml / z4-two.yaml / z4-three.yaml: one, two, three prefixes.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; both iBGP neighbors share one update-group and hold the first prefix | |
| Binding an outbound policy on the live neighbor moves it into its own update-group | |
| A prefix the policy denies to the bound neighbor still reaches its former group-mate | |
| Unbinding the policy on the live neighbor merges it back and re-syncs it | |
| Teardown topology | |
