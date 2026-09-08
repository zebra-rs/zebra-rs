# Binding an outbound policy on a live neighbor must re-form its update-group (IPv6)

## Overview

As a network operator
I want `afi-safi ipv6 policy out` bound (or unbound) on an Established
neighbor to take effect for that neighbor alone
So that the neighbor itself is filtered even when a group-mate is the
one whose UPDATE gets built, and its group-mates keep receiving what
the policy denies only to it.

IPv6 twin of `bgp_update_group_live_policy_out`. The outbound policy
name is an update-group signature field, but the signature was only
computed at Established, so a policy bound on a live neighbor left it
in its old group and the memoized canonical outcome was shared.

Here the policy is bound on the HIGHER-index member of the shared
group (z3), the opposite of the IPv4 feature: z2, the canonical
member, has no policy, so its permit is memoized and z3 receives the
very prefix its own policy denies — the other direction of the same
defect.

## Test Topology

```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │
   │  ::2  │      │  ::3  │      │  ::1  │      │  ::4  │
   └───────┘      └───────┘      └───────┘      └───────┘
```

## Notes

Session addresses are 2001:db8:70::N; router-ids 10.71.0.N. IPv4
unicast is negotiated by default on every session too, so z1 also
holds two ipv4-unicast groups (one iBGP pair, one eBGP) that an ipv6
policy must not touch: the group counts below include them.

- z4 originates 2001:db8:41::/64 from the start; both z2 and z3 hold it.
- While every session is Established, z1 binds `policy out DENY-P2`
  (deny 2001:db8:42::/64, permit the rest) toward z3 only.
- z4 then adds 2001:db8:42::/64: z2 must receive it, z3 must not.
- z1 unbinds the policy: z3 rejoins z2's group; z4's third prefix
  reaches both.

## Config Files

- z1.yaml: no policy; z1-deny-z3.yaml: policy bound toward z3;
  z1-undeny.yaml: policy defined but not bound.
- z2.yaml, z3.yaml: listeners.
- z4.yaml / z4-two.yaml / z4-three.yaml: one, two, three prefixes.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology; both iBGP neighbors share one update-group and hold the first prefix | |
| Binding an outbound policy on the live neighbor moves it into its own IPv6-unicast update-group | |
| The bound neighbor is filtered even though its former group-mate is the canonical member | |
| Unbinding the policy on the live neighbor merges it back and re-syncs it | |
| Teardown topology | |
