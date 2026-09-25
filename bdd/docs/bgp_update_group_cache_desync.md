# A prefix withdrawn after an attribute change inside one MRAI window is not re-announced (IPv4)

## Overview

As a network operator
I want a prefix whose attributes change and which is then withdrawn,
all within one advertisement interval, to be withdrawn downstream for
good — not re-announced at the next flush under its old attributes.

## Test Topology

```
  ┌─────────┐          ┌─────────┐          ┌─────────┐
  │   h1    │──eBGP───▶│   z1    │──eBGP───▶│   z2    │
  │scripted │          │  (DUT)  │          │ zebra-rs│
  │ AS65041 │          │ AS65040 │          │ AS65042 │
  │  .2     │          │  .1     │          │  .3     │
  └─────────┘          └─────────┘          └─────────┘
        192.168.40.0/24 (one bridge)
```

## Notes

h1 runs tests/scripts/bgp_attr_churn_send.py. It announces the warm-up
prefix 10.40.3.0/24 as soon as the session is up. On the trigger file
/tmp/bgp_update_group_cache_desync.burst it sends, in one write: announce 10.40.1.0/24
(ORIGIN IGP), announce it again (ORIGIN INCOMPLETE), withdraw it, and
announce the control prefix 10.40.2.0/24. z1's eBGP advertisement
interval is 5 s, so all of it lands in ONE flush window of z1's
update-group pending-advert cache.

Review finding #15: the cache inserted the prefix into the new
attribute bucket without evicting it from the old one, and the
withdraw purged only the new bucket — so the flush re-announced the
prefix under its first attributes while z1's Adj-RIB-Out no longer held
it, and no later withdraw could ever reach z2. The control prefix,
flushed in the same window, proves the flush happened.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The speaker's warm-up prefix reaches z2, so z1 has resolved its next-hop | |
| The churned prefix is withdrawn downstream for good | |
| Teardown topology | |
