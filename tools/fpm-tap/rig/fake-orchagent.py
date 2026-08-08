#!/usr/bin/env python3
"""Stand in for orchagent's route-response publication.

`fpmsyncd` only emits an offload acknowledgement when two things hold
(fpmsyncd.cpp:112-118, routesync.cpp:3635):

  1. CONFIG_DB `DEVICE_METADATA|localhost` has `suppress-fib-pending`
     set to `enabled`, and
  2. something publishes a per-route response on the APPL_STATE_DB
     notification channel `APPL_DB_ROUTE_TABLE_RESPONSE_CHANNEL`.

In a real switch (2) is orchagent, once SAI has programmed the route.
Reproducing that would mean standing up orchagent, syncd and a virtual
ASIC — far more machinery than is needed to learn the *shape* of the
acknowledgement, which is what the zebra-rs FPM client has to parse.

So this consumes routes the way orchagent does and publishes a success
response for each, using the real swsscommon classes so both the consume
and the notify side match production encoding.

Consuming matters as much as notifying. `fpmsyncd` writes routes with a
ProducerStateTable, which stages them under `_ROUTE_TABLE:<key>` plus a
`ROUTE_TABLE_KEY_SET`; they only become plain `ROUTE_TABLE:<key>` once a
ConsumerStateTable drains the key set. With no orchagent, reading
`Table(db, "ROUTE_TABLE")` finds nothing at all — the routes are there,
just still staged.

The `protocol` field is echoed back verbatim, mirroring orchagent, and it
matters: fpmsyncd feeds it through `rtnl_route_str2proto()` (falling back
to a numeric parse) to rebuild `rtm_protocol` in the reply.
"""

import sys
import time

from swsscommon import swsscommon

CHANNEL = "APPL_DB_ROUTE_TABLE_RESPONSE_CHANNEL"
ROUTE_TABLE = "ROUTE_TABLE"


def main() -> int:
    appl_db = swsscommon.DBConnector("APPL_DB", 0)
    state_db = swsscommon.DBConnector("APPL_STATE_DB", 0)
    producer = swsscommon.NotificationProducer(state_db, CHANNEL)
    consumer = swsscommon.ConsumerStateTable(appl_db, ROUTE_TABLE)

    acked = 0
    skipped = 0
    while True:
        key, op, fvs = consumer.pop()
        if not key:
            break

        # A DEL gets no acknowledgement: fpmsyncd identifies deletes by
        # the *absence* of a `protocol` field and returns early
        # (routesync.cpp:3678).
        if op != "SET":
            print(f"  {key}: {op} — no ack expected for deletes")
            skipped += 1
            continue

        protocol = dict(fvs).get("protocol", "")
        # An empty `protocol` is explicitly dropped as "programmed
        # without FRR knowledge" (routesync.cpp:3694). A silent no-op, so
        # flag it rather than leaving a mystery.
        if not protocol:
            print(f"  {key}: no protocol field — fpmsyncd would ignore this ack")
            skipped += 1
            continue

        # Must be a typed FieldValuePairs — the SWIG binding takes a
        # std::vector<FieldValueTuple>&, not a Python list of tuples.
        response = swsscommon.FieldValuePairs(
            [("protocol", protocol), ("err_str", "SWSS_RC_SUCCESS")]
        )
        producer.send("SET", key, response)
        print(f"  {key}: acked (protocol={protocol})")
        acked += 1
        # Space the sends out so each acknowledgement lands as its own
        # readable event in the capture rather than one coalesced burst.
        time.sleep(0.05)

    print(f"fake-orchagent: {acked} acked, {skipped} skipped")
    return 0 if acked else 1


if __name__ == "__main__":
    sys.exit(main())
