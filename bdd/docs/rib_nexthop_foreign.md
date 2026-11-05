# Next-hop objects another program makes while zebra-rs runs

## Overview

zebra-rs installs each next-hop group as a kernel object whose id is the
group's gid, with NLM_F_REPLACE. It keeps the ids of the objects the
kernel holds at startup from its groups. Another program, an operator or
systemd-networkd say, can make one later. Its id used to be handed to
the next group, whose install then took the object over: the program's
routes forwarded through our next hop. A gid freed when its last route
went was given back to the same next hop when it returned, whatever had
taken that id meanwhile.

## Test Topology

```
   z1 (vz1ns 192.168.0.1/24) ── br0
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| An object made while zebra-rs runs keeps its id | |
| A freed gid another program took is not given back | |
| Teardown topology | |
