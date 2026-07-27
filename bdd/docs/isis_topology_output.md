# show isis topology renders the FRR SPF-tree layout

## Overview

`show isis topology` lists the SPF tree as FRR does: every router,
pseudonode, and prefix is a vertex, ordered by SPF metric. Three L2
routers (a1, a2, a3) share one LAN (br0); a3 (LAN priority 100) is the
DIS. The layout must show:

## Test Scenarios

| Scenario | Result |
|----------|--------|
| the SPF tree lists self-prefixes, the pseudonode, and remote prefixes | |
| Teardown topology | |
