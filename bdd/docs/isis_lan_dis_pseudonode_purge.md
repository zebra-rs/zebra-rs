# A resigning DIS purges the pseudonode LSP it originated

## Overview

Regression for a pseudonode-LSP leak on DIS resignation.
On a broadcast LAN the Designated IS originates a pseudonode LSP. When it
ceases to be DIS it must purge that LSP (ISO 10589 §7.3.4.6) rather than
leave it to age out over MaxAge (~20 min). `dis_selection` does this via
`ifsm::dis_dropping`, but a circuit going down never reached that path —
`Isis::link_state_down` reset `adj` and `dis_status` directly, and
`dis_dropping` is the only caller that emits `Message::LspPurge` for a
pseudonode. So a DIS that lost its circuit left a zombie pseudonode LSP
behind, in its own LSDB and in every other LSDB in the area.
Forwarding survived it — SPF's two-way check discards a pseudonode the
ex-DIS's own LSP no longer references — which is exactly why a
reachability test cannot catch this. The assertion has to look at the
LSDB.
Three L2 routers (a1, a2, a3) share one broadcast LAN (br0). a1 holds LAN
priority 200 (a2/a3 default 64) so a1 is deterministically DIS and owns
the pseudonode. Dropping a1's circuit must purge it.
Note this scenario asserts on a1's *own* LSDB. With a single circuit a1
has nowhere to flood the purge once that circuit is down, so its peers
necessarily age the LSP out — unavoidable, and true of any
implementation. A router that still holds another circuit does flood the
purge to the rest of the area; the originator-side invariant asserted
here is what makes that possible.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| a DIS that loses its circuit purges its pseudonode LSP | |
| Teardown topology | |
