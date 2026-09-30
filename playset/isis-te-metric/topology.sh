# IS-IS TE metric / STAMP demo
# Each PLAYSET_LINKS entry is "ns_a:iface_a:ns_b:iface_b".

PLAYSET_NAMESPACES=(se sj ch da va at ln fr sg sy tk)

PLAYSET_LINKS=(
    se:se-sg:sg:sg-se
    se:se-sj:sj:sj-se
    se:se-ch:ch:ch-se
    sj:sj-sy:sy:sy-sj
    sj:sj-da:da:da-sj
    sj:sj-ch:ch:ch-sj
    sj:sj-tk:tk:tk-sj
    ch:ch-da:da:da-ch
    ch:ch-va:va:va-ch
    ch:ch-ln:ln:ln-ch
    da:da-at:at:at-da
    va:va-at:at:at-va
    va:va-fr:fr:fr-va
    ln:ln-fr:fr:fr-ln
    fr:fr-sg:sg:sg-fr
    sg:sg-tk:tk:tk-sg
    sg:sg-sy:sy:sy-sg
)

# One-way propagation delay of each link in milliseconds, keyed by the
# first-listed interface of its PLAYSET_LINKS entry — roughly what fiber
# between the two cities costs. up.sh applies it as a netem qdisc on both
# veth ends, so each direction is delayed by the same amount.
PLAYSET_LINK_DELAYS=(
    se-sg:85
    se-sj:10
    se-ch:25
    sj-sy:75
    sj-da:20
    sj-ch:25
    sj-tk:55
    ch-da:12
    ch-va:10
    ch-ln:45
    da-at:11
    va-at:9
    va-fr:45
    ln-fr:6
    fr-sg:80
    sg-tk:35
    sg-sy:45
)

# All namespaces that run zebra-rs.
PLAYSET_DAEMONS=(se sj ch da va at ln fr sg sy tk)

# Routers with vtyctl YAML config.
PLAYSET_ROUTERS=(se sj ch da va at ln fr sg sy tk)
