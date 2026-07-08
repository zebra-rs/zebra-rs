# Source all playset helpers for a demo script.
# Set PLAYSET_DEMO_DIR to the demo directory before sourcing.

: "${PLAYSET_DEMO_DIR:?PLAYSET_DEMO_DIR must be set before sourcing playset.sh}"

# shellcheck source=common.sh
source "${PLAYSET_DEMO_DIR}/../lib/common.sh"
# shellcheck source=netns.sh
source "${PLAYSET_ROOT}/lib/netns.sh"
# shellcheck source=zebra-rs.sh
source "${PLAYSET_ROOT}/lib/zebra-rs.sh"
# shellcheck source=topology.sh
source "${PLAYSET_ROOT}/lib/topology.sh"
