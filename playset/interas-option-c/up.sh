#!/bin/bash
# Bring up the Inter-AS Option C (labeled loopbacks between ASBRs, PE-to-PE VPNv4) namespace demo.

PLAYSET_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/playset.sh
source "${PLAYSET_DEMO_DIR}/../lib/playset.sh"
# shellcheck source=topology.sh
source "${PLAYSET_DEMO_DIR}/topology.sh"

playset_up
