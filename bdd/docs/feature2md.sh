#!/bin/bash
#
# Convert a Cucumber .feature file to Markdown format
#
# Usage: feature2md.sh <input.feature> <output.md>
#

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <input.feature> <output.md>"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

# Extract feature name (remove "Feature: " prefix)
FEATURE_NAME=$(grep "^Feature:" "$INPUT_FILE" | sed 's/Feature: //')

# Section header detection — accept an optional parenthesized
# qualifier between the keyword and the trailing colon, so both
# `Test Topology:` and `Test Topology (linear chain, ...):` are
# recognized. Same for `Config files (in foo/):` etc.
TOPO_RE='^  Test Topology[^:]*:'
CFG_RE='^  Config files[^:]*:'
SCEN_RE='^  Scenario:'

# Start building markdown
{
    echo "# $FEATURE_NAME"
    echo ""
    echo "## Overview"
    echo ""

    # Description: indented non-blank lines between `Feature:`
    # and the first section header (Test Topology / Config files /
    # Scenario). Continuation lines that start lowercase (e.g.
    # "so a static IPv6 route ...") still belong to the same
    # paragraph and must be captured — using `[^ ]` instead of
    # `[A-Z]` ensures that.
    awk -v topo="$TOPO_RE" -v cfg="$CFG_RE" -v scen="$SCEN_RE" '
        /^Feature:/{found=1; next}
        $0 ~ topo || $0 ~ cfg || $0 ~ scen {exit}
        found && /^  [^ ]/{sub(/^  /, ""); print}
    ' "$INPUT_FILE"

    echo ""

    # Test Topology section
    if grep -qE 'Test Topology[^:]*:' "$INPUT_FILE"; then
        echo "## Test Topology"
        echo ""
        # Extract topology block (from ``` to ```). The opening
        # fence is rewritten to a bare ``` so the rendered code
        # block starts at column 0.
        awk -v topo="$TOPO_RE" '
            $0 ~ topo {found=1; next}
            found && /^  ```$/ {
                if (in_block) exit
                in_block = 1
                print "```"
                next
            }
            found && in_block {print}
        ' "$INPUT_FILE"
        echo '```'
        echo ""
    fi

    # Notes section — bullet items and prose between the end of
    # the topology block and the Config files / Scenario header.
    # These describe the test setup but aren't part of the
    # diagram or the config file list. Skip silently if the
    # feature doesn't carry any.
    NOTES=$(awk -v cfg="$CFG_RE" -v scen="$SCEN_RE" '
        /^  ```$/ {
            if (!in_topo && !after_topo) {
                in_topo = 1
            } else if (in_topo) {
                in_topo = 0
                after_topo = 1
            }
            next
        }
        in_topo {next}
        after_topo && ($0 ~ cfg || $0 ~ scen) {exit}
        after_topo && /^   *[^ ]/{sub(/^  /, ""); print}
    ' "$INPUT_FILE")
    if [ -n "$NOTES" ]; then
        echo "## Notes"
        echo ""
        echo "$NOTES"
        echo ""
    fi

    # Config Files section
    if grep -qE 'Config files[^:]*:' "$INPUT_FILE"; then
        echo "## Config Files"
        echo ""
        awk -v cfg="$CFG_RE" -v scen="$SCEN_RE" '
            $0 ~ cfg {found=1; next}
            $0 ~ scen {exit}
            found && /^  - /{sub(/^  /, ""); print}
        ' "$INPUT_FILE"
        echo ""
    fi

    # Additional prose between Config files and the first
    # Scenario (non-bullet, non-empty lines). Preserved for
    # back-compat with features that put trailing notes there.
    ADDITIONAL=$(awk -v cfg="$CFG_RE" -v scen="$SCEN_RE" '
        $0 ~ cfg {found=1; next}
        $0 ~ scen {exit}
        found && !/^  - / && /^  [0-9A-Za-z]/{sub(/^  /, ""); print}
    ' "$INPUT_FILE")
    if [ -n "$ADDITIONAL" ]; then
        echo "$ADDITIONAL"
        echo ""
    fi

    echo "## Test Scenarios"
    echo ""
    echo "| Scenario | Result |"
    echo "|----------|--------|"

    # Extract all scenario names
    grep "^  Scenario:" "$INPUT_FILE" | sed 's/^  Scenario: //' | while read -r scenario; do
        echo "| $scenario | |"
    done

} > "$OUTPUT_FILE"

echo "Generated: $OUTPUT_FILE"
