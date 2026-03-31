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

# Start building markdown
{
    echo "# $FEATURE_NAME"
    echo ""
    echo "## Overview"
    echo ""

    # Extract description lines (lines after Feature: until Test Topology or Scenario)
    awk '/^Feature:/{found=1; next} /^  Test Topology:|^  Scenario:/{exit} found && /^  [A-Z]/{print}' "$INPUT_FILE" | sed 's/^  //'

    echo ""

    # Check if there's a Test Topology section
    if grep -q "Test Topology:" "$INPUT_FILE"; then
        echo "## Test Topology"
        echo ""
        # Extract topology block (from ``` to ```)
        awk '/Test Topology:/{found=1; next} found && /^  ```$/{if(in_block) exit; in_block=1; print "```"; next} found && in_block{print}' "$INPUT_FILE"
        echo '```'
        echo ""
    fi

    # Check if there's a Config files section
    if grep -q "Config files:" "$INPUT_FILE"; then
        echo "## Config Files"
        echo ""
        # Extract config files section
        awk '/Config files:/{found=1; next} /^  Scenario:/{exit} found && /^  - /{print}' "$INPUT_FILE" | sed 's/^  //'
        echo ""
    fi

    # Extract additional notes (lines between Config files and first Scenario that aren't config items)
    ADDITIONAL=$(awk '/Config files:/{found=1; next} /^  Scenario:/{exit} found && !/^  - / && /^  [0-9A-Za-z]/{print}' "$INPUT_FILE" | sed 's/^  //')
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
