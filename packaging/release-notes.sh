#!/usr/bin/env bash
#
# release-notes.sh — extract one CHANGELOG.yaml entry as GitHub-flavored Markdown.
#
# Prints the curated release notes for a single version to stdout, so the GitHub
# release body (nightly.yaml / release.yaml) renders the SAME prose that ships in
# the Debian changelog (packaging/changelog-gen.sh writes that from the same
# file). CHANGELOG.yaml is the single source of truth: edit it, and both the
# .deb changelog and the Releases-page summary follow — no second place to keep
# in sync.
#
# Usage:
#   release-notes.sh [SEMVER]
# With no argument, emits the newest (top) entry — used by the nightly release,
# which previews the notes accumulating for the next version. With a SEMVER
# (e.g. 26.7.5) emits that entry — the stable release passes the tag. Exits
# non-zero if the requested version is absent, so a release fails loudly rather
# than publishing an empty body.
#
# The notes in CHANGELOG.yaml are already written in Markdown (`### heading`,
# `* bullet`), so extraction is just: find the entry, print its `- note:` block
# bodies verbatim with the 8-space YAML block-scalar indent stripped, one blank
# line between blocks.
#
# Dependency-free by design: bash + coreutils only — no python/PyYAML/perl — so
# it runs unchanged on the minimal CI build container (mirrors changelog-gen.sh).

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../CHANGELOG.yaml"
want="${1:-}"

[ -f "$src" ] || { echo "release-notes: $src not found" >&2; exit 1; }

in_entry=0        # inside the requested entry's body
in_note=0         # inside a `- note: |` block scalar
found=0           # emitted at least one non-blank line
pending_blank=0   # a blank line is buffered, flushed before the next content

# Print one Markdown line. Runs of blank lines collapse to one, and a blank
# never leads the output (so blocks are cleanly separated, no top/bottom pad).
emit() {
    if [ -z "$1" ]; then
        [ "$found" = 1 ] && pending_blank=1
        return 0
    fi
    [ "$pending_blank" = 1 ] && printf '\n'
    pending_blank=0
    found=1
    printf '%s\n' "$1"
    return 0        # never let a short-circuited `&&` above leak rc=1 under set -e
}

while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"

    # Entry boundary (column-0 `- semver:`); never an 8-space note-body line.
    case "$line" in
        '- semver: '*)
            [ "$in_entry" = 1 ] && break          # next entry reached; done
            ver="${line#- semver: }"
            if [ -z "$want" ] || [ "$ver" = "$want" ]; then
                in_entry=1
            fi
            in_note=0
            continue
            ;;
    esac

    [ "$in_entry" = 1 ] || continue

    # Note block-scalar body: >= 8-space indent, or a blank line within the block.
    if [ "$in_note" = 1 ]; then
        if [ -z "$line" ]; then
            emit ""
            continue
        fi
        if [ "${line:0:8}" = "        " ]; then
            emit "${line:8}"
            continue
        fi
        in_note=0                                 # dedented out of the block
    fi

    case "$line" in
        '    - note: |'*) in_note=1; emit "" ;;    # blank line between blocks
        '    - note: '*)  emit "${line#    - note: }" ;;
        *) ;;                                      # date/distribution/changes/...
    esac
done < "$src"

if [ "$found" != 1 ]; then
    echo "release-notes: no entry for '${want:-<top>}' in $src" >&2
    exit 1
fi
