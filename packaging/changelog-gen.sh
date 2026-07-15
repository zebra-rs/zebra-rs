#!/usr/bin/env bash
#
# changelog-gen.sh — convert CHANGELOG.yaml into a Debian-format changelog.
#
# CHANGELOG.yaml (the single source of truth, formerly consumed by nfpm) uses
# the nfpm/chglog schema. cargo-deb's `changelog =` field wants a Debian-format
# changelog instead, so the packaging Makefile runs this before `cargo deb` to
# regenerate packaging/out/changelog.
#
# Dependency-free by design: bash + coreutils `date` only — no python, PyYAML,
# perl, or chglog — so it runs unchanged on the minimal CI build container.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../CHANGELOG.yaml"
out_dir="$here/out"
out="$out_dir/changelog"

pkg="zebra-rs"
default_maintainer="Kunihiro Ishiguro <kunihiro@zebra.rs>"
default_dist="unstable"
default_urgency="medium"

[ -f "$src" ] || { echo "changelog-gen: $src not found" >&2; exit 1; }
mkdir -p "$out_dir"
: > "$out"

# ISO-8601 -> RFC-2822, preserving the source wall-clock and offset. The naive
# datetime is interpreted as UTC (TZ=UTC0) so the weekday matches the printed
# calendar date; the original offset is appended verbatim (colon stripped;
# `Z` -> +0000).
to_rfc2822() {
    local iso="$1" naive off
    if [[ "$iso" =~ ^(.*)([+-][0-9][0-9]):?([0-9][0-9])$ ]]; then
        naive="${BASH_REMATCH[1]}"; off="${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
    elif [[ "$iso" =~ ^(.*)[Zz]$ ]]; then
        naive="${BASH_REMATCH[1]}"; off="+0000"
    else
        naive="$iso"; off="+0000"
    fi
    printf '%s %s' "$(TZ=UTC0 date -d "$naive" '+%a, %d %b %Y %H:%M:%S')" "$off"
}

# Render one note-body line (already de-indented) into a changelog body line.
emit_body_line() {
    case "$1" in
        '### '*) printf '  * %s\n'   "${1#'### '}" ;;
        '* ')    ;;                                    # empty bullet, skip
        '* '*)   printf '    - %s\n' "${1#'* '}" ;;
        '')      printf '\n' ;;
        *)       printf '    %s\n'   "$1" ;;
    esac
}

cur_semver=""; cur_date=""; cur_dist=""; cur_urg=""; cur_pkgr=""; body=""; in_note=0

flush_entry() {
    [ -n "$cur_semver" ] || return 0
    # Trim leading/trailing blank lines from the accumulated body.
    body="${body#$'\n'}"
    while [ "${body%$'\n'}" != "$body" ] && [ "${body%$'\n'$'\n'}" != "$body" ]; do
        body="${body%$'\n'}"
    done
    printf '%s (%s) %s; urgency=%s\n\n' \
        "$pkg" "$cur_semver" "${cur_dist:-$default_dist}" "${cur_urg:-$default_urgency}" >> "$out"
    if [ -n "$body" ]; then
        printf '%s\n' "$body" >> "$out"
    else
        printf '  * See CHANGELOG.yaml for details.\n' >> "$out"
    fi
    printf '\n -- %s  %s\n\n' \
        "${cur_pkgr:-$default_maintainer}" "$(to_rfc2822 "${cur_date}")" >> "$out"
}

while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"

    if [ -z "$line" ]; then
        [ "$in_note" = 1 ] && body+=$'\n'
        continue
    fi

    # A note body line is indented >= 8 spaces (block scalar under `- note: |`).
    if [ "$in_note" = 1 ] && [ "${line:0:8}" = "        " ]; then
        body+="$(emit_body_line "${line:8}")"$'\n'
        continue
    fi
    in_note=0

    case "$line" in
        '- semver: '*)
            flush_entry
            cur_semver="${line#- semver: }"
            cur_date=""; cur_dist=""; cur_urg=""; cur_pkgr=""; body=""
            ;;
        '  date: '*)         cur_date="${line#  date: }" ;;
        '  distribution: '*) cur_dist="${line#  distribution: }" ;;
        '  urgency: '*)      cur_urg="${line#  urgency: }" ;;
        '  packager: '*)     cur_pkgr="${line#  packager: }" ;;
        '  changes:'*)       ;;
        '    - note: |'*)
            in_note=1
            [ -n "$body" ] && body+=$'\n'    # blank line between notes
            ;;
        '    - note: '*)
            body+="$(emit_body_line "${line#    - note: }")"$'\n'
            ;;
    esac
done < "$src"

flush_entry

echo "changelog-gen: wrote $out ($(grep -c '^zebra-rs (' "$out") entries)"
