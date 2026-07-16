#!/usr/bin/env bash
#
# verify-playset-layout.sh — assert the playset labs landed in the .deb with
# their staged directory structure and modes intact.
#
# The Makefile's `playset` target already guards the *staged* file set: it fails
# the build if a file under out/playset matches none of the cargo-deb asset
# globs. What that guard cannot see is where cargo-deb ultimately *places* each
# file — glob destinations are resolved inside cargo-deb, so a mistaken pattern
# could flatten a scenario tree or collide same-named scripts (every up.sh
# landing on one path) and still produce a .deb the staging guard accepts,
# because the files themselves were all present in the staging set.
#
# This closes that gap: after `cargo deb` runs, diff the packaged layout against
# the staged tree, file for file, so a misplaced or dropped asset fails the
# build instead of shipping.
#
# Dependency-free by design: bash + coreutils + awk + dpkg — all already needed
# to build the package — so it runs unchanged on the minimal CI build container.

set -euo pipefail

deb="${1:-}"
if [ -z "$deb" ]; then
	echo "usage: verify-playset-layout.sh <path-to-deb>" >&2
	exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
staged="$here/out/playset"
prefix="usr/share/zebra-rs/playset"

if [ ! -d "$staged" ]; then
	echo "verify-playset-layout: no staged tree at $staged (run: make playset)" >&2
	exit 1
fi

# Expected: every staged regular file, at the mirrored path under $prefix.
# up.sh/down.sh are the operator entry points and ship executable; every other
# asset (the sourced lib/ helpers and the data files) ships 0644. This mirrors
# the mode column of the asset table in ../zebra-rs/Cargo.toml.
expected="$(
	cd "$staged"
	find . -type f | sed 's|^\./||' | while IFS= read -r f; do
		case "${f##*/}" in
		up.sh | down.sh) mode=755 ;;
		*) mode=644 ;;
		esac
		printf '%s %s/%s\n' "$mode" "$prefix" "$f"
	done | sort
)"

# Actual: the same view rendered from the archive. dpkg -c prints an ls-style
# permission string, so fold it back to octal — that way a mode regression (a
# helper shipped executable, an up.sh shipped non-executable) is caught too, not
# just a misplaced path. Regular files only: `$1 ~ /^-/` drops the directory
# entries, and with them the "name -> target" rows symlinks would produce.
actual="$(
	dpkg -c "$deb" | awk -v prefix="$prefix" '
		function octal(perm,   i, v, r) {
			r = ""
			for (i = 0; i < 3; i++) {
				v = 0
				if (substr(perm, 2 + i * 3, 1) == "r") v += 4
				if (substr(perm, 3 + i * 3, 1) == "w") v += 2
				if (substr(perm, 4 + i * 3, 1) == "x") v += 1
				r = r v
			}
			return r
		}
		$1 ~ /^-/ {
			path = $6
			for (i = 7; i <= NF; i++) path = path " " $i
			sub(/^\.\//, "", path)
			if (index(path, prefix "/") == 1) print octal($1), path
		}
	' | sort
)"

if [ "$expected" = "$actual" ]; then
	echo "verify-playset-layout: OK — $(printf '%s\n' "$expected" | wc -l | tr -d ' ') playset files packaged at their staged paths"
	exit 0
fi

{
	echo "verify-playset-layout: packaged playset layout does not match the staged tree."
	echo "  deb:    $deb"
	echo "  staged: $staged"
	echo
	echo "  -  staged, but not in the .deb at this path/mode (dropped or flattened)"
	echo "  +  in the .deb, but not staged at this path/mode (misplaced or stale)"
	echo
	diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") |
		sed -n 's/^</  -/p; s/^>/  +/p'
	echo
	echo "Fix the asset globs in ../zebra-rs/Cargo.toml ([package.metadata.deb] assets)."
} >&2
exit 1
