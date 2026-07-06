#!/bin/sh
set -e

case "$1" in
    purge)
        # Mirror postinstall's `groupadd -r`: use shadow-utils' groupdel
        # (same package) so the add/remove pair is symmetric.
        if command -v groupdel >/dev/null 2>&1; then
            if getent group zebra-rs >/dev/null 2>&1; then
                groupdel zebra-rs >/dev/null 2>&1 || true
            fi
        fi
        ;;
esac
