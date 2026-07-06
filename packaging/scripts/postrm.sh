#!/bin/sh
set -e

case "$1" in
    purge)
        if command -v delgroup >/dev/null 2>&1; then
            if getent group zebra-rs >/dev/null 2>&1; then
                delgroup --quiet --system zebra-rs >/dev/null 2>&1 || true
            fi
        fi
        ;;
esac
