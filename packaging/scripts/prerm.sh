#!/bin/sh
set -e

case "$1" in
    remove)
        # Stop the daemon before dpkg deletes the unit file — postrm runs
        # too late (systemd can no longer resolve the unit), which used to
        # leave an orphaned zebra-rs running with a deleted binary. Skip on
        # upgrade: the new package's postinstall restarts the service.
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop zebra-rs >/dev/null 2>&1 || true
        fi
        ;;
esac
