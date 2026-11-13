#!/bin/sh
# Interrupt (SIGINT) the process a pid file names.
#
#   sigint_pidfile.sh PIDFILE
#
# This is how `systemctl stop zebra-rs` stops it (the unit's ExecStop):
# zebra-rs then shuts down in order, taking back what it would not find
# again. The harness's own stop step kills it outright, which is the
# other case: everything stays for the next run to take over.
kill -INT "$(cat "$1")"
