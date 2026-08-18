#!/bin/bash
# MCP fleet server for the isis-flexalgo-ai demo.
#
# One stdio MCP server that fronts all eleven routers: every tool takes a
# `router` argument, and calls are forwarded into that router's network
# namespace. Point Claude Desktop (or any MCP client) at this script:
#
#   {
#     "mcpServers": {
#       "zebra-fleet": {
#         "command": "/path/to/zebra-rs/playset/isis-flexalgo-ai/mcp.sh"
#       }
#     }
#   }
#
# If Claude Desktop runs on another machine, wrap it in ssh instead:
#
#   "command": "ssh",
#   "args": ["-T", "user@lab-host", "/path/to/.../mcp.sh"]
#
# The server runs as root (it must enter the routers' namespaces, and
# committing configuration requires an admin session, which root holds
# automatically). Grant passwordless sudo for the vtyctl binary, e.g.
# with visudo:
#
#   <user> ALL=(root) NOPASSWD: /path/to/zebra-rs/target/debug/vtyctl
#
set -eu

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${DIR}/../.." && pwd)"

VTYCTL="${VTYCTL_BIN:-}"
if [ -z "${VTYCTL}" ]; then
    for candidate in \
        "${REPO}/target/debug/vtyctl" \
        "${REPO}/target/release/vtyctl" \
        /usr/bin/vtyctl; do
        if [ -x "${candidate}" ]; then
            VTYCTL="${candidate}"
            break
        fi
    done
fi
if [ -z "${VTYCTL}" ]; then
    echo "mcp.sh: no vtyctl binary found (set VTYCTL_BIN)" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    exec "${VTYCTL}" mcp --fleet "${DIR}/ontology.json"
fi
exec sudo -n "${VTYCTL}" mcp --fleet "${DIR}/ontology.json"
