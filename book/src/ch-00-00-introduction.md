# Introduction

Welcome to an introductory book about *zebra-rs*. zebra-rs is a BGP, OSPF, and
IS-IS routing stack with SRv6, SR-MPLS, L3VPN, and EVPN extensions, written from
scratch in Rust. Memory-safe, async to the core, idempotent by design — and the
first routing daemon to ship with a native MCP server for AI agents.

The original implementation of zebra-rs began in 1996 as the GNU Zebra project,
which was written in the C programming language. Since then, GNU Zebra has been
forked into several projects such as `quagga` and `FRR`. Current most updated
maintained version is [FRRouting](https://frrouting.org/).

zebra-rs is a reincarnation of GNU Zebra in Rust.

## AI Native

zebra-rs is the first routing daemon to ship with a native
[Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server, built
right into the client. Point Claude — or any MCP-aware agent — at the router and
operate it in plain language: inspect routes, diagnose adjacencies, or draft
policy. The agent sees exactly what an operator sees at the CLI, so the network
becomes a first-class participant in the conversation rather than a black box
your tools poke at from the outside. See [Native MCP
Server](ch-13-00-mcp-server.md) for details.

## Single Process Architecture

GNU Zebra was implemented using a multi-server architecture to take advantage of
multi-core CPUs. When it was designed in 1996, multi-process architecture was
the best approach for multi-core CPUs. Today, the Rust programming language
offers excellent support for multi-threading and multi-tasking, such as through
the tokio library. Therefore, zebra-rs is designed as a single-process
application that runs multiple tasks within it.

The single-process design is also a natural fit for container environments. A
single binary with one process maps cleanly onto a container's
one-process-per-container model, making zebra-rs straightforward to package and
deploy on platforms such as Kubernetes — no process supervisor or inter-daemon
socket orchestration required inside the container.

## Idempotent by Design

Configuration in zebra-rs is **declarative**: you describe the desired state of
the router and the daemon reconciles the running configuration to match.

The same configuration can be written as legacy CLI syntax, YAML, or JSON — pick
the format that fits your workflow. All three are views of one underlying
YANG-modeled tree, so they round-trip losslessly.

Applying a spec is idempotent: zebra-rs commits only the difference from the
running state, so re-applying an unchanged configuration is a no-op, and each
apply is atomic. That makes it safe to run on every GitOps or CI reconcile loop,
much like `kubectl` in Kubernetes:

```
vtyctl apply -f zebra.yaml
```

## XDP/eBPF Acceleration

Where the data plane has to be fast, zebra-rs aggressively offloads work to XDP
and eBPF. Latency- and throughput-sensitive paths are pushed down into the
kernel — and, where the NIC supports it, onto the hardware — so they run at line
rate instead of bouncing through user space.

[BFD](ch-10-00-bfd.md) liveness runs in an [XDP/eBPF data-plane
helper](ch-10-01-bfd-xdp-helper.md), sustaining sub-second failure detection —
including Echo mode, across BFD, S-BFD, and STAMP — without loading the control
plane. [EVPN BUM replication](ch-02-34-bgp-evpn-segmentation.md) is offloaded to
eBPF, fanning out broadcast, unknown-unicast, and multicast traffic inside the
kernel. More hot paths move behind XDP/eBPF over time, while the control plane
stays in safe, async Rust.
