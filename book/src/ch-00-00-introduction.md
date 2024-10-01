# Introduction

Welcome to *The Zebra Routing Software*, an introductory book about Zebra. Zebra
is routing software that supports various routing protocols, such as BGP, OSPF,
RIP, and IS-IS. It is built from scratch using the Rust programming language.

## History

The original implementation of The Zebra Routing Software began in 1996 as the
GNU Zebra project, which was written in the C programming language. Since then,
GNU Zebra has been forked into several projects, and it is currently maintained
as [FRRouting](https://frrouting.org/).

## Architecture

GNU Zebra was implemented using a multi-server architecture to take advantage of
multi-core CPUs. When it was designed in 1996, multi-process architecture was
the best approach for multi-core CPUs. Today, the Rust programming language
offers excellent support for multi-threading and multi-tasking, such as through
the tokio library. Therefore, The Zebra Routing Software is designed as a
single-process application that runs multiple tasks within it.

