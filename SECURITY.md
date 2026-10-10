# Security policy

## Reporting a vulnerability

Please do not report security problems in public issues, pull requests or
discussions. Email **kunihiro@zebra.rs** instead, with "security" in the
subject.

Include what you can of:

- the zebra-rs version (`zebra-rs --version`) or commit, and the OS release
  and architecture;
- the relevant configuration, with keys and passwords removed;
- how to trigger it: a packet capture, the hex bytes of the message, or a
  script;
- what happens: a crash, a hang, a wrong or missing route, a privilege change.

We will acknowledge the report, work on a fix with you, and agree on a
disclosure date before anything is published. Reporters are credited in the
release notes unless they ask not to be.

## Supported versions

Fixes are made on `main` and ship in the next
[release](https://github.com/zebra-rs/zebra-rs/releases). Only the latest
release is supported.

## Scope

[`.oss-scanner/threat_model.md`](.oss-scanner/threat_model.md) describes
where untrusted input enters zebra-rs, what is trusted, and how we rate
severity. In short, these are in scope:

- anything a BGP neighbor, a host on an OSPF, IS-IS, BFD or PIM enabled link,
  or a sender to one of the daemon's UDP listeners can do to crash zebra-rs,
  stall a protocol, or change routing state;
- a local user without admin rights gaining admin through the vty socket or
  `vtypam`, or reading secrets from the configuration.

These are not:

- problems that need admin access on the vty, a malicious configuration file,
  or control of the kernel;
- volumetric flooding of a listener.
