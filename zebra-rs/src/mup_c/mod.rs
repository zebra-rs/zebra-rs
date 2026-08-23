//! BGP MUP Controller (MUP-C) — Mobile User Plane controller.
//!
//! Implements the controller half of BGP MUP
//! (`draft-mpmz-bess-mup-safi`, SAFI 85). Per the draft §3.3.7/§3.3.10 a
//! MUP Controller learns per-session mobile state through a "northbound
//! API" (left out of scope by the draft) and originates Type-1 / Type-2
//! Session-Transformed routes from it. zebra-rs uses **PFCP / N4** (3GPP
//! TS 29.244, via the `rs-pfcp` codec) as that northbound, terminating it
//! as a **UP-node (UPF role)**: an external SMF/CP programs the controller
//! with Association Setup + Session Establishment/Modification/Deletion +
//! Heartbeat.
//!
//! The controller is **configured under the BGP instance** at
//! `router bgp mup-c { enable; pfcp … }` and is
//! spawned by the BGP task, which hands it the BGP instance's own
//! `mpsc::Sender<crate::bgp::inst::Message>` — exactly the way a BGP VRF
//! instance receives the global BGP channel. The controller reports
//! neutral session/association events back over that channel
//! ([`inst::MupCEvent`]); the BGP task records them for
//! `show bgp mup-c` (this slice) and originates MUP routes
//! from them (follow-up).
//!
//! Module layout: [`inst`] owns the task + the BGP-facing types,
//! [`pfcp`] the PFCP socket + message handling, [`session`] / [`assoc`]
//! the per-session and per-association tables.

pub mod assoc;
pub mod inst;
pub mod pfcp;
pub mod session;
