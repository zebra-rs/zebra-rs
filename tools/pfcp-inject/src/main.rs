//! `pfcp-inject` — a minimal PFCP/N4 SMF simulator.
//!
//! Drives the zebra-rs BGP MUP controller (`router bgp afi-safi
//! mup mup-c`) in tests: it sends a PFCP Association Setup
//! Request followed by a Session Establishment Request describing one
//! mobile session (UE IP, access-side F-TEID, Network Instance), so the
//! controller learns the session and originates a MUP Session-Transformed
//! route. With `--delete` it also tears the session down again.
//!
//! It is intentionally tiny and synchronous — the `rs-pfcp` crate is a
//! pure codec, and the only transport we need is a single blocking UDP
//! socket. Used from the `@bgp_mup_e2e` BDD feature via
//! `I execute "pfcp-inject …" in namespace "…"`, and runnable by hand
//! against a locally-spawned controller.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use clap::Parser;

use rs_pfcp::ie::IeType;
use rs_pfcp::ie::apply_action::ApplyAction;
use rs_pfcp::ie::create_far::CreateFar;
use rs_pfcp::ie::create_pdr::CreatePdrBuilder;
use rs_pfcp::ie::destination_interface::{DestinationInterface, Interface};
use rs_pfcp::ie::f_teid::FteidBuilder;
use rs_pfcp::ie::far_id::FarId;
use rs_pfcp::ie::forwarding_parameters::ForwardingParameters;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::network_instance::NetworkInstance;
use rs_pfcp::ie::outer_header_creation::OuterHeaderCreation;
use rs_pfcp::ie::pdi::PdiBuilder;
use rs_pfcp::ie::pdr_id::PdrId;
use rs_pfcp::ie::precedence::Precedence;
use rs_pfcp::ie::source_interface::{SourceInterface, SourceInterfaceValue};
use rs_pfcp::ie::ue_ip_address::UeIpAddress;
use rs_pfcp::message::association_setup_request::AssociationSetupRequestBuilder;
use rs_pfcp::message::session_deletion_request::SessionDeletionRequestBuilder;
use rs_pfcp::message::session_establishment_request::SessionEstablishmentRequestBuilder;
use rs_pfcp::message::{self, Message, MsgType};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Minimal PFCP/N4 SMF simulator for the zebra-rs MUP controller"
)]
struct Args {
    /// Controller PFCP listener address.
    #[arg(long)]
    target: IpAddr,

    /// Controller PFCP listener port.
    #[arg(long, default_value_t = 8805)]
    port: u16,

    /// Our (the SMF's) PFCP Node ID.
    #[arg(long, default_value = "10.0.0.99")]
    node_id: IpAddr,

    /// UE IPv4 address assigned to the session.
    #[arg(long)]
    ue_ipv4: Option<Ipv4Addr>,

    /// UE IPv6 address assigned to the session.
    #[arg(long)]
    ue_ipv6: Option<Ipv6Addr>,

    /// Access-side GTP-U TEID (decimal, or `0x`-prefixed hex).
    #[arg(long, default_value_t = 0x1234_5678, value_parser = parse_u32)]
    teid: u32,

    /// Access-side GTP-U endpoint (F-TEID) address. Used for the Type-1 ST
    /// (access side).
    #[arg(long, default_value = "10.0.0.1")]
    endpoint: IpAddr,

    /// Core-side GTP-U endpoint (F-TEID) address, used for the Type-2 ST
    /// (core side). When set, a second `SourceInterface=Core` PDR is added so
    /// the controller can distinguish the access and core endpoints; omit for
    /// a single-endpoint session (Type-2 falls back to the access endpoint).
    #[arg(long)]
    core_endpoint: Option<IpAddr>,

    /// Core-side GTP-U TEID (decimal, or `0x`-prefixed hex). Only used when
    /// `--core-endpoint` is set.
    #[arg(long, default_value_t = 0x8765_4321, value_parser = parse_u32)]
    core_teid: u32,

    /// The UPF's own uplink *receive* F-TEID address, CP-allocated
    /// (TS 29.244 CH=0): sent in the Access PDR's PDI local F-TEID, the way
    /// free5GC programs a UPF's N3 tunnel. Authoritative for the Type-2 ST
    /// on the controller. Requires `--n3-teid`.
    #[arg(long, requires = "n3_teid")]
    n3_endpoint: Option<IpAddr>,

    /// TEID paired with `--n3-endpoint` (decimal, or `0x`-prefixed hex).
    #[arg(long, value_parser = parse_u32)]
    n3_teid: Option<u32>,

    /// Network Instance (APN/DNN) — matched against a VRF `mup`
    /// config on the controller.
    #[arg(long, default_value = "access")]
    network_instance: String,

    /// CP-side F-SEID we advertise in the Session Establishment Request.
    #[arg(long, default_value_t = 1)]
    seid: u64,

    /// Also delete the session after establishing it.
    #[arg(long, default_value_t = false)]
    delete: bool,

    /// Per-exchange receive timeout (seconds).
    #[arg(long, default_value_t = 3)]
    timeout: u64,
}

/// Parse a `u32` accepting either decimal or a `0x`-prefixed hex string.
fn parse_u32(s: &str) -> std::result::Result<u32, String> {
    let s = s.trim();
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    parsed.map_err(|e| format!("invalid u32 `{s}`: {e}"))
}

/// A Create FAR that forwards to `dest` and GTP-U-encapsulates toward
/// `(teid, addr)` — the wire shape an SMF programs a gNB (Dest = Access) or
/// core (Dest = Core) GTP tunnel with. The MUP controller reads the ST-route
/// endpoints from these FAR Outer Header Creation IEs, not the PDI F-TEIDs.
fn gtpu_far(far_id: u32, dest: Interface, teid: u32, addr: IpAddr) -> Result<CreateFar> {
    let ohc = match addr {
        IpAddr::V4(v4) => OuterHeaderCreation::gtpu_ipv4(teid, v4),
        IpAddr::V6(v6) => OuterHeaderCreation::gtpu_ipv6(teid, v6),
    };
    let fp =
        ForwardingParameters::new(DestinationInterface::new(dest)).with_outer_header_creation(ohc);
    CreateFar::builder(FarId::new(far_id))
        .apply_action(ApplyAction::FORW)
        .forwarding_parameters(fp)
        .build()
        .context("build Create FAR")
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.ue_ipv4.is_none() && args.ue_ipv6.is_none() {
        bail!("at least one of --ue-ipv4 / --ue-ipv6 is required");
    }

    let dst = SocketAddr::new(args.target, args.port);
    let bind: SocketAddr = match args.target {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind).context("bind UDP socket")?;
    sock.set_read_timeout(Some(Duration::from_secs(args.timeout)))?;
    sock.connect(dst)
        .with_context(|| format!("connect {dst}"))?;

    // 1. Association Setup.
    let assoc = AssociationSetupRequestBuilder::new(1u32)
        .node_id(args.node_id)
        .recovery_time_stamp(SystemTime::now())
        .build();
    let resp = exchange(&sock, &assoc.marshal(), "Association Setup")?;
    expect_type(&resp, MsgType::AssociationSetupResponse)?;
    println!("pfcp-inject: association established with {dst}");

    // 2. Session Establishment.
    // The UE prefix + Network Instance ride in a PDR; the GTP-U tunnels ride
    // in the FARs' Outer Header Creation — the gNB (access) tunnel for the
    // Type-1 ST route, an optional core-facing tunnel for the Type-2 ST route.
    // This mirrors the real 5G model (the gNB F-TEID is programmed in the
    // downlink FAR, not the PDI), which the controller extracts from.
    let mut pdi_builder = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
        .ue_ip_address(UeIpAddress::new(args.ue_ipv4, args.ue_ipv6))
        .network_instance(NetworkInstance::new(&args.network_instance));
    // The CP-allocated local N3 F-TEID (free5GC style): the uplink tunnel
    // the UPF must terminate, carried in the Access PDR's PDI.
    if let (Some(ep), Some(teid)) = (args.n3_endpoint, args.n3_teid) {
        let b = FteidBuilder::new().teid(teid);
        let b = match ep {
            IpAddr::V4(v4) => b.ipv4(v4),
            IpAddr::V6(v6) => b.ipv6(v6),
        };
        pdi_builder = pdi_builder.f_teid(b.build().context("build PDI F-TEID")?);
    }
    let pdi = pdi_builder.build().context("build PDI")?;
    let pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(pdi)
        .far_id(FarId::new(1))
        .build()
        .context("build Create PDR")?;
    // gNB (access) tunnel → Type-1 ST route.
    let gnb_far = gtpu_far(1, Interface::Access, args.teid, args.endpoint)?;
    let mut create_fars = vec![gnb_far.to_ie()];
    // Optional core-facing GTP tunnel (e.g. N9) → Type-2 ST route.
    if let Some(core_endpoint) = args.core_endpoint {
        let core_far = gtpu_far(2, Interface::Core, args.core_teid, core_endpoint)?;
        create_fars.push(core_far.to_ie());
    }
    let establish = SessionEstablishmentRequestBuilder::new(args.seid, 2u32)
        .node_id(args.node_id)
        .fseid(args.seid, args.node_id)
        .create_pdrs(vec![pdr.to_ie()])
        .create_fars(create_fars)
        .build()
        .context("build Session Establishment Request")?;
    let resp = exchange(&sock, &establish.marshal(), "Session Establishment")?;
    expect_type(&resp, MsgType::SessionEstablishmentResponse)?;
    // The controller returns its local SEID in the F-SEID; the CP must
    // use it as the message SEID when addressing this session later.
    let up_seid = fseid_of(&resp).unwrap_or(args.seid);
    println!(
        "pfcp-inject: session established (UP F-SEID 0x{up_seid:016x}) ni={} teid=0x{:08x}",
        args.network_instance, args.teid
    );

    // 3. Optional Session Deletion.
    if args.delete {
        let del = SessionDeletionRequestBuilder::new(up_seid, 3u32).build();
        let resp = exchange(&sock, &del.marshal(), "Session Deletion")?;
        expect_type(&resp, MsgType::SessionDeletionResponse)?;
        println!("pfcp-inject: session 0x{up_seid:016x} deleted");
    }

    Ok(())
}

/// Send one request and read the matching response.
fn exchange(sock: &UdpSocket, req: &[u8], what: &str) -> Result<Vec<u8>> {
    sock.send(req).with_context(|| format!("send {what}"))?;
    let mut buf = vec![0u8; 65535];
    let n = sock
        .recv(&mut buf)
        .with_context(|| format!("no {what} response (timeout?)"))?;
    buf.truncate(n);
    Ok(buf)
}

/// Parse a response and assert its message type.
fn expect_type(bytes: &[u8], want: MsgType) -> Result<()> {
    let msg = message::parse(bytes).context("parse PFCP response")?;
    if msg.msg_type() != want {
        bail!("expected {want:?}, got {:?}", msg.msg_type());
    }
    Ok(())
}

/// Extract the F-SEID (the controller's UP SEID) from a response.
fn fseid_of(bytes: &[u8]) -> Option<u64> {
    let msg = message::parse(bytes).ok()?;
    let ie = msg.ies(IeType::Fseid).next()?;
    Some(Fseid::unmarshal(&ie.payload).ok()?.seid.value())
}
