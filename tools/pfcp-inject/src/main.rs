//! `pfcp-inject` — a minimal PFCP/N4 SMF simulator.
//!
//! Drives the zebra-rs BGP MUP controller (`router bgp afi-safi
//! mobile-uplane mup-c`) in tests: it sends a PFCP Association Setup
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
use rs_pfcp::ie::create_far::CreateFar;
use rs_pfcp::ie::create_pdr::CreatePdrBuilder;
use rs_pfcp::ie::destination_interface::Interface;
use rs_pfcp::ie::f_teid::FteidBuilder;
use rs_pfcp::ie::far_id::FarId;
use rs_pfcp::ie::fseid::Fseid;
use rs_pfcp::ie::network_instance::NetworkInstance;
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

    /// Access-side GTP-U endpoint (F-TEID) address.
    #[arg(long, default_value = "10.0.0.1")]
    endpoint: IpAddr,

    /// Network Instance (APN/DNN) — matched against a VRF `mobile-uplane`
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
    let fteid = {
        let b = FteidBuilder::new().teid(args.teid);
        match args.endpoint {
            IpAddr::V4(v4) => b.ipv4(v4),
            IpAddr::V6(v6) => b.ipv6(v6),
        }
        .build()
        .context("build F-TEID")?
    };
    let pdi = PdiBuilder::new(SourceInterface::new(SourceInterfaceValue::Access))
        .f_teid(fteid)
        .ue_ip_address(UeIpAddress::new(args.ue_ipv4, args.ue_ipv6))
        .network_instance(NetworkInstance::new(&args.network_instance))
        .build()
        .context("build PDI")?;
    let pdr = CreatePdrBuilder::new(PdrId::new(1))
        .precedence(Precedence::new(100))
        .pdi(pdi)
        .far_id(FarId::new(1))
        .build()
        .context("build Create PDR")?;
    let far = CreateFar::builder(FarId::new(1))
        .forward_to(Interface::Core)
        .build()
        .context("build Create FAR")?;
    let establish = SessionEstablishmentRequestBuilder::new(args.seid, 2u32)
        .node_id(args.node_id)
        .fseid(args.seid, args.node_id)
        .create_pdrs(vec![pdr.to_ie()])
        .create_fars(vec![far.to_ie()])
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
