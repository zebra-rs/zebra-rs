//! bgp-bench — synthetic BGP load generator for zebra-rs.
//!
//! Drives convergence benchmarks for the BGP RIB sharding work
//! (`docs/design/bgp-rib-sharding-plan.md` Phase 0): N sender
//! sessions blast a shared prefix set at the daemon (RIB-FIB ratio =
//! number of senders), R receiver sessions count the re-advertised
//! routes, and the headline number is blast-start → last UPDATE byte
//! at the slowest receiver.
//!
//! Packet encoding reuses the daemon's own `bgp_packet` crate, so the
//! generated wire format is exactly what zebra-rs itself emits.
//!
//! Two subcommands:
//! - `emit-config` prints the matching zebra-rs YAML config for the
//!   bench topology (port, adv-interval, one neighbor per session).
//! - `run` executes the benchmark against a running daemon.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::{Buf, BytesMut};
use clap::{Args, Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use bgp_packet::{
    Afi, AfiSafi, As4Path, BGP_HEADER_LEN, BGP_PACKET_LEN, BgpAttr, BgpCap, BgpHeader, BgpNexthop,
    BgpType, CapAs4, CapMultiProtocol, Ipv4Nlri, Med, OpenPacket, Origin, Safi, UpdatePacket,
};

/// Sender sessions bind 127.0.0.(SENDER_HOST_BASE + i).
const SENDER_HOST_BASE: u8 = 10;
/// Receiver sessions bind 127.0.0.(RECEIVER_HOST_BASE + j).
const RECEIVER_HOST_BASE: u8 = 200;
/// Sender i speaks AS (SENDER_AS_BASE + i).
const SENDER_AS_BASE: u32 = 65100;
/// Receiver j speaks AS (RECEIVER_AS_BASE + j).
const RECEIVER_AS_BASE: u32 = 65200;

#[derive(Parser)]
#[command(about = "Synthetic BGP load generator for zebra-rs benchmarks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the zebra-rs YAML config matching the bench topology.
    EmitConfig(EmitArgs),
    /// Run the benchmark against a running zebra-rs.
    Run(RunArgs),
}

/// Outbound policy attached to each receiver, to exercise the egress
/// out-policy build — the per-peer work the peer-task vs update-group
/// comparison turns on (the design memo puts it at ~75% of egress CPU).
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutPolicy {
    /// No out-policy; egress is a trivial copy of the Loc-RIB attr.
    None,
    /// One shared policy on every receiver → all receivers fall in ONE
    /// update-group. Coalescing-favorable (the route-reflector case):
    /// peer-task OFF builds+encodes once and replicates; ON re-does it
    /// per peer.
    Shared,
    /// A distinct policy per receiver → one update-group EACH. Diversity-
    /// favorable: neither model can coalesce, so the per-peer parallel
    /// build (peer-task ON) is free to win on many cores.
    Distinct,
}

#[derive(Args)]
struct EmitArgs {
    /// Daemon's AS number.
    #[arg(long, default_value_t = 65001)]
    daemon_as: u32,
    /// Daemon's router-id.
    #[arg(long, default_value = "10.255.0.1")]
    router_id: Ipv4Addr,
    /// BGP listen port (`router bgp port`) — non-privileged default
    /// so the daemon can run without root.
    #[arg(long, default_value_t = 1179)]
    port: u16,
    #[arg(long, default_value_t = 4)]
    senders: u8,
    #[arg(long, default_value_t = 1)]
    receivers: u8,
    /// MRAI for both peer types (`router bgp timer adv-interval`).
    /// 1s keeps debounce quantization out of the measurement.
    #[arg(long, default_value_t = 1)]
    adv_interval: u16,
    /// Emit `no-fib-install false` — i.e. let best paths go to the
    /// kernel FIB. Default is suppressed: without CAP_NET_ADMIN every
    /// install fails with per-route EPERM noise that pollutes the
    /// measurement, and the BGP-loop benchmark targets the control
    /// plane. Enable for a with-FIB run under root.
    #[arg(long)]
    fib_install: bool,
    /// Outbound policy applied to every receiver (set MED + AS-path-
    /// prepend, permit-all). `shared` puts all receivers in one update-
    /// group (coalescing case); `distinct` gives each its own (diversity
    /// case). `none` is a trivial-egress baseline.
    #[arg(long, value_enum, default_value = "none")]
    out_policy: OutPolicy,
}

/// eBGP AS prepended by the bench out-policy (distinct mode offsets per
/// receiver). Kept clear of the sender/receiver AS ranges.
const PREPEND_AS_BASE: u32 = 64600;

#[derive(Args)]
struct RunArgs {
    /// Daemon address:port (the `router bgp port` from emit-config).
    #[arg(long, default_value = "127.0.0.1:1179")]
    target: String,
    #[arg(long, default_value_t = 4)]
    senders: u8,
    #[arg(long, default_value_t = 1)]
    receivers: u8,
    /// Unique prefixes; every sender advertises the same set, so the
    /// RIB-FIB ratio equals --senders. Max 2^24 (carved from 10/8).
    #[arg(long, default_value_t = 100_000)]
    prefixes: u32,
    /// Distinct attribute buckets per sender (prefix k uses bucket
    /// k % attr-buckets, varying MED). Controls UPDATE packing.
    #[arg(long, default_value_t = 16)]
    attr_buckets: u32,
    /// Receiver is converged once it saw >= the expected prefix count
    /// and the line stayed quiet this long.
    #[arg(long, default_value_t = 3000)]
    quiet_ms: u64,
    /// Hard cap on the whole measurement.
    #[arg(long, default_value_t = 600)]
    timeout_secs: u64,
    /// Emit a single-line JSON result instead of the human summary.
    #[arg(long)]
    json: bool,
}

fn sender_addr(i: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, SENDER_HOST_BASE + i)
}

fn receiver_addr(j: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, RECEIVER_HOST_BASE + j)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::EmitConfig(args) => emit_config(&args),
        Cmd::Run(args) => tokio::runtime::Runtime::new()?.block_on(run(args)),
    }
}

// ── emit-config ──

/// Emit a `zebra-rs.conf` for the bench topology. The daemon loads
/// `<yang-dir>/../zebra-rs.conf` at startup; the loader accepts flat
/// semicolon-terminated statements (each becomes one `set` command).
fn emit_config(args: &EmitArgs) -> Result<()> {
    assert_addr_capacity(args.senders, args.receivers)?;
    let mut out = String::new();
    out.push_str(&format!(
        "router bgp global as {};\n\
         router bgp global router-id {};\n\
         router bgp port {};\n\
         router bgp timer adv-interval ibgp {};\n\
         router bgp timer adv-interval ebgp {};\n",
        args.daemon_as, args.router_id, args.port, args.adv_interval, args.adv_interval,
    ));
    if !args.fib_install {
        out.push_str("router bgp global no-fib-install true;\n");
    }

    // Out-policy definitions (before the neighbors that reference them).
    match args.out_policy {
        OutPolicy::None => {}
        OutPolicy::Shared => push_policy(&mut out, "bench-out", 100, PREPEND_AS_BASE, 2),
        OutPolicy::Distinct => {
            for j in 0..args.receivers {
                push_policy(
                    &mut out,
                    &format!("bench-out-{j}"),
                    100 + j as u32,
                    PREPEND_AS_BASE + j as u32,
                    2,
                );
            }
        }
    }

    // Senders inject only; no out-policy on them (they drain-and-discard).
    for i in 0..args.senders {
        push_neighbor(&mut out, sender_addr(i), SENDER_AS_BASE + i as u32, None);
    }
    // Receivers are the fan-out set we "reflect to" and measure; the
    // out-policy lives here so its build cost is on the measured path.
    for j in 0..args.receivers {
        let policy = match args.out_policy {
            OutPolicy::None => None,
            OutPolicy::Shared => Some("bench-out".to_string()),
            OutPolicy::Distinct => Some(format!("bench-out-{j}")),
        };
        push_neighbor(
            &mut out,
            receiver_addr(j),
            RECEIVER_AS_BASE + j as u32,
            policy.as_deref(),
        );
    }
    print!("{out}");
    Ok(())
}

/// Emit one neighbor: remote-as, ipv4-unicast enabled, and `passive-mode`.
/// Passive is essential at scale — without it the daemon *also* dials each
/// neighbor's address on port 179, and that outbound attempt collides with
/// the bench's inbound session (BGP §6.8 collision resolution), resetting
/// sessions once more than a handful of receivers are configured. Passive =
/// the daemon only accepts; the bench is always the dialer.
fn push_neighbor(out: &mut String, addr: Ipv4Addr, asn: u32, out_policy: Option<&str>) {
    out.push_str(&format!(
        "router bgp neighbor {addr} remote-as {asn};\n\
         router bgp neighbor {addr} afi-safi ipv4 enabled true;\n\
         router bgp neighbor {addr} transport passive-mode true;\n",
    ));
    if let Some(name) = out_policy {
        out.push_str(&format!("router bgp neighbor {addr} policy out {name};\n"));
    }
}

/// Emit a permit-all out-policy that sets MED and prepends `prepend_as`
/// `repeat` times. The prepend forces an AS_PATH rebuild per prefix per
/// advertisement, so the out-policy application is real work on the egress
/// path — exactly the per-peer cost the peer-task vs update-group benchmark
/// is comparing. A single permit entry with no match clause passes every
/// prefix (verified: a deny-all twin zeroes the receiver's routes).
fn push_policy(out: &mut String, name: &str, med: u32, prepend_as: u32, repeat: u8) {
    out.push_str(&format!(
        "policy {name} entry 10 action permit;\n\
         policy {name} entry 10 set med set {med};\n\
         policy {name} entry 10 set as-path-prepend asn {prepend_as};\n\
         policy {name} entry 10 set as-path-prepend repeat {repeat};\n",
    ));
}

fn assert_addr_capacity(senders: u8, receivers: u8) -> Result<()> {
    if senders == 0 {
        bail!("--senders must be >= 1");
    }
    if SENDER_HOST_BASE.checked_add(senders).is_none()
        || SENDER_HOST_BASE + senders > RECEIVER_HOST_BASE
    {
        bail!("too many senders for the 127.0.0.x address plan");
    }
    if receivers == 0 || RECEIVER_HOST_BASE.checked_add(receivers).is_none() {
        bail!("--receivers must be in 1..={}", 255 - RECEIVER_HOST_BASE);
    }
    Ok(())
}

// ── BGP session plumbing ──

fn keepalive_bytes() -> BytesMut {
    BgpHeader::new(BgpType::Keepalive, BGP_HEADER_LEN).into()
}

/// [`establish`] with retries: a freshly started daemon may accept
/// and reset connections for a few seconds while the config commit
/// is still materializing peers.
async fn establish_retry(
    local: Ipv4Addr,
    target: SocketAddr,
    asn: u32,
    hold_time: u16,
) -> Result<(OwnedReadHalf, OwnedWriteHalf)> {
    let mut last_err = None;
    for _ in 0..20 {
        match establish(local, target, asn, hold_time).await {
            Ok(halves) => return Ok(halves),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last_err.expect("at least one attempt ran"))
}

/// Open a session from `local` to `target` speaking `asn`, and drive
/// it to Established (OPEN sent, peer OPEN + KEEPALIVE seen, our
/// KEEPALIVE sent). The peer's BGP identifier is `local`, which is
/// unique per session by the address plan.
async fn establish(
    local: Ipv4Addr,
    target: SocketAddr,
    asn: u32,
    hold_time: u16,
) -> Result<(OwnedReadHalf, OwnedWriteHalf)> {
    let sock = TcpSocket::new_v4()?;
    sock.bind(SocketAddr::new(IpAddr::V4(local), 0))
        .with_context(|| format!("bind {local}"))?;
    let stream = sock
        .connect(target)
        .await
        .with_context(|| format!("connect {local} -> {target}"))?;
    stream.set_nodelay(true)?;
    let (mut rd, mut wr) = stream.into_split();

    let mut cap = BgpCap::default();
    cap.mp.insert(
        AfiSafi::new(Afi::Ip, Safi::Unicast),
        CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast),
    );
    cap.as4 = Some(CapAs4::new(asn));
    let open = OpenPacket::new(
        BgpHeader::new(BgpType::Open, BGP_HEADER_LEN),
        asn.try_into().unwrap_or(23456), // AS_TRANS if asn > 65535
        hold_time,
        &local,
        cap,
    );
    let bytes: BytesMut = open.into();
    wr.write_all(&bytes).await?;

    let mut buf = BytesMut::with_capacity(64 * 1024);
    let mut got_open = false;
    let mut got_keepalive = false;
    while !(got_open && got_keepalive) {
        if let Some((typ, _body)) = next_message(&mut buf) {
            match typ {
                1 => {
                    got_open = true;
                    wr.write_all(&keepalive_bytes()).await?;
                }
                4 => got_keepalive = true,
                3 => bail!("daemon sent NOTIFICATION during open (local {local})"),
                _ => {} // UPDATEs before our count starts are impossible pre-Established
            }
            continue;
        }
        if rd.read_buf(&mut buf).await? == 0 {
            bail!("daemon closed connection during open (local {local})");
        }
    }
    Ok((rd, wr))
}

/// Pop one complete BGP message off the front of `buf`, returning
/// `(type, body)` — body excludes the 19-byte header. `None` when the
/// buffer holds less than one full message.
fn next_message(buf: &mut BytesMut) -> Option<(u8, BytesMut)> {
    if buf.len() < 19 {
        return None;
    }
    let len = u16::from_be_bytes([buf[16], buf[17]]) as usize;
    if len < 19 || buf.len() < len {
        return None;
    }
    let typ = buf[18];
    let mut msg = buf.split_to(len);
    msg.advance(19);
    Some((typ, msg))
}

/// Count announced and withdrawn NLRI prefixes in one UPDATE body.
/// AddPath is never negotiated by this tool, so NLRIs are plain
/// `(len, prefix)` — no path-id prefix.
fn count_update_nlri(body: &[u8]) -> (u64, u64) {
    fn count_prefixes(mut nlri: &[u8]) -> u64 {
        let mut n = 0;
        while !nlri.is_empty() {
            let plen = nlri[0] as usize;
            let bytes = 1 + plen.div_ceil(8);
            if nlri.len() < bytes {
                break; // malformed; stop counting rather than panic
            }
            nlri = &nlri[bytes..];
            n += 1;
        }
        n
    }
    if body.len() < 4 {
        return (0, 0);
    }
    let wlen = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + wlen + 2 {
        return (0, 0);
    }
    let withdrawn = count_prefixes(&body[2..2 + wlen]);
    let alen = u16::from_be_bytes([body[2 + wlen], body[3 + wlen]]) as usize;
    let nlri_off = 4 + wlen + alen;
    if body.len() < nlri_off {
        return (0, withdrawn);
    }
    let announced = count_prefixes(&body[nlri_off..]);
    (announced, withdrawn)
}

// ── sender ──

/// Pre-encode sender `i`'s full blast: `prefixes` NLRIs spread over
/// `attr_buckets` attribute buckets (MED = bucket index), packed by
/// the daemon's own `UpdatePacket::pop_ipv4` encoder.
fn build_blast(prefixes: u32, attr_buckets: u32, local: Ipv4Addr, asn: u32) -> Vec<BytesMut> {
    let buckets = attr_buckets.clamp(1, prefixes.max(1));
    let mut by_bucket: Vec<Vec<Ipv4Nlri>> = vec![Vec::new(); buckets as usize];
    for k in 0..prefixes {
        let addr = Ipv4Addr::new(10, (k >> 16) as u8, (k >> 8) as u8, k as u8);
        let prefix = ipnet::Ipv4Net::new(addr, 32).expect("/32 is always valid");
        by_bucket[(k % buckets) as usize].push(Ipv4Nlri { id: 0, prefix });
    }
    let mut out = Vec::new();
    for (b, nlris) in by_bucket.into_iter().enumerate() {
        if nlris.is_empty() {
            continue;
        }
        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.aspath = Some(As4Path::from(vec![asn]));
        attr.nexthop = Some(BgpNexthop::Ipv4(local));
        attr.med = Some(Med::new(b as u32));
        let mut update = UpdatePacket::with_max_packet_size(BGP_PACKET_LEN);
        update.bgp_attr = Some(attr);
        update.ipv4_update = nlris;
        while let Some(bytes) = update.pop_ipv4() {
            out.push(bytes);
        }
    }
    out
}

/// Discard everything the daemon sends a sender (its own
/// re-advertisements); an undrained socket would stall the daemon's
/// writer once the TCP window fills.
async fn drain_forever(mut rd: OwnedReadHalf) {
    let mut buf = BytesMut::with_capacity(256 * 1024);
    loop {
        buf.clear();
        match rd.read_buf(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

async fn sender_blast(mut wr: OwnedWriteHalf, updates: Vec<BytesMut>) -> Result<Duration> {
    let start = Instant::now();
    for u in &updates {
        wr.write_all(u).await?;
    }
    let took = start.elapsed();
    // Keep the session alive (hold time is negotiated down to the
    // daemon's 180s default) until the bench tears everything down.
    let ka = keepalive_bytes();
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        if wr.write_all(&ka).await.is_err() {
            return Ok(took);
        }
    }
}

// ── receiver ──

struct ReceiverReport {
    announced: u64,
    withdrawn: u64,
    /// Last announce seen, relative to T0. None if nothing arrived.
    last_announce_rel: Option<Duration>,
    converged: bool,
}

async fn receiver_count(
    mut rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    t0: Instant,
    expected: u64,
    quiet: Duration,
    deadline: Instant,
) -> Result<ReceiverReport> {
    // Keepalive ticker on the write half; aborted when we return.
    let ka_task = tokio::spawn(async move {
        let mut wr = wr;
        let ka = keepalive_bytes();
        loop {
            tokio::time::sleep(Duration::from_secs(20)).await;
            if wr.write_all(&ka).await.is_err() {
                return;
            }
        }
    });

    let mut buf = BytesMut::with_capacity(1 << 20);
    let mut announced: u64 = 0;
    let mut withdrawn: u64 = 0;
    let mut last_announce: Option<Instant> = None;
    let converged = 'outer: loop {
        while let Some((typ, body)) = next_message(&mut buf) {
            match typ {
                2 => {
                    let (a, w) = count_update_nlri(&body);
                    announced += a;
                    withdrawn += w;
                    if a > 0 {
                        last_announce = Some(Instant::now());
                    }
                }
                3 => bail!("daemon sent NOTIFICATION to receiver"),
                _ => {}
            }
        }
        if announced >= expected
            && let Some(last) = last_announce
            && last.elapsed() >= quiet
        {
            break 'outer true;
        }
        if Instant::now() >= deadline {
            break 'outer false;
        }
        // read_buf is cancel-safe: on timeout no bytes are lost, we
        // just come back to re-check the convergence conditions.
        match tokio::time::timeout(Duration::from_millis(100), rd.read_buf(&mut buf)).await {
            Ok(Ok(0)) => break 'outer false,
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(e)) => return Err(e.into()),
        }
    };
    ka_task.abort();
    Ok(ReceiverReport {
        announced,
        withdrawn,
        last_announce_rel: last_announce.map(|t| t.duration_since(t0)),
        converged,
    })
}

// ── run ──

async fn run(args: RunArgs) -> Result<()> {
    assert_addr_capacity(args.senders, args.receivers)?;
    if args.prefixes == 0 || args.prefixes > 1 << 24 {
        bail!("--prefixes must be in 1..=2^24");
    }
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("bad --target {}", args.target))?;
    let quiet = Duration::from_millis(args.quiet_ms);
    let hold_time = 240u16;

    // Pre-encode every sender's blast before any session exists, so
    // encode cost stays out of the measurement window.
    let blasts: Vec<Vec<BytesMut>> = (0..args.senders)
        .map(|i| {
            build_blast(
                args.prefixes,
                args.attr_buckets,
                sender_addr(i),
                SENDER_AS_BASE + i as u32,
            )
        })
        .collect();
    let blast_msgs: usize = blasts.iter().map(Vec::len).sum();
    let blast_bytes: usize = blasts
        .iter()
        .flat_map(|b| b.iter().map(BytesMut::len))
        .sum();

    // Establish receivers first so nothing re-advertised is ever
    // missed, then the senders.
    let mut receivers = Vec::new();
    for j in 0..args.receivers {
        receivers.push(
            establish_retry(
                receiver_addr(j),
                target,
                RECEIVER_AS_BASE + j as u32,
                hold_time,
            )
            .await?,
        );
    }
    let mut senders = Vec::new();
    for i in 0..args.senders {
        senders.push(
            establish_retry(sender_addr(i), target, SENDER_AS_BASE + i as u32, hold_time).await?,
        );
    }
    eprintln!(
        "bgp-bench: {} sender(s) + {} receiver(s) established; blasting {} prefixes x {} senders ({} UPDATEs, {:.1} MiB)",
        args.senders,
        args.receivers,
        args.prefixes,
        args.senders,
        blast_msgs,
        blast_bytes as f64 / (1024.0 * 1024.0),
    );

    // T0: measurement starts when the blast starts.
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(args.timeout_secs);

    let mut sender_tasks = Vec::new();
    for ((rd, wr), updates) in senders.into_iter().zip(blasts) {
        tokio::spawn(drain_forever(rd));
        sender_tasks.push(tokio::spawn(sender_blast(wr, updates)));
    }
    let mut receiver_tasks = Vec::new();
    for (rd, wr) in receivers {
        receiver_tasks.push(tokio::spawn(receiver_count(
            rd,
            wr,
            t0,
            args.prefixes as u64,
            quiet,
            deadline,
        )));
    }

    let mut reports = Vec::new();
    for task in receiver_tasks {
        reports.push(task.await.expect("receiver task panicked")?);
    }
    // Senders run a keepalive loop forever; sample their blast
    // durations without awaiting completion.
    for task in &sender_tasks {
        task.abort();
    }

    let all_converged = reports.iter().all(|r| r.converged);
    let convergence = reports
        .iter()
        .filter_map(|r| r.last_announce_rel)
        .max()
        .unwrap_or_default();
    let conv_secs = convergence.as_secs_f64();
    let unique_rate = if conv_secs > 0.0 {
        args.prefixes as f64 / conv_secs
    } else {
        0.0
    };

    if args.json {
        let last_rels: Vec<String> = reports
            .iter()
            .map(|r| {
                r.last_announce_rel
                    .map(|d| format!("{:.3}", d.as_secs_f64()))
                    .unwrap_or_else(|| "null".to_string())
            })
            .collect();
        println!(
            "{{\"senders\":{},\"receivers\":{},\"prefixes\":{},\"attr_buckets\":{},\"converged\":{},\"convergence_secs\":{:.3},\"unique_prefixes_per_sec\":{:.0},\"receiver_last_announce_secs\":[{}],\"receiver_announced\":[{}],\"receiver_withdrawn\":[{}]}}",
            args.senders,
            args.receivers,
            args.prefixes,
            args.attr_buckets,
            all_converged,
            conv_secs,
            unique_rate,
            last_rels.join(","),
            reports
                .iter()
                .map(|r| r.announced.to_string())
                .collect::<Vec<_>>()
                .join(","),
            reports
                .iter()
                .map(|r| r.withdrawn.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    } else {
        println!("── bgp-bench result ──");
        println!(
            "topology     : {} senders x {} prefixes (RIB-FIB ratio {}), {} receivers",
            args.senders, args.prefixes, args.senders, args.receivers
        );
        for (j, r) in reports.iter().enumerate() {
            println!(
                "receiver {j}   : announced {} withdrawn {} last-announce {} converged {}",
                r.announced,
                r.withdrawn,
                r.last_announce_rel
                    .map(|d| format!("{:.3}s", d.as_secs_f64()))
                    .unwrap_or_else(|| "-".into()),
                r.converged,
            );
        }
        if all_converged {
            println!(
                "convergence  : {conv_secs:.3}s (blast start -> last announce at slowest receiver)"
            );
            println!("unique rate  : {unique_rate:.0} prefixes/s end-to-end");
        } else {
            println!(
                "convergence  : DID NOT CONVERGE within {}s (see per-receiver counts above)",
                args.timeout_secs
            );
        }
    }
    if !all_converged {
        std::process::exit(2);
    }
    Ok(())
}
