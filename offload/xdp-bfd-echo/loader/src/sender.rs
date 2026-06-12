//! BFD Echo **sender** datapath for the per-interface helper.
//!
//! eBPF/XDP can't originate packets, so the Echo *transmit* lives here in
//! userspace, driven by zebra-rs over the stdin/stdout line protocol (see
//! [`EchoEngine::handle_command`]). Per session we periodically transmit a
//! self-addressed Echo via an `AF_PACKET` raw socket; the peer's forwarding
//! plane loops it back inbound.
//!
//! **Detection is offloaded to the kernel.** The XDP program recognizes our
//! returning Echo (source ∈ `OUR_LOCAL_IPS`), arms / re-arms a per-session
//! `bpf_timer` keyed by discriminator in the `ECHO_TIMERS` map, and `XDP_DROP`s
//! the frame — so in steady state this socket never has to receive anything. If
//! returns stop for `tx-interval × detect-mult`, the timer fires in softirq and
//! sets the entry's `down` flag. The periodic tick here only *polls* that flag
//! (one map read per session) and reports `echo-down <discr>` to zebra-rs, which
//! drives the session Down (EchoFunctionFailed).
//!
//! The kernel timer only arms once the first return is seen, so a session whose
//! forwarding path is broken from the outset (Up, but Echo never returns) is
//! covered by a userspace bootstrap fallback: if the timer hasn't armed within
//! the detection time of `echo-add`, the tick reports `echo-down` itself.
//!
//! The same engine also fronts the **control-packet expiration watchdog**
//! (`detect-add <discr> <detect-us>` / `detect-del <discr>`): it seeds the
//! XDP `CONTROL_TIMERS` map entry whose `bpf_timer` the program re-arms on
//! every inbound BFD control packet for that discriminator, and the tick polls
//! the entry's `down` flag, reporting `detect-down <discr>` when control
//! packets stopped (RFC 5880 §6.8.4, evaluated in-kernel). There is no
//! transmit half — the daemon keeps sending its own control packets — so this
//! path needs no `AF_PACKET` socket. The same bootstrap fallback applies
//! before the first packet arms the kernel timer.
//!
//! The `AF_PACKET` socket (which needs `CAP_NET_RAW`) is opened lazily on the
//! first `echo-add`, so a reflector-only / watchdog-only / standalone run
//! never touches it.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use aya::Pod;
use aya::maps::{HashMap as BpfHashMap, MapData};
use log::{debug, warn};

/// Userspace mirror of the eBPF `DetectState` value shared by the
/// `ECHO_TIMERS` and `CONTROL_TIMERS` maps. Byte-identical layout
/// (`#[repr(C)]`, 32 bytes, 8-byte aligned). Userspace seeds an entry at
/// `echo-add` / `detect-add` with the `timer` zeroed (the kernel manages and
/// re-zeroes it; only XDP may `bpf_timer_init` it) and reads back `armed` /
/// `down` each tick.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DetectState {
    /// Opaque kernel `struct bpf_timer` (`[u64; 2]`). Never touched here.
    timer: [u64; 2],
    /// Detection time in nanoseconds; the timer's re-arm delay (set by us).
    detect_ns: u64,
    /// 1 once XDP has init'd + started the timer (it took over detection).
    armed: u8,
    /// 1 when the timer fired (tracked packets stopped). Polled here, reset by
    /// XDP on the next observed packet.
    down: u8,
    _pad: [u8; 6],
}

// SAFETY: `DetectState` is `#[repr(C)]`, `Copy`, and contains only integer
// fields with no padding beyond the explicit `_pad`, so it is safe to
// read/write as raw bytes to/from a BPF map (the contract of `aya::Pod`).
unsafe impl Pod for DetectState {}

impl DetectState {
    /// A fresh entry to seed: zeroed timer (only XDP may init it), the
    /// detection time, not yet armed, not down.
    fn seed(detect: Duration) -> Self {
        Self {
            timer: [0, 0],
            detect_ns: detect.as_nanos().min(u64::MAX as u128) as u64,
            armed: 0,
            down: 0,
            _pad: [0; 6],
        }
    }
}

/// Tags our Echo payload so the RX path only ever matches our own frames (a
/// peer's Echo carries the peer's own opaque payload). ASCII "zbfd".
const ECHO_MAGIC: u32 = 0x7a62_6664;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const BFD_ECHO_PORT: u16 = 3785;
const ECHO_TTL: u8 = 255;
const IPPROTO_UDP: u8 = 17;

const ETH_HLEN: usize = 14;
const IP_HLEN: usize = 20;
const IP6_HLEN: usize = 40;
const UDP_HLEN: usize = 8;
/// `{ magic:u32, discr:u32, seq:u32, tx_ts_us:u64 }`, big-endian.
const PAYLOAD_LEN: usize = 4 + 4 + 4 + 8;
const FRAME_LEN: usize = ETH_HLEN + IP_HLEN + UDP_HLEN + PAYLOAD_LEN;
/// IPv6 Echo frame length (Eth + 40-byte IPv6 header + UDP + payload).
const FRAME6_LEN: usize = ETH_HLEN + IP6_HLEN + UDP_HLEN + PAYLOAD_LEN;

/// Userspace key for the eBPF `OUR_LOCAL_IPS_V6` map: a 16-byte IPv6 address in
/// wire order. A newtype (not bare `[u8; 16]`) so we can implement `aya::Pod`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct In6Key([u8; 16]);

// SAFETY: `#[repr(C)]`, `Copy`, plain bytes with no padding — safe to read/write
// as raw map bytes (the `aya::Pod` contract).
unsafe impl Pod for In6Key {}

/// One originating Echo session, keyed by our local discriminator. `local` and
/// `peer` are both IPv4 or both IPv6 (the family of the protected adjacency).
struct EchoSession {
    local: IpAddr,
    peer: IpAddr,
    peer_mac: Option<[u8; 6]>,
    tx: Duration,
    detect: Duration,
    next_tx: Instant,
    /// When `echo-add` created this session — the start of the bootstrap window
    /// in which the kernel timer hasn't armed yet (no return seen).
    added: Instant,
    seq: u32,
    /// `echo-down` already reported for this session (don't re-report before the
    /// `echo-del` from zebra-rs arrives).
    down: bool,
}

/// One control-packet expiration watch, keyed by our local discriminator. The
/// timing itself lives in the kernel (`CONTROL_TIMERS`); this is only what the
/// poll loop needs: the bootstrap deadline and the reported-down latch.
struct DetectWatch {
    /// Detection time — the bootstrap fallback window from `added` until the
    /// first observed control packet arms the kernel timer.
    detect: Duration,
    /// When `detect-add` (re)created this watch.
    added: Instant,
    /// `detect-down` already reported (don't re-report before `detect-del`).
    down: bool,
}

pub struct EchoEngine {
    iface: String,
    ifindex: u32,
    /// `AF_PACKET` socket + our MAC, opened lazily on the first `echo-add`
    /// (needs CAP_NET_RAW). `None` until then — reflector-only runs never open it.
    io: Option<(OwnedFd, [u8; 6])>,
    /// Mirror of the XDP `OUR_LOCAL_IPS` map (key = `u32::from(Ipv4Addr)`).
    local_ips: BpfHashMap<MapData, u32, u8>,
    /// IPv6 mirror: the XDP `OUR_LOCAL_IPS_V6` map (key = 16-byte address).
    local_ips_v6: BpfHashMap<MapData, In6Key, u8>,
    /// The XDP `ECHO_TIMERS` map (key = discriminator). We seed an entry per
    /// session and poll its `down`/`armed` flags; the kernel owns the timer.
    timers: BpfHashMap<MapData, u32, DetectState>,
    /// The XDP `CONTROL_TIMERS` map (key = discriminator) — the control-packet
    /// expiration watchdog. Same seed/poll contract as `timers`.
    ctrl_timers: BpfHashMap<MapData, u32, DetectState>,
    /// Refcount of originating sessions per local IP (map entry added on first,
    /// removed on last).
    ip_refs: HashMap<IpAddr, u32>,
    sessions: HashMap<u32, EchoSession>,
    /// Active control-packet expiration watches, keyed by discriminator.
    detects: HashMap<u32, DetectWatch>,
}

impl EchoEngine {
    pub fn new(
        iface: &str,
        local_ips: BpfHashMap<MapData, u32, u8>,
        local_ips_v6: BpfHashMap<MapData, In6Key, u8>,
        timers: BpfHashMap<MapData, u32, DetectState>,
        ctrl_timers: BpfHashMap<MapData, u32, DetectState>,
    ) -> Result<Self> {
        Ok(Self {
            ifindex: if_nametoindex(iface)?,
            iface: iface.to_string(),
            io: None,
            local_ips,
            local_ips_v6,
            timers,
            ctrl_timers,
            ip_refs: HashMap::new(),
            sessions: HashMap::new(),
            detects: HashMap::new(),
        })
    }

    /// Teach the XDP guard one of our source IPs (so it recognises our looped-back
    /// Echo and drops it instead of re-reflecting). Family selects the map.
    fn local_ip_insert(&mut self, local: IpAddr) {
        match local {
            IpAddr::V4(a) => {
                if let Err(e) = self.local_ips.insert(u32::from(a), 1u8, 0) {
                    warn!("bfd echo sender: OUR_LOCAL_IPS insert {local}: {e}");
                }
            }
            IpAddr::V6(a) => {
                if let Err(e) = self.local_ips_v6.insert(In6Key(a.octets()), 1u8, 0) {
                    warn!("bfd echo sender: OUR_LOCAL_IPS_V6 insert {local}: {e}");
                }
            }
        }
    }

    /// Forget one of our source IPs (last originating session on it went away).
    fn local_ip_remove(&mut self, local: IpAddr) {
        match local {
            IpAddr::V4(a) => {
                let _ = self.local_ips.remove(&u32::from(a));
            }
            IpAddr::V6(a) => {
                let _ = self.local_ips_v6.remove(&In6Key(a.octets()));
            }
        }
    }

    /// Open the `AF_PACKET` socket on first use. Returns the raw fd + our MAC, or
    /// `None` if it failed (e.g. missing CAP_NET_RAW) — logged once.
    fn io(&mut self) -> Option<(i32, [u8; 6])> {
        if self.io.is_none() {
            match self.open_io() {
                Ok(io) => self.io = Some(io),
                Err(e) => {
                    warn!(
                        "bfd echo sender: cannot open AF_PACKET on {}: {e} (need CAP_NET_RAW)",
                        self.iface
                    );
                    return None;
                }
            }
        }
        self.io.as_ref().map(|(fd, mac)| (fd.as_raw_fd(), *mac))
    }

    fn open_io(&self) -> Result<(OwnedFd, [u8; 6])> {
        let fd = open_af_packet(self.ifindex)?;
        let mac = read_if_mac(&self.iface)?;
        Ok((fd, mac))
    }

    /// Handle one stdin line from zebra-rs.
    ///   `echo-add <discr> <local-ip> <peer-ip> <tx-us> <detect-mult>`
    ///   `echo-del <discr>`
    ///   `detect-add <discr> <detect-us>`
    ///   `detect-del <discr>`
    pub fn handle_command(&mut self, line: &str) {
        if let Err(e) = self.try_command(line) {
            warn!("bfd echo sender: bad command {line:?}: {e}");
        }
    }

    fn try_command(&mut self, line: &str) -> Result<()> {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("echo-add") => {
                let discr: u32 = it.next().context("discr")?.parse()?;
                // Accept either family; `local`/`peer` must match (both v4 or v6).
                let local: IpAddr = it.next().context("local")?.parse()?;
                let peer: IpAddr = it.next().context("peer")?.parse()?;
                let tx_us: u64 = it.next().context("tx-us")?.parse()?;
                let mult: u32 = it.next().context("mult")?.parse()?;
                self.add(discr, local, peer, tx_us, mult.max(1));
            }
            Some("echo-del") => {
                let discr: u32 = it.next().context("discr")?.parse()?;
                self.del(discr);
            }
            Some("detect-add") => {
                let discr: u32 = it.next().context("discr")?.parse()?;
                let detect_us: u64 = it.next().context("detect-us")?.parse()?;
                self.detect_add(discr, detect_us);
            }
            Some("detect-del") => {
                let discr: u32 = it.next().context("discr")?.parse()?;
                self.detect_del(discr);
            }
            other => bail!("unknown command {other:?}"),
        }
        Ok(())
    }

    fn add(&mut self, discr: u32, local: IpAddr, peer: IpAddr, tx_us: u64, mult: u32) {
        let _ = self.io(); // open the socket lazily (logs if it can't)
        let now = Instant::now();
        let tx = Duration::from_micros(tx_us.max(1));
        let detect = tx * mult;
        // First session on this local IP → teach the XDP guard our address.
        let refs = self.ip_refs.entry(local).or_insert(0);
        let first = *refs == 0;
        *refs += 1;
        if first {
            self.local_ip_insert(local);
        }
        // Seed the kernel detector. The timer stays zeroed (uninitialized) until
        // XDP arms it on the first return; the kernel re-zeroes the timer region
        // on this update regardless. `detect_ns` is the re-arm delay.
        if let Err(e) = self.timers.insert(discr, DetectState::seed(detect), 0) {
            warn!("bfd echo sender: ECHO_TIMERS insert discr={discr}: {e}");
        }
        self.sessions.insert(
            discr,
            EchoSession {
                local,
                peer,
                peer_mac: lookup_mac(self.ifindex, peer),
                tx,
                detect,
                next_tx: now,
                added: now,
                seq: 0,
                down: false,
            },
        );
        debug!("bfd echo sender: add discr={discr} {local}->{peer} tx={tx_us}us x{mult}");
    }

    fn del(&mut self, discr: u32) {
        let Some(s) = self.sessions.remove(&discr) else {
            return;
        };
        // Removing the map entry frees its embedded `bpf_timer` — the kernel
        // cancels any pending fire (`bpf_obj_free_fields`).
        let _ = self.timers.remove(&discr);
        let drop_ip = match self.ip_refs.get_mut(&s.local) {
            Some(refs) => {
                *refs = refs.saturating_sub(1);
                *refs == 0
            }
            None => false,
        };
        if drop_ip {
            self.ip_refs.remove(&s.local);
            self.local_ip_remove(s.local);
        }
        debug!("bfd echo sender: del discr={discr}");
    }

    /// Start (or retune) the control-packet expiration watchdog for `discr`.
    /// Re-issuing `detect-add` doubles as an update: replacing the map element
    /// cancels any armed `bpf_timer` (the kernel frees embedded timers on
    /// update) and re-enters the bootstrap window, which the `added` reset
    /// below re-covers.
    fn detect_add(&mut self, discr: u32, detect_us: u64) {
        let detect = Duration::from_micros(detect_us.max(1));
        if let Err(e) = self.ctrl_timers.insert(discr, DetectState::seed(detect), 0) {
            warn!("bfd detect: CONTROL_TIMERS insert discr={discr}: {e}");
        }
        self.detects.insert(
            discr,
            DetectWatch {
                detect,
                added: Instant::now(),
                down: false,
            },
        );
        debug!("bfd detect: add discr={discr} detect={detect_us}us");
    }

    /// Stop watching `discr`. Removing the map entry frees its embedded
    /// `bpf_timer` — the kernel cancels any pending fire.
    fn detect_del(&mut self, discr: u32) {
        if self.detects.remove(&discr).is_some() {
            let _ = self.ctrl_timers.remove(&discr);
            debug!("bfd detect: del discr={discr}");
        }
    }

    /// Poll the control-packet expiration watchdog: report `detect-down`
    /// (once per failure) when a session's kernel timer fired, or when no
    /// control packet armed it within the bootstrap window.
    fn tick_detect(&mut self, out: &mut impl Write) {
        let now = Instant::now();
        for (discr, w) in self.detects.iter_mut() {
            if w.down {
                continue;
            }
            let fired = match self.ctrl_timers.get(discr, 0) {
                Ok(st) => st.down != 0 || (st.armed == 0 && now.duration_since(w.added) > w.detect),
                // Entry vanished (shouldn't happen between add and del): treat
                // as a bootstrap timeout so we don't silently stop detecting.
                Err(_) => now.duration_since(w.added) > w.detect,
            };
            if fired {
                w.down = true;
                let _ = writeln!(out, "detect-down {discr}");
                let _ = out.flush();
            }
        }
    }

    /// Periodic work: poll the expiration watchdog, then transmit due Echoes
    /// and poll the Echo detector. Emits `echo-down` / `detect-down <discr>`
    /// (once per failure) to `out`.
    pub fn tick(&mut self, out: &mut impl Write) {
        // The watchdog half needs no socket — poll it even when Echo is idle
        // (or when CAP_NET_RAW is missing).
        self.tick_detect(out);
        if self.sessions.is_empty() {
            // No originating Echo session ⇒ don't open (or poll) the
            // AF_PACKET socket at all.
            return;
        }
        let Some((fd, if_mac)) = self.io() else {
            return;
        };
        let now = Instant::now();
        let ifindex = self.ifindex;
        for (discr, s) in self.sessions.iter_mut() {
            if now >= s.next_tx {
                if s.peer_mac.is_none() {
                    s.peer_mac = lookup_mac(ifindex, s.peer);
                }
                if let Some(mac) = s.peer_mac {
                    // Build the self-addressed Echo for the session's family and
                    // send it; the peer's forwarding plane (our XDP reflector at
                    // the far end) hairpins it back inbound.
                    let res = match s.local {
                        IpAddr::V4(local) => {
                            let frame =
                                build_echo(&if_mac, &mac, local, *discr, s.seq, now_micros());
                            send_frame(fd, ifindex, ETH_P_IP, &mac, &frame)
                        }
                        IpAddr::V6(local) => {
                            let frame =
                                build_echo_v6(&if_mac, &mac, local, *discr, s.seq, now_micros());
                            send_frame(fd, ifindex, ETH_P_IPV6, &mac, &frame)
                        }
                    };
                    if let Err(e) = res {
                        debug!("bfd echo sender: tx discr={discr}: {e}");
                    }
                    s.seq = s.seq.wrapping_add(1);
                }
                s.next_tx = now + jitter(s.tx);
            }
            if s.down {
                continue;
            }
            // Steady-state detection is in the kernel: read the timer entry's
            // `down` flag (set by the bpf_timer callback when returns stopped).
            // Before the timer arms (`armed == 0`, i.e. no return seen yet), fall
            // back to a userspace timeout from `echo-add` so a forwarding path
            // that's broken from the outset is still caught.
            let fired = match self.timers.get(discr, 0) {
                Ok(st) => st.down != 0 || (st.armed == 0 && now.duration_since(s.added) > s.detect),
                // Entry vanished (shouldn't happen between add and del): treat as
                // a bootstrap timeout so we don't silently stop detecting.
                Err(_) => now.duration_since(s.added) > s.detect,
            };
            if fired {
                s.down = true;
                let _ = writeln!(out, "echo-down {discr}");
                let _ = out.flush();
            }
        }
    }
}

// ---- frame construction / parsing ----------------------------------------

/// Build a self-addressed BFD Echo frame (Eth/IPv4/UDP + our payload). Source
/// and destination IP are both `local` so the peer's forwarding plane loops it
/// straight back; TTL 255 (the peer decrements it on the loop).
fn build_echo(
    if_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    local: Ipv4Addr,
    discr: u32,
    seq: u32,
    ts: u64,
) -> [u8; FRAME_LEN] {
    let mut f = [0u8; FRAME_LEN];
    // Ethernet
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(if_mac);
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    // IPv4
    {
        let ip = &mut f[ETH_HLEN..ETH_HLEN + IP_HLEN];
        ip[0] = 0x45; // version 4, IHL 5
        ip[1] = 0xc0; // DSCP CS6 (internetwork control), matches FRR
        let total = (IP_HLEN + UDP_HLEN + PAYLOAD_LEN) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        // id/flags/frag 0; ttl/proto
        ip[8] = ECHO_TTL;
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&local.octets());
        ip[16..20].copy_from_slice(&local.octets());
        let ipck = checksum(ip, 0);
        ip[10..12].copy_from_slice(&ipck.to_be_bytes());
    }
    // UDP
    let udp_off = ETH_HLEN + IP_HLEN;
    let udp_len = (UDP_HLEN + PAYLOAD_LEN) as u16;
    f[udp_off..udp_off + 2].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 2..udp_off + 4].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    // payload
    let pl = ETH_HLEN + IP_HLEN + UDP_HLEN;
    f[pl..pl + 4].copy_from_slice(&ECHO_MAGIC.to_be_bytes());
    f[pl + 4..pl + 8].copy_from_slice(&discr.to_be_bytes());
    f[pl + 8..pl + 12].copy_from_slice(&seq.to_be_bytes());
    f[pl + 12..pl + 20].copy_from_slice(&ts.to_be_bytes());
    // UDP checksum (pseudo-header + udp + payload)
    let udpck = udp_checksum(&local, &local, &f[udp_off..]);
    f[udp_off + 6..udp_off + 8].copy_from_slice(&udpck.to_be_bytes());
    f
}

/// IPv6 analogue of [`build_echo`]: a self-addressed Eth/IPv6/UDP Echo frame.
/// Source and destination IP are both `local` (link-local) so the peer hairpins
/// it back; Hop Limit 255 (decremented once on the loop). IPv6 has no header
/// checksum; the UDP checksum is mandatory and covers the IPv6 pseudo-header.
fn build_echo_v6(
    if_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    local: Ipv6Addr,
    discr: u32,
    seq: u32,
    ts: u64,
) -> [u8; FRAME6_LEN] {
    let mut f = [0u8; FRAME6_LEN];
    // Ethernet
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(if_mac);
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    // IPv6 (40-byte fixed header)
    {
        let ip = &mut f[ETH_HLEN..ETH_HLEN + IP6_HLEN];
        ip[0] = 0x60; // version 6, traffic class / flow label 0
        let payload_len = (UDP_HLEN + PAYLOAD_LEN) as u16;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes()); // Payload Length
        ip[6] = IPPROTO_UDP; // Next Header
        ip[7] = ECHO_TTL; // Hop Limit (255; peer decrements on the loop)
        ip[8..24].copy_from_slice(&local.octets()); // src
        ip[24..40].copy_from_slice(&local.octets()); // dst (self-addressed)
    }
    // UDP
    let udp_off = ETH_HLEN + IP6_HLEN;
    let udp_len = (UDP_HLEN + PAYLOAD_LEN) as u16;
    f[udp_off..udp_off + 2].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 2..udp_off + 4].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    // payload
    let pl = udp_off + UDP_HLEN;
    f[pl..pl + 4].copy_from_slice(&ECHO_MAGIC.to_be_bytes());
    f[pl + 4..pl + 8].copy_from_slice(&discr.to_be_bytes());
    f[pl + 8..pl + 12].copy_from_slice(&seq.to_be_bytes());
    f[pl + 12..pl + 20].copy_from_slice(&ts.to_be_bytes());
    // UDP checksum (mandatory for IPv6) over pseudo-header + UDP + payload
    let udpck = udp_checksum_v6(&local, &local, &f[udp_off..]);
    f[udp_off + 6..udp_off + 8].copy_from_slice(&udpck.to_be_bytes());
    f
}

/// If `frame` is one of our looped Echoes, return `(discriminator, src-ip)`.
/// Detection moved to the kernel (XDP matches our returns), so this is now only
/// exercised by the build/parse round-trip test below.
#[cfg(test)]
fn parse_return(frame: &[u8]) -> Option<(u32, Ipv4Addr)> {
    if frame.len() < FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETH_P_IP {
        return None;
    }
    let ip = &frame[ETH_HLEN..];
    if ip[0] != 0x45 || ip[9] != IPPROTO_UDP {
        return None;
    }
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let udp = &frame[ETH_HLEN + IP_HLEN..];
    if u16::from_be_bytes([udp[2], udp[3]]) != BFD_ECHO_PORT {
        return None;
    }
    let pl = ETH_HLEN + IP_HLEN + UDP_HLEN;
    if u32::from_be_bytes([frame[pl], frame[pl + 1], frame[pl + 2], frame[pl + 3]]) != ECHO_MAGIC {
        return None;
    }
    let discr = u32::from_be_bytes([frame[pl + 4], frame[pl + 5], frame[pl + 6], frame[pl + 7]]);
    Some((discr, src))
}

/// Internet checksum over `data` plus a 32-bit `initial` accumulator.
fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum: ones-complement over the IPv4 pseudo-header + UDP + payload.
fn udp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for o in [src.octets(), dst.octets()] {
        sum += u16::from_be_bytes([o[0], o[1]]) as u32;
        sum += u16::from_be_bytes([o[2], o[3]]) as u32;
    }
    sum += IPPROTO_UDP as u32;
    sum += udp.len() as u32;
    let ck = checksum(udp, sum);
    if ck == 0 { 0xffff } else { ck }
}

/// UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1) + UDP + payload.
/// The pseudo-header is src(16) + dst(16) + 32-bit Upper-Layer Length +
/// 24-bit zero + Next Header(UDP). IPv6 mandates a non-zero UDP checksum.
fn udp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for a in [src.octets(), dst.octets()] {
        let mut i = 0;
        while i < 16 {
            sum += u16::from_be_bytes([a[i], a[i + 1]]) as u32;
            i += 2;
        }
    }
    sum += udp.len() as u32; // Upper-Layer Packet Length (fits in 16 bits here)
    sum += IPPROTO_UDP as u32; // Next Header (zero-padded high bytes contribute 0)
    let ck = checksum(udp, sum);
    if ck == 0 { 0xffff } else { ck }
}

// ---- socket / interface helpers ------------------------------------------

fn if_nametoindex(iface: &str) -> Result<u32> {
    let cname = std::ffi::CString::new(iface)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        bail!(
            "if_nametoindex({iface}): {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(idx)
}

fn read_if_mac(iface: &str) -> Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("read MAC of {iface}"))?;
    parse_mac(s.trim()).with_context(|| format!("parse MAC {:?}", s.trim()))
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for b in mac.iter_mut() {
        *b = u8::from_str_radix(parts.next().context("mac octet")?, 16)?;
    }
    Ok(mac)
}

/// Resolve `peer` → MAC from the kernel ARP cache (`/proc/net/arp`) on this
/// interface. The OSPF/BFD adjacency keeps the entry warm; `None` if unresolved
/// yet (retried on the next tick).
fn arp_lookup(ifindex: u32, peer: Ipv4Addr) -> Option<[u8; 6]> {
    let want_dev = ifname_of(ifindex)?;
    let text = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in text.lines().skip(1) {
        // IP address  HW type  Flags  HW address  Mask  Device
        let mut c = line.split_whitespace();
        let ip = c.next()?;
        let _hw = c.next()?;
        let _flags = c.next()?;
        let mac = c.next()?;
        let _mask = c.next()?;
        let dev = c.next()?;
        if dev == want_dev
            && ip.parse::<Ipv4Addr>().ok() == Some(peer)
            && mac != "00:00:00:00:00:00"
        {
            return parse_mac(mac).ok();
        }
    }
    None
}

/// Resolve `peer` → MAC for either family on this interface.
fn lookup_mac(ifindex: u32, peer: IpAddr) -> Option<[u8; 6]> {
    match peer {
        IpAddr::V4(p) => arp_lookup(ifindex, p),
        IpAddr::V6(p) => ndp_lookup(ifindex, p),
    }
}

/// Resolve an IPv6 (link-local) `peer` → MAC from the kernel neighbour cache via
/// `ip -6 neigh show dev <ifname>`. There is no `/proc/net` equivalent for the
/// IPv6 neighbour table; BFD control to the peer's link-local keeps the entry
/// warm. `None` if unresolved yet (retried on the next tick).
fn ndp_lookup(ifindex: u32, peer: Ipv6Addr) -> Option<[u8; 6]> {
    let dev = ifname_of(ifindex)?;
    let out = std::process::Command::new("ip")
        .args(["-6", "neigh", "show", "dev", &dev])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // "<addr> lladdr <mac> <state>" (dev given, so no %zone suffix).
        let mut it = line.split_whitespace();
        let Some(addr) = it.next() else { continue };
        if addr.parse::<Ipv6Addr>().ok() != Some(peer) {
            continue;
        }
        while let Some(tok) = it.next() {
            if tok == "lladdr" {
                let mac = it.next()?;
                if mac != "00:00:00:00:00:00" {
                    return parse_mac(mac).ok();
                }
            }
        }
    }
    None
}

fn ifname_of(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return None;
    }
    let c = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    c.to_str().ok().map(str::to_string)
}

fn open_af_packet(ifindex: u32) -> Result<OwnedFd> {
    let proto = (ETH_P_IP).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_NONBLOCK, proto) };
    if fd < 0 {
        bail!("AF_PACKET socket: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (ETH_P_IP).to_be();
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        bail!(
            "bind AF_PACKET to ifindex {ifindex}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(fd)
}

fn send_frame(
    fd: i32,
    ifindex: u32,
    ethertype: u16,
    dst_mac: &[u8; 6],
    frame: &[u8],
) -> std::io::Result<()> {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ethertype.to_be();
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(dst_mac);
    let n = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// 75–100% of `base` (RFC 5880 §6.8.9), derived from the clock to avoid pulling
/// in a RNG crate — only needs to desynchronize sessions, not be unpredictable.
fn jitter(base: Duration) -> Duration {
    let pct = 75 + (now_micros() % 26); // 75..=100
    base * pct as u32 / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_build() {
        let if_mac = [0x02, 0, 0, 0, 0, 1];
        let peer_mac = [0x02, 0, 0, 0, 0, 2];
        let local = Ipv4Addr::new(192, 168, 10, 1);
        let frame = build_echo(&if_mac, &peer_mac, local, 0xdead_beef, 7, 12345);
        assert_eq!(frame.len(), FRAME_LEN);
        assert_eq!(&frame[0..6], &peer_mac); // self-addressed, dst MAC = peer
        assert_eq!(parse_return(&frame), Some((0xdead_beef, local)));
        // A valid IP header sums (incl. its checksum field) to 0 → !0 == 0.
        assert_eq!(checksum(&frame[ETH_HLEN..ETH_HLEN + IP_HLEN], 0), 0);
    }

    #[test]
    fn parse_rejects_foreign_payload() {
        let mut frame = build_echo(&[0; 6], &[0; 6], Ipv4Addr::new(10, 0, 0, 1), 1, 0, 0);
        let pl = ETH_HLEN + IP_HLEN + UDP_HLEN;
        frame[pl] ^= 0xff; // corrupt the magic
        assert_eq!(parse_return(&frame), None);
    }

    /// The userspace mirror must stay byte-identical to the eBPF `DetectState`
    /// (32 bytes, 8-byte aligned, timer at offset 0) — the kernel locates the
    /// embedded `bpf_timer` by the BTF of the eBPF side, and we read/write the
    /// value as raw bytes.
    #[test]
    fn detect_state_layout() {
        assert_eq!(core::mem::size_of::<DetectState>(), 32);
        assert_eq!(core::mem::align_of::<DetectState>(), 8);
        let st = DetectState::seed(Duration::from_micros(900_000));
        assert_eq!(st.detect_ns, 900_000_000);
        assert_eq!((st.armed, st.down), (0, 0));
    }

    #[test]
    fn jitter_in_range() {
        let base = Duration::from_millis(50);
        let j = jitter(base);
        assert!(j >= base * 75 / 100 && j <= base);
    }

    #[test]
    fn mac_parse() {
        assert_eq!(
            parse_mac("00:1c:42:45:b2:35").unwrap(),
            [0x00, 0x1c, 0x42, 0x45, 0xb2, 0x35]
        );
    }

    #[test]
    fn build_echo_v6_layout_and_checksum() {
        let if_mac = [0x02, 0, 0, 0, 0, 1];
        let peer_mac = [0x02, 0, 0, 0, 0, 2];
        let local: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut frame = build_echo_v6(&if_mac, &peer_mac, local, 0xdead_beef, 7, 12345);
        assert_eq!(frame.len(), FRAME6_LEN);
        // self-addressed: dst MAC = peer, ethertype = IPv6
        assert_eq!(&frame[0..6], &peer_mac);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETH_P_IPV6);
        // IPv6 header: version 6, Next Header UDP, Hop Limit 255, src==dst==local
        assert_eq!(frame[ETH_HLEN] >> 4, 6);
        assert_eq!(frame[ETH_HLEN + 6], IPPROTO_UDP);
        assert_eq!(frame[ETH_HLEN + 7], ECHO_TTL);
        assert_eq!(&frame[ETH_HLEN + 8..ETH_HLEN + 24], &local.octets());
        assert_eq!(&frame[ETH_HLEN + 24..ETH_HLEN + 40], &local.octets());
        let udp_off = ETH_HLEN + IP6_HLEN;
        assert_eq!(
            u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]),
            BFD_ECHO_PORT
        );
        // payload magic + discriminator
        let pl = udp_off + UDP_HLEN;
        assert_eq!(
            u32::from_be_bytes([frame[pl], frame[pl + 1], frame[pl + 2], frame[pl + 3]]),
            ECHO_MAGIC
        );
        assert_eq!(
            u32::from_be_bytes([frame[pl + 4], frame[pl + 5], frame[pl + 6], frame[pl + 7]]),
            0xdead_beef
        );
        // The embedded UDP checksum recomputes from the zeroed field (non-zero,
        // as IPv6 mandates).
        let embedded = u16::from_be_bytes([frame[udp_off + 6], frame[udp_off + 7]]);
        assert_ne!(embedded, 0);
        frame[udp_off + 6] = 0;
        frame[udp_off + 7] = 0;
        assert_eq!(udp_checksum_v6(&local, &local, &frame[udp_off..]), embedded);
    }
}
