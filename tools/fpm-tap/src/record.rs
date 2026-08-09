//! `fpm-tap record` — stand in for `fpmsyncd` and capture what zebra sends.
//!
//! `fpmsyncd` is the **server** side of FPM (it listens on TCP 2620 and
//! zebra dials out — `fpmsyncd/fpmlink.h:29-31`), so a recorder only has
//! to occupy that port. Two modes:
//!
//! * **Terminating** (no `--forward`): we are the only FPM peer. Good
//!   for capturing a clean trace from a standalone FRR with nothing else
//!   running.
//! * **Proxying** (`--forward host:port`): sit between zebra and a real
//!   `fpmsyncd` and record both directions while the real system keeps
//!   working. This is the only way to capture the **reverse** channel —
//!   the `RTM_F_OFFLOAD` acknowledgements — because those only exist if
//!   something is actually writing APPL_DB and reading APPL_STATE_DB.
//!
//! Bytes are passed through untouched and recorded as-is. The decoder is
//! only used to print a running summary.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::capture::{Dir, Writer};
use crate::decode;
use crate::frame::Framer;

pub struct Opts {
    pub listen: SocketAddr,
    pub forward: Option<SocketAddr>,
    pub out: PathBuf,
    pub quiet: bool,
    pub sync: bool,
    pub once: bool,
}

/// Shared capture state. A single mutex serializes both directions so
/// records land in true arrival order — with two independent tasks
/// writing, ordering is the only thing that could get scrambled, and a
/// trace whose causality is wrong is worse than no trace.
struct Sink {
    writer: Writer,
    start: Instant,
    sync: bool,
    quiet: bool,
}

impl Sink {
    fn record(&mut self, dir: Dir, msg: &[u8]) -> Result<()> {
        let usec = self.start.elapsed().as_micros() as u64;
        self.writer.write(dir, usec, msg)?;
        if self.sync {
            self.writer.flush()?;
        }
        if !self.quiet {
            let d = decode::decode(msg);
            println!(
                "[{:>10.6}] {} {}",
                usec as f64 / 1_000_000.0,
                dir.arrow(),
                d.summary
            );
        }
        Ok(())
    }
}

pub async fn run(opts: Opts) -> Result<()> {
    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("cannot bind {} — is fpmsyncd already running?", opts.listen))?;

    let writer = Writer::create(&opts.out)?;
    let sink = Arc::new(Mutex::new(Sink {
        writer,
        start: Instant::now(),
        sync: opts.sync,
        quiet: opts.quiet,
    }));

    eprintln!(
        "fpm-tap: listening on {} -> {}{}",
        opts.listen,
        opts.out.display(),
        match opts.forward {
            Some(f) => format!(" (forwarding to {f})"),
            None => String::new(),
        }
    );

    loop {
        let (stream, peer) = listener.accept().await.context("accept failed")?;
        eprintln!("fpm-tap: connection from {peer}");
        // Nagle would coalesce and delay the small messages FPM is made
        // of; disable it so the recorded timestamps reflect when zebra
        // produced a message rather than when the stack chose to flush.
        stream.set_nodelay(true).ok();

        if let Err(e) = session(stream, opts.forward, Arc::clone(&sink)).await {
            eprintln!("fpm-tap: session ended: {e:#}");
        } else {
            eprintln!("fpm-tap: connection closed");
        }

        {
            let mut s = sink.lock().await;
            s.writer.flush()?;
            eprintln!("fpm-tap: {} messages captured so far", s.writer.count());
        }

        if opts.once {
            break;
        }
        // Otherwise keep listening: zebra reconnects after a restart,
        // and a reconnect is itself worth capturing — it triggers the
        // full-table resync that FPM's replace semantics require.
    }
    Ok(())
}

async fn session(
    down: TcpStream,
    forward: Option<SocketAddr>,
    sink: Arc<Mutex<Sink>>,
) -> Result<()> {
    let (mut down_r, mut down_w) = down.into_split();

    let Some(target) = forward else {
        // Terminating mode: drain and record. Nothing is written back,
        // which is exactly what a bare fpmsyncd with no orchagent behind
        // it would do.
        let mut framer = Framer::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = down_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            framer.extend(&buf[..n]);
            while let Some(msg) = framer.next()? {
                sink.lock().await.record(Dir::ToFpm, &msg)?;
            }
        }
        if framer.pending() > 0 {
            eprintln!(
                "fpm-tap: warning — peer closed with {} bytes of a partial message",
                framer.pending()
            );
        }
        return Ok(());
    };

    let up = TcpStream::connect(target)
        .await
        .with_context(|| format!("cannot connect to upstream fpmsyncd at {target}"))?;
    up.set_nodelay(true).ok();
    let (mut up_r, mut up_w) = up.into_split();

    let sink_down = Arc::clone(&sink);
    let to_fpm = tokio::spawn(async move {
        let mut framer = Framer::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = down_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            framer.extend(&buf[..n]);
            while let Some(msg) = framer.next()? {
                sink_down.lock().await.record(Dir::ToFpm, &msg)?;
                up_w.write_all(&msg).await?;
            }
        }
        anyhow::Ok(())
    });

    let to_zebra = tokio::spawn(async move {
        let mut framer = Framer::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = up_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            framer.extend(&buf[..n]);
            while let Some(msg) = framer.next()? {
                sink.lock().await.record(Dir::ToZebra, &msg)?;
                down_w.write_all(&msg).await?;
            }
        }
        anyhow::Ok(())
    });

    // Either half closing ends the session; the surviving task is
    // dropped with its socket, which tears the other side down too.
    tokio::select! {
        r = to_fpm => r.context("downstream task panicked")?,
        r = to_zebra => r.context("upstream task panicked")?,
    }
}
