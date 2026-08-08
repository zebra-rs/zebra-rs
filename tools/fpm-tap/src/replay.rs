//! `fpm-tap replay` — push a recorded trace into a real `fpmsyncd`.
//!
//! This is what makes a capture a *test oracle* rather than a souvenir.
//! Replay FRR's recorded bytes into a live `fpmsyncd`, snapshot APPL_DB;
//! replay zebra-rs's bytes into a freshly-flushed one, snapshot again;
//! diff. The comparison needs neither routing daemon running, so it is
//! fast enough to sit in CI and precise enough to catch a single wrong
//! attribute.
//!
//! Only `zebra -> fpm` records are sent. Recorded offload replies are
//! skipped: they were `fpmsyncd`'s output, and on replay the live
//! `fpmsyncd` will produce its own.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::capture::{self, Dir};
use crate::decode;
use crate::frame::Framer;

pub struct Opts {
    pub input: PathBuf,
    pub target: SocketAddr,
    /// Fixed delay between messages. Zero sends as fast as the socket
    /// accepts.
    pub pace_ms: u64,
    /// Reproduce the original inter-message timing from the capture's
    /// timestamps instead of `--pace-ms`. Useful when a bug only shows
    /// up under the original arrival pattern.
    pub realtime: bool,
    /// Keep reading replies for this long after the last message, so
    /// asynchronous offload acknowledgements are counted.
    pub linger_ms: u64,
    pub quiet: bool,
}

pub async fn run(opts: Opts) -> Result<()> {
    let records = capture::read(&opts.input)?;
    let outbound: Vec<_> = records.iter().filter(|r| r.dir == Dir::ToFpm).collect();
    let skipped = records.len() - outbound.len();

    eprintln!(
        "fpm-tap: replaying {} messages from {} to {}{}",
        outbound.len(),
        opts.input.display(),
        opts.target,
        if skipped > 0 {
            format!(" ({skipped} recorded replies skipped)")
        } else {
            String::new()
        }
    );

    let stream = TcpStream::connect(opts.target)
        .await
        .with_context(|| format!("cannot connect to fpmsyncd at {}", opts.target))?;
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();

    // Count what comes back. With `bgp suppress-fib-pending` this is the
    // signal the encoder work in Phase 2 has to consume, so it is worth
    // seeing even in a plain replay.
    //
    // Replies accumulate into shared state rather than being returned,
    // because this task is never awaited to completion: `fpmsyncd` keeps
    // the connection open indefinitely, so the read half only ends at
    // EOF that never comes. Dropping the write half does not produce one
    // either — a split TcpStream is not closed until *both* halves are
    // gone, so with the reader still holding `rd` the peer sees no FIN.
    // The send loop therefore aborts the reader after the linger window
    // and collects whatever landed.
    let replies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&replies);
    let reader = tokio::spawn(async move {
        let mut framer = Framer::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            framer.extend(&buf[..n]);
            while let Ok(Some(msg)) = framer.next() {
                collected.lock().await.push(msg);
            }
        }
    });

    let mut prev_usec = outbound.first().map(|r| r.usec).unwrap_or(0);
    for (i, rec) in outbound.iter().enumerate() {
        if opts.realtime {
            let gap = rec.usec.saturating_sub(prev_usec);
            if gap > 0 {
                tokio::time::sleep(Duration::from_micros(gap)).await;
            }
            prev_usec = rec.usec;
        } else if opts.pace_ms > 0 && i > 0 {
            tokio::time::sleep(Duration::from_millis(opts.pace_ms)).await;
        }

        wr.write_all(&rec.bytes)
            .await
            .with_context(|| format!("write failed at message {i}"))?;

        if !opts.quiet {
            println!("[{i:>5}] -> {}", decode::decode(&rec.bytes).summary);
        }
    }
    wr.flush().await?;

    // Give fpmsyncd time to answer before we tear the socket down. Any
    // reply still in flight when the window closes is lost, which is the
    // cost of not being able to wait for an EOF the peer never sends;
    // raise --linger-ms if a slow responder is being clipped.
    tokio::time::sleep(Duration::from_millis(opts.linger_ms)).await;
    reader.abort();
    drop(wr);

    let replies = replies.lock().await;
    eprintln!(
        "fpm-tap: sent {} messages, received {} replies",
        outbound.len(),
        replies.len()
    );
    if !opts.quiet {
        for (i, msg) in replies.iter().enumerate() {
            println!("[{i:>5}] <- {}", decode::decode(msg).summary);
        }
    }
    Ok(())
}
