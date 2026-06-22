//! Non-blocking side-effect channel for scripts (feature = "lua").
//!
//! Scripts must never block the route-processing thread on external I/O.
//! Instead a hook calls `sideeffect.nft{...}`, which enqueues an [`NftOp`]
//! onto an unbounded channel drained by a dedicated background task that
//! runs the `nft` command off the hot path. Ordering is preserved per the
//! single drainer, so an import's `add` and a later withdraw's `delete`
//! of the same element stay in order.

use std::sync::{OnceLock, RwLock};

use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

/// One nftables set-element mutation requested by a script.
#[derive(Debug, Clone)]
pub struct NftOp {
    /// `true` → `nft add element`, `false` → `nft delete element`.
    pub add: bool,
    /// Table spec including family, e.g. `"bridge gbp_filter"`.
    pub table: String,
    /// Set name, e.g. `"tag_100"`.
    pub set: String,
    /// Element, e.g. a MAC `"aa:bb:cc:dd:ee:01"`.
    pub elem: String,
}

static SENDER: OnceLock<RwLock<Option<UnboundedSender<NftOp>>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<UnboundedSender<NftOp>>> {
    SENDER.get_or_init(|| RwLock::new(None))
}

/// Enqueue an op for the drainer. A no-op (dropped, with a one-shot warn
/// elsewhere) when no drainer is running — a script can still be exercised
/// without one.
pub fn enqueue(op: NftOp) {
    if let Some(tx) = slot().read().unwrap().as_ref() {
        let _ = tx.send(op);
    }
}

/// Spawn the background drainer task (idempotent — a second call while one
/// is registered is a no-op). Must be called inside the tokio runtime,
/// once, at daemon startup.
pub fn spawn_drainer() {
    let (tx, mut rx) = unbounded_channel::<NftOp>();
    {
        let mut guard = slot().write().unwrap();
        if guard.is_some() {
            return;
        }
        *guard = Some(tx);
    }
    tokio::spawn(async move {
        while let Some(op) = rx.recv().await {
            let args = nft_args(&op);
            match tokio::process::Command::new("nft")
                .args(&args)
                .status()
                .await
            {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    tracing::warn!("lua sideeffect: nft {args:?} exited with {status}")
                }
                Err(err) => tracing::warn!("lua sideeffect: nft spawn failed: {err}"),
            }
        }
    });
}

/// Build the `nft` argv for an op, e.g.
/// `["add", "element", "bridge", "gbp_filter", "tag_100", "{", "aa:..", "}"]`.
fn nft_args(op: &NftOp) -> Vec<String> {
    let mut args = vec![
        if op.add { "add" } else { "delete" }.to_string(),
        "element".to_string(),
    ];
    args.extend(op.table.split_whitespace().map(str::to_string));
    args.push(op.set.clone());
    args.push("{".to_string());
    args.push(op.elem.clone());
    args.push("}".to_string());
    args
}

/// Test-only: install a sender so a test can drain enqueued ops without a
/// running drainer / tokio runtime.
#[cfg(test)]
pub fn set_sender(tx: UnboundedSender<NftOp>) {
    *slot().write().unwrap() = Some(tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_args_add_and_delete() {
        let add = NftOp {
            add: true,
            table: "bridge gbp_filter".into(),
            set: "tag_100".into(),
            elem: "aa:bb:cc:dd:ee:01".into(),
        };
        assert_eq!(
            nft_args(&add),
            vec![
                "add",
                "element",
                "bridge",
                "gbp_filter",
                "tag_100",
                "{",
                "aa:bb:cc:dd:ee:01",
                "}",
            ]
        );
        let del = NftOp { add: false, ..add };
        assert_eq!(nft_args(&del)[0], "delete");
    }
}
