use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("../proto/vty.proto")?;
    // Running-config subscription API (zebra.config.v1).
    tonic_prost_build::compile_protos("../proto/config.proto")?;
    // External show-provider API (zebra.show.v1).
    tonic_prost_build::compile_protos("../proto/show.proto")?;
    // cradle eBPF data-plane control API (FibHandle tee target).
    tonic_prost_build::compile_protos("../proto/cradle.proto")?;

    // Capture git information at build time
    set_git_info();

    Ok(())
}

fn set_git_info() {
    // Get git commit hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Get git commit date
    let git_date = Command::new("git")
        .args(["log", "-1", "--format=%cd", "--date=iso"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Get git commit message (first line)
    let git_message = Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Get git branch name
    let git_branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Check if repository is dirty
    let git_dirty = Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(false);

    // Get build date
    let build_date = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // Set environment variables for use in the binary
    println!("cargo:rustc-env=GIT_HASH={git_hash}");
    println!("cargo:rustc-env=GIT_DATE={git_date}");
    println!("cargo:rustc-env=GIT_MESSAGE={git_message}");
    println!("cargo:rustc-env=GIT_BRANCH={git_branch}");
    println!("cargo:rustc-env=GIT_DIRTY={git_dirty}");
    println!("cargo:rustc-env=BUILD_DATE={build_date}");

    // Rerun the build script when HEAD or a ref moves. The paths are
    // resolved through git rather than assumed to be `../.git/<name>`,
    // because `../.git` is only a directory in a primary checkout: in a
    // linked git worktree it is a FILE holding `gitdir: …`, so
    // `../.git/HEAD` does not exist. `rerun-if-changed` on a MISSING path
    // makes cargo treat the build script as permanently dirty, which fully
    // rebuilt zebra-rs — the largest crate in the workspace — on every
    // cargo invocation in every worktree (and in any source-tarball build,
    // which has no git metadata at all). A path that still doesn't resolve
    // is therefore skipped rather than emitted.
    for name in ["HEAD", "refs"] {
        if let Some(path) = git_path(name) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

/// Absolute path to `name` inside the repository's git directory, or `None`
/// when this is not a git checkout.
///
/// `git rev-parse --git-path` knows the linked-worktree split that a plain
/// `../.git/<name>` join cannot express: HEAD lives in the worktree's
/// private directory while `refs` lives in the shared common directory.
fn git_path(name: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?.trim().to_string();
    std::path::Path::new(&path).exists().then_some(path)
}
